# cli/commands/sentinel/scan.py
#
# Purpose:
# verdict sentinel scan — post-deployment reality verification.
#
# Sentinel asks: "Did reality align with the governance decision?"
# Verdict asks:  "Should this deployment be allowed?"
#
# These are different questions at different lifecycle stages.
# Sentinel never creates new governance decisions — it records
# outcomes against existing decisions. This keeps the telemetry
# streams cleanly separated:
#
#   verdict evaluate  → decisions table  (what should happen)
#   sentinel scan     → outcomes table   (what actually happened)
#
# Usage:
#   # Compare current plan against most recent decision
#   verdict sentinel scan --plan terraform_plan.json
#
#   # Compare against a specific recorded decision
#   verdict sentinel scan \
#     --plan        terraform_plan.json \
#     --decision-id abc3a13b-83d5-4fad-87d8
#
#   # Override policy path (for decisions recorded before v0.4.0)
#   verdict sentinel scan \
#     --plan   terraform_plan.json \
#     --policy policies/cost/basic_budget.yaml
#
# Exit codes:
#   0   No drift detected
#   1   Drift or compliance violation detected
#   2   Error (no history, missing policy, evaluation failure)

from __future__ import annotations

import json
import logging
from typing import Any, Optional

import typer

from context.context_builder import build_context
from engine.orchestrator import PolicyOrchestrator
from engine.policy_loader import load_policy
from engine.validator import validate_policy
from telemetry.config import get_db_path, is_telemetry_enabled
from telemetry.store import (
    get_decision_by_id,
    get_recent_decisions,
    record_outcome,
)

sentinel_app = typer.Typer(
    help="Sentinel — post-deployment reality verification.",
)

# ── Outcome type constants ────────────────────────────
#
# Plan-comparison outcomes (Sentinel MVP — no cloud API):
#   no_drift             — plan state unchanged, decision holds
#   drift_detected       — conditions or risk score changed
#   compliance_violation — previously passing conditions now failing
#   budget_overrun       — cost risk escalated significantly
#
# Reserved for Sentinel with cloud API access (future):
#   deployment_success   — deployment completed successfully
#   deployment_failure   — deployment failed post-authorization
#   security_incident    — security event after allowed deployment
#   availability_event   — availability impact after deployment
#   manual_rollback      — deployment manually rolled back

_OUTCOME_NO_DRIFT = "no_drift"
_OUTCOME_DRIFT_DETECTED = "drift_detected"
_OUTCOME_COMPLIANCE_VIOLATION = "compliance_violation"
_OUTCOME_BUDGET_OVERRUN = "budget_overrun"

# Risk score increase above this threshold triggers drift_detected
# even when conditions have not changed.
_RISK_DELTA_THRESHOLD = 20

# Width for the formatted report output
_WIDTH = 72


@sentinel_app.command()
def scan(
    plan: str = typer.Option(
        ...,
        "--plan",
        help="Path to the current Terraform plan JSON file.",
    ),
    decision_id: Optional[str] = typer.Option(
        None,
        "--decision-id",
        help=(
            "Governance decision ID to compare against. "
            "Defaults to the most recent recorded decision."
        ),
    ),
    policy: Optional[str] = typer.Option(
        None,
        "--policy",
        help=(
            "Policy path override. "
            "Only required for decisions recorded before v0.4.0 "
            "when policy_path was not yet stored."
        ),
    ),
    role: str = typer.Option(
        "engineer",
        "--role",
        help="Role for the re-evaluation context.",
    ),
    current_spend: float = typer.Option(
        0.0,
        "--current-spend",
        help="Current period spend in USD for cost context.",
    ),
    pricing: str = typer.Option(
        "table",
        "--pricing",
        help="Pricing mode: table (default) or live.",
    ),
    region: str = typer.Option(
        "eastus",
        "--region",
        help="Cloud region for live pricing.",
    ),
) -> None:
    """
    Compare the current infrastructure plan against a previous
    governance decision and detect drift.

    Loads the comparison decision from governance history.
    Uses the policy path stored in that decision to re-evaluate
    the current plan — no need to re-specify the policy.

    Records an outcome event to governance history.
    Does not create a new governance decision.

    Exit codes:
      0   No drift detected
      1   Drift or compliance violation detected
      2   Error (no history, missing policy, evaluation failure)

    Examples:

      Compare current plan against last decision:
        verdict sentinel scan --plan terraform_plan.json

      Compare against a specific decision:
        verdict sentinel scan \\
          --plan        terraform_plan.json \\
          --decision-id abc3a13b-83d5-4fad-87d8

      Override policy for pre-v0.4.0 decisions:
        verdict sentinel scan \\
          --plan   terraform_plan.json \\
          --policy policies/cost/basic_budget.yaml
    """

    # Suppress audit logger output — sentinel output is
    # the comparison report, not evaluation log events.
    logging.disable(logging.INFO)

    # ── Governance history gate ───────────────────────
    if not is_telemetry_enabled():
        typer.echo(
            "\n  Governance history is disabled.\n"
            "  Sentinel requires decision history to compare against.\n\n"
            "  To enable:\n"
            "    export OW_HISTORY_ENABLED=true\n\n"
            f"  Storage: {get_db_path()}\n"
        )
        raise typer.Exit(code=2)

    # ── Load comparison decision ──────────────────────
    previous: dict[str, Any] | None = None

    if decision_id:
        previous = get_decision_by_id(decision_id)
        if not previous:
            typer.echo(
                f"\n  Decision not found: {decision_id}\n"
                f"  Run 'verdict audit' to see recorded decisions.\n"
            )
            raise typer.Exit(code=2)
    else:
        recent = get_recent_decisions(limit=1)
        if not recent:
            typer.echo(
                "\n  No governance decisions found in history.\n"
                "  Run 'verdict evaluate' first to record a decision.\n"
            )
            raise typer.Exit(code=2)
        previous = recent[0]

    # ── Resolve policy path ───────────────────────────
    # Use --policy override if provided.
    # Otherwise load from the stored decision record.
    # policy_path is stored since v0.4.0 — older decisions
    # will have NULL and require the --policy fallback.

    policy_path: str | None = policy or previous.get("policy_path")

    if not policy_path:
        typer.echo(
            "\n  Policy path not found in decision record.\n"
            "  This decision was recorded before v0.4.0.\n\n"
            "  Provide the policy path manually:\n"
            "    verdict sentinel scan \\\n"
            "      --plan   terraform_plan.json \\\n"
            "      --policy <path-to-policy>\n"
        )
        raise typer.Exit(code=2)

    # ── Re-evaluate current plan ──────────────────────
    try:
        policy_dict: dict[str, Any] = load_policy(policy_path)
        validate_policy(policy_dict)

        context: dict[str, Any] = build_context(
            plan_path=plan,
            current_spend=current_spend,
            pricing_mode=pricing,
            region=region,
        )

        engine = PolicyOrchestrator.from_policy_path(policy_path)
        current_result: dict[str, Any] = engine.evaluate(
            context=context,
            user_role=role,
        )

    except Exception as e:
        typer.echo(f"\n  Evaluation error during Sentinel scan.\n  Error: {e}\n")
        raise typer.Exit(code=2)

    # ── Extract comparison data ───────────────────────
    previous_decision: str = str(previous.get("decision", ""))
    current_decision: str = str(current_result.get("decision", ""))

    previous_risk: int = int(previous.get("overall_risk_score", 0))
    current_risk: int = int(
        current_result.get("risk_summary", {}).get("overall_risk_score", 0)
    )
    risk_delta: int = current_risk - previous_risk

    # Previous conditions from stored history
    previous_failed: set[str] = set(
        json.loads(previous.get("failed_conditions") or "[]")
    )
    previous_passed: set[str] = set(
        json.loads(previous.get("passed_conditions") or "[]")
    )

    # Current conditions from re-evaluation
    current_trace: list[dict[str, Any]] = current_result.get("trace", [])
    current_failed: set[str] = {
        t["condition_id"] for t in current_trace if not t.get("result", True)
    }
    current_passed: set[str] = {
        t["condition_id"] for t in current_trace if t.get("result", True)
    }

    # Conditions that changed state
    new_failures: set[str] = current_failed - previous_failed
    newly_resolved: set[str] = previous_failed - current_failed

    # All conditions seen across both evaluations
    all_conditions: set[str] = (
        previous_failed | previous_passed | current_failed | current_passed
    )

    # ── Determine outcome type ────────────────────────
    #
    # compliance_violation: previously passing conditions now failing.
    #   Highest priority — governance was satisfied before,
    #   reality has since diverged.
    #
    # budget_overrun: cost risk analyzer score increased significantly.
    #   Indicates the plan's cost profile has grown beyond
    #   what was previously evaluated.
    #
    # drift_detected: any change in conditions or risk score.
    #   Includes newly resolved conditions (improvement) and
    #   significant risk score changes in either direction.
    #
    # no_drift: plan state matches previous evaluation exactly.
    #   Neutral — not a success assertion. Sentinel cannot know
    #   whether a deployment succeeded without cloud API access.
    #   deployment_success is reserved for future Sentinel versions
    #   that can observe actual infrastructure state via cloud APIs.

    compliance_violation: bool = bool(new_failures)
    drift_detected: bool = bool(new_failures or newly_resolved) or (
        abs(risk_delta) >= _RISK_DELTA_THRESHOLD
    )

    # Budget overrun: cost risk analyzer score increased significantly
    previous_analyzer_scores: dict[str, int] = json.loads(
        previous.get("analyzer_scores") or "{}"
    )
    current_analyzer_scores: dict[str, int] = current_result.get(
        "risk_summary", {}
    ).get("analyzer_scores", {})
    previous_cost_risk: int = int(previous_analyzer_scores.get("cost_analysis", 0))
    current_cost_risk: int = int(current_analyzer_scores.get("cost_analysis", 0))
    budget_overrun: bool = (
        current_cost_risk - previous_cost_risk
    ) >= _RISK_DELTA_THRESHOLD

    if compliance_violation:
        outcome_type = _OUTCOME_COMPLIANCE_VIOLATION
        outcome_severity = "high"
    elif budget_overrun:
        outcome_type = _OUTCOME_BUDGET_OVERRUN
        outcome_severity = "medium"
    elif drift_detected:
        outcome_type = _OUTCOME_DRIFT_DETECTED
        outcome_severity = "low"
    else:
        # No drift detected. Using no_drift rather than deployment_success
        # because Sentinel cannot observe whether a deployment actually
        # occurred or succeeded without cloud API access.
        outcome_type = _OUTCOME_NO_DRIFT
        outcome_severity = "informational"

    # ── Record outcome to history ─────────────────────
    # Sentinel writes ONLY to the outcomes table.
    # No new decision record is created.

    record_outcome(
        decision_id=str(previous.get("id", "")),
        outcome_type=outcome_type,
        severity=outcome_severity,
        description=(
            f"Sentinel scan: {outcome_type}. "
            f"Previous: {previous_decision} (risk {previous_risk}/100). "
            f"Current: {current_decision} (risk {current_risk}/100)."
        ),
        metadata={
            "previous_decision": previous_decision,
            "current_decision": current_decision,
            "previous_risk_score": previous_risk,
            "current_risk_score": current_risk,
            "risk_delta": risk_delta,
            "new_failures": sorted(new_failures),
            "newly_resolved": sorted(newly_resolved),
            "plan_path": plan,
            "policy_path": policy_path,
        },
    )

    # ── Print scan report ─────────────────────────────
    _print_scan_report(
        previous=previous,
        current_result=current_result,
        previous_decision=previous_decision,
        current_decision=current_decision,
        previous_risk=previous_risk,
        current_risk=current_risk,
        risk_delta=risk_delta,
        all_conditions=all_conditions,
        previous_failed=previous_failed,
        current_failed=current_failed,
        new_failures=new_failures,
        newly_resolved=newly_resolved,
        outcome_type=outcome_type,
        plan=plan,
        policy_path=policy_path,
    )

    # ── Exit code ─────────────────────────────────────
    if compliance_violation or drift_detected:
        raise typer.Exit(code=1)

    raise typer.Exit(code=0)


# =====================================================
# REPORT RENDERER
# =====================================================


def _print_scan_report(
    previous: dict[str, Any],
    current_result: dict[str, Any],
    previous_decision: str,
    current_decision: str,
    previous_risk: int,
    current_risk: int,
    risk_delta: int,
    all_conditions: set[str],
    previous_failed: set[str],
    current_failed: set[str],
    new_failures: set[str],
    newly_resolved: set[str],
    outcome_type: str,
    plan: str,
    policy_path: str,
) -> None:
    """Render the Sentinel drift detection report."""

    short_id: str = str(previous.get("id", ""))[:8]
    timestamp: str = str(previous.get("timestamp", ""))[:19].replace("T", " ")
    policy_name: str = str(previous.get("policy_name", ""))

    typer.echo("\n" + "─" * _WIDTH)
    typer.echo("  ObsidianWall Sentinel — Drift Detection Report")
    typer.echo("─" * _WIDTH)

    typer.echo(f"\n  Decision:  {short_id}  ({timestamp})")
    typer.echo(f"  Policy:    {policy_name}")
    typer.echo(f"  Plan:      {plan}")

    # ── Decision comparison ───────────────────────────
    typer.echo(f"\n{'─' * _WIDTH}")
    typer.echo("  Decision Comparison")
    typer.echo("─" * _WIDTH)

    prev_icon: str = (
        "✅"
        if "ALLOW" in previous_decision and "DENY" not in previous_decision
        else "🚫"
    )
    curr_icon: str = (
        "✅" if "ALLOW" in current_decision and "DENY" not in current_decision else "🚫"
    )

    typer.echo(
        f"  Previous:  {prev_icon} {previous_decision:<28}  risk: {previous_risk}/100"
    )
    typer.echo(
        f"  Current:   {curr_icon} {current_decision:<28}  risk: {current_risk}/100"
    )

    delta_str: str = f"+{risk_delta}" if risk_delta > 0 else str(risk_delta)
    if risk_delta != 0:
        typer.echo(f"  Risk delta: {delta_str}")

    # ── Condition comparison ──────────────────────────
    if all_conditions:
        typer.echo(f"\n{'─' * _WIDTH}")
        typer.echo("  Condition Comparison")
        typer.echo("─" * _WIDTH)

        for condition in sorted(all_conditions):
            was_fail: bool = condition in previous_failed
            now_fail: bool = condition in current_failed
            is_new: bool = condition in new_failures
            resolved: bool = condition in newly_resolved

            prev_sym: str = "✗ FAIL" if was_fail else "✓ PASS"
            curr_sym: str = "✗ FAIL" if now_fail else "✓ PASS"

            if is_new:
                note = "  ← NEW FAILURE"
            elif resolved:
                note = "  ← RESOLVED"
            else:
                note = "  unchanged"

            typer.echo(f"  {condition:<38}  {prev_sym} → {curr_sym}{note}")

    # ── Outcome ───────────────────────────────────────
    typer.echo(f"\n{'─' * _WIDTH}")
    typer.echo("  Outcome")
    typer.echo("─" * _WIDTH)

    _OUTCOME_DISPLAY: dict[str, tuple[str, str]] = {
        _OUTCOME_NO_DRIFT: ("✅", "No drift detected"),
        _OUTCOME_DRIFT_DETECTED: ("⚠ ", "Drift detected"),
        _OUTCOME_COMPLIANCE_VIOLATION: (
            "🚨",
            "Compliance violation — previously passing conditions now failing",
        ),
        _OUTCOME_BUDGET_OVERRUN: (
            "💰",
            "Budget overrun — cost risk increased significantly",
        ),
    }

    icon, label = _OUTCOME_DISPLAY.get(outcome_type, ("ℹ ", outcome_type))
    typer.echo(f"  {icon} {label}")
    typer.echo(f"  Recorded: {outcome_type}")

    if new_failures:
        typer.echo("\n  New failures:")
        for condition in sorted(new_failures):
            typer.echo(f"    ✗ {condition}")

    if newly_resolved:
        typer.echo("\n  Resolved:")
        for condition in sorted(newly_resolved):
            typer.echo(f"    ✓ {condition}")

    typer.echo("\n" + "─" * _WIDTH + "\n")
