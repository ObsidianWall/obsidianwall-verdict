# cli/commands/sentinel/scan.py
#
# Purpose:
# verdict sentinel scan — post-deployment reality verification.
#
# Sentinel asks: "Did reality align with the governance decision?"
# Verdict asks:  "Should this deployment be allowed?"
#
# v0.6.0: reads from telemetry/governance_store.py
# (governance_records + governance_history), replacing the
# v0.5.x telemetry/store.py functions.
#
#   verdict evaluate  → governance_records + governance_history
#                       (CREATED entry) — what should happen
#   sentinel scan      → governance_history (outcome / drift
#                       entries) — what actually happened
#
# Field name change: the primary key on a governance record
# is "record_id", not "id" (the old decisions table's column
# name). failed_conditions/passed_conditions/analyzer_scores
# are now stored directly on governance_records, same as the
# old decisions table — Sentinel reads them the same way it
# always did, just from the new table.
#
# Usage:
#   verdict sentinel scan --plan terraform_plan.json
#   verdict sentinel scan --plan terraform_plan.json --decision-id abc3a13b
#   verdict sentinel scan --plan terraform_plan.json --policy policies/cost/basic_budget.yaml
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

from cli.display import decision_icon
from context.context_builder import build_context
from engine.orchestrator import PolicyOrchestrator
from engine.policy_loader import load_policy
from engine.validator import validate_policy
from notifications import dispatch_notifications
from telemetry.config import get_db_path, is_telemetry_enabled
from telemetry.governance_store import (
    add_history_entry,
    get_governance_record,
    get_most_recent_record,
)

sentinel_app = typer.Typer(
    help="Sentinel — post-deployment reality verification.",
)

# ── Outcome type constants ────────────────────────────
#
# Plan-comparison outcomes (Sentinel MVP — no cloud API):
#   no_drift             — plan state unchanged, decision holds
#   drift_detected        — conditions or risk score changed
#   compliance_violation  — previously passing conditions now failing
#   budget_overrun         — cost risk escalated significantly
#
# Reserved for Sentinel with cloud API access (future):
#   deployment_success, deployment_failure, security_incident,
#   availability_event, manual_rollback

_OUTCOME_NO_DRIFT = "no_drift"
_OUTCOME_DRIFT_DETECTED = "drift_detected"
_OUTCOME_COMPLIANCE_VIOLATION = "compliance_violation"
_OUTCOME_BUDGET_OVERRUN = "budget_overrun"

# Risk score increase above this threshold triggers drift_detected
# even when conditions have not changed.
_RISK_DELTA_THRESHOLD = 20

# Width for the formatted report output
_WIDTH = 72


# =====================================================
# History category/action mapping for outcome types
#
# governance_history splits events into history_category +
# history_action rather than one flat outcome_type string.
# This maps Sentinel's plan-comparison outcomes onto that
# two-dimensional model.
# =====================================================

_OUTCOME_TO_HISTORY: dict[str, tuple[str, str]] = {
    _OUTCOME_NO_DRIFT: ("outcome", "observed"),
    _OUTCOME_DRIFT_DETECTED: ("drift", "detected"),
    _OUTCOME_COMPLIANCE_VIOLATION: ("drift", "detected"),
    _OUTCOME_BUDGET_OVERRUN: ("drift", "detected"),
}


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
            "Governance record ID to compare against. "
            "Defaults to the most recent recorded decision."
        ),
    ),
    policy: Optional[str] = typer.Option(
        None,
        "--policy",
        help=(
            "Policy path override. "
            "Only required if the stored record has no "
            "policy_path (should not occur for records "
            "created under v0.6.0)."
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

    Loads the comparison record from governance history.
    Re-evaluates the current plan against the same policy.
    Records an outcome entry to governance history. Does not
    create a new governance record.

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

      Override policy explicitly:
        verdict sentinel scan \\
          --plan   terraform_plan.json \\
          --policy policies/cost/basic_budget.yaml
    """
    # Suppress structured INFO logs by default — same pattern
    # as verdict evaluate's --verbose flag. Sentinel's own
    # report is the point, not the internal evaluation trace.
    logging.disable(logging.INFO)

    # ── Governance history gate ───────────────────────
    if not is_telemetry_enabled():
        typer.echo(
            "\n  Governance history is disabled.\n"
            "  Sentinel requires decision history to compare against.\n\n"
            "  To enable:\n"
            "    unset OW_HISTORY_ENABLED\n\n"
            f"  Storage: {get_db_path()}\n"
        )
        raise typer.Exit(code=2)

    # ── Load comparison record ────────────────────────
    previous: dict[str, Any] | None = None
    if decision_id:
        previous = get_governance_record(decision_id)
        if not previous:
            typer.echo(
                f"\n  Governance record not found: {decision_id}\n"
                f"  Run 'verdict audit' to see recorded decisions.\n"
            )
            raise typer.Exit(code=2)
    else:
        previous = get_most_recent_record()
        if not previous:
            typer.echo(
                "\n  No governance records found in history.\n"
                "  Run 'verdict evaluate' first to record a decision.\n"
            )
            raise typer.Exit(code=2)

    # ── Resolve policy path ───────────────────────────
    # governance_records does not store policy_path directly
    # (only policy_content_hash, for privacy). --policy is
    # required unless a future version adds runtime policy
    # path resolution via the content hash.
    policy_path: str | None = policy
    if not policy_path:
        typer.echo(
            "\n  --policy is required for verdict sentinel scan.\n\n"
            "  Governance records store a privacy-safe content\n"
            "  hash of the policy, not the file path. Provide the\n"
            "  policy path explicitly:\n\n"
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
    except Exception as exception:
        typer.echo(
            f"\n  Evaluation error during Sentinel scan.\n  Error: {exception}\n"
        )
        raise typer.Exit(code=2)

    # ── Extract comparison data ────────────────────────
    record_id: str = str(previous.get("record_id", ""))
    previous_decision: str = str(previous.get("decision", ""))
    current_decision: str = str(current_result.get("decision", ""))
    previous_risk: int = int(previous.get("overall_risk_score", 0))
    current_risk: int = int(
        current_result.get("risk_summary", {}).get("overall_risk_score", 0)
    )
    risk_delta: int = current_risk - previous_risk

    # Previous conditions — now stored directly on
    # governance_records (analyzer_scores, failed_conditions,
    # passed_conditions columns), same as they were on the
    # old decisions table.
    previous_failed: set[str] = set(
        json.loads(previous.get("failed_conditions") or "[]")
    )
    previous_passed: set[str] = set(
        json.loads(previous.get("passed_conditions") or "[]")
    )

    # Current conditions from re-evaluation
    current_trace: list[dict[str, Any]] = current_result.get("trace", [])
    current_failed: set[str] = {
        trace_entry["condition_id"]
        for trace_entry in current_trace
        if not trace_entry.get("result", True)
    }
    current_passed: set[str] = {
        trace_entry["condition_id"]
        for trace_entry in current_trace
        if trace_entry.get("result", True)
    }

    new_failures: set[str] = current_failed - previous_failed
    newly_resolved: set[str] = previous_failed - current_failed

    all_conditions: set[str] = (
        previous_failed | previous_passed | current_failed | current_passed
    )

    # ── Determine outcome type ─────────────────────────
    compliance_violation: bool = bool(new_failures)
    drift_detected: bool = bool(new_failures or newly_resolved) or (
        abs(risk_delta) >= _RISK_DELTA_THRESHOLD
    )

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
        outcome_type = _OUTCOME_NO_DRIFT
        outcome_severity = "informational"

    # ── Record outcome to governance history ──────────
    # Sentinel writes ONLY a new history entry — no new
    # governance record is created.
    history_category, history_action = _OUTCOME_TO_HISTORY[outcome_type]

    add_history_entry(
        record_id=record_id,
        history_category=history_category,
        history_action=history_action,
        history_data={
            "outcome_type": outcome_type,
            "severity": outcome_severity,
            "description": (
                f"Sentinel scan: {outcome_type}. "
                f"Previous: {previous_decision} (risk {previous_risk}/100). "
                f"Current: {current_decision} (risk {current_risk}/100)."
            ),
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
        actor_role="sentinel-scan",
    )

    # ── Dispatch outcome notifications ────────────────
    if outcome_type != _OUTCOME_NO_DRIFT:
        _dispatch_outcome_notifications(
            outcome_type=outcome_type,
            outcome_severity=outcome_severity,
            policy_name=str(previous.get("policy_name", "")),
            previous_decision=previous_decision,
            current_decision=current_decision,
            previous_risk=previous_risk,
            current_risk=current_risk,
            new_failures=new_failures,
            decision_id=record_id,
            existing_manifest=current_result.get("notification_manifest", {}),
        )

    # ── Print scan report ──────────────────────────────
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

    # ── Exit code ───────────────────────────────────────
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
    short_id: str = str(previous.get("record_id", ""))[:8]
    timestamp: str = str(previous.get("created_at", ""))[:19].replace("T", " ")
    policy_name: str = str(previous.get("policy_name", ""))

    typer.echo("\n" + "─" * _WIDTH)
    typer.echo("  ObsidianWall Sentinel — Drift Detection Report")
    typer.echo("─" * _WIDTH)
    typer.echo(f"\n  Decision:  {short_id}  ({timestamp})")
    typer.echo(f"  Policy:    {policy_name}")
    typer.echo(f"  Plan:      {plan}")

    # ── Decision comparison ────────────────────────────
    typer.echo(f"\n{'─' * _WIDTH}")
    typer.echo("  Decision Comparison")
    typer.echo("─" * _WIDTH)
    previous_icon: str = decision_icon(previous_decision)
    current_icon: str = decision_icon(current_decision)
    typer.echo(
        f"  Previous:  {previous_icon} {previous_decision:<28}  risk: {previous_risk}/100"
    )
    typer.echo(
        f"  Current:   {current_icon} {current_decision:<28}  risk: {current_risk}/100"
    )
    risk_delta_string: str = f"+{risk_delta}" if risk_delta > 0 else str(risk_delta)
    if risk_delta != 0:
        typer.echo(f"  Risk delta: {risk_delta_string}")

    # ── Condition comparison ───────────────────────────
    if all_conditions:
        typer.echo(f"\n{'─' * _WIDTH}")
        typer.echo("  Condition Comparison")
        typer.echo("─" * _WIDTH)
        for condition in sorted(all_conditions):
            was_failing: bool = condition in previous_failed
            is_failing: bool = condition in current_failed
            is_new: bool = condition in new_failures
            is_resolved: bool = condition in newly_resolved

            previous_symbol: str = "✗ FAIL" if was_failing else "✓ PASS"
            current_symbol: str = "✗ FAIL" if is_failing else "✓ PASS"

            if is_new:
                note = "  ← NEW FAILURE"
            elif is_resolved:
                note = "  ← RESOLVED"
            else:
                note = "  unchanged"

            typer.echo(f"  {condition:<38}  {previous_symbol} → {current_symbol}{note}")

    # ── Sentinel observation ───────────────────────────
    typer.echo(f"\n{'─' * _WIDTH}")
    typer.echo("  Sentinel Observation")
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
    outcome_icon, outcome_label = _OUTCOME_DISPLAY.get(
        outcome_type, ("ℹ ", outcome_type)
    )
    typer.echo(f"  {outcome_icon} {outcome_label}")
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


# =====================================================
# OUTCOME NOTIFICATION DISPATCHER
# =====================================================


def _dispatch_outcome_notifications(
    outcome_type: str,
    outcome_severity: str,
    policy_name: str,
    previous_decision: str,
    current_decision: str,
    previous_risk: int,
    current_risk: int,
    new_failures: set[str],
    decision_id: str,
    existing_manifest: dict[str, Any],
) -> None:
    """
    Dispatch Sentinel outcome notifications to policy stakeholders.
    Reuses the same notification targets defined in the policy
    governance configuration. Silent no-op if no channels are
    configured. Never raises.
    """
    existing_notifications: list[dict[str, Any]] = existing_manifest.get(
        "notifications", []
    )
    if not existing_notifications:
        return

    _OUTCOME_SUBJECTS: dict[str, str] = {
        _OUTCOME_COMPLIANCE_VIOLATION: (
            "[ObsidianWall Sentinel] Compliance Violation Detected"
        ),
        _OUTCOME_DRIFT_DETECTED: ("[ObsidianWall Sentinel] Governance Drift Detected"),
        _OUTCOME_BUDGET_OVERRUN: ("[ObsidianWall Sentinel] Budget Overrun Detected"),
    }
    _OUTCOME_PRIORITY: dict[str, str] = {
        _OUTCOME_COMPLIANCE_VIOLATION: "urgent",
        _OUTCOME_DRIFT_DETECTED: "high",
        _OUTCOME_BUDGET_OVERRUN: "high",
    }

    subject: str = _OUTCOME_SUBJECTS.get(
        outcome_type, "[ObsidianWall Sentinel] Governance Alert"
    )
    priority: str = _OUTCOME_PRIORITY.get(outcome_type, "high")

    failure_detail: str = (
        f"\nNew failures: {', '.join(sorted(new_failures))}" if new_failures else ""
    )

    notification_body: str = (
        f"Sentinel detected: {outcome_type}\n\n"
        f"Policy:            {policy_name}\n"
        f"Previous decision: {previous_decision} (risk {previous_risk}/100)\n"
        f"Current decision:  {current_decision} (risk {current_risk}/100)"
        f"{failure_detail}"
    )

    sentinel_notifications: list[dict[str, Any]] = [
        {
            **existing_notification,
            "subject": subject,
            "body": notification_body,
            "priority": priority,
            "decision": outcome_type,
            "requires_action": outcome_type == _OUTCOME_COMPLIANCE_VIOLATION,
            "dispatch_status": "pending",
        }
        for existing_notification in existing_notifications
    ]

    dispatch_notifications(
        notification_manifest={
            "notifications_triggered": True,
            "notification_count": len(sentinel_notifications),
            "notifications": sentinel_notifications,
            "dispatch_status": "pending",
        },
        decision_id=decision_id,
    )
