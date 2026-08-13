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
#   sentinel scan       → governance_history (outcome / drift
#                       entries) — what actually happened
#
# v0.6.0 (cloud observation): comparison state can now come
# from a LIVE cloud observer (--cloud azure) instead of only
# a local Terraform plan file (--plan). Before evaluating in
# cloud mode, the observed context is checked against the
# policy's required context keys via
# context.observers.sufficiency.check_sufficiency() — if the
# observer doesn't cover everything the policy needs, NOTHING
# is evaluated and NOTHING is recorded to governance history.
# A policy must never silently evaluate against partial cloud
# coverage; POLICY_NOT_EVALUATED is reported clearly instead,
# distinguishing "this observer doesn't support that yet"
# from "the collection attempt itself failed" — different
# remediation paths for each.
#
# Field name change: the primary key on a governance record
# is "record_id", not "id" (the old decisions table's column
# name). failed_conditions/passed_conditions/analyzer_scores
# are now stored directly on governance_records, same as the
# old decisions table — Sentinel reads them the same way it
# always did, just from the new table.
#
# Usage:
#   verdict sentinel scan --plan terraform_plan.json --policy policies/cost/basic_budget.yaml
#   verdict sentinel scan --plan terraform_plan.json --decision-id abc3a13b --policy ...
#   verdict sentinel scan --cloud azure --subscription-id <sub> --resource-group <rg> --policy ...
#
# Exit codes:
#   0   No drift detected
#   1   Drift or compliance violation detected
#   2   Error (no history, missing policy, evaluation failure,
#       insufficient cloud observation coverage)

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
    get_most_recent_record_for_policy,
    get_risk_acceptance_records,
)

sentinel_app = typer.Typer(
    help="Sentinel — post-deployment reality verification.",
)

# ── Outcome type constants ────────────────────────────
#
# Plan-comparison outcomes:
#   no_drift              — state unchanged, decision holds
#   drift_detected          — conditions or risk score changed
#   compliance_violation    — previously passing conditions now failing
#   budget_overrun           — cost risk escalated significantly
#
# Reserved for future Sentinel capabilities:
#   deployment_success, deployment_failure, security_incident,
#   availability_event, manual_rollback

_OUTCOME_NO_DRIFT = "no_drift"
_OUTCOME_DRIFT_DETECTED = "drift_detected"
_OUTCOME_COMPLIANCE_VIOLATION = "compliance_violation"
_OUTCOME_BUDGET_OVERRUN = "budget_overrun"
# See ADR-0003. Distinct from drift_detected — this specifically
# means a DENY_WITH_OVERRIDE decision's violating condition is
# STILL present in observed state, with NO confirmed Ledger
# approval covering it. Not incidental drift — evidence the
# governed exception path was never taken.
_OUTCOME_GOVERNANCE_BYPASS = "governance_bypass"

# Risk score increase above this threshold triggers drift_detected
# even when conditions have not changed.
_RISK_DELTA_THRESHOLD = 20

# Width for the formatted report output
_WIDTH = 72

# Providers with a registered CloudObserver implementation.
# Checked explicitly at the top of scan() so an unsupported
# --cloud value fails with a clear message immediately,
# rather than an import error deep in the call stack.
_SUPPORTED_CLOUD_PROVIDERS = ("azure",)

# Five-level governance decision ordering, per
# schemas.policy_schema.GovernanceDecision — used to classify
# a decision transition as escalated/de-escalated/unchanged,
# independent of the raw risk score delta (which is NOT always
# directly comparable — see the analyzer-coverage warning
# logic below).
_DECISION_ORDER: dict[str, int] = {
    "ALLOW": 0,
    "ALLOW_WITH_NOTIFICATION": 1,
    "ALLOW_WITH_APPROVAL_REQUIRED": 2,
    "DENY_WITH_OVERRIDE": 3,
    "DENY": 4,
}


# =====================================================
# History category/action mapping for outcome types
#
# governance_history splits events into history_category +
# history_action rather than one flat outcome_type string.
# This maps Sentinel's comparison outcomes onto that
# two-dimensional model.
# =====================================================

_OUTCOME_TO_HISTORY: dict[str, tuple[str, str]] = {
    _OUTCOME_NO_DRIFT: ("outcome", "observed"),
    _OUTCOME_DRIFT_DETECTED: ("drift", "detected"),
    _OUTCOME_COMPLIANCE_VIOLATION: ("drift", "detected"),
    _OUTCOME_BUDGET_OVERRUN: ("drift", "detected"),
    # Distinct category from ordinary drift — see ADR-0003.
    # Kept separate so get_outcome_correlation() and future
    # Compass reporting can count bypasses independently from
    # incidental drift, rather than conflating the two.
    _OUTCOME_GOVERNANCE_BYPASS: ("governance", "bypassed"),
}


@sentinel_app.command()
def scan(
    plan: Optional[str] = typer.Option(
        None,
        "--plan",
        help=(
            "Path to a Terraform plan JSON file to compare against "
            "history. Mutually exclusive with --cloud — exactly "
            "one comparison source is required."
        ),
    ),
    cloud: Optional[str] = typer.Option(
        None,
        "--cloud",
        help=(
            "Observe LIVE state from a cloud provider instead of "
            "a plan file. Currently supported: azure. Mutually "
            "exclusive with --plan."
        ),
    ),
    subscription_id: Optional[str] = typer.Option(
        None,
        "--subscription-id",
        help="Azure subscription ID. Required when using --cloud azure.",
    ),
    resource_group: Optional[str] = typer.Option(
        None,
        "--resource-group",
        help="Azure resource group to observe. Required when using --cloud azure.",
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
            "Policy path override. Required — governance records "
            "store a privacy-safe content hash of the policy, not "
            "the file path."
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
        help="Current period spend in USD for cost context. Plan mode only.",
    ),
    pricing: str = typer.Option(
        "table",
        "--pricing",
        help="Pricing mode: table (default) or live. Plan mode only.",
    ),
    region: str = typer.Option(
        "eastus",
        "--region",
        help="Cloud region for live pricing. Plan mode only.",
    ),
) -> None:
    """
    Compare current infrastructure state against a previous
    governance decision and detect drift.

    Comparison state comes from EITHER a local Terraform plan
    file (--plan) OR a live cloud observation (--cloud azure).
    Exactly one is required.

    In cloud mode, the observed state is checked against the
    policy's required context keys BEFORE evaluation. If the
    observer doesn't cover everything the policy needs, nothing
    is evaluated and nothing is recorded — a governance decision
    must never be produced from partial evidence.

    Loads the comparison record from governance history.
    Re-evaluates current state against the same policy.
    Records an outcome entry to governance history. Does not
    create a new governance record.

    Exit codes:
      0   No drift detected
      1   Drift or compliance violation detected
      2   Error (no history, missing policy, evaluation failure,
          insufficient cloud observation coverage)

    Examples:

      Compare current plan against last decision:
        verdict sentinel scan --plan terraform_plan.json --policy policies/cost/basic_budget.yaml

      Compare against a specific decision:
        verdict sentinel scan \\
          --plan        terraform_plan.json \\
          --decision-id abc3a13b-83d5-4fad-87d8 \\
          --policy      policies/cost/basic_budget.yaml

      Compare against LIVE Azure state:
        verdict sentinel scan \\
          --cloud            azure \\
          --subscription-id  00000000-0000-0000-0000-000000000000 \\
          --resource-group   my-resource-group \\
          --policy           policies/security/network_policy.yaml
    """
    # Suppress structured INFO logs by default — same pattern
    # as verdict evaluate's --verbose flag. Sentinel's own
    # report is the point, not the internal evaluation trace.
    logging.disable(logging.INFO)

    # ── Validate comparison source ─────────────────────
    if plan and cloud:
        typer.echo(
            "\n  --plan and --cloud are mutually exclusive.\n"
            "  Choose exactly one comparison source.\n"
        )
        raise typer.Exit(code=2)

    if not plan and not cloud:
        typer.echo("\n  One comparison source is required: --plan or --cloud.\n")
        raise typer.Exit(code=2)

    if cloud and cloud not in _SUPPORTED_CLOUD_PROVIDERS:
        typer.echo(
            f"\n  Unsupported cloud provider: '{cloud}'\n"
            f"  Currently supported: {', '.join(_SUPPORTED_CLOUD_PROVIDERS)}\n"
        )
        raise typer.Exit(code=2)

    if cloud == "azure" and (not subscription_id or not resource_group):
        typer.echo(
            "\n  --cloud azure requires both --subscription-id and --resource-group.\n"
        )
        raise typer.Exit(code=2)

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

    # ── Resolve policy path ───────────────────────────
    # governance_records does not store policy_path directly
    # (only policy_content_hash, for privacy). --policy is
    # required regardless of comparison source.
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

    # ── Load and validate policy ──────────────────────
    # Loaded BEFORE the comparison record — the record lookup
    # below is scoped by this policy's name, fixing a real bug
    # where scanning policy A while the database's single most
    # recent decision happened to be from unrelated policy B
    # produced a nonsensical cross-policy comparison.
    try:
        policy_dict: dict[str, Any] = load_policy(policy_path)
        validate_policy(policy_dict)
    except Exception as exception:
        typer.echo(f"\n  Policy load error.\n  Error: {exception}\n")
        raise typer.Exit(code=2)

    # Real schema has NO "policy:" wrapper key — name lives at
    # metadata.name directly. Confirmed via schemas/policy_schema.py
    # and real working policy files. An earlier version of this
    # line assumed a wrapper that never existed.
    policy_name_being_scanned: str = str(
        policy_dict.get("metadata", {}).get("name", "")
    )

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
        previous = get_most_recent_record_for_policy(policy_name_being_scanned)
        if not previous:
            typer.echo(
                f"\n  No prior governance record found for policy "
                f"'{policy_name_being_scanned}'.\n"
                f"  Run 'verdict evaluate' with this policy first to "
                f"establish a baseline assessment.\n"
            )
            raise typer.Exit(code=2)

    # ── Guard against cross-policy comparison ─────────
    # Applies to BOTH lookup paths above — even an explicitly
    # passed --decision-id must belong to the SAME policy being
    # scanned right now. Without this, a mismatched
    # --decision-id would silently reproduce the exact bug this
    # fix exists to close.
    previous_policy_name = str(previous.get("policy_name", ""))
    if previous_policy_name != policy_name_being_scanned:
        typer.echo(
            f"\n  Policy mismatch — refusing to compare across "
            f"different policies.\n\n"
            f"  Comparison record's policy: {previous_policy_name}\n"
            f"  Policy being scanned now:   {policy_name_being_scanned}\n\n"
            f"  This would otherwise produce a nonsensical result — "
            f"e.g. conditions appearing to 'resolve' simply because "
            f"they belong to a different policy and were never "
            f"re-evaluated at all.\n"
        )
        raise typer.Exit(code=2)

    # ── Collect comparison context ────────────────────
    source_description: str
    context: dict[str, Any]

    if plan:
        source_description = f"Plan: {plan}"
        try:
            context = build_context(
                plan_path=plan,
                current_spend=current_spend,
                pricing_mode=pricing,
                region=region,
            )
        except Exception as exception:
            typer.echo(
                f"\n  Plan parsing error during Sentinel scan.\n  Error: {exception}\n"
            )
            raise typer.Exit(code=2)

    else:  # cloud mode
        source_description = f"Cloud: {cloud} / resource-group: {resource_group}"

        from context.observers.azure_observer import AzureObserver
        from context.observers.base_observer import CloudObserverError
        from context.observers.sufficiency import check_sufficiency

        observer = AzureObserver(subscription_id=subscription_id)

        collection_error: str | None = None
        try:
            observer.authenticate()
            context = observer.observe(resource_group)
        except CloudObserverError as exception:
            collection_error = str(exception)
            context = {}

        sufficiency = check_sufficiency(
            policy_dict, context, collection_error=collection_error
        )

        if not sufficiency.sufficient:
            typer.echo(
                f"\n  Policy not evaluated — insufficient evidence.\n\n"
                f"  Reason: {sufficiency.reason.value if sufficiency.reason else 'unknown'}\n"
            )
            if sufficiency.missing_keys:
                typer.echo(
                    f"  Missing context: {', '.join(sorted(sufficiency.missing_keys))}\n"
                )
            if sufficiency.detail:
                typer.echo(f"  {sufficiency.detail}\n")
            typer.echo(
                "\n  No governance decision was produced. Nothing was "
                "recorded to history — a decision must never be made "
                "from incomplete evidence.\n"
            )
            # No history_entry is written here — this is deliberate.
            # An insufficient-evidence outcome is not itself a
            # governance event worth recording; it's a configuration
            # gap (either in the observer's coverage or in cloud
            # access) that needs a human to address, not an
            # automatic audit trail entry.
            raise typer.Exit(code=2)

    # ── Re-evaluate against comparison context ────────
    try:
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

    # Previous conditions — stored directly on governance_records
    # (analyzer_scores, failed_conditions, passed_conditions
    # columns).
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

    # ── Governance bypass check (ADR-0003) ─────────────
    # Only relevant when the PREVIOUS decision was
    # DENY_WITH_OVERRIDE — that is the only decision type
    # for which a confirmed Ledger approval could exist at
    # all (is_risk_acceptance_candidate is only ever set for
    # DENY_WITH_OVERRIDE records).
    governance_bypass: bool = False
    if previous_decision == "DENY_WITH_OVERRIDE":
        confirmed_approvals = get_risk_acceptance_records(db_path=None)
        has_confirmed_approval = any(
            r.get("record_id") == record_id for r in confirmed_approvals
        )
        # Still failing in the CURRENT re-evaluation means the
        # violating configuration is still present in observed
        # state — not merely "was denied once," but "remains
        # true right now."
        still_failing = bool(previous_failed & current_failed)

        if still_failing and not has_confirmed_approval:
            governance_bypass = True

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

    if governance_bypass:
        outcome_type = _OUTCOME_GOVERNANCE_BYPASS
        outcome_severity = "critical"
    elif compliance_violation:
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

    history_data: dict[str, Any] = {
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
        "policy_path": policy_path,
        "comparison_source": source_description,
    }
    if plan:
        history_data["plan_path"] = plan
    else:
        history_data["cloud_provider"] = cloud
        history_data["subscription_id"] = subscription_id
        history_data["resource_group"] = resource_group

    add_history_entry(
        record_id=record_id,
        history_category=history_category,
        history_action=history_action,
        history_data=history_data,
        actor_role="sentinel-scan",
    )

    # ── Dispatch outcome notifications ────────────────
    if outcome_type != _OUTCOME_NO_DRIFT:
        _dispatch_outcome_notifications(
            outcome_type=outcome_type,
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
        source_description=source_description,
        previous_analyzer_scores=previous_analyzer_scores,
        current_analyzer_scores=current_analyzer_scores,
    )

    # ── Exit code ───────────────────────────────────────
    if governance_bypass or compliance_violation or drift_detected:
        raise typer.Exit(code=1)
    raise typer.Exit(code=0)


# =====================================================
# REPORT RENDERER
# =====================================================


def _print_scan_report(
    previous: dict[str, Any],
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
    source_description: str,
    previous_analyzer_scores: dict[str, int],
    current_analyzer_scores: dict[str, int],
) -> None:
    """Render the Sentinel drift detection report."""
    short_id: str = str(previous.get("record_id", ""))[:8]
    # created_at is stored in UTC — labeled explicitly so it's
    # never mistaken for local time, same fix applied to
    # audit.py and ledger.py earlier.
    raw_timestamp = str(previous.get("created_at", ""))
    timestamp: str = (
        f"{raw_timestamp[:19].replace('T', ' ')} UTC" if raw_timestamp else "—"
    )
    policy_name: str = str(previous.get("policy_name", ""))

    typer.echo("\n" + "─" * _WIDTH)
    typer.echo("  ObsidianWall Sentinel — Drift Detection Report")
    typer.echo("─" * _WIDTH)
    # Explicitly labeled "Baseline Assessment" — this is the
    # PREVIOUS decision being compared against, never a new
    # one this scan creates. A bare "Decision:" label made this
    # genuinely ambiguous to a real reader.
    typer.echo(f"\n  Baseline assessment:  {short_id}  ({timestamp})")
    typer.echo(f"  Policy:    {policy_name}")
    typer.echo(f"  {source_description}")

    # ── Executive summary ──────────────────────────────
    # One-glance view: current decision, current risk,
    # governance event — before the full comparison detail
    # below. For a reader who wants the headline first.
    summary_icon = decision_icon(current_decision)
    typer.echo(
        f"\n  {summary_icon} {current_decision}  ·  risk {current_risk}/100  ·  {outcome_type}"
    )

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

    # Decision transition — independent of the raw risk delta,
    # using the 5-level GovernanceDecision ordering. This is a
    # meaningful signal on its own even when the risk score
    # comparison below is flagged as unreliable.
    previous_level = _DECISION_ORDER.get(previous_decision)
    current_level = _DECISION_ORDER.get(current_decision)
    if previous_level is not None and current_level is not None:
        level_diff = current_level - previous_level
        if level_diff > 0:
            transition = (
                f"escalated ({level_diff} level{'s' if level_diff > 1 else ''})"
            )
        elif level_diff < 0:
            transition = f"de-escalated ({abs(level_diff)} level{'s' if abs(level_diff) > 1 else ''})"
        else:
            transition = "unchanged"
        typer.echo(f"  Decision change:  {transition}")
        # Only shown when we have REAL evidence of what drove
        # the change — new_failures directly feeds
        # compliance_violation in this codebase's own outcome
        # logic. An escalation CAN in principle stem from a
        # risk/severity threshold crossing with zero condition
        # changes — in that case new_failures is empty, and
        # this deliberately says nothing rather than fabricate
        # a causal story we don't actually have evidence for.
        if level_diff > 0 and new_failures:
            failure_list = ", ".join(f"{c} → FAIL" for c in sorted(new_failures))
            typer.echo(f"  Triggered by:     {failure_list}")

    risk_delta_string: str = f"+{risk_delta}" if risk_delta > 0 else str(risk_delta)
    if risk_delta != 0:
        typer.echo(f"  Risk change:      {risk_delta_string}")

    # Analyzer-coverage warning — overall_risk_score is a
    # SUMMATION across whichever analyzers contributed a score
    # (see engine/risk_scorer.py's compute_risk_summary()), NOT
    # a normalized measure independent of which analyzers ran.
    # Comparing risk scores across two evaluations that had
    # DIFFERENT analyzer coverage (e.g. a plan-based baseline
    # vs. a narrower cloud observation) compares two sums over
    # different inputs — not a valid delta. Flag this plainly
    # rather than let the risk change be read as meaningful
    # when it may not be.
    # Compare NON-ZERO contributors, not raw dict keys. An
    # earlier version of this check compared which analyzer
    # NAMES were present in each dict — but all analyzers
    # likely run unconditionally every time, each simply
    # scoring 0 when it has no relevant signal. That meant the
    # same four keys existed in both dicts even when the
    # underlying contribution was completely different,
    # silently failing to fire on exactly the case it was
    # built for. Checking which analyzers actually contributed
    # a nonzero score is the correct signal for "is this sum
    # comparable."
    previous_contributors = {
        name for name, score in previous_analyzer_scores.items() if score > 0
    }
    current_contributors = {
        name for name, score in current_analyzer_scores.items() if score > 0
    }
    if previous_contributors != current_contributors and risk_delta != 0:
        only_previous = previous_contributors - current_contributors
        only_current = current_contributors - previous_contributors
        typer.echo("\n  ⚠ Analyzer differences:")
        if only_previous:
            typer.echo(f"    Baseline only: {', '.join(sorted(only_previous))}")
        if only_current:
            typer.echo(f"    Current only:  {', '.join(sorted(only_current))}")
        typer.echo(
            "    Risk change reflects this difference, not necessarily "
            "overall risk reduction."
        )

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
    typer.echo("  Governance Assessment")
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
        _OUTCOME_GOVERNANCE_BYPASS: (
            "🛑",
            "GOVERNANCE BYPASS — decision was DENY_WITH_OVERRIDE, no "
            "confirmed Ledger approval exists, violation still present",
        ),
    }
    outcome_icon, outcome_label = _OUTCOME_DISPLAY.get(
        outcome_type, ("ℹ ", outcome_type)
    )
    typer.echo(f"  {outcome_icon} {outcome_label}")
    typer.echo(f"  Governance event: {outcome_type}")

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
