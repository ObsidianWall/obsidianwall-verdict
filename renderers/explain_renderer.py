# renderers/explain_renderer.py
#
# Purpose:
# Mid-tier detail renderer for verdict explain.
#
# Sits between the default text renderer (~15 lines,
# decision + remediation only) and the full JSON/YAML
# artifact (everything, unstructured for reading).
#
# Section order is deliberate — governance routing (who
# owns this, is approval needed) comes immediately after
# the decision header, because that is what an engineer
# needs to know first. Reasoning, conditions, findings,
# and recommendations follow for those who want the
# deeper dive.
#
# recommendation_confidence and priority_score are
# intentionally NOT shown here — they are internal
# scoring metadata useful to Compass, not to a human
# reading a single decision. Priority TIER (CRITICAL/
# HIGH/MEDIUM/LOW) is shown instead, since that is the
# human-readable version of the same signal. Both raw
# values remain available in --format json / --format yaml.
#
# Audience: engineers, auditors, or CISOs reviewing a
# specific past decision in detail.

from __future__ import annotations

from typing import Any

# Shared ANSI formatting — see renderers/ansi.py. Both
# text_renderer.py and explain_renderer.py used to each
# define their own private copies of these functions;
# consolidated into one shared, public module so nothing
# depends on another renderer's underscore-prefixed internals.
from renderers.ansi import _bold, _dim


def _section_header(title: str) -> str:
    return f"\n{_bold(title.upper())}\n{_dim('─' * 54)}"


# =====================================================
# RECOMMENDATION CATEGORY GROUPING
#
# Maps individual recommendation types onto three
# human-facing categories. This is a rendering-only
# grouping — it does not change what recommender.py
# or recommendation_explainer.py compute, only how the
# explain view presents them. Full Compass-level
# recommendation MERGING (collapsing multiple findings
# into one synthesized recommendation) is a separate,
# larger piece of work — this grouping is the lightweight
# v0.6.0 step toward that direction.
# =====================================================

_RECOMMENDATION_CATEGORIES: dict[str, str] = {
    "budget_exceeded": "Financial",
    "elevated_projected_cost": "Financial",
    "cost_optimization": "Financial",
    "cost_anomaly_review": "Financial",
    "resource_rightsizing": "Financial",
    "rightsizing": "Financial",
    "reserved_capacity": "Financial",
    "burstable_migration": "Financial",
    "serverless_candidate": "Financial",
    "lifecycle_policy": "Financial",
    "network_segmentation": "Security",
    "missing_network_segmentation": "Security",
    "security_posture": "Security",
    "load_balancer_coverage": "Security",
    "database_redundancy": "Security",
    "compute_redundancy": "Security",
    "enforcement": "Governance",
    "analyzer_finding": "Governance",
    "optimization_candidate": "Governance",
    "observability": "Governance",
}

_CATEGORY_ORDER = ["Financial", "Security", "Governance", "Other"]


def _group_recommendations_by_category(
    recommendations: list[dict[str, Any]],
) -> list[tuple[str, list[dict[str, Any]]]]:
    """
    Group recommendations into Financial / Security /
    Governance / Other categories, preserving a stable
    display order. Unrecognized recommendation types fall
    into "Other" rather than being dropped.
    """
    buckets: dict[str, list[dict[str, Any]]] = {cat: [] for cat in _CATEGORY_ORDER}

    for rec in recommendations:
        rtype = rec.get("type", "")
        category = _RECOMMENDATION_CATEGORIES.get(rtype, "Other")
        buckets[category].append(rec)

    return [(cat, buckets[cat]) for cat in _CATEGORY_ORDER]


def render_explain(
    artifact: dict[str, Any],
    artifact_hash: str | None = None,
    recorded_at: str | None = None,
    chain_verified: bool | None = None,
) -> None:
    """
    Render the mid-tier detail view for a stored decision
    artifact, retrieved from the evidence store by
    verdict explain.

    Section order:
      1. Decision summary
      2. Governance routing (who owns this, approval status)
      3. Governance reasoning chain (all stages)
      4. Condition trace (full expressions and values)
      5. Analyzer findings (all findings, all analyzers)
      6. Recommendations (priority tier, no raw scores)
      7. Evidence (decision ID, artifact hash, recorded time)

    Args:
        artifact:      the full stored evaluation artifact
        artifact_hash: SHA-256 hash of the stored artifact,
                       shown in the Evidence section if provided
        recorded_at:   timestamp the artifact was written to
                       the evidence store, shown in Evidence
                       section if provided
    """
    decision: str = artifact.get("decision", "UNKNOWN")
    policy: str = artifact.get("policy", "unknown")
    decision_id: str = artifact.get("decision_id", "")
    timestamp: str = artifact.get("timestamp", "")

    risk_summary: dict[str, Any] = artifact.get("risk_summary", {})
    risk_score: int = risk_summary.get("overall_risk_score", 0)
    eff_severity: str = risk_summary.get("effective_severity", "")
    risk_narrative: str = risk_summary.get("risk_narrative", "")

    lines: list[str] = []

    # ---- 1. Decision Summary ----
    lines.append(_dim("─" * 54))
    lines.append(f"{_bold('Governance Decision Explanation')}")
    lines.append(_dim("─" * 54))
    lines.append(f"  Policy       {policy}")
    lines.append(f"  Decision     {_bold(decision)}")
    lines.append(f"  Severity     {eff_severity}")
    lines.append(f"  Risk Score   {risk_score}/100")

    cost_metadata = (
        artifact.get("analyzer_results", {})
        .get("cost_analysis", {})
        .get("metadata", {})
    )
    cost_coverage = cost_metadata.get("cost_coverage", "complete")
    unpriced_count = cost_metadata.get("unpriced_resource_count", 0)

    if cost_coverage == "partial" and unpriced_count > 0:
        caveat_text = (
            "Cost estimate incomplete - "
            + str(unpriced_count)
            + " resource(s) unpriced (see --format json for detail)"
        )
        lines.append("  " + _dim(caveat_text))

    lines.append(f"  Timestamp    {timestamp}")

    if risk_narrative:
        lines.append("")
        lines.append(f"  {_dim(risk_narrative)}")

    # ---- 2. Governance Objective — optional ----
    # Only present if the policy declares
    # metadata.governance_objective.statement. Shows WHY
    # before HOW — the organizational outcome this decision
    # relates to, and whether it was upheld or violated.
    governance_objective: dict[str, Any] = artifact.get("governance_objective", {})
    if governance_objective:
        obj_statement = governance_objective.get("statement", "")
        obj_status = governance_objective.get("status", "")
        lines.append(_section_header("Governance Objective"))
        lines.append(f"  {obj_statement}")
        lines.append(f"  Objective Status: {_bold(obj_status)}")

    # ---- 3. Governance Routing — moved up front ----
    # This is what an engineer needs first: who owns this
    # decision, and is approval or override required.
    notif_manifest: dict[str, Any] = artifact.get("notification_manifest", {})
    notifications: list[dict[str, Any]] = notif_manifest.get("notifications", [])
    approval_request: dict[str, Any] = artifact.get("approval_request", {})
    override_possible: bool = artifact.get("override_possible", False)

    # Remediation steps — extracted early specifically so they
    # can be shown ALONGSIDE the override option below, as two
    # parallel alternatives, rather than override appearing to
    # be the only or mandatory path. Previously not read anywhere
    # in this renderer at all, even though text_renderer.py's
    # shorter default view already shows it — the fuller
    # explain view was missing something the shorter summary had.
    policy_reasoning: dict[str, Any] = artifact.get("explanation", {}).get(
        "policy_reasoning", {}
    )
    remediation: list[str] = policy_reasoning.get("remediation_steps", [])

    if notifications or approval_request or override_possible or remediation:
        lines.append(_section_header("Governance Routing"))

        # Notified / Approval are short single-line label-value
        # facts — a small shared width keeps them tight and
        # readable.
        _FACT_LABEL_WIDTH = 10

        for n in notifications:
            role: str = n.get("target_role", "")
            channel: str = n.get("channel", "")
            priority: str = n.get("priority", "")
            label = "Notified".ljust(_FACT_LABEL_WIDTH)
            lines.append(f"  {label}{role} via {channel}  {_dim(f'({priority})')}")

        approval_status: str = approval_request.get("approval_status", "")
        if approval_status:
            label = "Approval".ljust(_FACT_LABEL_WIDTH)
            lines.append(f"  {label}{approval_status}")

        # Resolution Options — remediation and override presented
        # as two clearly PARALLEL alternatives, not a mandatory
        # follow-on action. DENY_WITH_OVERRIDE means the proposed
        # state is prohibited, but an authorized exception is
        # available IF the engineer can't or won't fix the
        # underlying condition instead — showing the override
        # path alone, with no remediation option visible beside
        # it, made escalation look like the only next step.
        override_roles: list[str] = []
        if override_possible:
            override_roles = sorted(
                {
                    n.get("target_role", "")
                    for n in notifications
                    if n.get("target_role")
                }
            )

        if remediation or override_roles:
            lines.append("")
            lines.append(f"  {_bold('Resolution Options')}")

            if remediation:
                lines.append("")
                lines.append(f"    {_bold('Remediate')}")
                for step in remediation[:2]:
                    lines.append(f"      →  {step}")

            if override_roles:
                lines.append("")
                lines.append(f"    {_bold('Request Exception')}")
                lines.append("      If the current configuration is intentional,")
                lines.append("      request an override from:")
                for r in override_roles:
                    lines.append(f"        • {r}")

    # ---- 4. Governance Reasoning Chain ----
    explanation: dict[str, Any] = artifact.get("explanation", {})
    governance_reasoning: dict[str, Any] = explanation.get("governance_reasoning", {})
    reasoning_chain: list[dict[str, Any]] = governance_reasoning.get(
        "reasoning_chain", []
    )

    if reasoning_chain:
        lines.append(_section_header("Governance Reasoning"))
        for stage in reasoning_chain:
            seq: int = stage.get("sequence", 0)
            stage_name: str = stage.get("stage", "unknown")
            outcome: str = stage.get("outcome", "")
            reason: str = stage.get("reason", "")
            severity: str = stage.get("severity", "")

            lines.append(f"  {seq}. {_bold(stage_name)}  {_dim(f'[{severity}]')}")
            lines.append(f"     {outcome}")
            if reason and reason != outcome:
                lines.append(f"     {_dim(reason)}")
            lines.append("")

    # ---- 5. Condition Trace ----
    trace: list[dict[str, Any]] = artifact.get("trace", [])

    if trace:
        lines.append(_section_header("Condition Trace"))
        for t in trace:
            cid: str = t.get("condition_id", "unknown")
            expr: str = t.get("expression", "")
            desc: str = t.get("description", "")
            result: bool = t.get("result", True)
            icon: str = "✓" if result else "✗"

            lines.append(f"  {icon}  {_bold(cid)}")
            if desc:
                lines.append(f"     {desc}")
            if expr:
                lines.append(f"     {_dim(expr)}")
            lines.append("")

    # ---- 6. Analyzer Findings ----
    analyzer_findings: list[dict[str, Any]] = explanation.get("analyzer_findings", [])

    if analyzer_findings:
        lines.append(_section_header("Analyzer Findings"))
        for finding in analyzer_findings:
            analyzer: str = finding.get("analyzer", "unknown")
            ftype: str = finding.get("type", "")
            severity = finding.get("severity", "")
            message: str = finding.get("message", "")

            lines.append(f"  [{analyzer}] {_bold(ftype)}  {_dim(f'({severity})')}")
            lines.append(f"     {message}")
            lines.append("")

    # ---- 7. Recommendations — grouped by category ----
    explained_recs: dict[str, Any] = explanation.get("explained_recommendations", {})
    all_recs: list[dict[str, Any]] = explained_recs.get("all_recommendations", [])

    if all_recs:
        lines.append(_section_header("Recommendations"))

        grouped = _group_recommendations_by_category(all_recs)

        for category_label, recs_in_category in grouped:
            if not recs_in_category:
                continue

            lines.append(f"  {_bold(category_label)}")

            for rec in recs_in_category:
                message = rec.get("message", "")
                tier: str = rec.get("priority_tier", "")
                savings: int = rec.get("estimated_savings_percent", 0)

                lines.append(f"    [{tier.upper()}]  {message}")
                if savings > 0:
                    lines.append(f"           {_dim(f'Estimated savings: {savings}%')}")

            lines.append("")

    # ---- 8. Evidence ----
    lines.append(_section_header("Evidence"))
    lines.append(f"  Decision ID      {decision_id}")
    if artifact_hash:
        lines.append(f"  Artifact Hash    sha256:{artifact_hash}")
    if recorded_at:
        lines.append(f"  Recorded         {recorded_at}")
    lines.append("  Evidence Status  Stored locally")

    if chain_verified is not None:
        integrity_label = (
            "Verified — chain intact" if chain_verified else "TAMPERED — chain broken"
        )
        lines.append(f"  Integrity        {integrity_label}")

    lines.append("")
    lines.append(_dim("─" * 54))

    print("\n".join(lines))


# Purpose:
# Render the FULL lifecycle of a decision after it was
# created — every override request/approve/deny, every
# Sentinel drift/outcome entry — in chronological order.
#
# Why this is separate from render_explain():
# render_explain() renders the ORIGINAL evaluation's
# reasoning (the stored evidence artifact). It has no
# visibility into what happened to the record AFTERWARD —
# that data lives in governance_history, not in the
# evidence artifact, and is a fundamentally different
# question: "why was this decision made" vs. "what
# happened to it since." Keeping them separate functions
# also means this can be added without touching
# render_explain()'s existing, tested internals.


# Icons per history action — mirrors the icon conventions
# already used elsewhere (audit.py, text_renderer.py)
_ACTION_ICONS: dict[str, str] = {
    "requested": "→",
    "approved": "✓",
    "denied": "✗",
    "detected": "⚠",
    "observed": "ℹ",
}


def render_history_timeline(
    history: list[dict[str, Any]], record_id: str | None = None
) -> None:
    """
    Render every governance_history entry for a record in
    chronological order — the decision's full lifecycle
    after creation, not just its original evaluation.

    Args:
        history: result of get_governance_history(record_id),
            already ordered oldest-first by history_number.
        record_id: needed to call verify_signature() per
            entry — without it, signature status is shown
            (signed/unsigned) but not independently
            re-verified against the stored data.
    """
    import typer

    lifecycle_entries = [h for h in history if h.get("history_number", 0) > 1]

    if not lifecycle_entries:
        return

    width = 72
    typer.echo(f"\n{'─' * width}")
    typer.echo("  History Timeline")
    typer.echo("─" * width)

    for entry in lifecycle_entries:
        category = entry.get("history_category", "")
        action = entry.get("history_action", "")
        icon = _ACTION_ICONS.get(action, "•")

        raw_timestamp = str(entry.get("created_at", ""))
        # Full precision, including seconds — a truncated
        # [:16] slice (through the minute only) collapses
        # any decisions made within the same real minute into
        # an identical-looking timestamp, exactly the bug
        # found and fixed in cli/display.py for verdict audit
        # and verdict ledger. This is the same pattern in a
        # different file (renderers/, not cli/), which a
        # cli/**/*.py-scoped search would not have reached.
        timestamp = (
            f"{raw_timestamp[:19].replace('T', ' ')} UTC" if raw_timestamp else "—"
        )

        actor = entry.get("actor_identity") or entry.get("actor_role") or "—"

        data = entry.get("history_data") or {}
        reason = data.get("reason", "")

        typer.echo(f"  {icon}  {timestamp}  {category}.{action}  —  {actor}")
        if reason:
            typer.echo(f"       Reason: {reason}")

        if record_id is not None:
            from telemetry.governance_store import verify_signature

            history_number = entry.get("history_number")
            sig_status = verify_signature(record_id, history_number=history_number)

            if not sig_status["signed"]:
                typer.echo("       Unsigned")
            elif sig_status["verified"]:
                fp = sig_status.get("key_fingerprint") or ""
                typer.echo(
                    f"       Signed: {sig_status['signing_method']} "
                    f"(key {fp[:16]})  ✓ Verified"
                )
            else:
                typer.echo(
                    f"       Signed: {sig_status['signing_method']}  "
                    f"⚠ VERIFICATION FAILED — {sig_status['detail']}"
                )

    typer.echo("\n" + "─" * width + "\n")
