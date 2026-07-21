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

    if notifications or approval_request or override_possible:
        lines.append(_section_header("Governance Routing"))

        # Notified / Approval are short single-line label-value
        # facts — a small shared width keeps them tight and
        # readable. Action Required is a different KIND of
        # content — a heading introducing a multi-line list, not
        # a single-line fact — so it is rendered as its own
        # sub-block below, indented consistently, rather than
        # forced into the same label column as the short facts.
        # Trying to align a long label ("Action Required") with
        # short ones ("Notified", "Approval") in one shared
        # column always produces an oversized gap for the short
        # rows or a cramped one for the long row — treating it
        # as its own block avoids that tradeoff entirely.
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

        if override_possible:
            override_roles = sorted(
                {
                    n.get("target_role", "")
                    for n in notifications
                    if n.get("target_role")
                }
            )
            if override_roles:
                lines.append("")
                lines.append(f"  {_bold('Action Required')}")
                lines.append("    Request override from:")
                for r in override_roles:
                    lines.append(f"      • {r}")

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
    # recommendation_confidence and priority_score are
    # deliberately omitted here. They are internal scoring
    # metadata for Compass, not human-facing signal. Both
    # remain available via --format json / --format yaml.
    #
    # Recommendations are grouped into three categories
    # (Financial, Security, Governance) rather than listed
    # flat. Individual recommendation types (budget_exceeded,
    # elevated_projected_cost, cost_optimization) often
    # represent the same underlying issue from different
    # analyzer angles — grouping collapses that repetition
    # into one conversation per category instead of six
    # near-duplicate entries. Full per-finding detail with
    # zero grouping remains available via --format json.
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
    # Confirms this is governance evidence, not just a
    # policy check result. Artifact hash and recorded_at
    # come from the evidence store (decision_artifacts),
    # not from the artifact content itself.
    #
    # "Evidence Status" describes the current storage
    # backend honestly rather than referencing planned
    # future infrastructure that does not exist yet.
    # This line can be updated truthfully as the storage
    # backend evolves (local → immutable ledger → external
    # archive) without ever having overstated the current
    # guarantee at any point along the way.
    lines.append(_section_header("Evidence"))
    lines.append(f"  Decision ID      {decision_id}")
    if artifact_hash:
        lines.append(f"  Artifact Hash    sha256:{artifact_hash}")
    if recorded_at:
        lines.append(f"  Recorded         {recorded_at}")
    lines.append("  Evidence Status  Stored locally")

    # History chain integrity — verify_history_chain() recomputes
    # every history entry's hash and confirms the chain is intact.
    # This is real, computed verification (not aspirational text) —
    # it detects if any past revision was altered after the fact.
    if chain_verified is not None:
        integrity_label = (
            "Verified — chain intact" if chain_verified else "TAMPERED — chain broken"
        )
        lines.append(f"  Integrity        {integrity_label}")

    lines.append("")
    lines.append(_dim("─" * 54))

    print("\n".join(lines))
