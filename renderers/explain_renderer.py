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

import sys
from typing import Any

_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"


def _supports_color() -> bool:
    isatty = getattr(sys.stdout, "isatty", None)
    return callable(isatty) and isatty()


def _color(text: str, code: str) -> str:
    return f"{code}{text}{_RESET}" if _supports_color() else text


def _bold(text: str) -> str:
    return _color(text, _BOLD)


def _dim(text: str) -> str:
    return _color(text, _DIM)


def _section_header(title: str) -> str:
    return f"\n{_bold(title.upper())}\n{_dim('─' * 54)}"


def render_explain(
    artifact: dict[str, Any],
    artifact_hash: str | None = None,
    recorded_at: str | None = None,
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

    # ---- Governance Objective — optional ----
    governance_objective: dict[str, Any] | None = artifact.get("governance_objective")
    if governance_objective:
        obj_status = governance_objective.get("status", "")
        obj_statement = governance_objective.get("statement", "")
        lines.append("")
        lines.append(f"  {_bold('Governance Objective')}")
        lines.append(f"  {obj_statement}")
        lines.append(f"  Objective Status: {_bold(obj_status)}")

    # ---- 2. Governance Routing — moved up front ----
    # This is what an engineer needs first: who owns this
    # decision, and is approval or override required.
    notif_manifest: dict[str, Any] = artifact.get("notification_manifest", {})
    notifications: list[dict[str, Any]] = notif_manifest.get("notifications", [])
    approval_request: dict[str, Any] = artifact.get("approval_request", {})
    override_possible: bool = artifact.get("override_possible", False)

    if notifications or approval_request or override_possible:
        lines.append(_section_header("Governance Routing"))

        for n in notifications:
            role: str = n.get("target_role", "")
            channel: str = n.get("channel", "")
            priority: str = n.get("priority", "")
            lines.append(f"  Notified   {role} via {channel}  {_dim(f'({priority})')}")

        approval_status: str = approval_request.get("approval_status", "")
        if approval_status:
            lines.append(f"  Approval   {approval_status}")

        if override_possible:
            override_roles = sorted(
                {
                    n.get("target_role", "")
                    for n in notifications
                    if n.get("target_role")
                }
            )
            if override_roles:
                lines.append(f"  Override   available via {', '.join(override_roles)}")

    # ---- 3. Governance Reasoning Chain ----
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

    # ---- 4. Condition Trace ----
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

    # ---- 5. Analyzer Findings ----
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

    # ---- 6. Recommendations — priority tier only ----
    # recommendation_confidence and priority_score are
    # deliberately omitted here. They are internal scoring
    # metadata for Compass, not human-facing signal. Both
    # remain available via --format json / --format yaml.
    explained_recs: dict[str, Any] = explanation.get("explained_recommendations", {})
    all_recs: list[dict[str, Any]] = explained_recs.get("all_recommendations", [])

    if all_recs:
        lines.append(_section_header("Recommendations"))
        for rec in all_recs:
            rtype: str = rec.get("type", "")
            message = rec.get("message", "")
            tier: str = rec.get("priority_tier", "")
            savings: int = rec.get("estimated_savings_percent", 0)

            lines.append(f"  [{tier.upper()}] {_bold(rtype)}")
            lines.append(f"     {message}")
            if savings > 0:
                lines.append(f"     {_dim(f'Estimated savings: {savings}%')}")
            lines.append("")

    # ---- 7. Evidence ----
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

    lines.append("")
    lines.append(_dim("─" * 54))

    print("\n".join(lines))
