# renderers/text_renderer.py
#
# Purpose:
# Human-readable terminal summary of a governance decision.
#
# Design principles:
# - Engineers need to act on the decision, not read a report
# - Show only what is needed to understand and act
# - Default output — no flags required
# - Full artifact always available via --output file
# - Full detail always available via verdict explain {id}
#
# Output target: ~15 lines for DENY, ~10 lines for ALLOW
#
# Audience: engineers running verdict evaluate in terminal

from __future__ import annotations

import sys
from typing import Any

# =====================================================
# SEVERITY INDICATORS
# =====================================================

_DECISION_ICONS: dict[str, str] = {
    "ALLOW": "✓",
    "ALLOW_WITH_NOTIFICATION": "✓",
    "ALLOW_WITH_APPROVAL_REQUIRED": "⚠",
    "DENY_WITH_OVERRIDE": "✗",
    "DENY": "✗",
}

_SEVERITY_COLORS: dict[str, str] = {
    "critical": "\033[91m",  # bright red
    "high": "\033[93m",  # yellow
    "medium": "\033[93m",  # yellow
    "low": "\033[94m",  # blue
    "informational": "\033[37m",  # light grey
}

_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"


def _supports_color() -> bool:
    """Return True if the terminal supports ANSI color codes."""
    isatty = getattr(sys.stdout, "isatty", None)
    return callable(isatty) and isatty()


def _color(text: str, code: str) -> str:
    if _supports_color():
        return f"{code}{text}{_RESET}"
    return text


def _bold(text: str) -> str:
    return _color(text, _BOLD)


def _dim(text: str) -> str:
    return _color(text, _DIM)


def _severity_color(text: str, severity: str) -> str:
    code: str = _SEVERITY_COLORS.get(severity.lower(), "")
    return _color(text, code) if code else text


def _divider() -> str:
    return _dim("─" * 54)


# =====================================================
# RENDERER
# =====================================================


def render_text(
    result: dict[str, Any],
    output_path: str | None = None,
) -> None:
    """
    Print a concise human-readable governance decision
    summary to stdout.

    Shows the decision, failed conditions, top findings,
    remediation guidance, and decision ID.
    Everything else is in the --output artifact file.

    Args:
        result:      complete verdict evaluate result dict.
                     Never mutated — read-only for rendering.
        output_path: path to the full JSON artifact, shown
                     in the footer. Defaults to a generic
                     placeholder if not provided.
    """
    decision: str = result.get("decision", "UNKNOWN")
    policy: str = result.get("policy", "unknown")
    decision_id: str = result.get("decision_id", "")
    gov_severity: str = result.get("governance_severity", "")
    resolved_output_path: str = output_path or "output/result.json"

    risk_summary: dict[str, Any] = result.get("risk_summary", {})
    risk_score: int = risk_summary.get("overall_risk_score", 0)
    eff_severity: str = risk_summary.get("effective_severity", gov_severity)

    trace: list[dict[str, Any]] = result.get("trace", [])
    failed: list[dict[str, Any]] = [t for t in trace if not t.get("result", True)]
    passed: list[dict[str, Any]] = [t for t in trace if t.get("result", True)]

    explanation: dict[str, Any] = result.get("explanation", {})
    policy_reason: dict[str, Any] = explanation.get("policy_reasoning", {})
    remediation: list[str] = policy_reason.get("remediation_steps", [])

    notif_manifest: dict[str, Any] = result.get("notification_manifest", {})
    notifications: list[dict[str, Any]] = notif_manifest.get("notifications", [])

    override_possible: bool = result.get("override_possible", False)
    requires_approval: bool = result.get("requires_approval", False)

    icon: str = _DECISION_ICONS.get(decision, "?")

    lines: list[str] = []
    lines.append(_divider())
    lines.append(f"{_bold('ObsidianWall Verdict')}  {_dim('·')}  {policy}")
    lines.append(_divider())
    lines.append("")

    # Decision line
    decision_text: str = f"{icon}  {_bold(decision)}"
    if eff_severity:
        decision_text += (
            f"  {_dim('·')}  {_severity_color(eff_severity.upper(), eff_severity)}"
        )
    if risk_score:
        decision_text += f"  {_dim('·')}  Risk {risk_score}/100"
    lines.append(f"  {decision_text}")
    lines.append("")

    # Governance Objective — optional, only present if the
    # policy declares metadata.governance_objective.statement
    governance_objective: dict[str, Any] | None = result.get("governance_objective")
    if governance_objective:
        obj_status = governance_objective.get("status", "")
        obj_statement = governance_objective.get("statement", "")
        lines.append(f"  {_bold('Governance Objective')}  {obj_statement}")
        lines.append(f"  {_bold('Objective Status')}      {obj_status}")
        lines.append("")

    # Failed conditions
    if failed:
        lines.append(f"  {_bold('Failed Conditions')}")
        for t in failed:
            cid: str = t.get("condition_id", "unknown")
            expr: str = t.get("expression", "")
            desc: str = t.get("description", "")
            lines.append(f"    ✗  {cid}")
            if desc:
                lines.append(f"       {_dim(desc)}")
            if expr:
                lines.append(f"       {_dim(expr)}")
        lines.append("")

    # Passed conditions (brief)
    if passed and not failed:
        lines.append(f"  {_bold('Conditions')}  all passed ({len(passed)})")
        lines.append("")

    # Remediation
    if remediation:
        lines.append(f"  {_bold('Remediation')}")
        for step in remediation[:2]:  # top 2 only
            lines.append(f"    →  {step}")
        lines.append("")

    # Override / approval
    if override_possible and "DENY" in decision:
        notif_roles: list[str] = [
            n.get("target_role", "") for n in notifications if n.get("target_role")
        ]
        if notif_roles:
            lines.append(f"  {_bold('Override')}  contact {', '.join(notif_roles)}")
            lines.append("")

    if requires_approval:
        lines.append(f"  {_bold('Approval required')}  see artifact for approver")
        lines.append("")

    # Notifications brief
    if notifications and "DENY" not in decision:
        targets: list[str] = [n.get("target_role", "") for n in notifications]
        lines.append(f"  {_bold('Notified')}  {', '.join(t for t in targets if t)}")
        lines.append("")

    # Footer
    short_id: str = decision_id[:8] if decision_id else "—"
    lines.append(_divider())
    lines.append(
        f"  {_dim('Decision ID')}  {short_id}"
        f"  {_dim('·')}  {_dim(f'Full artifact: {resolved_output_path}')}"
    )
    lines.append(
        f"  {_dim('Run')}  {_dim(f'verdict explain {short_id}')}"
        f"  {_dim('for full reasoning chain')}"
    )
    lines.append(_divider())

    print("\n".join(lines))
