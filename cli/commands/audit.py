# cli/commands/audit.py
#
# Purpose:
# verdict audit — governance risk audit across recorded decisions.
#
# v0.6.0: reads from telemetry/governance_store.py
# (governance_records + governance_history), replacing the
# v0.5.x telemetry/store.py functions. Field name changes:
# the primary key is "record_id" (not "id"); condition and
# analyzer data now come from governance_records' own
# analyzer_scores/failed_conditions/passed_conditions columns.
# Outcome data comes from governance_history entries with
# history_category in ('outcome', 'drift').

from __future__ import annotations

import json
from typing import Any, Optional

import typer

from cli.display import decision_icon
from renderers.explain_renderer import _bold, _color
from telemetry.config import get_db_path, is_telemetry_enabled
from telemetry.governance_store import (
    get_domain_risk_summary,
    get_failed_conditions_summary,
    get_outcome_summary,
    get_passed_conditions_summary,
    get_policy_effectiveness,
    get_recent_records,
)



audit_app = typer.Typer(
    help="Governance risk audit across recorded decisions.",
)

_WIDTH = 72

_DOMAIN_LABELS: dict[str, str] = {
    "cost_analysis": "Cost",
    "topology_analysis": "Network / Topology",
    "architecture_analysis": "Architecture",
    "utilization_analysis": "Utilization",
}


@audit_app.callback(invoke_without_command=True)
def audit(
    policy: Optional[str] = typer.Option(
        None,
        "--policy",
        help="Filter to a specific policy name.",
    ),
    limit: int = typer.Option(
        50,
        "--limit",
        "-l",
        help="Number of recent decisions to include.",
    ),
    output_format: str = typer.Option(
        "table",
        "--format",
        "-f",
        help="Output format: table (default) or json.",
    ),
    insights: bool = typer.Option(
        False,
        "--insights",
        help=(
            "Include governance insights and recommendations — "
            "heuristic analysis of policy health, override "
            "patterns, and risk trends."
        ),
    ),
) -> None:
    """
    Governance risk audit across recorded decisions.

    Telemetry is enabled by default (opt-out model). See
    the Telemetry section of the docs to disable it.

    Reads from ~/.obsidianwall/decisions.db.

    Examples:
      verdict audit
      verdict audit --insights
      verdict audit --policy policies/cost/basic_budget.yaml
      verdict audit --format json
      verdict audit --limit 100
    """
    # ── Telemetry gate ────────────────────────────────
    if not is_telemetry_enabled():
        typer.echo(
            "\n  Telemetry is disabled.\n"
            "  verdict audit requires decision history.\n\n"
            "  To enable:\n"
            "    unset OW_HISTORY_ENABLED\n"
            "    (or explicitly: export OW_HISTORY_ENABLED=true)\n\n"
            "  What is stored locally:\n"
            "    Decision outcomes, risk scores, policy names,\n"
            "    condition results. No plan contents.\n"
            "    No cost amounts. No resource names.\n\n"
            f"  Storage: {get_db_path()}\n"
        )
        raise typer.Exit(code=1)

    # ── Load data ─────────────────────────────────────
    recent: list[dict[str, Any]] = get_recent_records(limit=limit)
    effectiveness: list[dict[str, Any]] = get_policy_effectiveness(policy_name=policy)
    domain_summary: dict[str, Any] = get_domain_risk_summary()
    failed_conditions: list[dict[str, Any]] = get_failed_conditions_summary()
    passed_conditions: list[dict[str, Any]] = get_passed_conditions_summary()
    outcomes: list[dict[str, Any]] = get_outcome_summary()

    if not recent:
        typer.echo(
            "\n  No decision history found.\n"
            "  Run verdict evaluate to record decisions.\n"
        )
        raise typer.Exit(code=0)

    # ── JSON output ───────────────────────────────────
    if output_format == "json":
        output: dict[str, Any] = {
            "audit_summary": domain_summary,
            "policy_effectiveness": effectiveness,
            "failed_conditions": failed_conditions,
            "passed_conditions": passed_conditions,
            "outcomes": outcomes,
            "recent_decisions": recent[:limit],
        }
        if insights:
            insight_lines, rec_lines = _generate_insights_and_recommendations(
                domain_summary,
                effectiveness,
                failed_conditions,
                passed_conditions,
                outcomes,
            )
            output["insights"] = insight_lines
            output["recommendations"] = rec_lines
        typer.echo(json.dumps(output, indent=2, default=str))
        return

    # ── Table output ──────────────────────────────────
    _print_audit_table(
        recent=recent,
        effectiveness=effectiveness,
        domain_summary=domain_summary,
        failed_conditions=failed_conditions,
        passed_conditions=passed_conditions,
        outcomes=outcomes,
        policy_filter=policy,
        limit=limit,
        show_insights=insights,
    )


# =====================================================
# TABLE RENDERER
# =====================================================


def _print_audit_table(
    recent: list[dict[str, Any]],
    effectiveness: list[dict[str, Any]],
    domain_summary: dict[str, Any],
    failed_conditions: list[dict[str, Any]],
    passed_conditions: list[dict[str, Any]],
    outcomes: list[dict[str, Any]],
    policy_filter: Optional[str],
    limit: int,
    show_insights: bool,
) -> None:
    """Render the governance audit as a formatted table."""
    typer.echo("\n" + "─" * _WIDTH)
    typer.echo(_bold("  ObsidianWall Verdict — Governance Audit"))
    if policy_filter:
        typer.echo(f"  Policy filter: {policy_filter}")
    typer.echo("─" * _WIDTH)

    # ── Overview ──────────────────────────────────────
    total: int = domain_summary.get("total_evaluations", 0)
    denied: int = domain_summary.get("total_denied", 0)
    deny_rate: float = domain_summary.get("deny_rate", 0.0)
    allowed: int = total - denied

    typer.echo(f"\n  Total evaluations:  {total}")
    typer.echo(f"  Allowed:            {allowed}")
    typer.echo(f"  Denied:             {denied}  ({deny_rate}%)")

    # ── Domain risk scores ────────────────────────────
    domain_scores: dict[str, float] = domain_summary.get("domain_avg_scores", {})
    if domain_scores:
        typer.echo(f"\n{'─' * _WIDTH}")
        typer.echo(_bold("  Domain Risk Scores  (average across recorded decisions)"))
        typer.echo("─" * _WIDTH)
        for domain, score in sorted(
            domain_scores.items(),
            key=lambda item: item[1],
            reverse=True,
        ):
            label: str = _DOMAIN_LABELS.get(domain, domain)
            bar: str = _risk_bar(score)
            severity: str = _score_to_severity(score)
            typer.echo(f"  {label:<24}  {bar}  {score:>5.1f}/100  {severity}")

    # ── Why decisions were made ───────────────────────
    if failed_conditions or passed_conditions:
        typer.echo(f"\n{'─' * _WIDTH}")
        typer.echo(_bold("  Why Decisions Were Made"))
        typer.echo("─" * _WIDTH)

        if failed_conditions:
            typer.echo("\n  Failed conditions  (why deployments were DENIED)")
            typer.echo(f"  {'Condition':<40}  {'Failures':>8}  {'Rate':>6}")
            typer.echo(f"  {'─' * 40}  {'─' * 8}  {'─' * 6}")
            for c in failed_conditions[:10]:
                typer.echo(
                    f"  {str(c['condition_id']):<40}  "
                    f"{int(c['count']):>8}  "
                    f"{float(c['rate']):>5.1f}%"
                )

        if passed_conditions:
            typer.echo("\n  Passed conditions  (why deployments were ALLOWED)")
            typer.echo(f"  {'Condition':<40}  {'Passes':>7}  {'Rate':>6}")
            typer.echo(f"  {'─' * 40}  {'─' * 7}  {'─' * 6}")
            for c in passed_conditions[:10]:
                typer.echo(
                    f"  {str(c['condition_id']):<40}  "
                    f"{int(c['count']):>7}  "
                    f"{float(c['rate']):>5.1f}%"
                )

    # ── Policy effectiveness ──────────────────────────
    if effectiveness:
        typer.echo(f"\n{'─' * _WIDTH}")
        typer.echo(_bold("  Policy Effectiveness"))
        typer.echo("─" * _WIDTH)
        typer.echo(
            f"  {'Policy':<34}  {'Evals':>5}  "
            f"{'Denied':>6}  {'Overrides':>9}  "
            f"{'Override%':>9}  {'Deny%':>6}"
        )
        typer.echo(
            f"  {'─' * 34}  {'─' * 5}  {'─' * 6}  {'─' * 9}  {'─' * 9}  {'─' * 6}"
        )
        for row in effectiveness:
            evals: int = int(row.get("total_evaluations", 0))
            denied_r: int = int(row.get("total_denied", 0))
            overrides: int = int(row.get("override_count", 0))
            deny_pct: float = round(denied_r / evals * 100, 1) if evals else 0.0
            over_pct: float = round(overrides / denied_r * 100, 1) if denied_r else 0.0
            name: str = str(row.get("policy_name", ""))[:32]
            typer.echo(
                f"  {name:<34}  {evals:>5}  "
                f"{denied_r:>6}  {overrides:>9}  "
                f"{over_pct:>8.1f}%  {deny_pct:>5.1f}%"
            )

    # ── Deployment outcomes ────────────────────────────
    typer.echo(f"\n{'─' * _WIDTH}")
    typer.echo(_bold("  Deployment Outcomes  (populated by verdict sentinel scan)"))
    typer.echo("─" * _WIDTH)
    if outcomes:
        typer.echo(f"  {'Outcome Type':<32}  {'Count':>6}")
        typer.echo(f"  {'─' * 32}  {'─' * 6}")
        for row in outcomes:
            typer.echo(f"  {str(row['outcome_type']):<32}  {int(row['count']):>6}")
    else:
        typer.echo(
            "  No outcomes recorded yet.\n"
            "  Run verdict sentinel scan to record what happened\n"
            "  after each deployment decision."
        )

    # ── Recent decisions ───────────────────────────────
    typer.echo(f"\n{'─' * _WIDTH}")
    typer.echo(_bold(f"  Recent Decisions  (last {min(len(recent), limit)})"))
    typer.echo("─" * _WIDTH)
    typer.echo(
        f"  {'Decision ID':<12}  {'When':<16}  {'Policy':<24}  "
        f"{'Decision':<24}  {'Score':>6}"
    )
    typer.echo(
        f"  {'─' * 12}  {'─' * 16}  {'─' * 24}  {'─' * 24}  {'─' * 6}"
    )
    for row in recent[:limit]:
        short_id: str = str(row.get("record_id", ""))[:8]
        # created_at is stored as an ISO 8601 timestamp
        # (e.g. "2026-07-18T00:08:30.863793+00:00"). Trim to
        # "2026-07-18 00:08" for a compact, readable column —
        # full precision remains in the record itself and in
        # verdict explain.
        raw_timestamp: str = str(row.get("created_at", ""))
        when: str = raw_timestamp[:16].replace("T", " ") if raw_timestamp else "—"
        name_r: str = str(row.get("policy_name", ""))[:22]
        decision: str = str(row.get("decision", ""))[:22]
        score: int = int(row.get("overall_risk_score", 0))
        icon: str = decision_icon(str(row.get("decision", "")))
        typer.echo(
            f"  {short_id:<12}  {when:<16}  {name_r:<24}  "
            f"{icon} {decision:<22}  {score:>5}/100"
        )

    # ── Governance insights + recommendations ─────────
    if show_insights:
        insight_lines, rec_lines = _generate_insights_and_recommendations(
            domain_summary,
            effectiveness,
            failed_conditions,
            passed_conditions,
            outcomes,
        )

        typer.echo(f"\n{'─' * _WIDTH}")
        typer.echo("  Governance Insights")
        typer.echo("─" * _WIDTH)
        if insight_lines:
            for line in insight_lines:
                typer.echo(f"  {line}")
        else:
            typer.echo(
                "  Not enough data for insights yet.\n"
                "  Run more evaluations to surface patterns."
            )

        typer.echo(f"\n{'─' * _WIDTH}")
        typer.echo("  Recommendations")
        typer.echo("─" * _WIDTH)
        if rec_lines:
            for i, line in enumerate(rec_lines, start=1):
                typer.echo(f"  {i}. {line}")
        else:
            typer.echo("  No recommendations at this time.")

    typer.echo("\n" + "─" * _WIDTH + "\n")


# =====================================================
# INSIGHTS + RECOMMENDATIONS ENGINE
#
# Pure heuristics over telemetry data.
# No ML. No LLMs. Deterministic pattern detection.
#
# Separation of concerns:
#   Insights        → interpretation of what happened
#   Recommendations → what to do about it
#
# Aligned with ObsidianWall doctrine:
#   AI may advise. AI may not govern.
# =====================================================


def _generate_insights_and_recommendations(
    domain_summary: dict[str, Any],
    effectiveness: list[dict[str, Any]],
    failed_conditions: list[dict[str, Any]],
    passed_conditions: list[dict[str, Any]],
    outcomes: list[dict[str, Any]],
) -> tuple[list[str], list[str]]:
    """
    Generate governance insights and recommendations
    from telemetry data.

    Returns:
        (insights, recommendations) — two separate lists.
    """
    insights: list[str] = []
    recommendations: list[str] = []

    total: int = domain_summary.get("total_evaluations", 0)
    domain_scores: dict[str, float] = domain_summary.get("domain_avg_scores", {})

    if total == 0:
        return insights, recommendations

    total_approvals: int = sum(
        int(row.get("approval_count", 0)) for row in effectiveness
    )
    total_overrides: int = sum(
        int(row.get("override_count", 0)) for row in effectiveness
    )
    total_denied_all: int = sum(
        int(row.get("total_denied", 0)) for row in effectiveness
    )

    # ── Policy health ─────────────────────────────────
    for row in effectiveness:
        name: str = str(row.get("policy_name", ""))
        evals: int = int(row.get("total_evaluations", 0))
        denied_: int = int(row.get("total_denied", 0))
        overrides: int = int(row.get("override_count", 0))

        if evals == 0:
            continue

        p_deny: float = round(denied_ / evals * 100, 1)
        p_over: float = round(overrides / denied_ * 100, 1) if denied_ else 0.0

        if p_deny == 100.0:
            insights.append(
                f"⚠  '{name}' is denying 100% of evaluations.\n"
                f"     Threshold may be too strict or deployments\n"
                f"     consistently exceed policy limits."
            )
            recommendations.append(
                f"Review '{name}' threshold — it is responsible\n"
                f"     for 100% of denials. Consider whether the\n"
                f"     policy limit reflects realistic deployment patterns."
            )
        elif p_deny == 0.0 and evals >= 5:
            insights.append(
                f"ℹ  '{name}' has not denied any deployments "
                f"across {evals} evaluations.\n"
                f"     Policy may be too permissive."
            )
            recommendations.append(
                f"Audit '{name}' — zero denials across {evals}\n"
                f"     evaluations may indicate the policy threshold\n"
                f"     is too lenient."
            )

        if p_over >= 60.0 and denied_ >= 3:
            insights.append(
                f"⚠  '{name}' has a {p_over:.0f}% override rate.\n"
                f"     Policy may not reflect deployment reality."
            )
            recommendations.append(
                f"Investigate override pattern for '{name}'.\n"
                f"     {p_over:.0f}% override rate suggests the policy\n"
                f"     threshold needs adjustment."
            )
        elif p_over >= 30.0 and denied_ >= 3:
            insights.append(
                f"ℹ  '{name}' has a moderate override rate "
                f"({p_over:.0f}%).\n"
                f"     Monitor whether overrides become the norm."
            )

    # ── Domain risk ───────────────────────────────────
    if domain_scores:
        top_domain: str = max(domain_scores, key=lambda d: domain_scores[d])
        top_score: float = domain_scores[top_domain]
        label: str = _DOMAIN_LABELS.get(top_domain, top_domain)

        if top_score >= 40.0:
            insights.append(
                f"ℹ  {label} is the highest risk domain "
                f"(avg score: {top_score:.0f}/100)."
            )
            recommendations.append(
                f"Review {label.lower()} governance policies.\n"
                f"     This domain is driving the most aggregate risk."
            )

    # ── Top failed condition ──────────────────────────
    if failed_conditions:
        top_failed: dict[str, Any] = failed_conditions[0]
        if float(top_failed.get("rate", 0)) >= 50.0:
            insights.append(
                f"ℹ  '{top_failed['condition_id']}' is the most "
                f"frequently failed condition\n"
                f"     ({top_failed['count']} failures, "
                f"{top_failed['rate']:.0f}% of evaluations)."
            )
            recommendations.append(
                f"Review '{top_failed['condition_id']}' condition —\n"
                f"     it is responsible for {top_failed['rate']:.0f}%\n"
                f"     of all denials. Check whether the threshold\n"
                f"     is calibrated correctly."
            )

    # ── Approval gap ──────────────────────────────────
    if total_denied_all > 0 and total_approvals == 0:
        insights.append(
            "ℹ  No approvals recorded.\n"
            "     Approval workflow has not been exercised yet."
        )
        recommendations.append(
            "Exercise the approval workflow.\n"
            "     Approvals have not been recorded. Ensure\n"
            "     authorized approvers know how to grant approvals\n"
            "     for blocked deployments."
        )

    # ── Override gap ──────────────────────────────────
    if total_denied_all > 0 and total_overrides == 0:
        insights.append(
            "ℹ  No overrides recorded.\n     Override authority has not been exercised."
        )
        recommendations.append(
            "Validate the override process.\n"
            "     No overrides have been recorded. Ensure\n"
            "     authorized roles are aware of their\n"
            "     override capability."
        )

    # ── Outcomes gap ──────────────────────────────────
    if not outcomes and total >= 5:
        insights.append(
            "ℹ  No deployment outcomes recorded.\n"
            "     Without outcomes, policy effectiveness cannot\n"
            "     be measured against real-world results."
        )
        recommendations.append(
            "Run verdict sentinel scan to record deployment\n"
            "     outcomes. Without outcome data, it is impossible\n"
            "     to know whether governance decisions are achieving\n"
            "     their intended effect."
        )

    return insights, recommendations


# =====================================================
# HELPERS
# =====================================================


def _risk_bar(score: float, width: int = 12) -> str:
    """Render a simple ASCII risk bar."""
    filled: int = round(score / 100 * width)
    return "[" + "█" * filled + "░" * (width - filled) + "]"


def _score_to_severity(score: float) -> str:
    """Map a 0–100 risk score to a severity label."""
    if score >= 80.0:
        return "critical"
    if score >= 60.0:
        return "high"
    if score >= 40.0:
        return "medium"
    if score >= 20.0:
        return "low"
    return "informational"
