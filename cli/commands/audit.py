# cli/commands/audit.py
#
# Purpose:
# verdict audit command — governance risk summary
# across all recorded decisions.
#
# Usage:
#   verdict audit
#   verdict audit --policy policies/cost/basic_budget.yaml
#   verdict audit --limit 100
#   verdict audit --format json
#
# Requires telemetry to be enabled.
# Data source: ~/.obsidianwall/decisions.db
#
# Output:
#   Domain-by-domain governance risk report
#   Policy effectiveness summary
#   Denial rate and override rate
#   Recent decision history

from __future__ import annotations

import json
from typing import Optional

import typer

from telemetry.config import get_db_path, is_telemetry_enabled
from telemetry.store import (
    get_domain_risk_summary,
    get_policy_effectiveness,
    get_recent_decisions,
)


def audit(
    policy: Optional[str] = typer.Option(
        None,
        "--policy",
        "-p",
        help="Filter audit to a specific policy name.",
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
) -> None:
    """
    Governance risk audit across recorded decisions.

    Requires OW_TELEMETRY_ENABLED=true.
    Reads from ~/.obsidianwall/decisions.db.
    """

    # ── Telemetry gate ───────────────────────────────
    if not is_telemetry_enabled():
        typer.echo(
            "\n  Telemetry is disabled.\n"
            "  verdict audit requires decision history.\n\n"
            "  To enable:\n"
            "    export OW_TELEMETRY_ENABLED=true\n\n"
            "  What is stored locally:\n"
            "    Decision outcomes, risk scores, policy names.\n"
            "    No plan contents. No cost amounts.\n"
            "    No resource names. No org identifiers.\n\n"
            f"  Storage: {get_db_path()}\n"
        )
        raise typer.Exit(code=1)

    # ── Load data ────────────────────────────────────
    recent       = get_recent_decisions(limit=limit)
    effectiveness = get_policy_effectiveness(policy_name=policy)
    domain_summary = get_domain_risk_summary()

    if not recent:
        typer.echo(
            "\n  No decision history found.\n"
            "  Run verdict evaluate to record decisions.\n"
        )
        raise typer.Exit(code=0)

    # ── JSON output ──────────────────────────────────
    if output_format == "json":
        output = {
            "audit_summary":       domain_summary,
            "policy_effectiveness": effectiveness,
            "recent_decisions":    recent[:limit],
        }
        typer.echo(json.dumps(output, indent=2))
        return

    # ── Table output ─────────────────────────────────
    _print_audit_table(
        recent=recent,
        effectiveness=effectiveness,
        domain_summary=domain_summary,
        policy_filter=policy,
        limit=limit,
    )


def _print_audit_table(
    recent:        list[dict],
    effectiveness: list[dict],
    domain_summary: dict,
    policy_filter: str | None,
    limit:         int,
) -> None:
    """Render the governance audit as a formatted table."""

    width = 72

    typer.echo("\n" + "─" * width)
    typer.echo("  ObsidianWall Verdict — Governance Audit")
    if policy_filter:
        typer.echo(f"  Policy filter: {policy_filter}")
    typer.echo("─" * width)

    # ── Overview ─────────────────────────────────────
    total      = domain_summary.get("total_evaluations", 0)
    denied     = domain_summary.get("total_denied", 0)
    deny_rate  = domain_summary.get("deny_rate", 0)
    allowed    = total - denied

    typer.echo(f"\n  Total evaluations:  {total}")
    typer.echo(f"  Allowed:            {allowed}")
    typer.echo(f"  Denied:             {denied}  ({deny_rate}%)")

    # ── Domain risk scores ────────────────────────────
    domain_scores: dict = domain_summary.get("domain_avg_scores", {})
    if domain_scores:
        typer.echo(f"\n{'─' * width}")
        typer.echo("  Domain Risk Scores  (average across recorded decisions)")
        typer.echo("─" * width)

        domain_labels = {
            "cost_analysis":         "Cost",
            "topology_analysis":     "Network/Topology",
            "architecture_analysis": "Architecture",
            "utilization_analysis":  "Utilization",
        }

        for domain, score in sorted(
            domain_scores.items(), key=lambda x: x[1], reverse=True
        ):
            label    = domain_labels.get(domain, domain)
            bar      = _risk_bar(score)
            severity = _score_to_severity(score)
            typer.echo(
                f"  {label:<24}  {bar}  {score:>5.1f}/100  {severity}"
            )

    # ── Policy effectiveness ──────────────────────────
    if effectiveness:
        typer.echo(f"\n{'─' * width}")
        typer.echo("  Policy Effectiveness")
        typer.echo("─" * width)
        typer.echo(
            f"  {'Policy':<40}  {'Evals':>6}  {'Denied':>7}  "
            f"{'Override':>9}  {'Rate':>6}"
        )
        typer.echo(f"  {'─'*40}  {'─'*6}  {'─'*7}  {'─'*9}  {'─'*6}")

        for row in effectiveness:
            evals     = row.get("total_evaluations", 0)
            denied    = row.get("total_denied", 0)
            overrides = row.get("override_count", 0)
            rate      = round(denied / evals * 100, 1) if evals else 0
            name      = row.get("policy_name", "")[:38]

            typer.echo(
                f"  {name:<40}  {evals:>6}  {denied:>7}  "
                f"{overrides:>9}  {rate:>5.1f}%"
            )

    # ── Recent decisions ──────────────────────────────
    typer.echo(f"\n{'─' * width}")
    typer.echo(f"  Recent Decisions  (last {min(len(recent), limit)})")
    typer.echo("─" * width)
    typer.echo(
        f"  {'Decision ID':<12}  {'Policy':<32}  "
        f"{'Decision':<24}  {'Score':>6}"
    )
    typer.echo(
        f"  {'─'*12}  {'─'*32}  {'─'*24}  {'─'*6}"
    )

    for row in recent[:limit]:
        short_id  = str(row.get("id", ""))[:8]
        name      = str(row.get("policy_name", ""))[:30]
        decision  = str(row.get("decision", ""))[:22]
        score     = row.get("overall_risk_score", 0)
        icon      = "✅" if "ALLOW" == row.get("decision") else "🚫"

        typer.echo(
            f"  {short_id:<12}  {name:<32}  "
            f"{icon} {decision:<22}  {score:>5}/100"
        )

    typer.echo("\n" + "─" * width + "\n")


def _risk_bar(score: float, width: int = 12) -> str:
    """Render a simple ASCII risk bar."""
    filled = round(score / 100 * width)
    return "[" + "█" * filled + "░" * (width - filled) + "]"


def _score_to_severity(score: float) -> str:
    """Map a 0-100 risk score to a severity label."""
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return "informational"