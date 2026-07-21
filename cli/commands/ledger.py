# cli/commands/ledger.py
#
# Purpose:
# verdict ledger — the Risk Acceptance Ledger.
#
# Lists every governance record where risk was CONFIRMED
# accepted — a DENY_WITH_OVERRIDE decision that was
# subsequently approved via an override, per
# get_risk_acceptance_records(). This is the accountability
# record: who accepted what risk, when, and under which
# policy.
#
# Per the June 20th roadmap, this is the "architecture" phase
# of the Risk Acceptance Ledger — tamper-evidence is provided
# by governance_history's chained SHA-256 hashes (see
# verify_history_chain()), not by cryptographic signing.
# True cryptographic signing (a keypair-based signature over
# each entry) is a larger future addition, not implemented here.
#
# Usage:
#   verdict ledger
#   verdict ledger --policy policies/cost/basic_budget.yaml
#   verdict ledger --format json
#
# For full detail on any single entry, use:
#   verdict explain <decision_id>
# Risk acceptance records ARE governance records — no
# separate detail view exists or is needed.

from __future__ import annotations

import json
from typing import Any, Optional

import typer

from renderers.ansi import _bold, _dim
from telemetry.config import get_db_path, is_telemetry_enabled
from telemetry.governance_store import get_risk_acceptance_records

ledger_app = typer.Typer(
    help="The Risk Acceptance Ledger — confirmed risk acceptances.",
)

_WIDTH = 72


@ledger_app.callback(invoke_without_command=True)
def ledger(
    policy: Optional[str] = typer.Option(
        None,
        "--policy",
        help="Filter to a specific policy name.",
    ),
    output_format: str = typer.Option(
        "table",
        "--format",
        "-f",
        help="Output format: table (default) or json.",
    ),
    limit: int = typer.Option(
        50,
        "--limit",
        "-l",
        help="Number of entries to show.",
    ),
) -> None:
    """
    The Risk Acceptance Ledger.

    Lists every governance decision where risk was CONFIRMED
    accepted — a blocked deployment that was subsequently
    overridden and approved. This is the accountability
    record for every risk acceptance decision: who accepted
    it, when, and under which policy.

    A record appears here only after BOTH conditions are met:
      1. The original decision was DENY_WITH_OVERRIDE
      2. An override was subsequently APPROVED against it

    This is not the same as every override attempt — denied
    or pending overrides do not appear here, only confirmed
    acceptances.

    Examples:
      verdict ledger
      verdict ledger --policy policies/cost/basic_budget.yaml
      verdict ledger --format json
    """
    if not is_telemetry_enabled():
        typer.echo(
            "\n  Telemetry is disabled.\n"
            "  verdict ledger requires decision history.\n\n"
            "  To enable:\n"
            "    unset OW_HISTORY_ENABLED\n\n"
            f"  Storage: {get_db_path()}\n"
        )
        raise typer.Exit(code=1)

    records: list[dict[str, Any]] = get_risk_acceptance_records()

    if policy:
        records = [r for r in records if r.get("policy_name") == policy]

    records = records[:limit]

    if not records:
        typer.echo(
            "\n  No confirmed risk acceptances found.\n"
            "  A record appears here after a DENY_WITH_OVERRIDE\n"
            "  decision has been overridden and approved.\n"
        )
        raise typer.Exit(code=0)

    if output_format == "json":
        typer.echo(json.dumps(records, indent=2, default=str))
        return

    _print_ledger_table(records, policy_filter=policy)


def _print_ledger_table(
    records: list[dict[str, Any]],
    policy_filter: Optional[str],
) -> None:
    """Render the Risk Acceptance Ledger as a formatted table."""
    typer.echo("\n" + "─" * _WIDTH)
    typer.echo(f"  {_bold('ObsidianWall Verdict — Risk Acceptance Ledger')}")
    if policy_filter:
        typer.echo(f"  Policy filter: {policy_filter}")
    typer.echo("─" * _WIDTH)

    typer.echo(f"\n  {len(records)} confirmed risk acceptance(s)")

    typer.echo(f"\n{'─' * _WIDTH}")
    header = (
        f"  {_bold('Decision ID'.ljust(12))}  {_bold('When'.ljust(16))}  "
        f"{_bold('Policy'.ljust(22))}  {_bold('Accepted By'.ljust(16))}  "
        f"{_bold('Risk'.rjust(6))}"
    )
    typer.echo(header)
    typer.echo(f"  {'─' * 12}  {'─' * 16}  {'─' * 22}  {'─' * 16}  {'─' * 6}")

    for record in records:
        short_id: str = str(record.get("record_id", ""))[:8]

        raw_timestamp: str = str(record.get("created_at", ""))
        when: str = raw_timestamp[:16].replace("T", " ") if raw_timestamp else "—"

        policy_name: str = str(record.get("policy_name", ""))[:20]
        accepted_by: str = str(record.get("accepted_by") or "—")[:14]
        risk_score: int = int(record.get("overall_risk_score", 0))

        typer.echo(
            f"  {short_id:<12}  {when:<16}  {policy_name:<22}  "
            f"{accepted_by:<16}  {risk_score:>4}/100"
        )

    typer.echo(f"\n{'─' * _WIDTH}")
    typer.echo(
        f"  {_dim('Run')} verdict explain <decision_id> "
        f"{_dim('for full detail on any entry')}"
    )
    typer.echo("─" * _WIDTH + "\n")
