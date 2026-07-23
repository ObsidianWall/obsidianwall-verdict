# cli/commands/explain.py
#
# Purpose:
# CLI command: verdict explain
#
# Retrieves the full evidence for a past governance decision
# by decision_id and renders a mid-tier detail view — richer
# than the default evaluate text summary, but organized for
# human reading rather than a raw JSON dump.
#
# v0.6.0: reads from telemetry/governance_store.py
# (governance_records + governance_evidence), not from the
# --output file — so this works even if the original file has
# been overwritten or deleted. See telemetry/governance_store.py
# module docstring for the Governance Record / History /
# Evidence design rationale.
#
# Short-ID resolution (resolve_record_id) lives in
# governance_store.py as a shared function, not duplicated
# here privately — verdict override uses the same lookup.
#
# Usage:
#   verdict explain <decision_id>
#   verdict explain 9e9c0819          (short ID prefix works)
#
# Exit codes:
#   0   Decision found and explained
#   1   Decision or evidence not found

from __future__ import annotations

import sys
from typing import Any

import typer

from telemetry.governance_store import (
    get_governance_evidence,
    get_governance_evidence_metadata,
    resolve_record_id,
    verify_history_chain,
)

explain_app = typer.Typer(
    name="explain",
    help="Show the full reasoning chain for a past governance decision.",
)


def _print_not_found(short_id: str) -> None:
    print(
        f"No governance decision found matching '{short_id}'.\n"
        f"Check the decision ID and try again, or run "
        f"'verdict audit' to see recent decisions.",
        file=sys.stderr,
    )


@explain_app.callback(invoke_without_command=True)
def explain(
    decision_id: str = typer.Argument(
        ...,
        help=(
            "Decision ID to explain. Accepts either the full "
            "UUID or the short 8-character prefix shown in "
            "verdict evaluate's output footer."
        ),
    ),
) -> None:
    """
    Show the full reasoning chain for a past governance decision.

    Retrieves the complete evidence from the local governance
    store and renders governance reasoning, condition trace,
    analyzer findings, and recommendations with confidence
    scores — everything the default evaluate summary
    intentionally leaves out.

    Examples:

      Using the short ID from evaluate's footer:
        verdict explain 9e9c0819

      Using the full decision ID:
        verdict explain 9e9c0819-58e2-4ac6-a5a6-513ca7258ff6
    """
    full_id = resolve_record_id(decision_id)

    if full_id is None:
        _print_not_found(decision_id)
        raise typer.Exit(code=1)

    artifact: dict[str, Any] | None = get_governance_evidence(
        full_id, evidence_type="evaluation"
    )

    if artifact is None:
        print(
            f"Decision '{full_id}' was found, but no evidence "
            f"is stored for it. This can happen for decisions "
            f"recorded before v0.5.2, or if telemetry was "
            f"disabled at evaluation time.",
            file=sys.stderr,
        )
        raise typer.Exit(code=1)

    metadata = get_governance_evidence_metadata(full_id, evidence_type="evaluation")

    # Verify the governance history chain's tamper-evidence.
    # This recomputes every history entry's hash and confirms
    # the chain is intact — real computed verification, shown
    # in the Evidence section as "Integrity: Verified".
    chain_result = verify_history_chain(full_id)

    from renderers.explain_renderer import render_explain

    render_explain(
        artifact,
        artifact_hash=metadata.get("evidence_hash") if metadata else None,
        recorded_at=metadata.get("created_at") if metadata else None,
        chain_verified=chain_result.get("verified"),
    )
