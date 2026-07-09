# cli/commands/explain.py
#
# Purpose:
# CLI command: verdict explain
#
# Retrieves the full evidence artifact for a past governance
# decision by decision_id and renders a mid-tier detail view —
# richer than the default evaluate text summary, but organized
# for human reading rather than a raw JSON dump.
#
# Reads from the evidence store (decision_artifacts table),
# not from the --output file — so this works even if the
# original file has been overwritten or deleted. See
# telemetry/store.py module docstring for the Decision vs.
# Evidence design rationale.
#
# Usage:
#   verdict explain <decision_id>
#   verdict explain 9e9c0819          (short ID prefix works)
#
# Exit codes:
#   0   Decision found and explained
#   1   Decision or artifact not found

from __future__ import annotations

import sys
from typing import Any

import typer

from telemetry.store import get_artifact, get_artifact_metadata, get_decision_by_id

explain_app = typer.Typer(
    name="explain",
    help="Show the full reasoning chain for a past governance decision.",
)


def _find_full_decision_id(short_id: str) -> str | None:
    """
    Resolve a short decision ID prefix (e.g. first 8 chars,
    as shown in verdict evaluate's text renderer footer) to
    a full decision_id.

    If short_id is already a full UUID and matches a stored
    decision, returns it unchanged. Otherwise searches recent
    decisions for a matching prefix.

    Returns None if no match is found.
    """
    # Try exact match first — handles full UUIDs directly.
    exact = get_decision_by_id(short_id)
    if exact is not None:
        return short_id

    # Fall back to prefix search across recent decisions.
    from telemetry.store import get_recent_decisions

    recent = get_recent_decisions(limit=500)
    matches = [d for d in recent if d.get("id", "").startswith(short_id)]

    if len(matches) == 1:
        return matches[0]["id"]

    return None


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

    Retrieves the complete evidence artifact from the local
    evidence store and renders governance reasoning, condition
    trace, analyzer findings, and recommendations with
    confidence scores — everything the default evaluate
    summary intentionally leaves out.

    Examples:

      Using the short ID from evaluate's footer:
        verdict explain 9e9c0819

      Using the full decision ID:
        verdict explain 9e9c0819-58e2-4ac6-a5a6-513ca7258ff6
    """
    full_id = _find_full_decision_id(decision_id)

    if full_id is None:
        _print_not_found(decision_id)
        raise typer.Exit(code=1)

    artifact: dict[str, Any] | None = get_artifact(full_id, artifact_type="evaluation")

    if artifact is None:
        print(
            f"Decision '{full_id}' was found, but no evidence "
            f"artifact is stored for it. This can happen for "
            f"decisions recorded before v0.5.2, or if telemetry "
            f"was disabled at evaluation time.",
            file=sys.stderr,
        )
        raise typer.Exit(code=1)

    metadata = get_artifact_metadata(full_id, artifact_type="evaluation")

    from renderers.explain_renderer import render_explain

    render_explain(
        artifact,
        artifact_hash=metadata.get("artifact_hash") if metadata else None,
        recorded_at=metadata.get("created_at") if metadata else None,
    )
