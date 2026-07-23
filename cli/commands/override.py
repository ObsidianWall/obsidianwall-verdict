# cli/commands/override.py
#
# Purpose:
# verdict override — the two-step override workflow.
#
# A DENY_WITH_OVERRIDE decision blocks deployment. This
# command lets an authorized human record that they are
# accepting the risk and proceeding anyway — but the
# override itself is subject to governance, not a single
# unilateral action.
#
#   verdict override request <decision_id> --reason "..."
#   verdict override approve <decision_id> --reason "..."
#   verdict override deny    <decision_id> --reason "..."
#
# request and approve are deliberately separate steps.
# approve REQUIRES a pending request to exist first — you
# cannot approve an override that was never requested. This
# is the one governance property worth enforcing today: the
# override mechanism itself doesn't become the weakest link
# in an otherwise deterministic system.
#
# What this is NOT:
#   - Not enforcement. Nothing here unblocks a CI/CD pipeline
#     or grants deployment permission. This is attestation —
#     a formal, tamper-evident record that a human made this
#     call, why, and when. See the architecture discussion in
#     the private roadmap notes on Verdict vs. enforcement.
#   - Not an approval chain. One approve/deny step, not a
#     multi-party workflow with required approvers per policy.
#     That's real future scope, not built here.
#   - Not cryptographic signing. Tamper-evidence comes from
#     governance_history's chained SHA-256 hashes
#     (verify_history_chain()), not a keypair signature.
#
# Usage:
#   verdict override request 5a09ef6d --reason "Emergency patch, CAB approved verbally, formal ticket to follow"
#   verdict override approve 5a09ef6d --reason "Confirmed with finance, one-time exception for Q3"
#   verdict override deny    5a09ef6d --reason "Insufficient justification, resubmit with cost breakdown"

from __future__ import annotations

import sys
from typing import Any

import typer

from telemetry.governance_store import (
    add_history_entry,
    get_governance_history,
    get_governance_record,
    resolve_record_id,
)

override_app = typer.Typer(
    help="Request and approve overrides on blocked deployments.",
)


def _print_not_found(short_id: str) -> None:
    print(
        f"No governance decision found matching '{short_id}'.\n"
        f"Check the decision ID and try again, or run "
        f"'verdict audit' to see recent decisions.",
        file=sys.stderr,
    )


def _resolve_or_exit(decision_id: str) -> str:
    full_id = resolve_record_id(decision_id)
    if full_id is None:
        _print_not_found(decision_id)
        raise typer.Exit(code=1)
    return full_id


def _latest_override_entry(full_id: str) -> dict[str, Any] | None:
    """Return the most recent override-category history entry
    for this record, or None if there isn't one."""
    history = get_governance_history(full_id, history_category="override")
    if not history:
        return None
    return history[-1]  # get_governance_history returns oldest-first


@override_app.command()
def request(
    decision_id: str = typer.Argument(
        ..., help="Decision ID to request an override for."
    ),
    reason: str = typer.Option(
        ...,
        "--reason",
        help="Why this override is being requested. Required.",
    ),
) -> None:
    """
    Request an override on a blocked (DENY_WITH_OVERRIDE)
    decision.

    Requires the decision to actually be override-eligible —
    a DENY_WITH_OVERRIDE decision where override_possible is
    true. This records the request only; it does not grant
    anything. A separate 'verdict override approve' step is
    required before this counts as a confirmed risk acceptance.
    """
    full_id = _resolve_or_exit(decision_id)
    record = get_governance_record(full_id)

    if record is None:
        _print_not_found(decision_id)
        raise typer.Exit(code=1)

    if not record.get("override_possible"):
        print(
            f"\n  Decision '{full_id[:8]}' is not eligible for override.\n"
            f"  Decision: {record.get('decision', '')}\n"
            f"  override_possible must be true for this command to apply.\n",
            file=sys.stderr,
        )
        raise typer.Exit(code=1)

    success = add_history_entry(
        record_id=full_id,
        history_category="override",
        history_action="requested",
        history_data={"reason": reason},
    )

    if not success:
        print(
            "\n  Failed to record override request. Telemetry may be disabled.\n",
            file=sys.stderr,
        )
        raise typer.Exit(code=1)

    print(
        f"\n  Override requested for decision {full_id[:8]}.\n"
        f"  Reason: {reason}\n\n"
        f"  Awaiting approval — run:\n"
        f'    verdict override approve {full_id[:8]} --reason "..."\n'
    )


@override_app.command()
def approve(
    decision_id: str = typer.Argument(
        ..., help="Decision ID to approve the override for."
    ),
    reason: str = typer.Option(
        ...,
        "--reason",
        help="Why this override is being approved. Required.",
    ),
) -> None:
    """
    Approve a previously requested override.

    Requires an existing 'requested' entry with no subsequent
    approve/deny resolution — you cannot approve an override
    that was never requested. This is what makes the override
    itself governed rather than a single unilateral action.

    Once approved, this decision appears in 'verdict ledger'
    as a confirmed risk acceptance.
    """
    full_id = _resolve_or_exit(decision_id)

    latest = _latest_override_entry(full_id)

    if latest is None:
        print(
            f"\n  No override request found for decision "
            f"{full_id[:8]}.\n"
            f"  Run 'verdict override request {full_id[:8]} "
            f'--reason "..."\' first.\n',
            file=sys.stderr,
        )
        raise typer.Exit(code=1)

    if latest.get("history_action") != "requested":
        print(
            f"\n  The most recent override action for "
            f"{full_id[:8]} is already '{latest.get('history_action')}'.\n"
            f"  A new request must be submitted before it can "
            f"be approved again.\n",
            file=sys.stderr,
        )
        raise typer.Exit(code=1)

    success = add_history_entry(
        record_id=full_id,
        history_category="override",
        history_action="approved",
        history_data={"reason": reason},
    )

    if not success:
        print(
            "\n  Failed to record override approval. Telemetry may be disabled.\n",
            file=sys.stderr,
        )
        raise typer.Exit(code=1)

    print(
        f"\n  Override approved for decision {full_id[:8]}.\n"
        f"  Reason: {reason}\n\n"
        f"  This now appears in 'verdict ledger' as a confirmed "
        f"risk acceptance.\n"
    )


@override_app.command()
def deny(
    decision_id: str = typer.Argument(
        ..., help="Decision ID to deny the override request for."
    ),
    reason: str = typer.Option(
        ...,
        "--reason",
        help="Why this override request is being denied. Required.",
    ),
) -> None:
    """
    Deny a previously requested override.

    Same pending-request requirement as 'approve' — you cannot
    deny a request that doesn't exist or was already resolved.
    Recording an explicit denial (rather than silently ignoring
    a request) preserves a complete history of the decision.
    """
    full_id = _resolve_or_exit(decision_id)

    latest = _latest_override_entry(full_id)

    if latest is None:
        print(
            f"\n  No override request found for decision {full_id[:8]}.\n",
            file=sys.stderr,
        )
        raise typer.Exit(code=1)

    if latest.get("history_action") != "requested":
        print(
            f"\n  The most recent override action for "
            f"{full_id[:8]} is already '{latest.get('history_action')}'.\n",
            file=sys.stderr,
        )
        raise typer.Exit(code=1)

    success = add_history_entry(
        record_id=full_id,
        history_category="override",
        history_action="denied",
        history_data={"reason": reason},
    )

    if not success:
        print(
            "\n  Failed to record override denial. Telemetry may be disabled.\n",
            file=sys.stderr,
        )
        raise typer.Exit(code=1)

    print(f"\n  Override denied for decision {full_id[:8]}.\n  Reason: {reason}\n")
