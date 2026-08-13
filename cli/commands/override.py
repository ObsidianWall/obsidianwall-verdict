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
# ATTESTATION SIGNING (v0.6.0 — see
# docs/architecture/decisions/0002-attestation-signing.md):
# Every action here is now cryptographically signed —
# mandatory, no unsigned fallback. Signing resolves in order:
#   1. An existing GPG key, if configured
#   2. An existing SSH key, if configured
#   3. An Ed25519 key auto-generated and stored transparently
#      in the OS's own keystore (macOS Keychain / Windows
#      Credential Manager / Linux Secret Service) — the
#      guaranteed fallback for an approver with no GPG/SSH
#      setup at all (an accountant, an exec, HR).
# If genuinely no signing method can be reached at all (no
# GPG, no SSH, AND no functional OS keystore), the command
# REFUSES to run rather than silently record an unsigned
# entry — an attestation record cannot have unsigned records,
# by design.
#
# What this proves, and what it does NOT:
#   Proves: the holder of a specific key produced this
#   specific signature over this specific action.
#   Does NOT prove: that key belongs to the named identity,
#   unless a registered identity-to-key binding exists
#   (it doesn't yet — see ADR-0002). The honest claim is KEY
#   CONSISTENCY across every action attributed to one
#   identity, layered on top of the existing best-effort
#   identity string — not a replacement for verified identity.
#   This is attestation (non-repudiation), NOT tamper-
#   protection signing — that requires an external trust
#   anchor (Sentinel Cloud, HSM, cloud KMS) that does not
#   exist yet. Tamper-EVIDENCE still comes from
#   governance_history's chained SHA-256 hashes
#   (verify_history_chain()), unchanged and independent of
#   this signature.
#
# What this is still NOT:
#   - Not enforcement. Nothing here unblocks a CI/CD pipeline
#     or grants deployment permission. See the architecture
#     discussion in the private roadmap notes on Verdict vs.
#     enforcement.
#   - Not an approval chain. One approve/deny step, not a
#     multi-party workflow with required approvers per policy.
#     That's real future scope, not built here.
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
    hash_history_data,
    resolve_record_id,
)
from telemetry.identity import resolve_actor_identity

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


# =====================================================
# ATTESTATION SIGNING
# =====================================================


def _resolve_signing_backend(identity: str):
    """
    Resolve the first available signing backend, in order:
    GPG → SSH → OS keystore (guaranteed fallback).

    Returns None only if genuinely nothing works — no GPG, no
    SSH, AND no functional OS keystore backend at all. Callers
    must treat that as a hard stop, per ADR-0002's "no unsigned
    fallback" rule.
    """
    from telemetry.signing.gpg_backend import GPGSigningBackend

    gpg_backend = GPGSigningBackend()
    if gpg_backend.is_available():
        return gpg_backend

    from telemetry.signing.ssh_backend import SSHSigningBackend

    ssh_backend = SSHSigningBackend(identity=identity)
    if ssh_backend.is_available():
        return ssh_backend

    from telemetry.signing.os_keystore_backend import OSKeystoreSigningBackend

    keystore_backend = OSKeystoreSigningBackend(identity=identity)
    if keystore_backend.is_available():
        return keystore_backend

    return None


def _sign_and_record(full_id: str, history_action: str, reason: str) -> bool:
    """
    Resolve identity, sign the entry, and record it via
    add_history_entry(). Mandatory signing, no unsigned
    fallback — returns False (and prints a clear, actionable
    error) if no signing backend can be reached at all, rather
    than silently recording an unsigned entry.

    The same resolved identity is used for BOTH the signing
    key lookup AND actor_identity on the recorded entry, so
    "who signed this" and "who this is attributed to" are
    always consistent.
    """
    from telemetry.signing.base_signing import SigningError

    identity = resolve_actor_identity()
    history_data = {"reason": reason}
    history_hash = hash_history_data(history_data)

    backend = _resolve_signing_backend(identity)
    if backend is None:
        print(
            "\n  No signing method available — this action cannot be "
            "recorded.\n\n"
            "  Attestation requires a real cryptographic signature. "
            "Set up ONE of:\n"
            "    GPG:  gpg --full-generate-key\n"
            "    SSH:  ssh-keygen -t ed25519\n\n"
            "  If neither is available, a key should be generated "
            "automatically\n"
            "  via your OS keystore — this failure means that could "
            "not be\n"
            "  reached either. Confirm a secret storage service is "
            "running on\n"
            "  this machine (macOS Keychain, Windows Credential "
            "Manager, or a\n"
            "  Linux Secret Service daemon such as gnome-keyring or "
            "kwallet).\n",
            file=sys.stderr,
        )
        return False

    try:
        signature_result = backend.sign(history_hash)
    except SigningError as exc:
        print(f"\n  Signing failed: {exc}\n", file=sys.stderr)
        return False

    # First-use notice — only for the OS-keystore fallback, only
    # the first time a key is generated for this identity on
    # this machine. GPG/SSH never hit this since the user
    # already has a key by definition if that backend was chosen.
    if backend.method_name == "os-keystore-ed25519" and getattr(
        backend, "last_operation_created_new_key", False
    ):
        print(
            "\n  A secure signing key has been created for you and "
            "stored in your system keychain. This happens once.\n",
            file=sys.stderr,
        )

    success = add_history_entry(
        record_id=full_id,
        history_category="override",
        history_action=history_action,
        history_data=history_data,
        actor_identity=identity,
        signature=signature_result.signature,
        signing_public_key=signature_result.public_key,
        signing_key_fingerprint=signature_result.key_fingerprint,
        signing_method=signature_result.signing_method,
    )

    if success:
        print(
            f"  Signed with {signature_result.signing_method} "
            f"(key {signature_result.key_fingerprint[:16]})\n"
        )

    return success


# =====================================================
# COMMANDS
# =====================================================


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

    Signed — see module docstring for the signing resolution
    order and what the signature does and does not prove.
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

    success = _sign_and_record(full_id, "requested", reason)

    if not success:
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

    Signed — see module docstring for the signing resolution
    order and what the signature does and does not prove.
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

    # ── Separation of duties ──────────────────────────
    # The requester and approver must be different
    # identities. Applied to approve() specifically, not
    # deny() — denying your own request isn't a governance
    # risk (you're not granting yourself anything, just
    # withdrawing it), so self-denial is a legitimate,
    # ordinary action. Self-APPROVAL is the actual conflict
    # of interest: the person with the strongest incentive
    # to avoid scrutiny would otherwise be the one deciding
    # whether their own exception is granted.
    requester_identity = latest.get("actor_identity")
    approver_identity = resolve_actor_identity()

    if requester_identity and requester_identity == approver_identity:
        print(
            f"\n  Separation of duties violation — the requester "
            f"and approver cannot be the same identity.\n\n"
            f"  Requested by: {requester_identity}\n"
            f"  Attempting to approve as: {approver_identity}\n\n"
            f"  A different, authorized person must approve this "
            f"override.\n",
            file=sys.stderr,
        )
        raise typer.Exit(code=1)

    success = _sign_and_record(full_id, "approved", reason)

    if not success:
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

    Signed — see module docstring for the signing resolution
    order and what the signature does and does not prove.
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

    success = _sign_and_record(full_id, "denied", reason)

    if not success:
        raise typer.Exit(code=1)

    print(f"\n  Override denied for decision {full_id[:8]}.\n  Reason: {reason}\n")
