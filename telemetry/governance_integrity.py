# telemetry/governance_integrity.py
#
# Purpose:
# Two DIFFERENT, independently-checkable guarantees about a
# record's history:
#   verify_history_chain()   proves the DATA hasn't been
#                            silently altered (tamper-evidence,
#                            recomputed hash chain)
#   verify_signature()        proves a SPECIFIC KEY produced
#                            the signature over that data
#                            (attestation — see ADR-0002)
# Kept together in one module because both answer "can this
# record be trusted," even though they check fundamentally
# different things. Likely to expand later (checkpoint
# verification, Merkle roots, external attestation) — see
# original governance_store.py module docstring.

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from telemetry.governance_db import init_governance_db
from telemetry.governance_hashing import hash_history_data


def verify_history_chain(
    record_id: str,
    db_path: Path | None = None,
) -> dict[str, Any]:
    """
    Verify the tamper-evidence chain for a record's history.
    Recomputes each entry's hash from its stored data and
    confirms prev_history_hash links match.

    Returns:
        dict with "verified" (bool), "history_count" (int),
        and "broken_at" (int | None — the history_number
        where verification first failed, if any).
    """
    conn = None
    try:
        conn = init_governance_db(db_path)
        cursor = conn.execute(
            """
            SELECT history_number, history_data, history_hash,
                   prev_history_hash
            FROM governance_history
            WHERE record_id = ?
            ORDER BY history_number ASC
            """,
            (record_id,),
        )
        rows = [dict(row) for row in cursor.fetchall()]

        if not rows:
            return {"verified": True, "history_count": 0, "broken_at": None}

        expected_prev_hash: str | None = None

        for row in rows:
            try:
                data = json.loads(row["history_data"])
            except (json.JSONDecodeError, TypeError):
                data = row["history_data"]

            recomputed_hash = hash_history_data(
                data if isinstance(data, dict) else {"_raw": data}
            )

            if recomputed_hash != row["history_hash"]:
                return {
                    "verified": False,
                    "history_count": len(rows),
                    "broken_at": row["history_number"],
                }

            if row["prev_history_hash"] != expected_prev_hash:
                return {
                    "verified": False,
                    "history_count": len(rows),
                    "broken_at": row["history_number"],
                }

            expected_prev_hash = row["history_hash"]

        return {"verified": True, "history_count": len(rows), "broken_at": None}

    except Exception:
        return {"verified": False, "history_count": 0, "broken_at": None}


def verify_signature(
    record_id: str,
    history_number: int | None = None,
    db_path: Path | None = None,
) -> dict[str, Any]:
    """
    Verify the cryptographic attestation signature on a specific
    history entry — see ADR-0002.

    This is a DIFFERENT guarantee from verify_history_chain():
    the chain proves the DATA hasn't been silently altered.
    This proves a SPECIFIC KEY produced the signature over that
    data — attestation, not tamper-protection. Checked
    independently; a record can have valid chain integrity with
    no signature at all (pre-signing-era entries), or in
    principle a broken chain with a technically-valid signature
    (if the DATA changed after signing) — both are meaningful,
    distinct facts worth surfacing separately.

    Args:
        record_id: the governance record whose history entry to
            verify.
        history_number: which entry to check. Defaults to the
            MOST RECENT entry for this record if not given.

    Returns:
        dict with:
          "signed" (bool)          — was this entry ever signed
                                     at all
          "verified" (bool | None)  — None if unsigned (nothing
                                     to verify), True/False if
                                     signed
          "signing_method" (str | None)
          "key_fingerprint" (str | None)
          "detail" (str)            — human-readable explanation,
                                     always populated
    """
    conn = None
    try:
        conn = init_governance_db(db_path)

        if history_number is not None:
            cursor = conn.execute(
                """
                SELECT history_data, history_hash, signature,
                       signing_public_key, signing_key_fingerprint,
                       signing_method
                FROM governance_history
                WHERE record_id = ? AND history_number = ?
                """,
                (record_id, history_number),
            )
        else:
            cursor = conn.execute(
                """
                SELECT history_data, history_hash, signature,
                       signing_public_key, signing_key_fingerprint,
                       signing_method
                FROM governance_history
                WHERE record_id = ?
                ORDER BY history_number DESC LIMIT 1
                """,
                (record_id,),
            )

        row = cursor.fetchone()
        if row is None:
            return {
                "signed": False,
                "verified": None,
                "signing_method": None,
                "key_fingerprint": None,
                "detail": "No matching history entry found.",
            }

        row = dict(row)

        if not row.get("signature"):
            return {
                "signed": False,
                "verified": None,
                "signing_method": None,
                "key_fingerprint": None,
                "detail": (
                    "This entry has no attestation signature — "
                    "either it predates signing support, or "
                    "signing was not applicable to this entry type."
                ),
            }

        signing_method = row.get("signing_method")

        try:
            from telemetry.signing.base_signing import (
                SignatureResult,
                SigningError,
            )

            if signing_method == "gpg":
                from telemetry.signing.gpg_backend import GPGSigningBackend

                backend = GPGSigningBackend()
            elif signing_method == "ssh":
                from telemetry.signing.ssh_backend import SSHSigningBackend

                backend = SSHSigningBackend(identity="")
            else:
                return {
                    "signed": True,
                    "verified": False,
                    "signing_method": signing_method,
                    "key_fingerprint": row.get("signing_key_fingerprint"),
                    "detail": f"Unknown signing method: {signing_method!r}",
                }

            signature_result = SignatureResult(
                signature=row["signature"],
                public_key=row.get("signing_public_key", ""),
                key_fingerprint=row.get("signing_key_fingerprint", ""),
                signing_method=signing_method,
            )

            # What was actually signed is history_hash — the
            # SAME digest already covered by the tamper-evidence
            # chain, not a second representation. See ADR-0002.
            is_valid = backend.verify(row["history_hash"], signature_result)

            return {
                "signed": True,
                "verified": is_valid,
                "signing_method": signing_method,
                "key_fingerprint": row.get("signing_key_fingerprint"),
                "detail": (
                    "Signature verified — this key produced this attestation."
                    if is_valid
                    else "Signature verification FAILED — the "
                    "signature does not match this entry's data, "
                    "or does not match the embedded public key."
                ),
            }

        except SigningError as exc:
            return {
                "signed": True,
                "verified": False,
                "signing_method": signing_method,
                "key_fingerprint": row.get("signing_key_fingerprint"),
                "detail": f"Verification could not be completed: {exc}",
            }

    except Exception as exc:
        return {
            "signed": False,
            "verified": None,
            "signing_method": None,
            "key_fingerprint": None,
            "detail": f"Unexpected error during verification: {exc}",
        }

    finally:
        if conn is not None:
            conn.close()


# =====================================================
# READ — Aggregate / Relational Queries
# =====================================================
