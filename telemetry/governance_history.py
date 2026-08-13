# telemetry/governance_history.py
#
# Purpose:
# The append-only history lifecycle — every event after a
# governance record's creation (override requests/approvals,
# outcomes, drift, evidence additions) is a new entry here.
# Nothing in this table is ever updated in place. See
# telemetry/governance_db.py for the schema definition and
# telemetry/governance_store.py's original module docstring
# for the full design rationale behind this object model.

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from telemetry.config import is_telemetry_enabled
from telemetry.governance_db import init_governance_db
from telemetry.governance_hashing import hash_history_data
from telemetry.identity import resolve_actor_identity, resolve_execution_host


def _get_latest_history_hash(
    conn: sqlite3.Connection,
    record_id: str,
) -> str | None:
    """Return the history_hash of the most recent entry for a
    record, or None if this will be the first entry."""
    cursor = conn.execute(
        """
        SELECT history_hash FROM governance_history
        WHERE record_id = ?
        ORDER BY history_number DESC
        LIMIT 1
        """,
        (record_id,),
    )
    row = cursor.fetchone()
    return row["history_hash"] if row else None


def _get_next_history_number(
    conn: sqlite3.Connection,
    record_id: str,
) -> int:
    """Return the next sequential history_number for a record."""
    cursor = conn.execute(
        """
        SELECT MAX(history_number) as max_num
        FROM governance_history
        WHERE record_id = ?
        """,
        (record_id,),
    )
    row = cursor.fetchone()
    max_num = row["max_num"] if row and row["max_num"] is not None else 0
    return max_num + 1


# =====================================================
# WRITE — Create a Governance Record
# =====================================================


def add_history_entry(
    record_id: str,
    history_category: str,
    history_action: str,
    history_data: dict[str, Any],
    actor_role: str | None = None,
    actor_identity: str | None = None,
    execution_host: str | None = None,
    signature: str | None = None,
    signing_public_key: str | None = None,
    signing_key_fingerprint: str | None = None,
    signing_method: str | None = None,
    db_path: Path | None = None,
) -> bool:
    """
    Append a new entry to a governance record's history.

    This is the single mutation mechanism for a record's
    entire lifecycle — override requests/approvals, approval
    decisions, outcome observations, drift detection, evidence
    additions, and any future event type — all use this one
    function.

    history_category + history_action are split so queries
    stay simple as new event types accumulate. "Every
    override-related event" is WHERE history_category =
    'override' — no growing IN (...) list to maintain.

    Args:
        record_id:         the governance record this entry
                           applies to
        history_category:  decision | override | approval |
                           outcome | drift | evidence
        history_action:     created | requested | approved |
                           denied | revoked | observed |
                           detected | resolved
        history_data:        type-specific JSON-serializable
                           payload
        actor_role:          claimed authorization role
                           (e.g. "budget_owner") — who or
                           what CLAIMS to have triggered this
        actor_identity:      best-effort resolved identity
                           (see telemetry/identity.py) — WHO
                           actually ran the command. Auto-
                           resolved via resolve_actor_identity()
                           if not explicitly provided. NOT
                           authentication — a signal, not a
                           security control.
        db_path:              optional path override (for testing)
        signature:            attestation signature, if the caller
                             already signed this entry's data
                             BEFORE calling this function — see
                             ADR-0002 and telemetry/signing/.
                             This function does NOT sign
                             anything itself; it only persists
                             a signature the caller produced.
        signing_public_key:     embedded public key, for self-
                             contained verification — see
                             verify_signature() below.
        signing_key_fingerprint: for display and cross-entry
                             key-consistency checking.
        signing_method:           "gpg" | "ssh" — which backend
                             produced this signature.

    Returns:
        True if written, False if telemetry disabled, the
        parent record does not exist, or the write failed.
        Never raises.
    """
    if not is_telemetry_enabled():
        return False

    if actor_identity is None:
        actor_identity = resolve_actor_identity()
    if execution_host is None:
        execution_host = resolve_execution_host()

    conn = None
    try:
        conn = init_governance_db(db_path)

        parent = conn.execute(
            "SELECT record_id FROM governance_records WHERE record_id = ?",
            (record_id,),
        ).fetchone()
        if parent is None:
            return False

        history_number = _get_next_history_number(conn, record_id)
        prev_hash = _get_latest_history_hash(conn, record_id)
        history_hash = hash_history_data(history_data)
        timestamp = datetime.now(timezone.utc).isoformat()

        conn.execute(
            """
            INSERT INTO governance_history (
                history_id, record_id, history_number,
                history_category, history_action,
                history_data, history_hash,
                prev_history_hash, actor_role, actor_identity,
                execution_host, signature, signing_public_key,
                signing_key_fingerprint, signing_method, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()),
                record_id,
                history_number,
                history_category,
                history_action,
                json.dumps(history_data, default=str),
                history_hash,
                prev_hash,
                actor_role,
                actor_identity,
                execution_host,
                signature,
                signing_public_key,
                signing_key_fingerprint,
                signing_method,
                timestamp,
            ),
        )

        conn.execute(
            """
            UPDATE governance_records
            SET current_history_number = ?,
                current_history_category = ?,
                current_history_action = ?
            WHERE record_id = ?
            """,
            (history_number, history_category, history_action, record_id),
        )

        conn.commit()
        return True

    except Exception:
        return False

    finally:
        if conn is not None:
            conn.close()


# =====================================================
# READ — Governance Record
# =====================================================


def get_governance_history(
    record_id: str,
    history_category: str | None = None,
    db_path: Path | None = None,
) -> list[dict[str, Any]]:
    """
    Return the full history for a governance record, oldest
    first. Each entry includes its parsed history_data.

    Args:
        record_id:         the governance record
        history_category:  optional filter, e.g. "override" to
                           see only override-related events
        db_path:             optional path override (for testing)

    Returns an empty list if the record has no history or on
    read error. Never raises.
    """
    conn = None
    try:
        conn = init_governance_db(db_path)

        if history_category:
            cursor = conn.execute(
                """
                SELECT * FROM governance_history
                WHERE record_id = ? AND history_category = ?
                ORDER BY history_number ASC
                """,
                (record_id, history_category),
            )
        else:
            cursor = conn.execute(
                """
                SELECT * FROM governance_history
                WHERE record_id = ?
                ORDER BY history_number ASC
                """,
                (record_id,),
            )

        rows = [dict(row) for row in cursor.fetchall()]

        for row in rows:
            try:
                row["history_data"] = json.loads(row["history_data"])
            except (json.JSONDecodeError, TypeError):
                pass

        return rows

    except Exception:
        return []

    finally:
        if conn is not None:
            conn.close()
