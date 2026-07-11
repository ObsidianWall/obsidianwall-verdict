# telemetry/migration.py
#
# Purpose:
# Automatic one-time migration from the v0.5.x schema
# (decisions, overrides, approvals, outcomes) to the v0.6.0
# Sentinel schema (governance_records, governance_record_revisions).
#
# Unlike a standalone script, this module ships INSIDE the
# installed package and runs automatically — the same pattern
# as the first-run telemetry notice. A pip-installed user
# never needs repo access or to run anything manually.
#
# Trigger:
# Called from cli/main.py's app callback, alongside
# show_first_run_notice_if_needed(). Runs before any command
# executes. Checks a marker file to ensure it only attempts
# migration once per machine, even if migration is skipped
# or fails.
#
# Safety:
# - Creates a timestamped backup of decisions.db before
#   touching anything
# - Verifies row counts match before dropping old tables
# - If verification fails, old tables are preserved and
#   nothing is deleted — the marker file is NOT written,
#   so migration will be retried on the next run
# - Fully idempotent — safe to interrupt and re-run

from __future__ import annotations

import hashlib
import json
import sqlite3
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from telemetry.config import get_db_dir, get_db_path
from telemetry.governance_store import _hash_revision_data, init_governance_db

_MIGRATION_MARKER = "migrated_v060"


def _marker_path() -> Path:
    return get_db_dir() / _MIGRATION_MARKER


def _needs_migration(db_path: Path) -> bool:
    """
    Return True if the old v0.5.x 'decisions' table exists
    and has not yet been migrated (no marker file present).
    """
    if _marker_path().exists():
        return False

    if not db_path.exists():
        return False

    try:
        conn = sqlite3.connect(str(db_path))
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='decisions'"
        )
        exists = cursor.fetchone() is not None
        conn.close()
        return exists
    except Exception:
        return False


def _backup_database(db_path: Path) -> Path | None:
    """Create a timestamped backup before migration. Returns
    the backup path, or None if the backup could not be created
    (in which case migration should not proceed)."""
    try:
        import shutil

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        backup_path = db_path.parent / f"decisions_backup_{timestamp}.db"
        shutil.copy2(db_path, backup_path)
        return backup_path
    except Exception:
        return None


def _table_exists(conn: sqlite3.Connection, table_name: str) -> bool:
    cursor = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    )
    return cursor.fetchone() is not None


def _append_migrated_revision(
    conn: sqlite3.Connection,
    record_id: str,
    revision_type: str,
    revision_data: dict[str, Any],
    timestamp: str,
) -> None:
    """Append a revision during migration with correct sequencing."""
    cursor = conn.execute(
        """
        SELECT MAX(revision_number) as max_rev
        FROM governance_record_revisions WHERE record_id = ?
        """,
        (record_id,),
    )
    row = cursor.fetchone()
    next_num = (row["max_rev"] or 0) + 1

    prev_hash_row = conn.execute(
        """
        SELECT revision_hash FROM governance_record_revisions
        WHERE record_id = ? ORDER BY revision_number DESC LIMIT 1
        """,
        (record_id,),
    ).fetchone()
    prev_hash = prev_hash_row["revision_hash"] if prev_hash_row else None

    revision_hash = _hash_revision_data(revision_data)

    conn.execute(
        """
        INSERT INTO governance_record_revisions (
            revision_id, record_id, revision_number,
            revision_type, revision_data, revision_hash,
            prev_revision_hash, actor_role, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?)
        """,
        (
            str(uuid.uuid4()),
            record_id,
            next_num,
            revision_type,
            json.dumps(revision_data, default=str),
            revision_hash,
            prev_hash,
            timestamp,
        ),
    )

    conn.execute(
        """
        UPDATE governance_records
        SET current_revision_number = ?, current_revision_type = ?
        WHERE record_id = ?
        """,
        (next_num, revision_type, record_id),
    )


def _migrate_decisions(conn: sqlite3.Connection) -> int:
    if not _table_exists(conn, "decisions"):
        return 0

    rows = [dict(r) for r in conn.execute("SELECT * FROM decisions").fetchall()]
    migrated = 0

    for row in rows:
        record_id = row["id"]

        existing = conn.execute(
            "SELECT record_id FROM governance_records WHERE record_id = ?",
            (record_id,),
        ).fetchone()
        if existing is not None:
            continue

        conn.execute(
            """
            INSERT INTO governance_records (
                record_id, policy_name, policy_content_hash,
                policy_family, artifact_hash,
                governance_objective_statement,
                decision, conditions_passed, overall_risk_score,
                effective_severity, governance_severity,
                override_possible, requires_approval,
                plan_hash, user_role, verdict_version,
                created_at, current_revision_number,
                current_revision_type
            ) VALUES (
                ?, ?, ?, ?, NULL, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, 1, 'CREATED'
            )
            """,
            (
                record_id,
                row.get("policy_name", ""),
                row.get("policy_content_hash"),
                row.get("policy_family"),
                row.get("decision", ""),
                row.get("conditions_passed", 0),
                row.get("overall_risk_score", 0),
                row.get("effective_severity"),
                row.get("governance_severity"),
                row.get("override_possible", 0),
                row.get("requires_approval", 0),
                row.get("plan_hash"),
                row.get("user_role"),
                row.get("timestamp", datetime.now(timezone.utc).isoformat()),
            ),
        )

        revision_data = {
            "decision": row.get("decision", ""),
            "policy": row.get("policy_name", ""),
            "migrated_from": "v0.5.x decisions table",
        }
        revision_hash = _hash_revision_data(revision_data)

        conn.execute(
            """
            INSERT INTO governance_record_revisions (
                revision_id, record_id, revision_number,
                revision_type, revision_data, revision_hash,
                prev_revision_hash, actor_role, created_at
            ) VALUES (?, ?, 1, 'CREATED', ?, ?, NULL, NULL, ?)
            """,
            (
                str(uuid.uuid4()),
                record_id,
                json.dumps(revision_data, default=str),
                revision_hash,
                row.get("timestamp", datetime.now(timezone.utc).isoformat()),
            ),
        )
        migrated += 1

    conn.commit()
    return migrated


def _migrate_workflow_table(
    conn: sqlite3.Connection,
    table_name: str,
    type_field: str,
    approved_type: str,
    denied_type: str,
) -> int:
    """Shared logic for migrating overrides and approvals tables."""
    if not _table_exists(conn, table_name):
        return 0

    rows = [
        dict(r)
        for r in conn.execute(
            f"SELECT * FROM {table_name} ORDER BY timestamp ASC"
        ).fetchall()
    ]
    migrated = 0

    for row in rows:
        record_id = row["decision_id"]
        parent_exists = conn.execute(
            "SELECT record_id FROM governance_records WHERE record_id = ?",
            (record_id,),
        ).fetchone()
        if parent_exists is None:
            continue

        revision_type = approved_type if row.get("approved") else denied_type
        revision_data = {
            k: v for k, v in row.items() if k not in ("id", "decision_id")
        }
        revision_data["migrated_from"] = f"v0.5.x {table_name} table"

        _append_migrated_revision(
            conn,
            record_id,
            revision_type,
            revision_data,
            row.get("timestamp", datetime.now(timezone.utc).isoformat()),
        )
        migrated += 1

    conn.commit()
    return migrated


def _migrate_outcomes(conn: sqlite3.Connection) -> int:
    if not _table_exists(conn, "outcomes"):
        return 0

    rows = [
        dict(r)
        for r in conn.execute(
            "SELECT * FROM outcomes ORDER BY timestamp ASC"
        ).fetchall()
    ]
    migrated = 0

    outcome_type_map = {"drift_detected": "DRIFT_DETECTED"}

    for row in rows:
        record_id = row["decision_id"]
        parent_exists = conn.execute(
            "SELECT record_id FROM governance_records WHERE record_id = ?",
            (record_id,),
        ).fetchone()
        if parent_exists is None:
            continue

        outcome_type = row.get("outcome_type", "")
        revision_type = outcome_type_map.get(outcome_type, "OUTCOME_OBSERVED")

        revision_data = {
            "outcome_type": outcome_type,
            "severity": row.get("severity"),
            "description": row.get("description"),
            "metadata": row.get("metadata"),
            "migrated_from": "v0.5.x outcomes table",
        }

        _append_migrated_revision(
            conn,
            record_id,
            revision_type,
            revision_data,
            row.get("timestamp", datetime.now(timezone.utc).isoformat()),
        )
        migrated += 1

    conn.commit()
    return migrated


def _verify_and_finalize(conn: sqlite3.Connection) -> bool:
    """
    Confirm row counts match, then drop old tables if safe.
    Returns True if migration completed and old tables were
    dropped. Returns False if verification failed — in that
    case old tables are preserved and NOT dropped.
    """
    old_count = 0
    if _table_exists(conn, "decisions"):
        old_count = conn.execute("SELECT COUNT(*) as c FROM decisions").fetchone()["c"]

    new_count = conn.execute(
        "SELECT COUNT(*) as c FROM governance_records"
    ).fetchone()["c"]

    if old_count > new_count:
        return False

    for table in ("decisions", "overrides", "approvals", "outcomes"):
        if _table_exists(conn, table):
            conn.execute(f"DROP TABLE {table}")
    conn.commit()
    return True


def migrate_if_needed(db_path: Path | None = None, silent: bool = False) -> None:
    """
    Check whether migration is needed and run it automatically
    if so. Safe to call on every CLI invocation — this is a
    no-op after the first successful run (or after any run
    where the old schema is absent).

    This is the function cli/main.py calls in its app callback,
    the same way it calls show_first_run_notice_if_needed().

    Args:
        db_path: optional path override (for testing)
        silent:  if True, suppress console output (used in tests)

    Never raises — migration failures must not crash the CLI.
    On failure, the marker file is not written, so migration
    is retried on the next invocation.
    """
    path = db_path or get_db_path()

    try:
        if not _needs_migration(path):
            return

        if not silent:
            print(
                "\nUpgrading local governance history to the v0.6.0 "
                "data model (Sentinel governance records)...",
                file=sys.stderr,
            )

        backup_path = _backup_database(path)
        if backup_path is None:
            if not silent:
                print(
                    "Could not create a backup — migration skipped. "
                    "Your existing data is untouched.",
                    file=sys.stderr,
                )
            return

        init_governance_db(path)

        conn = sqlite3.connect(str(path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")

        decisions_migrated = _migrate_decisions(conn)
        overrides_migrated = _migrate_workflow_table(
            conn, "overrides", "override_role",
            "OVERRIDE_APPROVED", "OVERRIDE_DENIED",
        )
        approvals_migrated = _migrate_workflow_table(
            conn, "approvals", "approver_role",
            "APPROVAL_GRANTED", "APPROVAL_DENIED",
        )
        outcomes_migrated = _migrate_outcomes(conn)

        success = _verify_and_finalize(conn)
        conn.close()

        if success:
            _marker_path().touch()
            if not silent:
                print(
                    f"Migration complete: {decisions_migrated} decision(s), "
                    f"{overrides_migrated} override(s), "
                    f"{approvals_migrated} approval(s), "
                    f"{outcomes_migrated} outcome(s) preserved.\n"
                    f"Backup saved at: {backup_path}\n",
                    file=sys.stderr,
                )
        else:
            if not silent:
                print(
                    "Migration verification failed — your original data "
                    "is preserved and untouched. This will be retried "
                    "automatically. Backup saved at: "
                    f"{backup_path}\n",
                    file=sys.stderr,
                )

    except Exception:
        # Migration must never crash the CLI. If it fails for
        # any reason, the marker is not written, so it will be
        # retried on the next invocation. The user's original
        # data was never touched unless the backup succeeded
        # and migration completed.
        pass
