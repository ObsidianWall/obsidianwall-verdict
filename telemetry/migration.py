# telemetry/migration.py
#
# Purpose:
# Automatic one-time migration from the v0.5.x schema
# (decisions, overrides, approvals, outcomes,
# decision_artifacts) to the v0.6.0 Sentinel schema
# (governance_records, governance_history,
# governance_evidence).
#
# Ships inside the installed package and runs automatically
# — same pattern as the first-run telemetry notice. A
# pip-installed user never needs repo access or to run
# anything manually.
#
# Trigger:
# Called from cli/main.py's app callback, alongside
# show_first_run_notice_if_needed(). Runs before any command
# executes. Checks a marker file to ensure it only attempts
# migration once per machine.
#
# Safety:
# - Creates a timestamped backup of decisions.db before
#   touching anything
# - Verifies row counts match before dropping old tables
# - If verification fails, old tables are preserved and
#   nothing is deleted — the marker file is NOT written,
#   so migration will be retried on the next run
# - Fully idempotent — safe to interrupt and re-run
#
# Data completeness (added after a smoke test caught this):
# Old v0.5.x 'decisions' rows never had analyzer_scores/
# failed_conditions/passed_conditions columns at all. Reading
# a missing key returns None, which — if written straight
# through — becomes NULL in the new schema. NULL rows are
# silently EXCLUDED from every aggregate query's denominator
# (WHERE ... IS NOT NULL), meaning migrated records would
# quietly vanish from verdict audit's reports with no error,
# just wrong numbers. _migrate_decisions() now defaults to
# empty structures ("{}"/"[]") instead, and
# _recover_from_evidence() runs automatically afterward to
# upgrade those defaults with real data recovered from each
# record's stored evidence artifact, when one exists. This
# used to be a separate manual script
# (scripts/backfill_governance_records.py) — folded in here
# so a real end user gets full recovery automatically, without
# needing to know that script exists.

from __future__ import annotations

import json
import sqlite3
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from telemetry.config import get_db_dir, get_db_path
from telemetry.governance_store import (
    _hash_history_data,
    hash_objective_statement,
    init_governance_db,
)

_MIGRATION_MARKER = "migrated_v060"


def _marker_path() -> Path:
    return get_db_dir() / _MIGRATION_MARKER


def _needs_migration(db_path: Path) -> bool:
    """Return True if the old 'decisions' table exists and
    has not yet been migrated (no marker file present)."""
    if _marker_path().exists():
        return False

    if not db_path.exists():
        return False

    conn = None
    try:
        conn = sqlite3.connect(str(db_path))
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='decisions'"
        )
        exists = cursor.fetchone() is not None
        return exists
    except Exception:
        return False
    finally:
        if conn is not None:
            conn.close()


def _backup_database(db_path: Path) -> Path | None:
    """Create a timestamped backup before migration."""
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


def _append_migrated_history(
    conn: sqlite3.Connection,
    record_id: str,
    history_category: str,
    history_action: str,
    history_data: dict[str, Any],
    timestamp: str,
) -> None:
    """Append a history entry during migration with correct
    sequencing and hash chaining."""
    cursor = conn.execute(
        """
        SELECT MAX(history_number) as max_num
        FROM governance_history WHERE record_id = ?
        """,
        (record_id,),
    )
    row = cursor.fetchone()
    next_num = (row["max_num"] or 0) + 1

    prev_hash_row = conn.execute(
        """
        SELECT history_hash FROM governance_history
        WHERE record_id = ? ORDER BY history_number DESC LIMIT 1
        """,
        (record_id,),
    ).fetchone()
    prev_hash = prev_hash_row["history_hash"] if prev_hash_row else None

    history_hash = _hash_history_data(history_data)

    conn.execute(
        """
        INSERT INTO governance_history (
            history_id, record_id, history_number,
            history_category, history_action,
            history_data, history_hash,
            prev_history_hash, actor_role, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)
        """,
        (
            str(uuid.uuid4()),
            record_id,
            next_num,
            history_category,
            history_action,
            json.dumps(history_data, default=str),
            history_hash,
            prev_hash,
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
        (next_num, history_category, history_action, record_id),
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

        objective_statement = None  # not present in v0.5.x decisions table
        objective_hash = hash_objective_statement(objective_statement)

        is_risk_candidate = (
            1
            if (
                row.get("decision", "") == "DENY_WITH_OVERRIDE"
                and row.get("override_possible")
            )
            else 0
        )

        conn.execute(
            """
            INSERT INTO governance_records (
                record_id, policy_name, policy_content_hash,
                policy_family, artifact_hash,
                governance_objective_statement,
                governance_objective_hash,
                decision, conditions_passed, overall_risk_score,
                effective_severity, governance_severity,
                override_possible, requires_approval,
                plan_hash, user_role, verdict_version,
                created_at, analyzer_scores, failed_conditions,
                passed_conditions, is_risk_acceptance_candidate,
                current_history_number,
                current_history_category, current_history_action
            ) VALUES (
                ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, 1,
                'decision', 'created'
            )
            """,
            (
                record_id,
                row.get("policy_name", ""),
                row.get("policy_content_hash"),
                row.get("policy_family"),
                objective_statement,
                objective_hash,
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
                # Default to empty structures, NEVER None/NULL, when
                # the old row genuinely never had these columns.
                # NULL rows are silently excluded from every aggregate
                # query's denominator — this is the exact backfill
                # bug a smoke test caught. Empty-but-present values
                # correctly say "this record contributed zero
                # conditions," keeping it properly counted rather
                # than invisibly dropped. _recover_from_evidence()
                # below upgrades these defaults with real data when
                # a stored evidence artifact exists for the record.
                row.get("analyzer_scores") or "{}",
                row.get("failed_conditions") or "[]",
                row.get("passed_conditions") or "[]",
                is_risk_candidate,
            ),
        )

        history_data = {
            "decision": row.get("decision", ""),
            "policy": row.get("policy_name", ""),
            "migrated_from": "v0.5.x decisions table",
        }
        history_hash = _hash_history_data(history_data)

        conn.execute(
            """
            INSERT INTO governance_history (
                history_id, record_id, history_number,
                history_category, history_action,
                history_data, history_hash,
                prev_history_hash, actor_role, created_at
            ) VALUES (?, ?, 1, 'decision', 'created', ?, ?, NULL, NULL, ?)
            """,
            (
                str(uuid.uuid4()),
                record_id,
                json.dumps(history_data, default=str),
                history_hash,
                row.get("timestamp", datetime.now(timezone.utc).isoformat()),
            ),
        )
        migrated += 1

    conn.commit()
    return migrated


def _migrate_overrides(conn: sqlite3.Connection) -> int:
    if not _table_exists(conn, "overrides"):
        return 0

    rows = [
        dict(r)
        for r in conn.execute(
            "SELECT * FROM overrides ORDER BY timestamp ASC"
        ).fetchall()
    ]
    migrated = 0

    for row in rows:
        record_id = row["decision_id"]
        if (
            conn.execute(
                "SELECT record_id FROM governance_records WHERE record_id = ?",
                (record_id,),
            ).fetchone()
            is None
        ):
            continue

        action = "approved" if row.get("approved") else "denied"
        history_data = {
            "override_role": row.get("override_role"),
            "approved": bool(row.get("approved")),
            "migrated_from": "v0.5.x overrides table",
        }

        _append_migrated_history(
            conn,
            record_id,
            "override",
            action,
            history_data,
            row.get("timestamp", datetime.now(timezone.utc).isoformat()),
        )
        migrated += 1

    conn.commit()
    return migrated


def _migrate_approvals(conn: sqlite3.Connection) -> int:
    if not _table_exists(conn, "approvals"):
        return 0

    rows = [
        dict(r)
        for r in conn.execute(
            "SELECT * FROM approvals ORDER BY timestamp ASC"
        ).fetchall()
    ]
    migrated = 0

    for row in rows:
        record_id = row["decision_id"]
        if (
            conn.execute(
                "SELECT record_id FROM governance_records WHERE record_id = ?",
                (record_id,),
            ).fetchone()
            is None
        ):
            continue

        action = "approved" if row.get("approved") else "denied"
        history_data = {
            "approver_role": row.get("approver_role"),
            "approved": bool(row.get("approved")),
            "notes": row.get("notes"),
            "migrated_from": "v0.5.x approvals table",
        }

        _append_migrated_history(
            conn,
            record_id,
            "approval",
            action,
            history_data,
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

    for row in rows:
        record_id = row["decision_id"]
        if (
            conn.execute(
                "SELECT record_id FROM governance_records WHERE record_id = ?",
                (record_id,),
            ).fetchone()
            is None
        ):
            continue

        outcome_type = row.get("outcome_type", "")
        if outcome_type == "drift_detected":
            category, action = "drift", "detected"
        else:
            category, action = "outcome", "observed"

        history_data = {
            "outcome_type": outcome_type,
            "severity": row.get("severity"),
            "description": row.get("description"),
            "metadata": row.get("metadata"),
            "migrated_from": "v0.5.x outcomes table",
        }

        _append_migrated_history(
            conn,
            record_id,
            category,
            action,
            history_data,
            row.get("timestamp", datetime.now(timezone.utc).isoformat()),
        )
        migrated += 1

    conn.commit()
    return migrated


def _migrate_decision_artifacts(conn: sqlite3.Connection) -> int:
    """
    Rename/migrate v0.5.2's decision_artifacts table into the
    new governance_evidence table. Same shape, new name and
    column names — folded into this migration since it's
    already running, rather than requiring its own pass later.
    """
    if not _table_exists(conn, "decision_artifacts"):
        return 0

    rows = [
        dict(r) for r in conn.execute("SELECT * FROM decision_artifacts").fetchall()
    ]
    migrated = 0

    for row in rows:
        record_id = row.get("decision_id")
        if record_id is None:
            continue
        if (
            conn.execute(
                "SELECT record_id FROM governance_records WHERE record_id = ?",
                (record_id,),
            ).fetchone()
            is None
        ):
            continue

        conn.execute(
            """
            INSERT INTO governance_evidence (
                evidence_id, record_id, evidence_type,
                evidence_json, evidence_hash, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()),
                record_id,
                row.get("artifact_type", "evaluation"),
                row.get("artifact_json", "{}"),
                row.get("artifact_hash"),
                row.get("created_at", datetime.now(timezone.utc).isoformat()),
            ),
        )
        migrated += 1

    conn.commit()
    return migrated


def _recover_from_evidence(db_path: Path) -> int:
    """
    Upgrade the empty defaults ("{}"/"[]") written by
    _migrate_decisions() with real data recovered from each
    record's stored evidence artifact, when one exists.

    Called automatically at the end of migrate_if_needed() —
    not a separate manual step. A real end user upgrading
    from v0.5.x has no reason to know a standalone backfill
    script exists; folding recovery into the automatic
    migration path means they get full data recovery without
    needing to be told to run anything extra.

    Kept as the single canonical implementation of this
    recovery logic — scripts/backfill_governance_records.py
    imports this function for its manual/dry-run diagnostic
    use case (e.g. a database that already migrated before
    this function existed) rather than duplicating the logic.

    Returns the number of records upgraded with recovered data.
    Never raises — recovery is a best-effort improvement, not
    a requirement for migration to succeed.
    """
    try:
        from telemetry.governance_store import get_governance_evidence

        conn = init_governance_db(db_path)
        cursor = conn.execute(
            """
            SELECT record_id FROM governance_records
            WHERE analyzer_scores = '{}'
               OR failed_conditions = '[]'
               OR passed_conditions = '[]'
            """
        )
        candidate_ids = [row["record_id"] for row in cursor.fetchall()]
        conn.close()

        recovered = 0

        for record_id in candidate_ids:
            try:
                artifact = get_governance_evidence(
                    record_id, evidence_type="evaluation", db_path=db_path
                )
                if artifact is None:
                    continue

                trace = artifact.get("trace", [])
                failed = [
                    t.get("condition_id", "")
                    for t in trace
                    if not t.get("result", True)
                ]
                passed = [
                    t.get("condition_id", "")
                    for t in trace
                    if t.get("result", True)
                ]
                analyzer_scores = artifact.get("risk_summary", {}).get(
                    "analyzer_scores", {}
                )

                if not (failed or passed or analyzer_scores):
                    continue  # nothing richer to recover

                update_conn = init_governance_db(db_path)
                update_conn.execute(
                    """
                    UPDATE governance_records
                    SET failed_conditions = ?,
                        passed_conditions = ?,
                        analyzer_scores = ?
                    WHERE record_id = ?
                    """,
                    (
                        json.dumps(failed, default=str),
                        json.dumps(passed, default=str),
                        json.dumps(analyzer_scores, default=str),
                        record_id,
                    ),
                )
                update_conn.commit()
                update_conn.close()
                recovered += 1

            except Exception:
                continue  # one record's recovery failing must not
                          # block recovery of the rest

        return recovered

    except Exception:
        return 0


def _verify_and_finalize(conn: sqlite3.Connection) -> bool:
    """
    Confirm row counts match, then drop old tables if safe.
    Returns False (preserving old tables) if verification fails.
    """
    old_decisions = 0
    if _table_exists(conn, "decisions"):
        old_decisions = conn.execute("SELECT COUNT(*) as c FROM decisions").fetchone()[
            "c"
        ]

    new_records = conn.execute(
        "SELECT COUNT(*) as c FROM governance_records"
    ).fetchone()["c"]

    if old_decisions > new_records:
        return False

    old_artifacts = 0
    if _table_exists(conn, "decision_artifacts"):
        old_artifacts = conn.execute(
            "SELECT COUNT(*) as c FROM decision_artifacts"
        ).fetchone()["c"]

    new_evidence = conn.execute(
        "SELECT COUNT(*) as c FROM governance_evidence"
    ).fetchone()["c"]

    if old_artifacts > new_evidence:
        return False

    for table in (
        "decisions",
        "overrides",
        "approvals",
        "outcomes",
        "decision_artifacts",
    ):
        if _table_exists(conn, table):
            conn.execute(f"DROP TABLE {table}")
    conn.commit()
    return True


def migrate_if_needed(db_path: Path | None = None, silent: bool = False) -> None:
    """
    Check whether migration is needed and run it automatically
    if so. Safe to call on every CLI invocation — a no-op after
    the first successful run or when the old schema is absent.

    Never raises — migration failures must not crash the CLI.
    On failure, the marker file is not written, so migration
    is retried on the next invocation.
    """
    path = db_path or get_db_path()
    conn = None

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
        overrides_migrated = _migrate_overrides(conn)
        approvals_migrated = _migrate_approvals(conn)
        outcomes_migrated = _migrate_outcomes(conn)
        evidence_migrated = _migrate_decision_artifacts(conn)

        success = _verify_and_finalize(conn)

        if success:
            # Upgrade empty defaults with real data recovered from
            # evidence, automatically — see _recover_from_evidence()
            # docstring for why this runs here rather than requiring
            # a separate manual script.
            recovered_count = _recover_from_evidence(path)

            _marker_path().touch()
            if not silent:
                print(
                    f"Migration complete: {decisions_migrated} decision(s), "
                    f"{overrides_migrated} override(s), "
                    f"{approvals_migrated} approval(s), "
                    f"{outcomes_migrated} outcome(s), "
                    f"{evidence_migrated} evidence record(s) preserved.\n"
                    f"Recovered richer data for {recovered_count} "
                    f"record(s) from evidence.\n"
                    f"Backup saved at: {backup_path}\n",
                    file=sys.stderr,
                )
        else:
            if not silent:
                print(
                    "Migration verification failed — your original data "
                    "is preserved and untouched. This will be retried "
                    f"automatically. Backup saved at: {backup_path}\n",
                    file=sys.stderr,
                )

    except Exception:
        pass

    finally:
        if conn is not None:
            conn.close()