#!/usr/bin/env python3
# scripts/backfill_governance_records.py
#
# Purpose:
# One-time recovery for governance_records rows created before
# the analyzer_scores / failed_conditions / passed_conditions
# columns existed on this machine.
#
# Why this is needed:
# ALTER TABLE ADD COLUMN (used by governance_store.py's
# _MIGRATIONS) never backfills existing rows — new columns
# are added as NULL for every row that existed before the
# migration ran. Any record created before those three
# columns were added to the schema during v0.6.0 development
# has NULL in all three, silently excluding it from
# get_domain_risk_summary(), get_failed_conditions_summary(),
# and get_passed_conditions_summary().
#
# This script recovers that data. Nothing was actually lost —
# the full evaluation artifact is still intact in
# governance_evidence (evidence_type='evaluation') for every
# record, since that table was never affected by the column
# gap. This script reads each NULL record's stored artifact,
# extracts trace and analyzer_scores from it, and writes them
# back into the three NULL columns.
#
# Safety:
# - Creates a timestamped backup before making any changes
# - Only touches rows where the columns are currently NULL —
#   safe to interrupt and re-run, will simply pick up where
#   it left off
# - Records with no stored evidence (should not occur in
#   practice, since record_governance_evidence() is always
#   called immediately after create_governance_record()) are
#   skipped and reported, never causing a crash
#
# Usage:
#   python3 scripts/backfill_governance_records.py
#   python3 scripts/backfill_governance_records.py --dry-run

from __future__ import annotations

import argparse
import json
import shutil
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from telemetry.config import get_db_path
from telemetry.governance_store import get_governance_evidence, init_governance_db


def _backup_database(db_path: Path) -> Path:
    """Create a timestamped backup before making any changes."""
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    backup_path = db_path.parent / f"decisions_pre_backfill_{timestamp}.db"
    shutil.copy2(db_path, backup_path)
    return backup_path


def _find_incomplete_records(conn: sqlite3.Connection) -> list[str]:
    """
    Return record_ids where failed_conditions, passed_conditions,
    or analyzer_scores is NULL — candidates for backfill.
    """
    cursor = conn.execute(
        """
        SELECT record_id FROM governance_records
        WHERE failed_conditions IS NULL
           OR passed_conditions IS NULL
           OR analyzer_scores IS NULL
        """
    )
    return [row["record_id"] for row in cursor.fetchall()]


def _extract_recovery_data(
    artifact: dict,
) -> tuple[list[str], list[str], dict]:
    """
    Extract failed_conditions, passed_conditions, and
    analyzer_scores from a stored evaluation artifact — the
    same extraction logic create_governance_record() uses on
    a fresh evaluation, applied here retroactively to a
    previously stored artifact.
    """
    trace = artifact.get("trace", [])
    failed = [t.get("condition_id", "") for t in trace if not t.get("result", True)]
    passed = [t.get("condition_id", "") for t in trace if t.get("result", True)]

    analyzer_scores = artifact.get("risk_summary", {}).get("analyzer_scores", {})

    return failed, passed, analyzer_scores


def backfill(db_path: Path | None = None, dry_run: bool = False) -> dict:
    """
    Run the backfill. Returns a summary dict:
      total_incomplete, recovered, skipped_no_evidence, errors
    """
    path = db_path or get_db_path()

    if not path.exists():
        print(f"No database found at {path}. Nothing to backfill.")
        return {"total_incomplete": 0, "recovered": 0, "skipped_no_evidence": 0, "errors": 0}

    if not dry_run:
        backup_path = _backup_database(path)
        print(f"Backup created: {backup_path}")

    conn = init_governance_db(path)

    incomplete_ids = _find_incomplete_records(conn)
    total = len(incomplete_ids)
    print(f"Found {total} record(s) with missing analytics data.")

    if total == 0:
        conn.close()
        return {"total_incomplete": 0, "recovered": 0, "skipped_no_evidence": 0, "errors": 0}

    recovered = 0
    skipped_no_evidence = 0
    errors = 0

    for record_id in incomplete_ids:
        try:
            artifact = get_governance_evidence(
                record_id, evidence_type="evaluation", db_path=path
            )

            if artifact is None:
                skipped_no_evidence += 1
                print(f"  SKIP  {record_id[:8]}  no stored evidence found")
                continue

            failed, passed, analyzer_scores = _extract_recovery_data(artifact)

            if dry_run:
                print(
                    f"  WOULD RECOVER  {record_id[:8]}  "
                    f"failed={len(failed)} passed={len(passed)} "
                    f"analyzers={len(analyzer_scores)}"
                )
                recovered += 1
                continue

            conn.execute(
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
            recovered += 1
            print(f"  RECOVERED  {record_id[:8]}")

        except Exception as exc:
            errors += 1
            print(f"  ERROR  {record_id[:8]}  {exc}")

    if not dry_run:
        conn.commit()

    conn.close()

    summary = {
        "total_incomplete": total,
        "recovered": recovered,
        "skipped_no_evidence": skipped_no_evidence,
        "errors": errors,
    }

    print()
    print("─" * 50)
    print("Backfill Summary" + (" (DRY RUN — no changes written)" if dry_run else ""))
    print("─" * 50)
    print(f"  Records needing backfill:  {summary['total_incomplete']}")
    print(f"  Successfully recovered:    {summary['recovered']}")
    print(f"  Skipped (no evidence):     {summary['skipped_no_evidence']}")
    print(f"  Errors:                    {summary['errors']}")
    print("─" * 50)

    return summary


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Backfill missing failed_conditions/passed_conditions/"
            "analyzer_scores on governance_records created before "
            "those columns existed on this machine."
        )
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be recovered without writing any changes.",
    )
    args = parser.parse_args()

    backfill(dry_run=args.dry_run)


if __name__ == "__main__":
    main()