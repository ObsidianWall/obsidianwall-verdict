# tests/unit/test_migration.py
#
# Tests for telemetry/migration.py — the automatic v0.5.x to
# v0.6.0 migration that ships inside the installed package
# and runs on first invocation against an old-schema database.

import sqlite3
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest

from telemetry.governance_store import get_governance_history, get_governance_record
from telemetry.migration import (
    _marker_path,
    _needs_migration,
    migrate_if_needed,
)


def _tmp_db(tmp_path: Path) -> Path:
    return tmp_path / "decisions.db"


def _create_old_schema_db(db_path: Path) -> None:
    """
    Create a minimal v0.5.x-shaped database — decisions,
    overrides, approvals, outcomes, decision_artifacts —
    for migration testing.
    """
    conn = sqlite3.connect(str(db_path))
    conn.executescript(
        """
        CREATE TABLE decisions (
            id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            policy_name TEXT NOT NULL,
            decision TEXT NOT NULL,
            conditions_passed INTEGER DEFAULT 0,
            overall_risk_score INTEGER DEFAULT 0,
            effective_severity TEXT,
            governance_severity TEXT,
            override_possible INTEGER DEFAULT 0,
            requires_approval INTEGER DEFAULT 0,
            plan_hash TEXT,
            user_role TEXT,
            policy_content_hash TEXT,
            policy_family TEXT
        );
        CREATE TABLE overrides (
            id TEXT PRIMARY KEY,
            decision_id TEXT NOT NULL,
            override_role TEXT,
            timestamp TEXT NOT NULL,
            approved INTEGER DEFAULT 0
        );
        CREATE TABLE approvals (
            id TEXT PRIMARY KEY,
            decision_id TEXT NOT NULL,
            approver_role TEXT,
            timestamp TEXT NOT NULL,
            approved INTEGER DEFAULT 0,
            notes TEXT
        );
        CREATE TABLE outcomes (
            id TEXT PRIMARY KEY,
            decision_id TEXT NOT NULL,
            outcome_type TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            severity TEXT,
            description TEXT,
            metadata TEXT
        );
        CREATE TABLE decision_artifacts (
            id TEXT PRIMARY KEY,
            decision_id TEXT NOT NULL,
            artifact_type TEXT NOT NULL,
            artifact_json TEXT NOT NULL,
            artifact_hash TEXT,
            created_at TEXT NOT NULL
        );
        """
    )
    conn.commit()
    conn.close()


def _insert_decision(
    db_path: Path,
    decision_id: str,
    decision: str = "DENY_WITH_OVERRIDE",
) -> None:
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        """
        INSERT INTO decisions (
            id, timestamp, policy_name, decision,
            conditions_passed, overall_risk_score,
            effective_severity, governance_severity,
            override_possible, requires_approval
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            decision_id,
            "2026-01-01T00:00:00+00:00",
            "test_policy",
            decision,
            0,
            75,
            "critical",
            "medium",
            1,
            0,
        ),
    )
    conn.commit()
    conn.close()


# =====================================================
# _needs_migration
# =====================================================


class TestNeedsMigration:
    def test_false_when_db_does_not_exist(self, tmp_path):
        db = _tmp_db(tmp_path)
        assert _needs_migration(db) is False

    def test_true_when_old_decisions_table_exists(self, tmp_path):
        db = _tmp_db(tmp_path)
        _create_old_schema_db(db)
        with patch("telemetry.migration.get_db_dir", return_value=tmp_path):
            assert _needs_migration(db) is True

    def test_false_when_marker_exists(self, tmp_path):
        db = _tmp_db(tmp_path)
        _create_old_schema_db(db)
        with patch("telemetry.migration.get_db_dir", return_value=tmp_path):
            _marker_path().touch()
            assert _needs_migration(db) is False


# =====================================================
# migrate_if_needed — full integration
# =====================================================


class TestMigrateIfNeeded:
    def test_migrates_decisions_to_governance_records(self, tmp_path):
        db = _tmp_db(tmp_path)
        _create_old_schema_db(db)
        decision_id = str(uuid.uuid4())
        _insert_decision(db, decision_id)

        with patch("telemetry.migration.get_db_dir", return_value=tmp_path):
            migrate_if_needed(db_path=db, silent=True)

        record = get_governance_record(decision_id, db_path=db)
        assert record is not None
        assert record["decision"] == "DENY_WITH_OVERRIDE"

    def test_creates_marker_after_successful_migration(self, tmp_path):
        db = _tmp_db(tmp_path)
        _create_old_schema_db(db)
        _insert_decision(db, str(uuid.uuid4()))

        with patch("telemetry.migration.get_db_dir", return_value=tmp_path):
            migrate_if_needed(db_path=db, silent=True)
            assert _marker_path().exists()

    def test_drops_old_tables_after_verified_migration(self, tmp_path):
        db = _tmp_db(tmp_path)
        _create_old_schema_db(db)
        _insert_decision(db, str(uuid.uuid4()))

        with patch("telemetry.migration.get_db_dir", return_value=tmp_path):
            migrate_if_needed(db_path=db, silent=True)

        conn = sqlite3.connect(str(db))
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        conn.close()
        assert "decisions" not in tables
        assert "governance_records" in tables

    def test_creates_backup_file(self, tmp_path):
        db = _tmp_db(tmp_path)
        _create_old_schema_db(db)
        _insert_decision(db, str(uuid.uuid4()))

        with patch("telemetry.migration.get_db_dir", return_value=tmp_path):
            migrate_if_needed(db_path=db, silent=True)

        backups = list(tmp_path.glob("decisions_backup_*.db"))
        assert len(backups) == 1

    def test_no_op_on_second_run(self, tmp_path):
        db = _tmp_db(tmp_path)
        _create_old_schema_db(db)
        _insert_decision(db, str(uuid.uuid4()))

        with patch("telemetry.migration.get_db_dir", return_value=tmp_path):
            migrate_if_needed(db_path=db, silent=True)
            backups_after_first = list(tmp_path.glob("decisions_backup_*.db"))

            # Second call should be a no-op — marker exists
            migrate_if_needed(db_path=db, silent=True)
            backups_after_second = list(tmp_path.glob("decisions_backup_*.db"))

        assert len(backups_after_first) == len(backups_after_second)

    def test_no_op_on_fresh_database_with_no_old_schema(self, tmp_path):
        db = _tmp_db(tmp_path)
        # No old schema created at all — db doesn't even exist

        with patch("telemetry.migration.get_db_dir", return_value=tmp_path):
            try:
                migrate_if_needed(db_path=db, silent=True)
            except Exception as exc:
                pytest.fail(f"migrate_if_needed raised unexpectedly: {exc}")
            
            assert not _marker_path().exists()

    def test_migrates_overrides_to_history(self, tmp_path):
        db = _tmp_db(tmp_path)
        _create_old_schema_db(db)
        decision_id = str(uuid.uuid4())
        _insert_decision(db, decision_id)

        conn = sqlite3.connect(str(db))
        conn.execute(
            """
            INSERT INTO overrides (id, decision_id, override_role, timestamp, approved)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()),
                decision_id,
                "budget_owner",
                "2026-01-01T01:00:00+00:00",
                1,
            ),
        )
        conn.commit()
        conn.close()

        with patch("telemetry.migration.get_db_dir", return_value=tmp_path):
            migrate_if_needed(db_path=db, silent=True)

        history = get_governance_history(decision_id, db_path=db)
        override_entries = [h for h in history if h["history_category"] == "override"]
        assert len(override_entries) == 1
        assert override_entries[0]["history_action"] == "approved"

    def test_migrates_outcomes_to_history(self, tmp_path):
        db = _tmp_db(tmp_path)
        _create_old_schema_db(db)
        decision_id = str(uuid.uuid4())
        _insert_decision(db, decision_id)

        conn = sqlite3.connect(str(db))
        conn.execute(
            """
            INSERT INTO outcomes (id, decision_id, outcome_type, timestamp, severity, description)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()),
                decision_id,
                "drift_detected",
                "2026-01-01T02:00:00+00:00",
                "high",
                "Config drifted from declared state",
            ),
        )
        conn.commit()
        conn.close()

        with patch("telemetry.migration.get_db_dir", return_value=tmp_path):
            migrate_if_needed(db_path=db, silent=True)

        history = get_governance_history(decision_id, db_path=db)
        drift_entries = [h for h in history if h["history_category"] == "drift"]
        assert len(drift_entries) == 1
        assert drift_entries[0]["history_action"] == "detected"

    def test_migrates_orphaned_override_gracefully(self, tmp_path):
        """
        An override referencing a decision_id that doesn't
        exist in the decisions table should be skipped, not
        crash the migration.
        """
        db = _tmp_db(tmp_path)
        _create_old_schema_db(db)

        conn = sqlite3.connect(str(db))
        conn.execute(
            """
            INSERT INTO overrides (id, decision_id, override_role, timestamp, approved)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()),
                "orphaned-decision-id",
                "budget_owner",
                "2026-01-01T00:00:00+00:00",
                1,
            ),
        )
        conn.commit()
        conn.close()

        with patch("telemetry.migration.get_db_dir", return_value=tmp_path):
            try:
                migrate_if_needed(db_path=db, silent=True)
            except Exception as exc:
                pytest.fail(f"migrate_if_needed raised unexpectedly: {exc}")
