# tests/unit/test_governance_history_gaps.py
#
# Targets the four confirmed remaining coverage gaps in
# telemetry/governance_history.py — lines 139, 207-208,
# 266-267, 271-272.

import json
import sqlite3
import uuid
from pathlib import Path
from unittest.mock import patch

from telemetry.governance_history import add_history_entry, get_governance_history
from telemetry.governance_records import create_governance_record

from tests.helpers.telemetry_patching import patch_telemetry


def _make_result() -> dict:
    return {
        "decision_id": str(uuid.uuid4()),
        "decision": "DENY_WITH_OVERRIDE",
        "policy": "test_policy",
        "conditions_passed": False,
        "governance_severity": "medium",
        "override_possible": True,
        "requires_approval": False,
        "timestamp": "2026-08-12T00:00:00+00:00",
        "risk_summary": {"overall_risk_score": 75, "effective_severity": "critical"},
    }


class TestAddHistoryEntryTelemetryDisabled:
    def test_returns_false_when_telemetry_disabled(self, tmp_path):
        """Covers line 139."""
        db = tmp_path / "test.db"

        with patch_telemetry(db_path=db, enabled=False):
            result = add_history_entry(
                record_id="some-id",
                history_category="override",
                history_action="requested",
                history_data={},
                db_path=db,
            )

        assert result is False


class TestAddHistoryEntryDatabaseError:
    def test_returns_false_on_database_error(self, tmp_path):
        """
        Covers lines 207-208 — the generic exception handler.
        Mocking execute() to raise unconditionally means the
        FIRST call (the parent-record lookup) raises immediately,
        caught by the outer try/except — no real parent record
        needs to exist for this specific path.
        """
        db = tmp_path / "test.db"

        with patch_telemetry(db_path=db, enabled=True):
            with patch(
                "telemetry.governance_history.init_governance_db"
            ) as mock_init:
                mock_conn = mock_init.return_value
                mock_conn.execute.side_effect = Exception("simulated DB failure")

                result = add_history_entry(
                    record_id="some-id",
                    history_category="override",
                    history_action="requested",
                    history_data={},
                    db_path=db,
                )

        assert result is False


class TestGetGovernanceHistoryUnparseableData:
    def test_skips_unparseable_history_data_without_crashing(self, tmp_path):
        """
        Covers lines 266-267 — the per-row JSON parse failure
        branch. Every entry written through the real API
        (add_history_entry/create_governance_record) always
        calls json.dumps() first, so this can only be reached
        by directly corrupting stored data via raw SQL —
        same pattern already used for the tamper-detection
        test in test_governance_store.py.
        """
        db = tmp_path / "test.db"
        result = _make_result()

        with patch_telemetry(db_path=db, enabled=True):
            create_governance_record(result=result, db_path=db)

        conn = sqlite3.connect(str(db))
        conn.execute(
            "UPDATE governance_history SET history_data = ? WHERE record_id = ?",
            ("not valid json {{{", result["decision_id"]),
        )
        conn.commit()
        conn.close()

        history = get_governance_history(result["decision_id"], db_path=db)

        assert len(history) == 1
        # Parsing failed, so history_data stays as the raw string
        # rather than crashing or silently dropping the entry.
        assert history[0]["history_data"] == "not valid json {{{"


class TestGetGovernanceHistoryDatabaseError:
    def test_returns_empty_list_on_database_error(self, tmp_path):
        """Covers lines 271-272 — the outer exception handler."""
        db = tmp_path / "test.db"

        with patch(
            "telemetry.governance_history.init_governance_db"
        ) as mock_init:
            mock_conn = mock_init.return_value
            mock_conn.execute.side_effect = Exception("simulated DB failure")

            result = get_governance_history("some-id", db_path=db)

        assert result == []