# tests/unit/test_telemetry_store_evidence.py
#
# Tests for the v0.5.2 evidence store additions to
# telemetry/store.py:
#   - decision_artifacts table
#   - record_artifact()
#   - get_artifact()
#   - list_artifact_types()
#
# NOTE: decision_artifacts has a FOREIGN KEY constraint on
# decision_id referencing decisions(id), enforced via
# PRAGMA foreign_keys=ON in init_db(). This mirrors production
# behavior, where record_artifact() is always called after
# record_decision() has already inserted the parent row.
# Every test here must insert a minimal decisions row first —
# see _seed_decision() below.

import uuid
from pathlib import Path
from unittest.mock import patch

import pytest

from telemetry.store import (
    get_artifact,
    init_db,
    list_artifact_types,
    record_artifact,
)


# =====================================================
# FIXTURES
# =====================================================


def _tmp_db(tmp_path: Path) -> Path:
    """Return a fresh temp SQLite database path."""
    return tmp_path / "test_decisions.db"


def _make_decision_id() -> str:
    return str(uuid.uuid4())


def _make_artifact() -> dict:
    """Minimal artifact payload for testing."""
    return {
        "decision_id": "abc123",
        "decision": "DENY_WITH_OVERRIDE",
        "risk_summary": {"overall_risk_score": 75},
        "explanation": {"governance_reasoning": {"total_stages": 7}},
    }


def _seed_decision(db_path: Path, decision_id: str) -> None:
    """
    Insert a minimal parent row into the decisions table.

    decision_artifacts has a FOREIGN KEY constraint on
    decision_id, so any test writing an artifact must first
    ensure a matching decisions row exists — exactly as
    happens in production, where record_decision() always
    runs before record_artifact().
    """
    conn = init_db(db_path)
    conn.execute(
        """
        INSERT INTO decisions (
            id, timestamp, policy_name, decision
        ) VALUES (?, ?, ?, ?)
        """,
        (decision_id, "2026-01-01T00:00:00+00:00", "test_policy", "ALLOW"),
    )
    conn.commit()
    conn.close()


# =====================================================
# SCHEMA
# =====================================================


class TestDecisionArtifactsSchema:
    def test_table_exists_after_init(self, tmp_path):
        db = _tmp_db(tmp_path)
        conn = init_db(db)

        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name='decision_artifacts'"
        )
        row = cursor.fetchone()
        conn.close()

        assert row is not None

    def test_expected_columns_exist(self, tmp_path):
        db = _tmp_db(tmp_path)
        conn = init_db(db)

        cursor = conn.execute("PRAGMA table_info(decision_artifacts)")
        columns = {row["name"] for row in cursor.fetchall()}
        conn.close()

        assert "id" in columns
        assert "decision_id" in columns
        assert "artifact_type" in columns
        assert "artifact_json" in columns
        assert "artifact_hash" in columns
        assert "created_at" in columns


# =====================================================
# record_artifact
# =====================================================


class TestRecordArtifact:
    def test_records_successfully_when_enabled(self, tmp_path):
        db = _tmp_db(tmp_path)
        decision_id = _make_decision_id()
        _seed_decision(db, decision_id)
        artifact = _make_artifact()

        with patch("telemetry.store.is_telemetry_enabled", return_value=True):
            success = record_artifact(
                decision_id=decision_id,
                artifact=artifact,
                db_path=db,
            )

        assert success is True

    def test_returns_false_when_telemetry_disabled(self, tmp_path):
        db = _tmp_db(tmp_path)
        decision_id = _make_decision_id()
        _seed_decision(db, decision_id)
        artifact = _make_artifact()

        with patch("telemetry.store.is_telemetry_enabled", return_value=False):
            success = record_artifact(
                decision_id=decision_id,
                artifact=artifact,
                db_path=db,
            )

        assert success is False

    def test_default_artifact_type_is_evaluation(self, tmp_path):
        db = _tmp_db(tmp_path)
        decision_id = _make_decision_id()
        _seed_decision(db, decision_id)
        artifact = _make_artifact()

        with patch("telemetry.store.is_telemetry_enabled", return_value=True):
            record_artifact(decision_id=decision_id, artifact=artifact, db_path=db)

        types = list_artifact_types(decision_id, db_path=db)
        assert "evaluation" in types

    def test_custom_artifact_type_stored(self, tmp_path):
        db = _tmp_db(tmp_path)
        decision_id = _make_decision_id()
        _seed_decision(db, decision_id)
        artifact = {"drift": "detected"}

        with patch("telemetry.store.is_telemetry_enabled", return_value=True):
            record_artifact(
                decision_id=decision_id,
                artifact=artifact,
                artifact_type="sentinel_snapshot",
                db_path=db,
            )

        types = list_artifact_types(decision_id, db_path=db)
        assert "sentinel_snapshot" in types

    def test_multiple_artifact_types_for_same_decision(self, tmp_path):
        db = _tmp_db(tmp_path)
        decision_id = _make_decision_id()
        _seed_decision(db, decision_id)

        with patch("telemetry.store.is_telemetry_enabled", return_value=True):
            record_artifact(
                decision_id=decision_id,
                artifact=_make_artifact(),
                artifact_type="evaluation",
                db_path=db,
            )
            record_artifact(
                decision_id=decision_id,
                artifact={"drift": "none"},
                artifact_type="sentinel_snapshot",
                db_path=db,
            )

        types = set(list_artifact_types(decision_id, db_path=db))
        assert types == {"evaluation", "sentinel_snapshot"}

    def test_does_not_raise_on_unserializable_content(self, tmp_path):
        """
        record_artifact must never crash the CLI, even if
        given content that can't be cleanly JSON-serialized.
        json.dumps(default=str) should handle most cases,
        but confirm this doesn't raise regardless.
        """
        db = _tmp_db(tmp_path)
        decision_id = _make_decision_id()
        _seed_decision(db, decision_id)

        class Unserializable:
            def __str__(self):
                return "unserializable-object"

        artifact = {"weird": Unserializable()}

        with patch("telemetry.store.is_telemetry_enabled", return_value=True):
            try:
                record_artifact(
                    decision_id=decision_id,
                    artifact=artifact,
                    db_path=db,
                )
            except Exception as exc:
                pytest.fail(f"record_artifact raised unexpectedly: {exc}")


# =====================================================
# get_artifact
# =====================================================


class TestGetArtifact:
    def test_retrieves_stored_artifact(self, tmp_path):
        db = _tmp_db(tmp_path)
        decision_id = _make_decision_id()
        _seed_decision(db, decision_id)
        artifact = _make_artifact()

        with patch("telemetry.store.is_telemetry_enabled", return_value=True):
            record_artifact(decision_id=decision_id, artifact=artifact, db_path=db)

        retrieved = get_artifact(decision_id, db_path=db)

        assert retrieved is not None
        assert retrieved["decision"] == "DENY_WITH_OVERRIDE"
        assert retrieved["risk_summary"]["overall_risk_score"] == 75

    def test_returns_none_for_nonexistent_decision(self, tmp_path):
        db = _tmp_db(tmp_path)
        result = get_artifact("nonexistent-id", db_path=db)
        assert result is None

    def test_returns_none_for_wrong_artifact_type(self, tmp_path):
        db = _tmp_db(tmp_path)
        decision_id = _make_decision_id()
        _seed_decision(db, decision_id)

        with patch("telemetry.store.is_telemetry_enabled", return_value=True):
            record_artifact(
                decision_id=decision_id,
                artifact=_make_artifact(),
                artifact_type="evaluation",
                db_path=db,
            )

        result = get_artifact(
            decision_id, artifact_type="sentinel_snapshot", db_path=db
        )
        assert result is None

    def test_returns_most_recent_when_multiple_same_type(self, tmp_path):
        """
        If record_artifact is called twice with the same
        decision_id and artifact_type, get_artifact should
        return the most recently written one.
        """
        db = _tmp_db(tmp_path)
        decision_id = _make_decision_id()
        _seed_decision(db, decision_id)

        with patch("telemetry.store.is_telemetry_enabled", return_value=True):
            record_artifact(
                decision_id=decision_id,
                artifact={"version": 1},
                artifact_type="evaluation",
                db_path=db,
            )
            record_artifact(
                decision_id=decision_id,
                artifact={"version": 2},
                artifact_type="evaluation",
                db_path=db,
            )

        result = get_artifact(decision_id, db_path=db)
        assert result["version"] == 2

    def test_survives_missing_output_file_scenario(self, tmp_path):
        """
        The entire point of the evidence store: retrieval
        works even though no --output file was ever written
        to disk for this call. Confirms decoupling from
        the filesystem.
        """
        db = _tmp_db(tmp_path)
        decision_id = _make_decision_id()
        _seed_decision(db, decision_id)
        artifact = _make_artifact()

        with patch("telemetry.store.is_telemetry_enabled", return_value=True):
            record_artifact(decision_id=decision_id, artifact=artifact, db_path=db)

        # No file was ever written — retrieval is purely from the DB.
        retrieved = get_artifact(decision_id, db_path=db)
        assert retrieved == artifact


# =====================================================
# list_artifact_types
# =====================================================


class TestListArtifactTypes:
    def test_empty_list_for_unknown_decision(self, tmp_path):
        db = _tmp_db(tmp_path)
        types = list_artifact_types("unknown-id", db_path=db)
        assert types == []

    def test_returns_all_types_for_decision(self, tmp_path):
        db = _tmp_db(tmp_path)
        decision_id = _make_decision_id()
        _seed_decision(db, decision_id)

        with patch("telemetry.store.is_telemetry_enabled", return_value=True):
            record_artifact(
                decision_id=decision_id,
                artifact={"a": 1},
                artifact_type="evaluation",
                db_path=db,
            )
            record_artifact(
                decision_id=decision_id,
                artifact={"b": 2},
                artifact_type="sbom",
                db_path=db,
            )
            record_artifact(
                decision_id=decision_id,
                artifact={"c": 3},
                artifact_type="cost_report",
                db_path=db,
            )

        types = set(list_artifact_types(decision_id, db_path=db))
        assert types == {"evaluation", "sbom", "cost_report"}