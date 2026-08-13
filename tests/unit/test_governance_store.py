
# tests/unit/test_governance_store.py
#
# Tests for telemetry/governance_store.py — the v0.6.0
# Sentinel governance record store, replacing telemetry/store.py.
#
# Uses patch_telemetry() from tests/helpers/telemetry_patching.py
# rather than patching "telemetry.governance_store.
# is_telemetry_enabled" directly — since the module split,
# create_governance_record/add_history_entry/etc. live in
# governance_records.py/governance_history.py, each with their
# OWN independent binding of is_telemetry_enabled. Patching
# only governance_store's copy silently did nothing to those,
# and every test here always passes db_path explicitly, so
# get_db_path() patching isn't needed in this specific file.

import uuid
from pathlib import Path

import pytest

from telemetry.governance_store import (
    add_history_entry,
    create_governance_record,
    get_governance_evidence,
    get_governance_evidence_metadata,
    get_governance_history,
    get_governance_record,
    get_records_by_objective,
    get_records_by_policy,
    hash_objective_statement,
    init_governance_db,
    record_governance_evidence,
    verify_history_chain,
)

from tests.helpers.telemetry_patching import patch_telemetry


def _tmp_db(tmp_path: Path) -> Path:
    return tmp_path / "test_governance.db"


def _make_result(
    decision: str = "DENY_WITH_OVERRIDE",
    objective_statement: str | None = None,
) -> dict:
    result = {
        "decision_id": str(uuid.uuid4()),
        "decision": decision,
        "policy": "test_policy",
        "conditions_passed": False,
        "governance_severity": "medium",
        "override_possible": True,
        "requires_approval": False,
        "timestamp": "2026-07-13T00:00:00+00:00",
        "risk_summary": {
            "overall_risk_score": 75,
            "effective_severity": "critical",
        },
    }
    if objective_statement:
        result["governance_objective"] = {
            "statement": objective_statement,
            "status": "Violated" if "DENY" in decision else "Upheld",
        }
    return result


class TestSchema:
    def test_all_tables_exist(self, tmp_path):
        db = _tmp_db(tmp_path)
        conn = init_governance_db(db)
        tables = {
            row["name"]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        conn.close()
        assert "governance_records" in tables
        assert "governance_history" in tables
        assert "governance_evidence" in tables

    def test_governance_records_has_objective_hash_column(self, tmp_path):
        db = _tmp_db(tmp_path)
        conn = init_governance_db(db)
        columns = {
            row["name"]
            for row in conn.execute(
                "PRAGMA table_info(governance_records)"
            ).fetchall()
        }
        conn.close()
        assert "governance_objective_statement" in columns
        assert "governance_objective_hash" in columns

    def test_governance_history_has_split_category_action(self, tmp_path):
        db = _tmp_db(tmp_path)
        conn = init_governance_db(db)
        columns = {
            row["name"]
            for row in conn.execute(
                "PRAGMA table_info(governance_history)"
            ).fetchall()
        }
        conn.close()
        assert "history_category" in columns
        assert "history_action" in columns


class TestHashObjectiveStatement:
    def test_none_for_none_input(self):
        assert hash_objective_statement(None) is None

    def test_none_for_empty_string(self):
        assert hash_objective_statement("") is None

    def test_same_text_same_hash(self):
        a = hash_objective_statement("Maintain cloud spend within budget")
        b = hash_objective_statement("Maintain cloud spend within budget")
        assert a == b

    def test_different_text_different_hash(self):
        a = hash_objective_statement("Maintain cloud spend within budget")
        b = hash_objective_statement("Enforce network segmentation")
        assert a != b


class TestCreateGovernanceRecord:
    def test_creates_record_when_enabled(self, tmp_path):
        db = _tmp_db(tmp_path)
        result = _make_result()

        with patch_telemetry(enabled=True):
            success = create_governance_record(result=result, db_path=db)

        assert success is True

    def test_returns_false_when_disabled(self, tmp_path):
        db = _tmp_db(tmp_path)
        result = _make_result()

        with patch_telemetry(enabled=False):
            success = create_governance_record(result=result, db_path=db)

        assert success is False

    def test_returns_false_without_decision_id(self, tmp_path):
        db = _tmp_db(tmp_path)
        result = _make_result()
        result["decision_id"] = ""

        with patch_telemetry(enabled=True):
            success = create_governance_record(result=result, db_path=db)

        assert success is False

    def test_record_is_retrievable_after_creation(self, tmp_path):
        db = _tmp_db(tmp_path)
        result = _make_result()

        with patch_telemetry(enabled=True):
            create_governance_record(result=result, db_path=db)

        record = get_governance_record(result["decision_id"], db_path=db)
        assert record is not None
        assert record["decision"] == "DENY_WITH_OVERRIDE"
        assert record["overall_risk_score"] == 75

    def test_creates_first_history_entry(self, tmp_path):
        db = _tmp_db(tmp_path)
        result = _make_result()

        with patch_telemetry(enabled=True):
            create_governance_record(result=result, db_path=db)

        history = get_governance_history(result["decision_id"], db_path=db)
        assert len(history) == 1
        assert history[0]["history_category"] == "decision"
        assert history[0]["history_action"] == "created"
        assert history[0]["prev_history_hash"] is None

    def test_objective_statement_and_hash_both_stored(self, tmp_path):
        db = _tmp_db(tmp_path)
        statement = "Maintain cloud spend within approved budget"
        result = _make_result(objective_statement=statement)

        with patch_telemetry(enabled=True):
            create_governance_record(result=result, db_path=db)

        record = get_governance_record(result["decision_id"], db_path=db)
        assert record["governance_objective_statement"] == statement
        assert record["governance_objective_hash"] == hash_objective_statement(
            statement
        )

    def test_no_objective_fields_when_not_declared(self, tmp_path):
        db = _tmp_db(tmp_path)
        result = _make_result()

        with patch_telemetry(enabled=True):
            create_governance_record(result=result, db_path=db)

        record = get_governance_record(result["decision_id"], db_path=db)
        assert record["governance_objective_statement"] is None
        assert record["governance_objective_hash"] is None

    def test_auto_computes_policy_content_hash_from_path(self, tmp_path):
        db = _tmp_db(tmp_path)
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text("metadata:\n  name: test_budget\n")
        result = _make_result()

        with patch_telemetry(enabled=True):
            create_governance_record(
                result=result,
                policy_path=str(policy_file),
                db_path=db,
            )

        record = get_governance_record(result["decision_id"], db_path=db)
        assert record["policy_content_hash"] is not None

    def test_explicit_hash_overrides_auto_compute(self, tmp_path):
        db = _tmp_db(tmp_path)
        result = _make_result()

        with patch_telemetry(enabled=True):
            create_governance_record(
                result=result,
                policy_content_hash="explicit_hash_value",
                db_path=db,
            )

        record = get_governance_record(result["decision_id"], db_path=db)
        assert record["policy_content_hash"] == "explicit_hash_value"


class TestAddHistoryEntry:
    def _create_parent(self, db_path) -> str:
        result = _make_result()
        with patch_telemetry(enabled=True):
            create_governance_record(result=result, db_path=db_path)
        return result["decision_id"]

    def test_appends_second_entry(self, tmp_path):
        db = _tmp_db(tmp_path)
        record_id = self._create_parent(db)

        with patch_telemetry(enabled=True):
            success = add_history_entry(
                record_id=record_id,
                history_category="override",
                history_action="approved",
                history_data={"override_role": "budget_owner"},
                db_path=db,
            )

        assert success is True
        history = get_governance_history(record_id, db_path=db)
        assert len(history) == 2
        assert history[1]["history_category"] == "override"
        assert history[1]["history_action"] == "approved"

    def test_returns_false_for_nonexistent_record(self, tmp_path):
        db = _tmp_db(tmp_path)

        with patch_telemetry(enabled=True):
            success = add_history_entry(
                record_id="nonexistent-id",
                history_category="override",
                history_action="approved",
                history_data={},
                db_path=db,
            )

        assert success is False

    def test_updates_denormalized_current_state(self, tmp_path):
        db = _tmp_db(tmp_path)
        record_id = self._create_parent(db)

        with patch_telemetry(enabled=True):
            add_history_entry(
                record_id=record_id,
                history_category="drift",
                history_action="detected",
                history_data={"drift_type": "config_change"},
                db_path=db,
            )

        record = get_governance_record(record_id, db_path=db)
        assert record["current_history_category"] == "drift"
        assert record["current_history_action"] == "detected"
        assert record["current_history_number"] == 2

    def test_history_hashes_are_chained(self, tmp_path):
        db = _tmp_db(tmp_path)
        record_id = self._create_parent(db)

        with patch_telemetry(enabled=True):
            add_history_entry(
                record_id=record_id,
                history_category="outcome",
                history_action="observed",
                history_data={"outcome_type": "deployment_success"},
                db_path=db,
            )

        history = get_governance_history(record_id, db_path=db)
        assert history[1]["prev_history_hash"] == history[0]["history_hash"]

    def test_filter_by_category(self, tmp_path):
        db = _tmp_db(tmp_path)
        record_id = self._create_parent(db)

        with patch_telemetry(enabled=True):
            add_history_entry(
                record_id=record_id,
                history_category="override",
                history_action="requested",
                history_data={},
                db_path=db,
            )
            add_history_entry(
                record_id=record_id,
                history_category="outcome",
                history_action="observed",
                history_data={},
                db_path=db,
            )
            add_history_entry(
                record_id=record_id,
                history_category="override",
                history_action="approved",
                history_data={},
                db_path=db,
            )

        override_history = get_governance_history(
            record_id, history_category="override", db_path=db
        )
        assert len(override_history) == 2
        assert all(h["history_category"] == "override" for h in override_history)


class TestVerifyHistoryChain:
    def test_verified_true_for_intact_chain(self, tmp_path):
        db = _tmp_db(tmp_path)
        result = _make_result()

        with patch_telemetry(enabled=True):
            create_governance_record(result=result, db_path=db)
            add_history_entry(
                record_id=result["decision_id"],
                history_category="outcome",
                history_action="observed",
                history_data={"test": "data"},
                db_path=db,
            )

        verification = verify_history_chain(result["decision_id"], db_path=db)
        assert verification["verified"] is True
        assert verification["history_count"] == 2
        assert verification["broken_at"] is None

    def test_verified_true_empty_for_unknown_record(self, tmp_path):
        db = _tmp_db(tmp_path)
        verification = verify_history_chain("unknown-id", db_path=db)
        assert verification["verified"] is True
        assert verification["history_count"] == 0

    def test_detects_tampered_history_data(self, tmp_path):
        db = _tmp_db(tmp_path)
        result = _make_result()

        with patch_telemetry(enabled=True):
            create_governance_record(result=result, db_path=db)

        import sqlite3

        conn = sqlite3.connect(str(db))
        conn.execute(
            "UPDATE governance_history SET history_data = ? WHERE record_id = ?",
            ('{"decision": "TAMPERED"}', result["decision_id"]),
        )
        conn.commit()
        conn.close()

        verification = verify_history_chain(result["decision_id"], db_path=db)
        assert verification["verified"] is False


class TestGovernanceEvidence:
    def _create_parent(self, db_path) -> str:
        result = _make_result()
        with patch_telemetry(enabled=True):
            create_governance_record(result=result, db_path=db_path)
        return result["decision_id"]

    def test_record_and_retrieve_evidence(self, tmp_path):
        db = _tmp_db(tmp_path)
        record_id = self._create_parent(db)
        evidence = {"trace": [1, 2, 3], "decision": "DENY_WITH_OVERRIDE"}

        with patch_telemetry(enabled=True):
            success = record_governance_evidence(
                record_id=record_id, evidence=evidence, db_path=db
            )

        assert success is True
        retrieved = get_governance_evidence(record_id, db_path=db)
        assert retrieved == evidence

    def test_evidence_metadata_without_full_content(self, tmp_path):
        db = _tmp_db(tmp_path)
        record_id = self._create_parent(db)

        with patch_telemetry(enabled=True):
            record_governance_evidence(
                record_id=record_id, evidence={"data": "x"}, db_path=db
            )

        metadata = get_governance_evidence_metadata(record_id, db_path=db)
        assert metadata is not None
        assert "evidence_hash" in metadata
        assert "created_at" in metadata

    def test_none_for_missing_evidence(self, tmp_path):
        db = _tmp_db(tmp_path)
        result = get_governance_evidence("nonexistent-id", db_path=db)
        assert result is None


class TestRelationalQueries:
    def test_get_records_by_objective(self, tmp_path):
        db = _tmp_db(tmp_path)
        statement = "Maintain cloud spend within approved budget"

        with patch_telemetry(enabled=True):
            create_governance_record(
                result=_make_result(objective_statement=statement),
                db_path=db,
            )
            create_governance_record(
                result=_make_result(objective_statement=statement),
                db_path=db,
            )
            create_governance_record(
                result=_make_result(objective_statement="Different objective"),
                db_path=db,
            )

        records = get_records_by_objective(statement, db_path=db)
        assert len(records) == 2

    def test_get_records_by_policy(self, tmp_path):
        db = _tmp_db(tmp_path)
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text("metadata:\n  name: shared_policy\n")

        with patch_telemetry(enabled=True):
            create_governance_record(
                result=_make_result(),
                policy_path=str(policy_file),
                db_path=db,
            )
            create_governance_record(
                result=_make_result(),
                policy_path=str(policy_file),
                db_path=db,
            )

        expected_hash = _compute_hash_for_test(policy_file)
        records = get_records_by_policy(expected_hash, db_path=db)
        assert len(records) == 2


def _compute_hash_for_test(policy_file: Path) -> str:
    """Test helper mirroring the internal hash computation."""
    import hashlib

    contents = policy_file.read_bytes()
    return hashlib.sha256(contents).hexdigest()[:16]