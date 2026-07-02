# tests/unit/test_telemetry_store_v051.py
#
# Tests for the v0.5.1 additions to telemetry/store.py:
#   - policy_content_hash column
#   - policy_family column
#   - _compute_policy_content_hash() helper
#
# Complements existing test_telemetry_store.py and
# test_telemetry_store_extended.py — does not duplicate
# their coverage.

import hashlib
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest

from telemetry.store import (
    _compute_policy_content_hash,
    get_recent_decisions,
    init_db,
    record_decision,
)


# =====================================================
# FIXTURES
# =====================================================


def _tmp_db(tmp_path: Path) -> Path:
    """Return a fresh temp SQLite database path."""
    return tmp_path / "test_decisions.db"


def _make_result(decision: str = "ALLOW") -> dict:
    """Build a minimal evaluate result dict."""
    return {
        "decision_id": str(uuid.uuid4()),
        "decision": decision,
        "policy": "test_policy",
        "conditions_passed": True,
        "governance_severity": "low",
        "override_required": False,
        "override_possible": False,
        "requires_approval": False,
        "pricing_mode": "table",
        "timestamp": "2026-06-30T00:00:00+00:00",
        "risk_summary": {
            "overall_risk_score": 10,
            "effective_severity": "low",
            "total_findings": 0,
            "analyzer_scores": {},
        },
        "trace": [],
        "notification_manifest": {},
    }


# =====================================================
# _compute_policy_content_hash
# =====================================================


class TestComputePolicyContentHash:
    def test_returns_none_for_none_path(self):
        assert _compute_policy_content_hash(None) is None

    def test_returns_none_for_missing_file(self):
        assert _compute_policy_content_hash("/nonexistent/path.yaml") is None

    def test_returns_16_char_hex_string(self, tmp_path):
        p = tmp_path / "policy.yaml"
        p.write_text("name: test")
        result = _compute_policy_content_hash(str(p))
        assert isinstance(result, str)
        assert len(result) == 16
        assert all(c in "0123456789abcdef" for c in result)

    def test_same_content_same_hash(self, tmp_path):
        """Same file contents produce the same hash regardless of filename."""
        content = "name: budget_policy\nversion: 1.0"
        p1 = tmp_path / "policy_a.yaml"
        p2 = tmp_path / "policy_b.yaml"
        p1.write_text(content)
        p2.write_text(content)

        assert _compute_policy_content_hash(str(p1)) == \
               _compute_policy_content_hash(str(p2))

    def test_different_content_different_hash(self, tmp_path):
        """Different file contents produce different hashes."""
        p1 = tmp_path / "policy_one.yaml"
        p2 = tmp_path / "policy_two.yaml"
        p1.write_text("name: policy_one")
        p2.write_text("name: policy_two")

        assert _compute_policy_content_hash(str(p1)) != \
               _compute_policy_content_hash(str(p2))

    def test_matches_expected_sha256(self, tmp_path):
        """Hash matches independently computed SHA-256 of file contents."""
        content = "name: deterministic_test"
        p = tmp_path / "policy.yaml"
        p.write_bytes(content.encode())

        expected = hashlib.sha256(content.encode()).hexdigest()[:16]
        assert _compute_policy_content_hash(str(p)) == expected

    def test_content_hash_portable_across_paths(self, tmp_path):
        """
        The core property: same contents at different paths
        produce the same hash. This is what makes it more
        useful than a path hash for cross-environment telemetry.
        """
        content = "metadata:\n  name: shared_policy\n"
        machine_a = tmp_path / "machine_a_policy.yaml"
        machine_b = tmp_path / "machine_b_policy.yaml"
        machine_a.write_text(content)
        machine_b.write_text(content)

        assert _compute_policy_content_hash(str(machine_a)) == \
               _compute_policy_content_hash(str(machine_b))


# =====================================================
# record_decision — new columns populated
# =====================================================


class TestRecordDecisionNewFields:
    def test_policy_content_hash_stored(self, tmp_path):
        """policy_content_hash is stored when a real policy file exists."""
        db = _tmp_db(tmp_path)
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text("metadata:\n  name: test_budget\n")

        result = _make_result()

        with patch("telemetry.store.is_telemetry_enabled", return_value=True):
            record_decision(
                result=result,
                plan_path="plan.json",
                policy_path=str(policy_file),
                db_path=db,
            )

        decisions = get_recent_decisions(db_path=db)
        assert len(decisions) == 1

        stored = decisions[0]["policy_content_hash"]
        expected = _compute_policy_content_hash(str(policy_file))
        assert stored == expected

    def test_policy_content_hash_none_without_policy_path(self, tmp_path):
        """policy_content_hash is None when no policy_path is given."""
        db = _tmp_db(tmp_path)
        result = _make_result()

        with patch("telemetry.store.is_telemetry_enabled", return_value=True):
            record_decision(
                result=result,
                plan_path="plan.json",
                policy_path=None,
                db_path=db,
            )

        decisions = get_recent_decisions(db_path=db)
        assert decisions[0]["policy_content_hash"] is None

    def test_record_succeeds_with_missing_policy_file(self, tmp_path):
        """
        record_decision must not fail if the policy file
        does not exist. Hash and family should both be None.
        """
        db = _tmp_db(tmp_path)
        result = _make_result()

        with patch("telemetry.store.is_telemetry_enabled", return_value=True):
            success = record_decision(
                result=result,
                plan_path="plan.json",
                policy_path="/nonexistent/policy.yaml",
                db_path=db,
            )

        assert success is True
        decisions = get_recent_decisions(db_path=db)
        assert len(decisions) == 1
        assert decisions[0]["policy_content_hash"] is None


# =====================================================
# SCHEMA — new columns exist after init
# =====================================================


class TestSchemaColumns:
    def test_new_columns_exist_in_schema(self, tmp_path):
        """Verify all v0.5.1 columns exist after init_db."""
        db = _tmp_db(tmp_path)
        conn = init_db(db)

        cursor = conn.execute("PRAGMA table_info(decisions)")
        columns = {row["name"] for row in cursor.fetchall()}
        conn.close()

        assert "policy_content_hash" in columns, \
            "policy_content_hash column missing from decisions table"
        assert "policy_family" in columns, \
            "policy_family column missing from decisions table"
        assert "policy_path" in columns, \
            "policy_path column (v0.4.0) should still be present"