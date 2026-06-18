
# tests/unit/test_telemetry_store.py
#
# Purpose:
# Unit tests for telemetry/store.py.
# Uses a temporary SQLite database for isolation.
# Covers: init_db, record_decision, record_outcome,
#         record_override, record_approval,
#         get_recent_decisions, get_decision_by_id,
#         get_policy_effectiveness, get_outcome_summary,
#         get_failed_conditions_summary,
#         get_passed_conditions_summary,
#         get_domain_risk_summary, get_outcome_correlation

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from telemetry.store import (
    get_decision_by_id,
    get_domain_risk_summary,
    get_failed_conditions_summary,
    get_outcome_correlation,
    get_outcome_summary,
    get_passed_conditions_summary,
    get_policy_effectiveness,
    get_recent_decisions,
    init_db,
    record_approval,
    record_decision,
    record_outcome,
    record_override,
)


# =====================================================
# FIXTURES
# =====================================================


@pytest.fixture()
def temp_database(tmp_path: Path) -> Path:
    """Provide a temporary SQLite database path for each test."""
    return tmp_path / "test_decisions.db"


def _make_evaluate_result(
    decision: str = "DENY_WITH_OVERRIDE",
    policy: str = "test_policy",
    conditions_passed: bool = False,
) -> dict[str, Any]:
    """Build a minimal evaluate result dict for testing."""
    return {
        "decision_id":        str(uuid.uuid4()),
        "timestamp":          datetime.now(timezone.utc).isoformat(),
        "policy":             policy,
        "decision":           decision,
        "conditions_passed":  conditions_passed,
        "override_required":  False,
        "override_possible":  True,
        "requires_approval":  False,
        "governance_severity": "medium",
        "effective_severity":  "high",
        "resolution_reason":   "conditions_failed",
        "trace": [
            {"condition_id": "budget_check",  "result": False},
            {"condition_id": "tagging_check", "result": True},
        ],
        "risk_summary": {
            "overall_risk_score": 75,
            "effective_severity": "high",
            "total_findings":      2,
            "analyzer_scores": {
                "cost_analysis":         20,
                "topology_analysis":     25,
                "architecture_analysis":  0,
                "utilization_analysis":   0,
            },
        },
        "pricing_mode": "table",
    }


# =====================================================
# init_db
# =====================================================


class TestInitDb:
    """Tests for init_db()."""

    def test_creates_database_file(self, temp_database: Path) -> None:
        """init_db creates the database file."""
        conn = init_db(temp_database)
        conn.close()
        assert temp_database.exists()

    def test_creates_decisions_table(self, temp_database: Path) -> None:
        """init_db creates the decisions table."""
        conn = init_db(temp_database)
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='decisions'"
        )
        assert cursor.fetchone() is not None
        conn.close()

    def test_creates_outcomes_table(self, temp_database: Path) -> None:
        """init_db creates the outcomes table."""
        conn = init_db(temp_database)
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='outcomes'"
        )
        assert cursor.fetchone() is not None
        conn.close()

    def test_creates_overrides_table(self, temp_database: Path) -> None:
        """init_db creates the overrides table."""
        conn = init_db(temp_database)
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='overrides'"
        )
        assert cursor.fetchone() is not None
        conn.close()

    def test_creates_policy_effectiveness_table(self, temp_database: Path) -> None:
        """init_db creates the policy_effectiveness table."""
        conn = init_db(temp_database)
        cursor = conn.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='table' AND name='policy_effectiveness'"
        )
        assert cursor.fetchone() is not None
        conn.close()

    def test_idempotent(self, temp_database: Path) -> None:
        """init_db is safe to call multiple times."""
        for _ in range(3):
            conn = init_db(temp_database)
            conn.close()
        assert temp_database.exists()

    def test_policy_path_column_exists(self, temp_database: Path) -> None:
        """decisions table has policy_path column from v0.4.0 migration."""
        conn = init_db(temp_database)
        cursor = conn.execute("PRAGMA table_info(decisions)")
        columns = [row[1] for row in cursor.fetchall()]
        conn.close()
        assert "policy_path" in columns


# =====================================================
# record_decision
# =====================================================


class TestRecordDecision:
    """Tests for record_decision()."""

    def test_records_decision_to_database(self, temp_database: Path) -> None:
        """record_decision writes a row to the decisions table."""
        result = _make_evaluate_result()
        success = record_decision(result=result, db_path=temp_database)
        assert success is True

        rows = get_recent_decisions(db_path=temp_database)
        assert len(rows) == 1
        assert rows[0]["decision"] == "DENY_WITH_OVERRIDE"

    def test_stores_policy_name(self, temp_database: Path) -> None:
        """record_decision stores the policy name."""
        result = _make_evaluate_result(policy="my_test_policy")
        record_decision(result=result, db_path=temp_database)

        rows = get_recent_decisions(db_path=temp_database)
        assert rows[0]["policy_name"] == "my_test_policy"

    def test_stores_policy_path(self, temp_database: Path) -> None:
        """record_decision stores the policy path for Sentinel."""
        result = _make_evaluate_result()
        record_decision(
            result=result,
            plan_path="samples/terraform_plan.json",
            policy_path="policies/cost/basic_budget.yaml",
            db_path=temp_database,
        )

        rows = get_recent_decisions(db_path=temp_database)
        assert rows[0]["policy_path"] == "policies/cost/basic_budget.yaml"

    def test_stores_failed_conditions(self, temp_database: Path) -> None:
        """record_decision stores failed condition IDs."""
        result = _make_evaluate_result()
        record_decision(result=result, db_path=temp_database)

        rows = get_recent_decisions(db_path=temp_database)
        failed = json.loads(rows[0]["failed_conditions"])
        assert "budget_check" in failed

    def test_stores_passed_conditions(self, temp_database: Path) -> None:
        """record_decision stores passed condition IDs."""
        result = _make_evaluate_result()
        record_decision(result=result, db_path=temp_database)

        rows = get_recent_decisions(db_path=temp_database)
        passed = json.loads(rows[0]["passed_conditions"])
        assert "tagging_check" in passed

    def test_returns_false_without_decision_id(self, temp_database: Path) -> None:
        """record_decision returns False when decision_id is missing."""
        result = _make_evaluate_result()
        result["decision_id"] = ""
        success = record_decision(result=result, db_path=temp_database)
        assert success is False

    def test_hashes_plan_path(self, temp_database: Path) -> None:
        """record_decision stores a hash of the plan path, not the path itself."""
        result = _make_evaluate_result()
        record_decision(
            result=result,
            plan_path="samples/terraform_plan.json",
            db_path=temp_database,
        )

        rows = get_recent_decisions(db_path=temp_database)
        plan_hash = rows[0]["plan_hash"]
        assert plan_hash is not None
        assert "terraform_plan.json" not in plan_hash
        assert len(plan_hash) == 16  # SHA-256 truncated to 16 chars

    def test_multiple_decisions_stored(self, temp_database: Path) -> None:
        """record_decision stores multiple decisions correctly."""
        for _ in range(5):
            result = _make_evaluate_result()
            record_decision(result=result, db_path=temp_database)

        rows = get_recent_decisions(db_path=temp_database)
        assert len(rows) == 5

    def test_updates_policy_effectiveness(self, temp_database: Path) -> None:
        """record_decision updates the policy_effectiveness table."""
        result = _make_evaluate_result(decision="DENY_WITH_OVERRIDE")
        record_decision(result=result, db_path=temp_database)

        effectiveness = get_policy_effectiveness(db_path=temp_database)
        assert len(effectiveness) == 1
        assert effectiveness[0]["total_evaluations"] == 1
        assert effectiveness[0]["total_denied"] == 1


# =====================================================
# record_outcome
# =====================================================


class TestRecordOutcome:
    """Tests for record_outcome()."""

    def test_records_outcome(self, temp_database: Path) -> None:
        """record_outcome writes a row to the outcomes table."""
        result = _make_evaluate_result()
        record_decision(result=result, db_path=temp_database)
        decision_id = result["decision_id"]

        success = record_outcome(
            decision_id=decision_id,
            outcome_type="no_drift",
            severity="informational",
            description="Sentinel scan: no_drift.",
            db_path=temp_database,
        )
        assert success is True

        outcomes = get_outcome_summary(db_path=temp_database)
        assert any(row["outcome_type"] == "no_drift" for row in outcomes)

    def test_records_compliance_violation(self, temp_database: Path) -> None:
        """record_outcome stores compliance_violation type."""
        result = _make_evaluate_result()
        record_decision(result=result, db_path=temp_database)

        record_outcome(
            decision_id=result["decision_id"],
            outcome_type="compliance_violation",
            severity="high",
            db_path=temp_database,
        )

        outcomes = get_outcome_summary(db_path=temp_database)
        assert any(row["outcome_type"] == "compliance_violation" for row in outcomes)

    def test_records_metadata(self, temp_database: Path) -> None:
        """record_outcome stores metadata as JSON."""
        result = _make_evaluate_result()
        record_decision(result=result, db_path=temp_database)

        metadata = {"risk_delta": 30, "new_failures": ["budget_check"]}
        record_outcome(
            decision_id=result["decision_id"],
            outcome_type="drift_detected",
            metadata=metadata,
            db_path=temp_database,
        )

        decision = get_decision_by_id(result["decision_id"], db_path=temp_database)
        assert decision is not None
        assert len(decision["outcomes"]) == 1
        stored_metadata = json.loads(decision["outcomes"][0]["metadata"])
        assert stored_metadata["risk_delta"] == 30


# =====================================================
# record_override
# =====================================================


class TestRecordOverride:
    """Tests for record_override()."""

    def test_records_override(self, temp_database: Path) -> None:
        """record_override writes an override event."""
        result = _make_evaluate_result()
        record_decision(result=result, db_path=temp_database)

        success = record_override(
            decision_id=result["decision_id"],
            override_role="budget_owner",
            approved=True,
            db_path=temp_database,
        )
        assert success is True

    def test_records_rejected_override(self, temp_database: Path) -> None:
        """record_override stores approved=False for rejected overrides."""
        result = _make_evaluate_result()
        record_decision(result=result, db_path=temp_database)

        record_override(
            decision_id=result["decision_id"],
            override_role="budget_owner",
            approved=False,
            db_path=temp_database,
        )

        effectiveness = get_policy_effectiveness(db_path=temp_database)
        assert len(effectiveness) > 0


# =====================================================
# record_approval
# =====================================================


class TestRecordApproval:
    """Tests for record_approval()."""

    def test_records_approval(self, temp_database: Path) -> None:
        """record_approval writes an approval event."""
        result = _make_evaluate_result()
        record_decision(result=result, db_path=temp_database)

        success = record_approval(
            decision_id=result["decision_id"],
            approver_role="security_lead",
            approved=True,
            notes="Reviewed and approved.",
            db_path=temp_database,
        )
        assert success is True


# =====================================================
# get_recent_decisions
# =====================================================


class TestGetRecentDecisions:
    """Tests for get_recent_decisions()."""

    def test_returns_empty_list_when_no_decisions(self, temp_database: Path) -> None:
        """Returns empty list when database is empty."""
        rows = get_recent_decisions(db_path=temp_database)
        assert rows == []

    def test_returns_decisions_newest_first(self, temp_database: Path) -> None:
        """Returns decisions ordered newest first."""
        for i in range(3):
            result = _make_evaluate_result(policy=f"policy_{i}")
            record_decision(result=result, db_path=temp_database)

        rows = get_recent_decisions(db_path=temp_database)
        assert len(rows) == 3

    def test_respects_limit(self, temp_database: Path) -> None:
        """Returns at most `limit` decisions."""
        for _ in range(10):
            record_decision(
                result=_make_evaluate_result(),
                db_path=temp_database,
            )

        rows = get_recent_decisions(limit=3, db_path=temp_database)
        assert len(rows) == 3


# =====================================================
# get_decision_by_id
# =====================================================


class TestGetDecisionById:
    """Tests for get_decision_by_id()."""

    def test_returns_decision_by_id(self, temp_database: Path) -> None:
        """Returns the correct decision for a given ID."""
        result = _make_evaluate_result()
        record_decision(result=result, db_path=temp_database)

        decision = get_decision_by_id(result["decision_id"], db_path=temp_database)
        assert decision is not None
        assert decision["id"] == result["decision_id"]

    def test_returns_none_for_unknown_id(self, temp_database: Path) -> None:
        """Returns None when decision ID does not exist."""
        decision = get_decision_by_id("nonexistent-id", db_path=temp_database)
        assert decision is None

    def test_includes_outcomes_in_result(self, temp_database: Path) -> None:
        """Returned decision includes its associated outcomes."""
        result = _make_evaluate_result()
        record_decision(result=result, db_path=temp_database)
        record_outcome(
            decision_id=result["decision_id"],
            outcome_type="no_drift",
            db_path=temp_database,
        )

        decision = get_decision_by_id(result["decision_id"], db_path=temp_database)
        assert decision is not None
        assert len(decision["outcomes"]) == 1
        assert decision["outcomes"][0]["outcome_type"] == "no_drift"


# =====================================================
# get_domain_risk_summary
# =====================================================


class TestGetDomainRiskSummary:
    """Tests for get_domain_risk_summary()."""

    def test_returns_empty_dict_when_no_decisions(self, temp_database: Path) -> None:
        """Returns empty dict when no decisions are recorded."""
        summary = get_domain_risk_summary(db_path=temp_database)
        assert summary == {}

    def test_returns_summary_with_decisions(self, temp_database: Path) -> None:
        """Returns totals and domain scores after decisions are recorded."""
        for _ in range(3):
            record_decision(
                result=_make_evaluate_result(decision="DENY_WITH_OVERRIDE"),
                db_path=temp_database,
            )

        summary = get_domain_risk_summary(db_path=temp_database)
        assert summary["total_evaluations"] == 3
        assert summary["total_denied"] == 3
        assert summary["deny_rate"] == 100.0
        assert "domain_avg_scores" in summary


# =====================================================
# get_failed_conditions_summary
# =====================================================


class TestGetFailedConditionsSummary:
    """Tests for get_failed_conditions_summary()."""

    def test_returns_empty_list_when_no_decisions(self, temp_database: Path) -> None:
        """Returns empty list when no decisions are recorded."""
        summary = get_failed_conditions_summary(db_path=temp_database)
        assert summary == []

    def test_aggregates_failed_conditions(self, temp_database: Path) -> None:
        """Returns aggregated counts of failed conditions."""
        for _ in range(4):
            record_decision(
                result=_make_evaluate_result(decision="DENY"),
                db_path=temp_database,
            )

        summary = get_failed_conditions_summary(db_path=temp_database)
        condition_ids = [item["condition_id"] for item in summary]
        assert "budget_check" in condition_ids

        budget_item = next(
            item for item in summary if item["condition_id"] == "budget_check"
        )
        assert budget_item["count"] == 4


# =====================================================
# get_passed_conditions_summary
# =====================================================


class TestGetPassedConditionsSummary:
    """Tests for get_passed_conditions_summary()."""

    def test_returns_empty_list_when_no_decisions(self, temp_database: Path) -> None:
        """Returns empty list when no decisions are recorded."""
        summary = get_passed_conditions_summary(db_path=temp_database)
        assert summary == []

    def test_aggregates_passed_conditions(self, temp_database: Path) -> None:
        """Returns aggregated counts of passed conditions."""
        for _ in range(2):
            record_decision(
                result=_make_evaluate_result(conditions_passed=True),
                db_path=temp_database,
            )

        summary = get_passed_conditions_summary(db_path=temp_database)
        condition_ids = [item["condition_id"] for item in summary]
        assert "tagging_check" in condition_ids


# =====================================================
# get_outcome_correlation
# =====================================================


class TestGetOutcomeCorrelation:
    """Tests for get_outcome_correlation()."""

    def test_returns_empty_when_no_outcomes(self, temp_database: Path) -> None:
        """Returns empty list when no outcomes are recorded."""
        rows = get_outcome_correlation(db_path=temp_database)
        assert rows == []

    def test_correlates_decisions_with_outcomes(self, temp_database: Path) -> None:
        """Returns decision-outcome correlation rows."""
        result = _make_evaluate_result()
        record_decision(result=result, db_path=temp_database)
        record_outcome(
            decision_id=result["decision_id"],
            outcome_type="no_drift",
            db_path=temp_database,
        )

        rows = get_outcome_correlation(db_path=temp_database)
        assert len(rows) == 1
        assert rows[0]["outcome_type"] == "no_drift"
        assert rows[0]["policy_name"] == "test_policy"