
# tests/unit/test_telemetry_store_extended.py
#
# Purpose:
# Extended unit tests for telemetry/store.py edge cases.
# Covers error handling, telemetry-disabled paths,
# and summary function edge cases.

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import patch

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
    policy:   str = "test_policy",
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
# Telemetry disabled paths
# =====================================================


class TestTelemetryDisabled:
    """Tests for behavior when governance history is disabled."""

    def test_record_decision_returns_false_when_disabled(
        self, temp_database: Path
    ) -> None:
        """record_decision returns False when history is disabled."""
        with patch("telemetry.store.is_telemetry_enabled", return_value=False):
            result = _make_evaluate_result()
            success = record_decision(result=result, db_path=temp_database)
        assert success is False

    def test_record_outcome_returns_false_when_disabled(
        self, temp_database: Path
    ) -> None:
        """record_outcome returns False when history is disabled."""
        with patch("telemetry.store.is_telemetry_enabled", return_value=False):
            success = record_outcome(
                decision_id="some-id",
                outcome_type="no_drift",
                db_path=temp_database,
            )
        assert success is False

    def test_record_override_returns_false_when_disabled(
        self, temp_database: Path
    ) -> None:
        """record_override returns False when history is disabled."""
        with patch("telemetry.store.is_telemetry_enabled", return_value=False):
            success = record_override(
                decision_id="some-id",
                override_role="budget_owner",
                approved=True,
                db_path=temp_database,
            )
        assert success is False

    def test_record_approval_returns_false_when_disabled(
        self, temp_database: Path
    ) -> None:
        """record_approval returns False when history is disabled."""
        with patch("telemetry.store.is_telemetry_enabled", return_value=False):
            success = record_approval(
                decision_id="some-id",
                approver_role="security_lead",
                approved=True,
                db_path=temp_database,
            )
        assert success is False


# =====================================================
# Policy effectiveness tracking
# =====================================================


class TestPolicyEffectivenessTracking:
    """Tests for policy effectiveness aggregation."""

    def test_allow_decisions_count_separately(self, temp_database: Path) -> None:
        """ALLOW decisions increment total_allowed not total_denied."""
        result = _make_evaluate_result(decision="ALLOW", conditions_passed=True)
        record_decision(result=result, db_path=temp_database)

        effectiveness = get_policy_effectiveness(db_path=temp_database)
        assert effectiveness[0]["total_allowed"] == 1
        assert effectiveness[0]["total_denied"] == 0

    def test_multiple_policies_tracked_separately(
        self, temp_database: Path
    ) -> None:
        """Each policy has its own effectiveness row."""
        for policy_name in ["policy_a", "policy_b", "policy_c"]:
            result = _make_evaluate_result(policy=policy_name)
            record_decision(result=result, db_path=temp_database)

        effectiveness = get_policy_effectiveness(db_path=temp_database)
        assert len(effectiveness) == 3

    def test_policy_effectiveness_by_name(self, temp_database: Path) -> None:
        """get_policy_effectiveness filters by policy name."""
        for policy_name in ["policy_a", "policy_b"]:
            result = _make_evaluate_result(policy=policy_name)
            record_decision(result=result, db_path=temp_database)

        effectiveness = get_policy_effectiveness(
            policy_name="policy_a", db_path=temp_database
        )
        assert len(effectiveness) == 1
        assert effectiveness[0]["policy_name"] == "policy_a"

    def test_running_totals_accumulate(self, temp_database: Path) -> None:
        """Running totals accumulate correctly across multiple evaluations."""
        for _ in range(5):
            result = _make_evaluate_result(decision="DENY")
            record_decision(result=result, db_path=temp_database)

        effectiveness = get_policy_effectiveness(db_path=temp_database)
        assert effectiveness[0]["total_evaluations"] == 5
        assert effectiveness[0]["total_denied"] == 5


# =====================================================
# Domain risk summary with diverse data
# =====================================================


class TestDomainRiskSummaryDiverse:
    """Tests for get_domain_risk_summary() with mixed decision types."""

    def test_deny_rate_calculation(self, temp_database: Path) -> None:
        """Deny rate is calculated correctly from mixed decisions."""
        for _ in range(2):
            record_decision(
                result=_make_evaluate_result(decision="DENY"),
                db_path=temp_database,
            )
        for _ in range(2):
            record_decision(
                result=_make_evaluate_result(decision="ALLOW"),
                db_path=temp_database,
            )

        summary = get_domain_risk_summary(db_path=temp_database)
        assert summary["total_evaluations"] == 4
        assert summary["total_denied"] == 2
        assert summary["deny_rate"] == 50.0

    def test_domain_average_scores_computed(self, temp_database: Path) -> None:
        """Domain average scores are computed from analyzer scores."""
        record_decision(
            result=_make_evaluate_result(decision="DENY"),
            db_path=temp_database,
        )

        summary = get_domain_risk_summary(db_path=temp_database)
        domain_scores = summary.get("domain_avg_scores", {})
        assert "cost_analysis" in domain_scores
        assert domain_scores["cost_analysis"] == 20.0


# =====================================================
# Conditions summary with diverse data
# =====================================================


class TestConditionsSummaryDiverse:
    """Tests for conditions summary functions with diverse data."""

    def test_failed_condition_rate_calculation(
        self, temp_database: Path
    ) -> None:
        """Failure rate is percentage of total evaluations, not total failures."""
        for _ in range(4):
            record_decision(
                result=_make_evaluate_result(decision="DENY"),
                db_path=temp_database,
            )

        summary = get_failed_conditions_summary(db_path=temp_database)
        budget_item = next(
            item for item in summary if item["condition_id"] == "budget_check"
        )
        assert budget_item["count"] == 4
        assert budget_item["rate"] == 100.0

    def test_passed_condition_rate_calculation(
        self, temp_database: Path
    ) -> None:
        """Pass rate is percentage of total evaluations."""
        for _ in range(3):
            record_decision(
                result=_make_evaluate_result(conditions_passed=True),
                db_path=temp_database,
            )

        summary = get_passed_conditions_summary(db_path=temp_database)
        tagging_item = next(
            item for item in summary if item["condition_id"] == "tagging_check"
        )
        assert tagging_item["count"] == 3

    def test_sorted_by_count_descending(self, temp_database: Path) -> None:
        """Failed conditions are sorted highest count first."""
        for _ in range(5):
            record_decision(
                result=_make_evaluate_result(decision="DENY"),
                db_path=temp_database,
            )

        summary = get_failed_conditions_summary(db_path=temp_database)
        counts = [item["count"] for item in summary]
        assert counts == sorted(counts, reverse=True)


# =====================================================
# Outcome summary with multiple types
# =====================================================


class TestOutcomeSummaryDiverse:
    """Tests for get_outcome_summary() with multiple outcome types."""

    def test_multiple_outcome_types_counted(self, temp_database: Path) -> None:
        """Multiple outcome types are counted and returned separately."""
        result = _make_evaluate_result()
        record_decision(result=result, db_path=temp_database)
        decision_id = result["decision_id"]

        record_outcome(
            decision_id=decision_id,
            outcome_type="no_drift",
            db_path=temp_database,
        )
        record_outcome(
            decision_id=decision_id,
            outcome_type="drift_detected",
            db_path=temp_database,
        )

        outcomes = get_outcome_summary(db_path=temp_database)
        outcome_types = {row["outcome_type"] for row in outcomes}
        assert "no_drift" in outcome_types
        assert "drift_detected" in outcome_types

    def test_outcome_counts_accurate(self, temp_database: Path) -> None:
        """Outcome counts reflect the number of recorded events."""
        result = _make_evaluate_result()
        record_decision(result=result, db_path=temp_database)

        for _ in range(3):
            record_outcome(
                decision_id=result["decision_id"],
                outcome_type="no_drift",
                db_path=temp_database,
            )

        outcomes = get_outcome_summary(db_path=temp_database)
        no_drift_row = next(
            row for row in outcomes if row["outcome_type"] == "no_drift"
        )
        assert no_drift_row["count"] == 3


# =====================================================
# get_recent_decisions ordering
# =====================================================


class TestGetRecentDecisionsOrdering:
    """Tests for decision ordering and limit behavior."""

    def test_returns_most_recent_first(self, temp_database: Path) -> None:
        """Most recent decisions appear first in the result."""
        policies = ["first_policy", "second_policy", "third_policy"]
        for policy_name in policies:
            result = _make_evaluate_result(policy=policy_name)
            record_decision(result=result, db_path=temp_database)

        rows = get_recent_decisions(db_path=temp_database)
        assert len(rows) == 3
        # Most recent (third_policy) should be first
        assert rows[0]["policy_name"] == "third_policy"

    def test_limit_zero_returns_empty(self, temp_database: Path) -> None:
        """Limit of zero returns empty list."""
        record_decision(
            result=_make_evaluate_result(),
            db_path=temp_database,
        )
        rows = get_recent_decisions(limit=0, db_path=temp_database)
        assert rows == []

    def test_limit_larger_than_total(self, temp_database: Path) -> None:
        """Limit larger than total decisions returns all decisions."""
        for _ in range(3):
            record_decision(
                result=_make_evaluate_result(),
                db_path=temp_database,
            )

        rows = get_recent_decisions(limit=100, db_path=temp_database)
        assert len(rows) == 3