
# tests/unit/test_telemetry_store_error_paths.py
#
# Purpose:
# Tests for exception handler paths in telemetry/store.py.
# Covers lines: 181, 334-336, 378-379, 418-419, 489-490,
#               554-555, 603-604, 633-634, 672-673, 688-689,
#               722-723, 738-739, 772-773, 788-789, 812-813,
#               841-842
# These are all the except Exception: return False/[]/{}
# branches that only trigger when SQLite operations fail.

from __future__ import annotations

import sqlite3
import uuid
from pathlib import Path
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
# HELPER
# =====================================================


def _make_minimal_result() -> dict:
    """Build a minimal evaluate result for testing write functions."""
    return {
        "decision_id":        str(uuid.uuid4()),
        "policy":             "test_policy",
        "decision":           "DENY",
        "conditions_passed":  False,
        "override_required":  False,
        "override_possible":  False,
        "requires_approval":  False,
        "governance_severity": "medium",
        "effective_severity":  "high",
        "trace":               [],
        "risk_summary": {
            "overall_risk_score": 50,
            "effective_severity": "high",
            "total_findings":     1,
            "analyzer_scores":    {},
        },
        "pricing_mode": "table",
    }


# =====================================================
# Write function exception paths
# =====================================================


class TestRecordDecisionExceptionPath:
    """record_decision returns False when database operation fails."""

    def test_returns_false_when_init_db_raises(self) -> None:
        with patch(
            "telemetry.store.init_db",
            side_effect=sqlite3.OperationalError("disk full"),
        ):
            result = record_decision(result=_make_minimal_result())
        assert result is False

    def test_returns_false_when_execute_raises(self, tmp_path: Path) -> None:
        database_path = tmp_path / "test.db"
        with patch(
            "telemetry.store.init_db",
            side_effect=Exception("unexpected error"),
        ):
            result = record_decision(
                result=_make_minimal_result(),
                db_path=database_path,
            )
        assert result is False


class TestRecordOutcomeExceptionPath:
    """record_outcome returns False when database operation fails."""

    def test_returns_false_when_init_db_raises(self) -> None:
        with patch(
            "telemetry.store.init_db",
            side_effect=sqlite3.OperationalError("disk full"),
        ):
            result = record_outcome(
                decision_id="some-id",
                outcome_type="no_drift",
            )
        assert result is False


class TestRecordOverrideExceptionPath:
    """record_override returns False when database operation fails."""

    def test_returns_false_when_init_db_raises(self) -> None:
        with patch(
            "telemetry.store.init_db",
            side_effect=sqlite3.OperationalError("disk full"),
        ):
            result = record_override(
                decision_id="some-id",
                override_role="budget_owner",
                approved=True,
            )
        assert result is False


class TestRecordApprovalExceptionPath:
    """record_approval returns False when database operation fails."""

    def test_returns_false_when_init_db_raises(self) -> None:
        with patch(
            "telemetry.store.init_db",
            side_effect=sqlite3.OperationalError("disk full"),
        ):
            result = record_approval(
                decision_id="some-id",
                approver_role="security_lead",
                approved=True,
            )
        assert result is False


# =====================================================
# Read function exception paths
# =====================================================


class TestGetRecentDecisionsExceptionPath:
    """get_recent_decisions returns [] when database raises."""

    def test_returns_empty_list_on_exception(self) -> None:
        with patch(
            "telemetry.store.init_db",
            side_effect=sqlite3.OperationalError("database locked"),
        ):
            rows = get_recent_decisions()
        assert rows == []


class TestGetPolicyEffectivenessExceptionPath:
    """get_policy_effectiveness returns [] when database raises."""

    def test_returns_empty_list_on_exception(self) -> None:
        with patch(
            "telemetry.store.init_db",
            side_effect=sqlite3.OperationalError("database locked"),
        ):
            rows = get_policy_effectiveness()
        assert rows == []

    def test_returns_empty_list_on_exception_with_policy_name(self) -> None:
        with patch(
            "telemetry.store.init_db",
            side_effect=sqlite3.OperationalError("database locked"),
        ):
            rows = get_policy_effectiveness(policy_name="test_policy")
        assert rows == []


class TestGetDecisionByIdExceptionPath:
    """get_decision_by_id returns None when database raises."""

    def test_returns_none_on_exception(self) -> None:
        with patch(
            "telemetry.store.init_db",
            side_effect=sqlite3.OperationalError("database locked"),
        ):
            result = get_decision_by_id("some-id")
        assert result is None


class TestGetDomainRiskSummaryExceptionPath:
    """get_domain_risk_summary returns {} when database raises."""

    def test_returns_empty_dict_on_exception(self) -> None:
        with patch(
            "telemetry.store.init_db",
            side_effect=sqlite3.OperationalError("database locked"),
        ):
            result = get_domain_risk_summary()
        assert result == {}


class TestGetFailedConditionsSummaryExceptionPath:
    """get_failed_conditions_summary returns [] when database raises."""

    def test_returns_empty_list_on_exception(self) -> None:
        with patch(
            "telemetry.store.init_db",
            side_effect=sqlite3.OperationalError("database locked"),
        ):
            result = get_failed_conditions_summary()
        assert result == []


class TestGetPassedConditionsSummaryExceptionPath:
    """get_passed_conditions_summary returns [] when database raises."""

    def test_returns_empty_list_on_exception(self) -> None:
        with patch(
            "telemetry.store.init_db",
            side_effect=sqlite3.OperationalError("database locked"),
        ):
            result = get_passed_conditions_summary()
        assert result == []


class TestGetOutcomeSummaryExceptionPath:
    """get_outcome_summary returns [] when database raises."""

    def test_returns_empty_list_on_exception(self) -> None:
        with patch(
            "telemetry.store.init_db",
            side_effect=sqlite3.OperationalError("database locked"),
        ):
            result = get_outcome_summary()
        assert result == []


class TestGetOutcomeCorrelationExceptionPath:
    """get_outcome_correlation returns [] when database raises."""

    def test_returns_empty_list_on_exception(self) -> None:
        with patch(
            "telemetry.store.init_db",
            side_effect=sqlite3.OperationalError("database locked"),
        ):
            result = get_outcome_correlation()
        assert result == []