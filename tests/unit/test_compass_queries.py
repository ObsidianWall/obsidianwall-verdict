# tests/unit/test_compass_queries.py
#
# Tests for the Compass Query Foundation functions in
# telemetry/governance_store.py: get_outcome_correlation()
# and get_objective_summary().

import uuid
from pathlib import Path
from unittest.mock import patch

from telemetry.governance_store import (
    add_history_entry,
    create_governance_record,
    get_objective_summary,
    get_outcome_correlation,
)


def _tmp_db(tmp_path: Path) -> Path:
    return tmp_path / "test_compass.db"


def _make_result(
    decision: str = "ALLOW",
    policy: str = "budget_policy",
    objective_statement: str | None = "Maintain cloud spend within budget",
) -> dict:
    result = {
        "decision_id": str(uuid.uuid4()),
        "decision": decision,
        "policy": policy,
        "conditions_passed": decision == "ALLOW",
        "governance_severity": "medium",
        "override_possible": decision == "DENY_WITH_OVERRIDE",
        "requires_approval": decision == "ALLOW_WITH_APPROVAL_REQUIRED",
        "timestamp": "2026-07-17T00:00:00+00:00",
        "risk_summary": {"overall_risk_score": 50, "effective_severity": "medium"},
    }
    if objective_statement:
        result["governance_objective"] = {
            "statement": objective_statement,
            "status": "n/a",
        }
    return result


def _create(result: dict, db_path: Path) -> str:
    with patch("telemetry.governance_store.is_telemetry_enabled", return_value=True):
        create_governance_record(result=result, db_path=db_path)
    return result["decision_id"]


# =====================================================
# get_outcome_correlation
# =====================================================


class TestGetOutcomeCorrelation:
    def test_empty_list_for_no_history(self, tmp_path):
        db = _tmp_db(tmp_path)
        assert get_outcome_correlation(db_path=db) == []

    def test_correlates_decision_with_outcome(self, tmp_path):
        db = _tmp_db(tmp_path)
        record_id = _create(
            _make_result(decision="DENY_WITH_OVERRIDE", policy="budget_policy"), db
        )

        with patch(
            "telemetry.governance_store.is_telemetry_enabled", return_value=True
        ):
            add_history_entry(
                record_id=record_id,
                history_category="outcome",
                history_action="observed",
                history_data={"outcome_type": "budget_overrun"},
                db_path=db,
            )

        results = get_outcome_correlation(db_path=db)
        assert len(results) == 1
        assert results[0]["policy_name"] == "budget_policy"
        assert results[0]["decision"] == "DENY_WITH_OVERRIDE"
        assert results[0]["outcome_type"] == "budget_overrun"
        assert results[0]["frequency"] == 1

    def test_aggregates_repeated_correlations(self, tmp_path):
        """
        Three records with the same policy/decision/outcome
        combination should collapse into one row with
        frequency=3, not three separate rows.
        """
        db = _tmp_db(tmp_path)

        for _ in range(3):
            record_id = _create(
                _make_result(decision="DENY_WITH_OVERRIDE", policy="budget_policy"),
                db,
            )
            with patch(
                "telemetry.governance_store.is_telemetry_enabled",
                return_value=True,
            ):
                add_history_entry(
                    record_id=record_id,
                    history_category="outcome",
                    history_action="observed",
                    history_data={"outcome_type": "budget_overrun"},
                    db_path=db,
                )

        results = get_outcome_correlation(db_path=db)
        assert len(results) == 1
        assert results[0]["frequency"] == 3

    def test_sorted_by_frequency_descending(self, tmp_path):
        db = _tmp_db(tmp_path)

        # 1x rare outcome
        record_id = _create(_make_result(policy="p1"), db)
        with patch(
            "telemetry.governance_store.is_telemetry_enabled", return_value=True
        ):
            add_history_entry(
                record_id=record_id,
                history_category="outcome",
                history_action="observed",
                history_data={"outcome_type": "rare_outcome"},
                db_path=db,
            )

        # 2x common outcome
        for _ in range(2):
            record_id = _create(_make_result(policy="p2"), db)
            with patch(
                "telemetry.governance_store.is_telemetry_enabled",
                return_value=True,
            ):
                add_history_entry(
                    record_id=record_id,
                    history_category="outcome",
                    history_action="observed",
                    history_data={"outcome_type": "common_outcome"},
                    db_path=db,
                )

        results = get_outcome_correlation(db_path=db)
        assert results[0]["outcome_type"] == "common_outcome"
        assert results[0]["frequency"] == 2

    def test_ignores_non_outcome_drift_categories(self, tmp_path):
        """Decision/override/approval history entries must not
        appear in outcome correlation — only outcome/drift."""
        db = _tmp_db(tmp_path)
        record_id = _create(_make_result(decision="DENY_WITH_OVERRIDE"), db)

        with patch(
            "telemetry.governance_store.is_telemetry_enabled", return_value=True
        ):
            add_history_entry(
                record_id=record_id,
                history_category="override",
                history_action="approved",
                history_data={"outcome_type": "should_not_appear"},
                db_path=db,
            )

        assert get_outcome_correlation(db_path=db) == []

    def test_includes_drift_category(self, tmp_path):
        db = _tmp_db(tmp_path)
        record_id = _create(_make_result(decision="ALLOW"), db)

        with patch(
            "telemetry.governance_store.is_telemetry_enabled", return_value=True
        ):
            add_history_entry(
                record_id=record_id,
                history_category="drift",
                history_action="detected",
                history_data={"outcome_type": "drift_detected"},
                db_path=db,
            )

        results = get_outcome_correlation(db_path=db)
        assert len(results) == 1
        assert results[0]["outcome_type"] == "drift_detected"


# =====================================================
# get_objective_summary
# =====================================================


class TestGetObjectiveSummary:
    def test_all_zero_for_unknown_objective(self, tmp_path):
        db = _tmp_db(tmp_path)
        summary = get_objective_summary("Nonexistent objective", db_path=db)
        assert summary["total_records"] == 0
        assert summary["trend"] == "insufficient_data"

    def test_counts_upheld_and_violated(self, tmp_path):
        db = _tmp_db(tmp_path)
        statement = "Maintain cloud spend within budget"

        _create(_make_result(decision="ALLOW", objective_statement=statement), db)
        _create(_make_result(decision="ALLOW", objective_statement=statement), db)
        _create(
            _make_result(
                decision="DENY_WITH_OVERRIDE", objective_statement=statement
            ),
            db,
        )

        summary = get_objective_summary(statement, db_path=db)
        assert summary["total_records"] == 3
        assert summary["upheld_count"] == 2
        assert summary["violated_count"] == 1
        assert summary["pending_count"] == 0

    def test_upheld_rate_computed_correctly(self, tmp_path):
        db = _tmp_db(tmp_path)
        statement = "Test objective"

        for _ in range(3):
            _create(
                _make_result(decision="ALLOW", objective_statement=statement), db
            )
        _create(
            _make_result(decision="DENY", objective_statement=statement), db
        )

        summary = get_objective_summary(statement, db_path=db)
        assert summary["upheld_rate"] == 75.0

    def test_pending_counted_separately(self, tmp_path):
        db = _tmp_db(tmp_path)
        statement = "Approval-gated objective"

        _create(
            _make_result(
                decision="ALLOW_WITH_APPROVAL_REQUIRED",
                objective_statement=statement,
            ),
            db,
        )

        summary = get_objective_summary(statement, db_path=db)
        assert summary["pending_count"] == 1
        assert summary["upheld_count"] == 0
        assert summary["violated_count"] == 0

    def test_insufficient_data_trend_below_four_records(self, tmp_path):
        db = _tmp_db(tmp_path)
        statement = "Sparse objective"

        for _ in range(3):
            _create(
                _make_result(decision="ALLOW", objective_statement=statement), db
            )

        summary = get_objective_summary(statement, db_path=db)
        assert summary["total_records"] == 3
        assert summary["trend"] == "insufficient_data"

    def test_stable_trend_with_consistent_rate(self, tmp_path):
        db = _tmp_db(tmp_path)
        statement = "Stable objective"

        # 4 ALLOW, 4 ALLOW — same rate throughout, should be stable
        for _ in range(8):
            _create(
                _make_result(decision="ALLOW", objective_statement=statement), db
            )

        summary = get_objective_summary(statement, db_path=db)
        assert summary["trend"] == "stable"

    def test_does_not_raise_on_malformed_records(self, tmp_path):
        db = _tmp_db(tmp_path)
        try:
            get_objective_summary("anything", db_path=db)
        except Exception as exc:
            import pytest
            pytest.fail(f"get_objective_summary raised unexpectedly: {exc}")

    def test_statement_preserved_in_summary(self, tmp_path):
        db = _tmp_db(tmp_path)
        statement = "Exact statement text preserved"
        _create(_make_result(objective_statement=statement), db)

        summary = get_objective_summary(statement, db_path=db)
        assert summary["statement"] == statement