# tests/unit/test_governance_store_aggregates.py
#
# Tests for the aggregate analytics functions in
# telemetry/governance_store.py added to support v0.6.0's
# rewired verdict audit and verdict sentinel scan:
#   get_most_recent_record, get_recent_records,
#   get_policy_effectiveness, get_domain_risk_summary,
#   get_failed_conditions_summary, get_passed_conditions_summary,
#   get_outcome_summary, get_risk_acceptance_records

import uuid
from pathlib import Path
from unittest.mock import patch

from telemetry.governance_store import (
    add_history_entry,
    create_governance_record,
    get_domain_risk_summary,
    get_failed_conditions_summary,
    get_most_recent_record,
    get_outcome_summary,
    get_passed_conditions_summary,
    get_policy_effectiveness,
    get_recent_records,
    get_risk_acceptance_records,
)


def _tmp_db(tmp_path: Path) -> Path:
    return tmp_path / "test_aggregates.db"


def _make_result(
    decision: str = "DENY_WITH_OVERRIDE",
    policy: str = "budget_policy",
    risk_score: int = 75,
    override_possible: bool = True,
    analyzer_scores: dict | None = None,
    failed: list | None = None,
    passed: list | None = None,
) -> dict:
    trace = []
    for cid in (failed or []):
        trace.append({"condition_id": cid, "result": False})
    for cid in (passed or []):
        trace.append({"condition_id": cid, "result": True})

    return {
        "decision_id": str(uuid.uuid4()),
        "decision": decision,
        "policy": policy,
        "conditions_passed": decision == "ALLOW",
        "governance_severity": "medium",
        "override_possible": override_possible,
        "requires_approval": False,
        "timestamp": "2026-07-16T00:00:00+00:00",
        "risk_summary": {
            "overall_risk_score": risk_score,
            "effective_severity": "critical",
            "analyzer_scores": analyzer_scores or {},
        },
        "trace": trace,
    }


def _create(result: dict, db_path: Path) -> str:
    with patch("telemetry.governance_store.is_telemetry_enabled", return_value=True):
        create_governance_record(result=result, db_path=db_path)
    return result["decision_id"]


# =====================================================
# get_most_recent_record
# =====================================================


class TestGetMostRecentRecord:
    def test_returns_none_for_empty_db(self, tmp_path):
        db = _tmp_db(tmp_path)
        assert get_most_recent_record(db_path=db) is None

    def test_returns_single_record(self, tmp_path):
        db = _tmp_db(tmp_path)
        record_id = _create(_make_result(), db)
        result = get_most_recent_record(db_path=db)
        assert result is not None
        assert result["record_id"] == record_id

    def test_returns_newest_of_multiple(self, tmp_path):
        db = _tmp_db(tmp_path)
        _create(_make_result(policy="policy_a"), db)
        second_id = _create(_make_result(policy="policy_b"), db)
        result = get_most_recent_record(db_path=db)
        assert result["record_id"] == second_id


# =====================================================
# get_recent_records
# =====================================================


class TestGetRecentRecords:
    def test_empty_list_for_empty_db(self, tmp_path):
        db = _tmp_db(tmp_path)
        assert get_recent_records(db_path=db) == []

    def test_respects_limit(self, tmp_path):
        db = _tmp_db(tmp_path)
        for _ in range(5):
            _create(_make_result(), db)
        results = get_recent_records(limit=3, db_path=db)
        assert len(results) == 3

    def test_newest_first(self, tmp_path):
        db = _tmp_db(tmp_path)
        _create(_make_result(policy="first"), db)
        _create(_make_result(policy="second"), db)
        results = get_recent_records(db_path=db)
        assert results[0]["policy_name"] == "second"


# =====================================================
# get_policy_effectiveness
# =====================================================


class TestGetPolicyEffectiveness:
    def test_empty_for_no_records(self, tmp_path):
        db = _tmp_db(tmp_path)
        assert get_policy_effectiveness(db_path=db) == []

    def test_counts_evaluations_per_policy(self, tmp_path):
        db = _tmp_db(tmp_path)
        _create(_make_result(policy="budget_policy", decision="ALLOW"), db)
        _create(_make_result(policy="budget_policy", decision="DENY"), db)
        _create(_make_result(policy="security_policy", decision="ALLOW"), db)

        results = get_policy_effectiveness(db_path=db)
        by_name = {r["policy_name"]: r for r in results}

        assert by_name["budget_policy"]["total_evaluations"] == 2
        assert by_name["security_policy"]["total_evaluations"] == 1

    def test_counts_denials(self, tmp_path):
        db = _tmp_db(tmp_path)
        _create(_make_result(policy="p1", decision="DENY"), db)
        _create(_make_result(policy="p1", decision="DENY_WITH_OVERRIDE"), db)
        _create(_make_result(policy="p1", decision="ALLOW"), db)

        results = get_policy_effectiveness(policy_name="p1", db_path=db)
        assert results[0]["total_denied"] == 2

    def test_counts_override_history_entries(self, tmp_path):
        db = _tmp_db(tmp_path)
        record_id = _create(
            _make_result(policy="p1", decision="DENY_WITH_OVERRIDE"), db
        )

        with patch(
            "telemetry.governance_store.is_telemetry_enabled", return_value=True
        ):
            add_history_entry(
                record_id=record_id,
                history_category="override",
                history_action="approved",
                history_data={"override_role": "budget_owner"},
                db_path=db,
            )

        results = get_policy_effectiveness(policy_name="p1", db_path=db)
        assert results[0]["override_count"] == 1

    def test_filter_by_policy_name_returns_single(self, tmp_path):
        db = _tmp_db(tmp_path)
        _create(_make_result(policy="p1"), db)
        _create(_make_result(policy="p2"), db)

        results = get_policy_effectiveness(policy_name="p1", db_path=db)
        assert len(results) == 1
        assert results[0]["policy_name"] == "p1"


# =====================================================
# get_domain_risk_summary
# =====================================================


class TestGetDomainRiskSummary:
    def test_empty_dict_for_no_records(self, tmp_path):
        db = _tmp_db(tmp_path)
        assert get_domain_risk_summary(db_path=db) == {}

    def test_computes_totals(self, tmp_path):
        db = _tmp_db(tmp_path)
        _create(_make_result(decision="ALLOW"), db)
        _create(_make_result(decision="DENY"), db)
        _create(_make_result(decision="DENY_WITH_OVERRIDE"), db)

        summary = get_domain_risk_summary(db_path=db)
        assert summary["total_evaluations"] == 3
        assert summary["total_denied"] == 2

    def test_computes_domain_averages(self, tmp_path):
        db = _tmp_db(tmp_path)
        _create(
            _make_result(analyzer_scores={"cost_analysis": 50}),
            db,
        )
        _create(
            _make_result(analyzer_scores={"cost_analysis": 30}),
            db,
        )

        summary = get_domain_risk_summary(db_path=db)
        assert summary["domain_avg_scores"]["cost_analysis"] == 40.0


# =====================================================
# get_failed_conditions_summary / get_passed_conditions_summary
# =====================================================


class TestConditionSummaries:
    def test_failed_conditions_empty_for_no_records(self, tmp_path):
        db = _tmp_db(tmp_path)
        assert get_failed_conditions_summary(db_path=db) == []

    def test_aggregates_failed_condition_counts(self, tmp_path):
        db = _tmp_db(tmp_path)
        _create(_make_result(failed=["budget_check"]), db)
        _create(_make_result(failed=["budget_check"]), db)
        _create(_make_result(failed=["encryption_check"]), db)

        results = get_failed_conditions_summary(db_path=db)
        by_id = {r["condition_id"]: r for r in results}
        assert by_id["budget_check"]["count"] == 2
        assert by_id["encryption_check"]["count"] == 1

    def test_aggregates_passed_condition_counts(self, tmp_path):
        db = _tmp_db(tmp_path)
        _create(_make_result(passed=["mfa_check"]), db)
        _create(_make_result(passed=["mfa_check"]), db)

        results = get_passed_conditions_summary(db_path=db)
        assert results[0]["condition_id"] == "mfa_check"
        assert results[0]["count"] == 2

    def test_sorted_by_count_descending(self, tmp_path):
        db = _tmp_db(tmp_path)
        _create(_make_result(failed=["rare_failure"]), db)
        _create(_make_result(failed=["common_failure"]), db)
        _create(_make_result(failed=["common_failure"]), db)
        _create(_make_result(failed=["common_failure"]), db)

        results = get_failed_conditions_summary(db_path=db)
        assert results[0]["condition_id"] == "common_failure"


# =====================================================
# get_outcome_summary
# =====================================================


class TestGetOutcomeSummary:
    def test_empty_for_no_outcomes(self, tmp_path):
        db = _tmp_db(tmp_path)
        assert get_outcome_summary(db_path=db) == []

    def test_counts_outcome_types_from_history(self, tmp_path):
        db = _tmp_db(tmp_path)
        record_id = _create(_make_result(), db)

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
            add_history_entry(
                record_id=record_id,
                history_category="outcome",
                history_action="observed",
                history_data={"outcome_type": "no_drift"},
                db_path=db,
            )

        results = get_outcome_summary(db_path=db)
        by_type = {r["outcome_type"]: r["count"] for r in results}
        assert by_type["drift_detected"] == 1
        assert by_type["no_drift"] == 1

    def test_ignores_non_outcome_history_categories(self, tmp_path):
        """Decision/override/approval history entries should
        not appear in outcome summary — only outcome/drift."""
        db = _tmp_db(tmp_path)
        record_id = _create(_make_result(), db)

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

        results = get_outcome_summary(db_path=db)
        assert results == []


# =====================================================
# get_risk_acceptance_records
# =====================================================


class TestGetRiskAcceptanceRecords:
    def test_empty_when_no_candidates(self, tmp_path):
        db = _tmp_db(tmp_path)
        _create(_make_result(decision="ALLOW"), db)
        assert get_risk_acceptance_records(db_path=db) == []

    def test_candidate_alone_not_returned_without_approval(self, tmp_path):
        """
        A DENY_WITH_OVERRIDE record is only a CANDIDATE until
        an OVERRIDE_APPROVED history entry confirms it. Without
        that confirmation, it must not appear as a confirmed
        risk acceptance.
        """
        db = _tmp_db(tmp_path)
        _create(
            _make_result(decision="DENY_WITH_OVERRIDE", override_possible=True),
            db,
        )
        assert get_risk_acceptance_records(db_path=db) == []

    def test_confirmed_after_override_approved(self, tmp_path):
        db = _tmp_db(tmp_path)
        record_id = _create(
            _make_result(decision="DENY_WITH_OVERRIDE", override_possible=True),
            db,
        )

        with patch(
            "telemetry.governance_store.is_telemetry_enabled", return_value=True
        ):
            add_history_entry(
                record_id=record_id,
                history_category="override",
                history_action="approved",
                history_data={"override_role": "budget_owner"},
                actor_role="budget_owner",
                db_path=db,
            )

        results = get_risk_acceptance_records(db_path=db)
        assert len(results) == 1
        assert results[0]["record_id"] == record_id
        assert results[0]["accepted_by"] == "budget_owner"

    def test_denied_override_not_included(self, tmp_path):
        """An OVERRIDE_DENIED entry should not create a
        confirmed risk acceptance."""
        db = _tmp_db(tmp_path)
        record_id = _create(
            _make_result(decision="DENY_WITH_OVERRIDE", override_possible=True),
            db,
        )

        with patch(
            "telemetry.governance_store.is_telemetry_enabled", return_value=True
        ):
            add_history_entry(
                record_id=record_id,
                history_category="override",
                history_action="denied",
                history_data={"override_role": "budget_owner"},
                db_path=db,
            )

        assert get_risk_acceptance_records(db_path=db) == []

    def test_non_override_decision_never_a_candidate(self, tmp_path):
        """ALLOW decisions should never be risk acceptance
        candidates, regardless of any history entries added."""
        db = _tmp_db(tmp_path)
        record_id = _create(_make_result(decision="ALLOW"), db)

        with patch(
            "telemetry.governance_store.is_telemetry_enabled", return_value=True
        ):
            add_history_entry(
                record_id=record_id,
                history_category="override",
                history_action="approved",
                history_data={},
                db_path=db,
            )

        assert get_risk_acceptance_records(db_path=db) == []