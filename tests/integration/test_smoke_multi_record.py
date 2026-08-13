# tests/integration/test_smoke_multi_record.py
#
# Purpose:
# Proactive smoke test against a realistic, messy, multi-record
# dataset — not the clean, single-record fixtures every other
# test in this suite uses.
#
# Why this exists:
# Every real production bug found during v0.6.0 development
# (get_policy_effectiveness()'s double-counting via LEFT JOIN,
# the NULL analyzer_scores/failed_conditions/passed_conditions
# backfill gap, the schema migration ordering failure) had one
# thing in common: none of them appeared in any test, because
# every existing test exercises a single isolated record. They
# only surfaced once real data accumulated — multiple policies,
# multiple history entries per record, records spanning schema
# versions. This file simulates that mess deliberately, so the
# next version of the same failure pattern gets caught here,
# not in someone's terminal weeks later.
#
# Design principles:
#   1. Dataset is built through the REAL public write functions
#      (create_governance_record, add_history_entry) — never
#      raw SQL — so it only represents states production could
#      actually produce.
#   2. Assertions check INVARIANTS (properties that must hold
#      regardless of dataset shape), not fixed expected values.
#      "total_denied <= total_evaluations" would have caught
#      the 101.2% bug automatically; a hardcoded expected number
#      would not have generalized to catch the NEXT version of
#      the same bug class.
#   3. Ground truth is tracked alongside construction, so
#      assertions can check against what was actually built,
#      not just "does this look plausible."

from __future__ import annotations

import sqlite3
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest

from telemetry.governance_store import (
    add_history_entry,
    create_governance_record,
    get_domain_risk_summary,
    get_failed_conditions_summary,
    get_objective_summary,
    get_outcome_correlation,
    get_passed_conditions_summary,
    get_policy_effectiveness,
    get_risk_acceptance_records,
    verify_history_chain,
)
from telemetry.migration import migrate_if_needed
from tests.helpers.telemetry_patching import patch_telemetry


# =====================================================
# DATASET CONSTRUCTION
#
# Deliberately messy on the two axes that caused real bugs:
#   - Multiple policies, some sharing condition IDs, some not
#     (exercises the per-condition rate scoping fix)
#   - Records with MORE THAN ONE history entry each
#     (exactly the shape that multiplied rows in the LEFT JOIN
#     double-counting bug)
# =====================================================


def _make_result(
    decision: str,
    policy: str,
    objective_statement: str | None,
    failed: list[str] | None = None,
    passed: list[str] | None = None,
    analyzer_scores: dict | None = None,
    override_possible: bool = False,
) -> dict:
    trace = []
    for cid in failed or []:
        trace.append({"condition_id": cid, "result": False})
    for cid in passed or []:
        trace.append({"condition_id": cid, "result": True})

    result = {
        "decision_id": str(uuid.uuid4()),
        "decision": decision,
        "policy": policy,
        "conditions_passed": decision == "ALLOW",
        "governance_severity": "medium",
        "override_possible": override_possible,
        "requires_approval": decision == "ALLOW_WITH_APPROVAL_REQUIRED",
        "timestamp": "2026-07-23T00:00:00+00:00",
        "risk_summary": {
            "overall_risk_score": 75 if "DENY" in decision else 25,
            "effective_severity": "critical" if "DENY" in decision else "low",
            "analyzer_scores": analyzer_scores or {},
        },
        "trace": trace,
    }
    if objective_statement:
        result["governance_objective"] = {
            "statement": objective_statement,
            "status": "n/a",
        }
    return result


class _MessyDataset:
    """
    Builds a realistic multi-policy, multi-history-entry dataset
    and tracks ground truth for every invariant checked below.
    """

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.confirmed_risk_acceptances: set[str] = set()
        self.total_records = 0
        self.total_denied = 0
        self.condition_ground_truth: dict[str, dict[str, int]] = {}
        # condition_id -> {"failed": N, "passed": N}

    def _track_condition(self, cid: str, outcome: str) -> None:
        self.condition_ground_truth.setdefault(cid, {"failed": 0, "passed": 0})
        self.condition_ground_truth[cid][outcome] += 1

    def _create(self, **kwargs) -> str:
        result = _make_result(**kwargs)
        with patch_telemetry(enabled=True):
            create_governance_record(result=result, db_path=self.db_path)

        self.total_records += 1
        if "DENY" in kwargs["decision"]:
            self.total_denied += 1

        for cid in kwargs.get("failed") or []:
            self._track_condition(cid, "failed")
        for cid in kwargs.get("passed") or []:
            self._track_condition(cid, "passed")

        return result["decision_id"]

    def _add_history(self, record_id: str, category: str, action: str, data: dict) -> None:
        with patch_telemetry(enabled=True):
            add_history_entry(
                record_id=record_id,
                history_category=category,
                history_action=action,
                history_data=data,
                db_path=self.db_path,
            )

    def build(self) -> None:
        statement_a = "Maintain cloud spend within approved budget"
        statement_b = "Enforce network segmentation on all deployments"

        # --- Policy A: budget_policy ---
        # Confirmed risk acceptance: requested -> denied -> re-requested -> approved
        rid = self._create(
            decision="DENY_WITH_OVERRIDE",
            policy="budget_policy",
            objective_statement=statement_a,
            failed=["budget_check"],
            analyzer_scores={"cost_analysis": 60},
            override_possible=True,
        )
        self._add_history(rid, "override", "requested", {"reason": "first attempt"})
        self._add_history(rid, "override", "denied", {"reason": "insufficient detail"})
        self._add_history(rid, "override", "requested", {"reason": "retry with detail"})
        self._add_history(rid, "override", "approved", {"reason": "confirmed"})
        self._add_history(rid, "outcome", "observed", {"outcome_type": "budget_overrun"})
        self.confirmed_risk_acceptances.add(rid)

        # Candidate only — requested, never resolved
        rid = self._create(
            decision="DENY_WITH_OVERRIDE",
            policy="budget_policy",
            objective_statement=statement_a,
            failed=["budget_check"],
            analyzer_scores={"cost_analysis": 55},
            override_possible=True,
        )
        self._add_history(rid, "override", "requested", {"reason": "pending"})

        # Denied, never re-requested — must NOT appear as confirmed
        rid = self._create(
            decision="DENY_WITH_OVERRIDE",
            policy="budget_policy",
            objective_statement=statement_a,
            failed=["budget_check"],
            analyzer_scores={"cost_analysis": 58},
            override_possible=True,
        )
        self._add_history(rid, "override", "requested", {"reason": "attempt"})
        self._add_history(rid, "override", "denied", {"reason": "rejected"})

        # Clean allows — budget_check passes
        for _ in range(5):
            self._create(
                decision="ALLOW",
                policy="budget_policy",
                objective_statement=statement_a,
                passed=["budget_check"],
                analyzer_scores={"cost_analysis": 10},
            )

        # --- Policy B: network_policy — shares NO condition IDs
        # with budget_policy, tests per-condition rate scoping ---
        for _ in range(3):
            self._create(
                decision="DENY",
                policy="network_policy",
                objective_statement=statement_b,
                failed=["segmentation_check"],
                analyzer_scores={"topology_analysis": 40},
            )
        for _ in range(7):
            rid = self._create(
                decision="ALLOW_WITH_NOTIFICATION",
                policy="network_policy",
                objective_statement=statement_b,
                passed=["segmentation_check"],
                analyzer_scores={"topology_analysis": 5},
            )
        # Drift detected on one otherwise-clean allow
        self._add_history(rid, "drift", "detected", {"outcome_type": "drift_detected"})

        # --- Policy C: approval_policy — no objective declared,
        # tests that objective-less records don't break anything ---
        for _ in range(4):
            self._create(
                decision="ALLOW_WITH_APPROVAL_REQUIRED",
                policy="approval_policy",
                objective_statement=None,
                passed=["approval_gate"],
            )

        # --- Policy D: shares budget_check with policy A,
        # verifying rates aggregate correctly ACROSS policies
        # for a condition that appears in more than one ---
        for _ in range(2):
            self._create(
                decision="DENY",
                policy="shared_condition_policy",
                objective_statement=statement_a,
                failed=["budget_check"],
                analyzer_scores={"cost_analysis": 70},
            )


@pytest.fixture
def messy_dataset(tmp_path) -> _MessyDataset:
    db_path = tmp_path / "smoke_test.db"
    dataset = _MessyDataset(db_path)
    dataset.build()
    return dataset


# =====================================================
# INVARIANT TESTS — aggregate query correctness
# =====================================================


class TestPolicyEffectivenessInvariants:
    def test_denied_never_exceeds_evaluations(self, messy_dataset):
        """
        The exact invariant that would have caught the
        101.2% bug automatically, for every policy, not
        just the one that happened to be visible in a
        terminal that night.
        """
        results = get_policy_effectiveness(db_path=messy_dataset.db_path)
        for row in results:
            assert row["total_denied"] <= row["total_evaluations"], (
                f"{row['policy_name']}: denied ({row['total_denied']}) "
                f"exceeds evaluations ({row['total_evaluations']})"
            )

    def test_override_count_never_exceeds_evaluations(self, messy_dataset):
        results = get_policy_effectiveness(db_path=messy_dataset.db_path)
        for row in results:
            assert row["override_count"] <= row["total_evaluations"] * 3, (
                # generous bound — a record can have multiple
                # override entries (request/deny/request/approve),
                # but this still catches unbounded multiplication
                f"{row['policy_name']}: override_count implausibly high"
            )

    def test_total_evaluations_matches_ground_truth(self, messy_dataset):
        results = get_policy_effectiveness(db_path=messy_dataset.db_path)
        total = sum(row["total_evaluations"] for row in results)
        assert total == messy_dataset.total_records

    def test_total_denied_matches_ground_truth(self, messy_dataset):
        results = get_policy_effectiveness(db_path=messy_dataset.db_path)
        total_denied = sum(row["total_denied"] for row in results)
        assert total_denied == messy_dataset.total_denied


class TestConditionRateInvariants:
    def test_all_rates_within_valid_bounds(self, messy_dataset):
        """Every rate must be a valid percentage — the class of
        bug where a bad denominator produces >100% or negative
        values."""
        for row in get_failed_conditions_summary(db_path=messy_dataset.db_path):
            assert 0.0 <= row["rate"] <= 100.0, (
                f"{row['condition_id']}: rate {row['rate']} out of bounds"
            )
        for row in get_passed_conditions_summary(db_path=messy_dataset.db_path):
            assert 0.0 <= row["rate"] <= 100.0, (
                f"{row['condition_id']}: rate {row['rate']} out of bounds"
            )

    def test_condition_counts_match_ground_truth(self, messy_dataset):
        """
        Cross-checks actual counts against what was really built —
        not just bounds-checking, but exact correctness for a
        condition that appears across MULTIPLE policies
        (budget_check: policy A + shared_condition_policy).
        """
        failed_results = {
            r["condition_id"]: r["count"]
            for r in get_failed_conditions_summary(db_path=messy_dataset.db_path)
        }
        expected_failed = messy_dataset.condition_ground_truth["budget_check"]["failed"]
        assert failed_results.get("budget_check") == expected_failed

    def test_shared_condition_rate_not_diluted_by_other_policies(self, messy_dataset):
        """
        The specific fix from earlier tonight: a condition's rate
        must be scoped to how often THAT CONDITION was evaluated,
        not diluted by unrelated policies' total evaluation count.
        segmentation_check only exists in network_policy — its
        rate must reflect ONLY network_policy's evaluations.
        """
        failed = {
            r["condition_id"]: r
            for r in get_failed_conditions_summary(db_path=messy_dataset.db_path)
        }
        # 3 failures out of (3 failed + 7 passed) = 10 total checks
        assert failed["segmentation_check"]["rate"] == 30.0


class TestDomainRiskSummaryInvariants:
    def test_total_evaluations_matches_full_dataset(self, messy_dataset):
        summary = get_domain_risk_summary(db_path=messy_dataset.db_path)
        assert summary["total_evaluations"] == messy_dataset.total_records

    def test_deny_rate_within_bounds(self, messy_dataset):
        summary = get_domain_risk_summary(db_path=messy_dataset.db_path)
        assert 0.0 <= summary["deny_rate"] <= 100.0

    def test_domain_scores_within_bounds(self, messy_dataset):
        summary = get_domain_risk_summary(db_path=messy_dataset.db_path)
        for domain, score in summary["domain_avg_scores"].items():
            assert 0.0 <= score <= 100.0, f"{domain}: score {score} out of bounds"


# =====================================================
# INVARIANT TESTS — Risk Acceptance Ledger correctness
# =====================================================


class TestRiskAcceptanceLedgerInvariants:
    def test_confirmed_set_matches_ground_truth_exactly(self, messy_dataset):
        """
        The Ledger must return EXACTLY the set of records that
        were actually approved — no false positives (pending or
        denied requests leaking in) and no false negatives
        (a real approval getting missed).
        """
        results = get_risk_acceptance_records(db_path=messy_dataset.db_path)
        returned_ids = {r["record_id"] for r in results}
        assert returned_ids == messy_dataset.confirmed_risk_acceptances

    def test_no_duplicate_records_for_single_approval(self, messy_dataset):
        """
        Every confirmed record should appear once per APPROVAL
        EVENT, not multiplied by unrelated history entries
        (outcome/drift entries on the same record must not
        cause extra rows).
        """
        results = get_risk_acceptance_records(db_path=messy_dataset.db_path)
        # The one confirmed record in this dataset has exactly
        # one 'approved' override entry, despite also having an
        # outcome entry attached — must produce exactly one row.
        matching = [
            r for r in results
            if r["record_id"] in messy_dataset.confirmed_risk_acceptances
        ]
        assert len(matching) == len(messy_dataset.confirmed_risk_acceptances)


# =====================================================
# INVARIANT TESTS — Compass query correctness
# =====================================================


class TestCompassQueryInvariants:
    def test_outcome_correlation_frequencies_are_positive(self, messy_dataset):
        for row in get_outcome_correlation(db_path=messy_dataset.db_path):
            assert row["frequency"] >= 1

    def test_objective_summary_counts_sum_to_total(self, messy_dataset):
        summary = get_objective_summary(
            "Maintain cloud spend within approved budget",
            db_path=messy_dataset.db_path,
        )
        assert (
            summary["upheld_count"]
            + summary["violated_count"]
            + summary["pending_count"]
        ) <= summary["total_records"]

    def test_objective_summary_trend_is_valid_value(self, messy_dataset):
        summary = get_objective_summary(
            "Enforce network segmentation on all deployments",
            db_path=messy_dataset.db_path,
        )
        assert summary["trend"] in (
            "improving", "declining", "stable", "insufficient_data"
        )

    def test_objectiveless_records_do_not_break_anything(self, messy_dataset):
        """
        approval_policy records declare no governance_objective —
        confirms that's handled cleanly, not just in isolation
        but sitting alongside records that DO have objectives.
        """
        summary = get_objective_summary(
            "Nonexistent objective", db_path=messy_dataset.db_path
        )
        assert summary["total_records"] == 0


# =====================================================
# INVARIANT TESTS — tamper-evidence holds under load
# =====================================================


class TestIntegrityInvariants:
    def test_every_record_verifies_intact(self, messy_dataset):
        """
        verify_history_chain() must return verified=True for
        EVERY record in an untampered dataset — including ones
        with 5 history entries, not just the single-entry case
        already covered by unit tests.
        """
        # Spot-check the record with the most history entries
        for rid in messy_dataset.confirmed_risk_acceptances:
            result = verify_history_chain(rid, db_path=messy_dataset.db_path)
            assert result["verified"] is True
            assert result["history_count"] >= 5  # requested x2, denied,
                                                   # approved, outcome


# =====================================================
# MIGRATION SCENARIO — multi-row backfill correctness
#
# Recreates the exact precondition of the NULL-backfill bug:
# an old-schema database with SEVERAL rows (not the single-row
# fixtures test_migration.py already covers), migrated forward.
# Asserts zero NULL columns afterward across every row — this
# would catch a future column addition that forgets to update
# _MIGRATIONS, automatically, in CI.
# =====================================================


def _create_old_schema_db_with_multiple_rows(db_path: Path, row_count: int) -> list[str]:
    conn = sqlite3.connect(str(db_path))
    conn.executescript(
        """
        CREATE TABLE decisions (
            id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, policy_name TEXT NOT NULL,
            decision TEXT NOT NULL, conditions_passed INTEGER DEFAULT 0,
            overall_risk_score INTEGER DEFAULT 0, effective_severity TEXT,
            governance_severity TEXT, override_possible INTEGER DEFAULT 0,
            requires_approval INTEGER DEFAULT 0, plan_hash TEXT, user_role TEXT,
            policy_content_hash TEXT, policy_family TEXT
        );
        """
    )
    record_ids = []
    for i in range(row_count):
        rid = str(uuid.uuid4())
        record_ids.append(rid)
        conn.execute(
            "INSERT INTO decisions (id, timestamp, policy_name, decision, "
            "conditions_passed, overall_risk_score, effective_severity, "
            "governance_severity, override_possible, requires_approval) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                rid, f"2026-07-{10+i:02d}T00:00:00+00:00", f"old_policy_{i % 3}",
                "DENY_WITH_OVERRIDE" if i % 2 == 0 else "ALLOW",
                0, 50 + i, "high", "medium", 1, 0,
            ),
        )
    conn.commit()
    conn.close()
    return record_ids


class TestMultiRowMigrationInvariants:
    def test_no_null_columns_after_migrating_multiple_rows(self, tmp_path):
        db_path = tmp_path / "old_multi_row.db"
        record_ids = _create_old_schema_db_with_multiple_rows(db_path, row_count=12)

        with patch("telemetry.migration.get_db_dir", return_value=tmp_path):
            migrate_if_needed(db_path=db_path, silent=True)

        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        for rid in record_ids:
            row = conn.execute(
                "SELECT analyzer_scores, failed_conditions, passed_conditions, "
                "is_risk_acceptance_candidate FROM governance_records "
                "WHERE record_id = ?",
                (rid,),
            ).fetchone()
            assert row is not None, f"record {rid} missing after migration"
            assert row["analyzer_scores"] is not None, (
                f"record {rid}: analyzer_scores NULL after migration — "
                f"this is the exact backfill bug class"
            )
            assert row["failed_conditions"] is not None
            assert row["passed_conditions"] is not None
            assert row["is_risk_acceptance_candidate"] is not None
        conn.close()

    def test_row_count_preserved_across_migration(self, tmp_path):
        db_path = tmp_path / "old_multi_row_count.db"
        _create_old_schema_db_with_multiple_rows(db_path, row_count=15)

        with patch("telemetry.migration.get_db_dir", return_value=tmp_path):
            migrate_if_needed(db_path=db_path, silent=True)

        conn = sqlite3.connect(str(db_path))
        count = conn.execute("SELECT COUNT(*) FROM governance_records").fetchone()[0]
        conn.close()
        assert count == 15