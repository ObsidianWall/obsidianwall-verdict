# tests/unit/test_sentinel_governance_bypass.py
#
# Tests for the governance-bypass detection logic added to
# cli/commands/sentinel/scan.py per ADR-0003. New file,
# deliberately separate from any pre-existing sentinel/scan
# test coverage, to avoid guessing at that file's structure.
#
# Every test now takes tmp_path and threads a real, isolated
# db_path through patch_telemetry() — the original version of
# this file had NO tmp_path fixture at all, meaning any real
# write escaping the mocked functions (most likely
# create_governance_record(), persisting scan's fresh
# re-evaluation as its own governance record — separate from
# the mocked add_history_entry() call for the bypass event
# specifically) went straight to the real default database,
# unconditionally, on every test run. Confirmed as a real,
# ongoing leak: verdict audit's total_evaluations count grew
# on every full-suite run before this fix.

from __future__ import annotations

import json
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from cli.commands.sentinel.scan import sentinel_app

from tests.helpers.telemetry_patching import patch_telemetry

runner = CliRunner()


def _make_previous_record(
    decision: str = "DENY_WITH_OVERRIDE",
    failed_conditions: list[str] | None = None,
) -> dict:
    return {
        "record_id": str(uuid.uuid4()),
        "decision": decision,
        "policy_name": "basic_budget_verdict",
        "overall_risk_score": 75,
        "failed_conditions": json.dumps(failed_conditions or ["budget_check"]),
        "passed_conditions": json.dumps([]),
        "analyzer_scores": json.dumps({"cost_analysis": 60}),
        "created_at": "2026-07-31T00:00:00+00:00",
        "override_possible": True,
    }


def _make_current_evaluation(
    decision: str = "DENY_WITH_OVERRIDE",
    failed_condition_ids: list[str] | None = None,
) -> dict:
    failed = failed_condition_ids if failed_condition_ids is not None else ["budget_check"]
    trace = [{"condition_id": cid, "result": False} for cid in failed]
    return {
        "decision": decision,
        "risk_summary": {
            "overall_risk_score": 75,
            "analyzer_scores": {"cost_analysis": 60},
        },
        "trace": trace,
        "notification_manifest": {},
    }


def _run_scan(previous_record, current_result, confirmed_approvals, db_path: Path):
    """
    Invokes `verdict sentinel scan --plan ...` with every
    external dependency mocked, isolating ONLY the bypass-
    detection logic itself as the thing under test.

    db_path is now REQUIRED and threaded through
    patch_telemetry() — any real call this test doesn't
    explicitly mock (e.g. create_governance_record persisting
    the scan's own fresh re-evaluation) redirects to this
    isolated path instead of the real default database.
    """
    with patch_telemetry(db_path=db_path, enabled=True):
        with patch(
            "cli.commands.sentinel.scan.get_most_recent_record_for_policy",
            return_value=previous_record,
        ):
            with patch(
                "cli.commands.sentinel.scan.load_policy",
                # Must match _make_previous_record()'s policy_name.
                # Real schema has NO "policy:" wrapper — name lives
                # at metadata.name directly (confirmed against
                # schemas/policy_schema.py and real policy files).
                return_value={"metadata": {"name": "basic_budget_verdict"}},
            ):
                with patch("cli.commands.sentinel.scan.validate_policy"):
                    with patch(
                        "cli.commands.sentinel.scan.build_context",
                        return_value={},
                    ):
                        with patch(
                            "cli.commands.sentinel.scan.PolicyOrchestrator"
                        ) as mock_orchestrator_class:
                            mock_engine = MagicMock()
                            mock_engine.evaluate.return_value = current_result
                            mock_orchestrator_class.from_policy_path.return_value = (
                                mock_engine
                            )

                            with patch(
                                "cli.commands.sentinel.scan.get_risk_acceptance_records",
                                return_value=confirmed_approvals,
                            ):
                                with patch(
                                    "cli.commands.sentinel.scan.add_history_entry"
                                ) as mock_add_history:
                                    # sentinel_app has exactly ONE
                                    # registered command (scan) — Typer/
                                    # Click auto-collapses single-command
                                    # apps, so the command name must NOT
                                    # be passed here, only its options.
                                    result = runner.invoke(
                                        sentinel_app,
                                        [
                                            "--plan", "fake_plan.json",
                                            "--policy", "fake_policy.yaml",
                                        ],
                                    )
                                    return result, mock_add_history


class TestGovernanceBypassDetection:
    def test_bypass_detected_when_no_confirmed_approval_exists(self, tmp_path):
        """
        The core case: DENY_WITH_OVERRIDE, still failing, ZERO
        confirmed approvals for this record. Must be flagged
        as governance_bypass, not ordinary drift.
        """
        db = tmp_path / "test.db"
        previous = _make_previous_record()
        current = _make_current_evaluation()

        result, mock_add_history = _run_scan(
            previous, current, confirmed_approvals=[], db_path=db
        )

        assert "GOVERNANCE BYPASS" in result.output
        assert result.exit_code == 1

        call_kwargs = mock_add_history.call_args.kwargs
        assert call_kwargs["history_category"] == "governance"
        assert call_kwargs["history_action"] == "bypassed"
        assert call_kwargs["history_data"]["outcome_type"] == "governance_bypass"

    def test_no_bypass_when_confirmed_approval_exists(self, tmp_path):
        """
        Same failing condition, same decision type — but a
        confirmed approval DOES exist for this exact record.
        Must NOT be flagged as a bypass.
        """
        db = tmp_path / "test.db"
        previous = _make_previous_record()
        current = _make_current_evaluation()

        confirmed = [{"record_id": previous["record_id"]}]

        result, mock_add_history = _run_scan(
            previous, current, confirmed_approvals=confirmed, db_path=db
        )

        assert "GOVERNANCE BYPASS" not in result.output

        call_kwargs = mock_add_history.call_args.kwargs
        assert call_kwargs["history_data"]["outcome_type"] != "governance_bypass"

    def test_no_bypass_when_condition_no_longer_failing(self, tmp_path):
        """
        The condition that originally failed is now RESOLVED in
        the current re-evaluation. Even with zero confirmed
        approvals, this must not be flagged as a bypass — the
        violation itself is gone, there's nothing to bypass.
        """
        db = tmp_path / "test.db"
        previous = _make_previous_record(failed_conditions=["budget_check"])
        current = _make_current_evaluation(
            decision="ALLOW", failed_condition_ids=[]
        )

        result, mock_add_history = _run_scan(
            previous, current, confirmed_approvals=[], db_path=db
        )

        # Confirm the command actually ran successfully first —
        # otherwise "GOVERNANCE BYPASS" not in output would pass
        # trivially even on an unrelated failure.
        mock_add_history.assert_called_once()
        assert "GOVERNANCE BYPASS" not in result.output

    def test_no_bypass_check_for_non_override_decisions(self, tmp_path):
        """
        The bypass check is scoped specifically to
        DENY_WITH_OVERRIDE — that's the only decision type for
        which a confirmed Ledger approval could ever exist
        (is_risk_acceptance_candidate is only set for
        DENY_WITH_OVERRIDE records). A plain DENY (no override
        path at all) must never be checked against the Ledger.
        """
        db = tmp_path / "test.db"
        previous = _make_previous_record(decision="DENY")
        current = _make_current_evaluation(decision="DENY")

        result, mock_add_history = _run_scan(
            previous, current, confirmed_approvals=[], db_path=db
        )

        mock_add_history.assert_called_once()
        assert "GOVERNANCE BYPASS" not in result.output

    def test_bypass_takes_priority_over_ordinary_compliance_violation(self, tmp_path):
        """
        When a NEW failure appears (which would normally
        trigger compliance_violation) on a record that's ALSO
        an unapproved DENY_WITH_OVERRIDE bypass, the more
        severe governance_bypass classification must win.
        """
        db = tmp_path / "test.db"
        previous = _make_previous_record(failed_conditions=["budget_check"])
        current = _make_current_evaluation(
            failed_condition_ids=["budget_check", "new_condition"]
        )

        result, mock_add_history = _run_scan(
            previous, current, confirmed_approvals=[], db_path=db
        )

        call_kwargs = mock_add_history.call_args.kwargs
        assert call_kwargs["history_data"]["outcome_type"] == "governance_bypass"

    def test_bypass_severity_is_critical(self, tmp_path):
        db = tmp_path / "test.db"
        previous = _make_previous_record()
        current = _make_current_evaluation()

        _, mock_add_history = _run_scan(
            previous, current, confirmed_approvals=[], db_path=db
        )

        call_kwargs = mock_add_history.call_args.kwargs
        assert call_kwargs["history_data"]["severity"] == "critical"