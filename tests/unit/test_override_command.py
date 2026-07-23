# tests/unit/test_override_command.py
#
# Tests for cli/commands/override.py — the two-step
# request/approve/deny override workflow.

import uuid
from unittest.mock import patch

from typer.testing import CliRunner

from cli.commands.override import override_app
from telemetry.governance_store import (
    create_governance_record,
    get_governance_history,
    get_risk_acceptance_records,
)

runner = CliRunner()


def _make_result(
    decision: str = "DENY_WITH_OVERRIDE",
    override_possible: bool = True,
) -> dict:
    return {
        "decision_id": str(uuid.uuid4()),
        "decision": decision,
        "policy": "budget_policy",
        "conditions_passed": False,
        "governance_severity": "medium",
        "override_possible": override_possible,
        "requires_approval": False,
        "timestamp": "2026-07-21T00:00:00+00:00",
        "risk_summary": {"overall_risk_score": 75, "effective_severity": "critical"},
    }


def _create_record(db_path, **kwargs) -> str:
    result = _make_result(**kwargs)
    with patch("telemetry.governance_store.is_telemetry_enabled", return_value=True):
        create_governance_record(result=result, db_path=db_path)
    return result["decision_id"]


def _invoke(app, args, db_path):
    """Invoke a command with telemetry enabled and db_path patched
    through both governance_store's own calls and get_db_path."""
    with patch("telemetry.governance_store.is_telemetry_enabled", return_value=True):
        with patch("telemetry.governance_store.get_db_path", return_value=db_path):
            return runner.invoke(app, args)


class TestOverrideRequest:
    def test_request_succeeds_on_eligible_decision(self, tmp_path):
        db = tmp_path / "test.db"
        record_id = _create_record(db)

        result = _invoke(
            override_app, ["request", record_id, "--reason", "Emergency patch"], db
        )

        assert result.exit_code == 0
        assert "Override requested" in result.output

        history = get_governance_history(record_id, db_path=db)
        override_entries = [h for h in history if h["history_category"] == "override"]
        assert len(override_entries) == 1
        assert override_entries[0]["history_action"] == "requested"

    def test_request_rejected_when_not_override_possible(self, tmp_path):
        db = tmp_path / "test.db"
        record_id = _create_record(db, override_possible=False)

        result = _invoke(
            override_app, ["request", record_id, "--reason", "test"], db
        )

        assert result.exit_code == 1
        assert "not eligible" in result.output

    def test_request_fails_without_reason(self, tmp_path):
        db = tmp_path / "test.db"
        record_id = _create_record(db)

        result = _invoke(override_app, ["request", record_id], db)

        assert result.exit_code != 0

    def test_request_fails_for_unknown_decision(self, tmp_path):
        db = tmp_path / "test.db"

        result = _invoke(
            override_app,
            ["request", "nonexistent12", "--reason", "test"],
            db,
        )

        assert result.exit_code == 1
        assert "No governance decision found" in result.output


class TestOverrideApprove:
    def test_approve_fails_without_prior_request(self, tmp_path):
        db = tmp_path / "test.db"
        record_id = _create_record(db)

        result = _invoke(
            override_app, ["approve", record_id, "--reason", "Approved"], db
        )

        assert result.exit_code == 1
        assert "No override request found" in result.output

    def test_approve_succeeds_after_request(self, tmp_path):
        db = tmp_path / "test.db"
        record_id = _create_record(db)

        _invoke(override_app, ["request", record_id, "--reason", "Emergency"], db)
        result = _invoke(
            override_app, ["approve", record_id, "--reason", "Confirmed with finance"], db
        )

        assert result.exit_code == 0
        assert "Override approved" in result.output

    def test_approve_creates_confirmed_risk_acceptance(self, tmp_path):
        db = tmp_path / "test.db"
        record_id = _create_record(db)

        _invoke(override_app, ["request", record_id, "--reason", "Emergency"], db)
        _invoke(override_app, ["approve", record_id, "--reason", "Confirmed"], db)

        records = get_risk_acceptance_records(db_path=db)
        assert len(records) == 1
        assert records[0]["record_id"] == record_id

    def test_cannot_approve_twice(self, tmp_path):
        """Once approved, a second approve without a new
        request must fail — enforces that the override is
        governed, not a repeatable rubber stamp."""
        db = tmp_path / "test.db"
        record_id = _create_record(db)

        _invoke(override_app, ["request", record_id, "--reason", "Emergency"], db)
        _invoke(override_app, ["approve", record_id, "--reason", "Confirmed"], db)
        second_approve = _invoke(
            override_app, ["approve", record_id, "--reason", "Again?"], db
        )

        assert second_approve.exit_code == 1
        assert "already" in second_approve.output

    def test_new_request_allows_reapproval(self, tmp_path):
        """A denied request followed by a NEW request should
        be approvable — the history is append-only, so
        re-requesting after denial is a legitimate path."""
        db = tmp_path / "test.db"
        record_id = _create_record(db)

        _invoke(override_app, ["request", record_id, "--reason", "First try"], db)
        _invoke(override_app, ["deny", record_id, "--reason", "Not enough detail"], db)
        _invoke(override_app, ["request", record_id, "--reason", "Second try, detailed"], db)
        result = _invoke(
            override_app, ["approve", record_id, "--reason", "Now confirmed"], db
        )

        assert result.exit_code == 0


class TestOverrideDeny:
    def test_deny_fails_without_prior_request(self, tmp_path):
        db = tmp_path / "test.db"
        record_id = _create_record(db)

        result = _invoke(
            override_app, ["deny", record_id, "--reason", "No"], db
        )

        assert result.exit_code == 1

    def test_deny_succeeds_after_request(self, tmp_path):
        db = tmp_path / "test.db"
        record_id = _create_record(db)

        _invoke(override_app, ["request", record_id, "--reason", "Emergency"], db)
        result = _invoke(
            override_app, ["deny", record_id, "--reason", "Insufficient justification"], db
        )

        assert result.exit_code == 0
        assert "Override denied" in result.output

    def test_denied_override_not_in_ledger(self, tmp_path):
        db = tmp_path / "test.db"
        record_id = _create_record(db)

        _invoke(override_app, ["request", record_id, "--reason", "Emergency"], db)
        _invoke(override_app, ["deny", record_id, "--reason", "No"], db)

        records = get_risk_acceptance_records(db_path=db)
        assert records == []
