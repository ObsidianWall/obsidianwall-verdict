# tests/unit/test_ledger_command.py
#
# Tests for cli/commands/ledger.py — the verdict ledger command.

import json
import uuid
from unittest.mock import patch

from typer.testing import CliRunner

from cli.commands.ledger import ledger_app
from telemetry.governance_store import add_history_entry, create_governance_record

runner = CliRunner()


def _make_result(
    decision: str = "DENY_WITH_OVERRIDE",
    policy: str = "budget_policy",
    override_possible: bool = True,
) -> dict:
    return {
        "decision_id": str(uuid.uuid4()),
        "decision": decision,
        "policy": policy,
        "conditions_passed": False,
        "governance_severity": "medium",
        "override_possible": override_possible,
        "requires_approval": False,
        "timestamp": "2026-07-18T00:00:00+00:00",
        "risk_summary": {"overall_risk_score": 75, "effective_severity": "critical"},
    }


def _create_confirmed_risk_acceptance(db_path, policy="budget_policy") -> str:
    """Create a record that IS a confirmed risk acceptance —
    DENY_WITH_OVERRIDE + subsequently OVERRIDE_APPROVED."""
    result = _make_result(policy=policy)
    with patch("telemetry.governance_store.is_telemetry_enabled", return_value=True):
        create_governance_record(result=result, db_path=db_path)
        add_history_entry(
            record_id=result["decision_id"],
            history_category="override",
            history_action="approved",
            history_data={"override_role": "budget_owner"},
            actor_role="budget_owner",
            db_path=db_path,
        )
    return result["decision_id"]


class TestLedgerCommand:
    def test_empty_ledger_message(self, tmp_path):
        db = tmp_path / "test.db"
        with patch("telemetry.config.get_db_path", return_value=db):
            with patch(
                "cli.commands.ledger.is_telemetry_enabled", return_value=True
            ):
                with patch(
                    "cli.commands.ledger.get_risk_acceptance_records",
                    return_value=[],
                ):
                    result = runner.invoke(ledger_app, [])

        assert result.exit_code == 0
        assert "No confirmed risk acceptances found" in result.output

    def test_telemetry_disabled_message(self):
        with patch(
            "cli.commands.ledger.is_telemetry_enabled", return_value=False
        ):
            result = runner.invoke(ledger_app, [])

        assert result.exit_code == 1
        assert "Telemetry is disabled" in result.output

    def test_shows_confirmed_risk_acceptance(self, tmp_path):
        db = tmp_path / "test.db"
        _create_confirmed_risk_acceptance(db, policy="budget_policy")

        with patch(
            "cli.commands.ledger.is_telemetry_enabled", return_value=True
        ):
            with patch(
                "cli.commands.ledger.get_db_path", return_value=db
            ):
                with patch(
                    "telemetry.governance_store.get_db_path", return_value=db
                ):
                    result = runner.invoke(ledger_app, [])

        assert result.exit_code == 0
        assert "budget_policy" in result.output
        assert "budget_owner" in result.output

    def test_json_format_valid(self, tmp_path):
        db = tmp_path / "test.db"
        _create_confirmed_risk_acceptance(db, policy="budget_policy")

        with patch(
            "cli.commands.ledger.is_telemetry_enabled", return_value=True
        ):
            with patch(
                "telemetry.governance_store.get_db_path", return_value=db
            ):
                result = runner.invoke(ledger_app, ["--format", "json"])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["policy_name"] == "budget_policy"

    def test_policy_filter(self, tmp_path):
        db = tmp_path / "test.db"
        _create_confirmed_risk_acceptance(db, policy="policy_a")
        _create_confirmed_risk_acceptance(db, policy="policy_b")

        with patch(
            "cli.commands.ledger.is_telemetry_enabled", return_value=True
        ):
            with patch(
                "telemetry.governance_store.get_db_path", return_value=db
            ):
                result = runner.invoke(
                    ledger_app, ["--policy", "policy_a", "--format", "json"]
                )

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert all(r["policy_name"] == "policy_a" for r in data)

    def test_shows_explain_hint(self, tmp_path):
        db = tmp_path / "test.db"
        _create_confirmed_risk_acceptance(db)

        with patch(
            "cli.commands.ledger.is_telemetry_enabled", return_value=True
        ):
            with patch(
                "telemetry.governance_store.get_db_path", return_value=db
            ):
                result = runner.invoke(ledger_app, [])

        assert "verdict explain" in result.output