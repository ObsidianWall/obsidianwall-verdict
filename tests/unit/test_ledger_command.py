# tests/unit/test_ledger_command.py
#
# Tests for cli/commands/ledger.py — the verdict ledger command.
#
# Uses patch_telemetry() from tests/helpers/telemetry_patching.py
# — the setup helper writes via create_governance_record/
# add_history_entry (living in governance_records.py/
# governance_history.py post-split), while the command itself
# reads via get_risk_acceptance_records (governance_ledger.py)
# and cli.commands.ledger's own bindings. All three need
# get_db_path patched to the SAME test db, or the command
# reads from the real default database instead of the test's
# isolated one — exactly the bug that caused test_json_format_valid
# to see 5 real records instead of the 1 the test created.

import json
import uuid
from unittest.mock import patch

from typer.testing import CliRunner

from cli.commands.ledger import ledger_app
from telemetry.governance_store import add_history_entry, create_governance_record

from tests.helpers.telemetry_patching import patch_telemetry

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
    DENY_WITH_OVERRIDE + subsequently OVERRIDE_APPROVED.

    actor_identity is passed EXPLICITLY rather than relying on
    resolve_actor_identity()'s auto-detection — auto-detection
    reads the real test environment's git config/OS username,
    which is non-deterministic across machines and would make
    this test flaky.
    """
    result = _make_result(policy=policy)
    with patch_telemetry(db_path=db_path, enabled=True):
        create_governance_record(result=result, db_path=db_path)
        add_history_entry(
            record_id=result["decision_id"],
            history_category="override",
            history_action="approved",
            history_data={"override_role": "budget_owner"},
            actor_role="budget_owner",
            actor_identity="jsmith@example.com",
            db_path=db_path,
        )
    return result["decision_id"]


class TestLedgerCommand:
    def test_empty_ledger_message(self, tmp_path):
        db = tmp_path / "test.db"
        with patch_telemetry(db_path=db, enabled=True):
            with patch(
                "cli.commands.ledger.get_risk_acceptance_records",
                return_value=[],
            ):
                result = runner.invoke(ledger_app, [])

        assert result.exit_code == 0
        assert "No confirmed risk acceptances found" in result.output

    def test_telemetry_disabled_message(self):
        with patch_telemetry(enabled=False):
            result = runner.invoke(ledger_app, [])

        assert result.exit_code == 1
        assert "Telemetry is disabled" in result.output

    def test_shows_confirmed_risk_acceptance(self, tmp_path):
        db = tmp_path / "test.db"
        _create_confirmed_risk_acceptance(db, policy="budget_policy")

        with patch_telemetry(db_path=db, enabled=True):
            result = runner.invoke(ledger_app, [])

        assert result.exit_code == 0
        assert "budget_policy" in result.output
        # ledger.py's Accepted By column shows the resolved
        # IDENTITY (actor_identity), not the claimed role.
        assert "jsmith@example.com" in result.output

    def test_json_format_valid(self, tmp_path):
        db = tmp_path / "test.db"
        _create_confirmed_risk_acceptance(db, policy="budget_policy")

        with patch_telemetry(db_path=db, enabled=True):
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

        with patch_telemetry(db_path=db, enabled=True):
            result = runner.invoke(
                ledger_app, ["--policy", "policy_a", "--format", "json"]
            )

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert all(r["policy_name"] == "policy_a" for r in data)

    def test_shows_explain_hint(self, tmp_path):
        db = tmp_path / "test.db"
        _create_confirmed_risk_acceptance(db)

        with patch_telemetry(db_path=db, enabled=True):
            result = runner.invoke(ledger_app, [])

        assert "verdict explain" in result.output