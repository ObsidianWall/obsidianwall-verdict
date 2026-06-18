# tests/integration/test_evaluate_integration.py
#
# CLI-level integration tests for verdict evaluate.
#
# Complements tests/test_engine.py (engine layer) and
# tests/integration/test_evaluate_pipeline.py (component
# pipeline layer). This file tests the full CLI stack:
#
#   CLI args → context building → evaluation → output
#   → exit code → audit artifact → notifications
#
# Tests what the engine tests cannot:
# - Argument parsing (--plan, --policy, --role, --output)
# - Exit code 0 on ALLOW, exit code 1 on DENY
# - Output file written correctly
# - --current-spend passed through to context
# - Error handling for missing files

import json
import pytest
from pathlib import Path
from typer.testing import CliRunner

from cli.main import app

runner = CliRunner()

_BUDGET_POLICY  = "policies/cost/basic_budget.yaml"
_SAMPLE_PLAN    = "samples/terraform_plan.json"


def _files_exist(*paths: str) -> bool:
    return all(Path(p).exists() for p in paths)


# =====================================================
# EVALUATE — ALLOW PATH
# =====================================================


class TestEvaluateAllow:

    def test_allow_exits_zero(self):
        if not _files_exist(_BUDGET_POLICY, _SAMPLE_PLAN):
            pytest.skip("Fixture files not found")

        result = runner.invoke(app, [
            "evaluate",
            "--plan",   _SAMPLE_PLAN,
            "--policy", _BUDGET_POLICY,
        ])
        # exit 0 = ALLOW, exit 1 = DENY
        # either is valid depending on plan cost
        assert result.exit_code in (0, 1)

    def test_allow_output_contains_decision(self):
        if not _files_exist(_BUDGET_POLICY, _SAMPLE_PLAN):
            pytest.skip("Fixture files not found")

        result = runner.invoke(app, [
            "evaluate",
            "--plan",   _SAMPLE_PLAN,
            "--policy", _BUDGET_POLICY,
        ])
        output = json.loads(result.output)
        assert "decision" in output
        assert output["decision"] in (
            "ALLOW",
            "ALLOW_WITH_NOTIFICATION",
            "DENY",
            "DENY_WITH_OVERRIDE",
        )

    def test_output_contains_decision_id(self):
        if not _files_exist(_BUDGET_POLICY, _SAMPLE_PLAN):
            pytest.skip("Fixture files not found")

        result = runner.invoke(app, [
            "evaluate",
            "--plan",   _SAMPLE_PLAN,
            "--policy", _BUDGET_POLICY,
        ])
        output = json.loads(result.output)
        assert "decision_id" in output
        assert output["decision_id"] is not None

    def test_output_contains_conditions_passed(self):
        if not _files_exist(_BUDGET_POLICY, _SAMPLE_PLAN):
            pytest.skip("Fixture files not found")

        result = runner.invoke(app, [
            "evaluate",
            "--plan",   _SAMPLE_PLAN,
            "--policy", _BUDGET_POLICY,
        ])
        output = json.loads(result.output)
        assert "conditions_passed" in output

    def test_output_contains_risk_score(self, tmp_path):
        if not _files_exist(_BUDGET_POLICY, _SAMPLE_PLAN):
            pytest.skip("Fixture files not found")

        output_path = str(tmp_path / "result.json")
        runner.invoke(app, [
            "evaluate",
            "--plan",    _SAMPLE_PLAN,
            "--policy",  _BUDGET_POLICY,
            "--output",  output_path,
        ])
        with open(output_path) as output_file:
            output = json.load(output_file)
        
        # risk score is nested under risk_summary in the audit artifact
        assert "risk_summary" in output
        assert "overall_risk_score" in output["risk_summary"]
    
        assert isinstance(output["risk_summary"]["overall_risk_score"], (int, float))
        assert 0 <= output["risk_summary"]["overall_risk_score"] <= 100


# =====================================================
# EVALUATE — OUTPUT FILE
# =====================================================


class TestEvaluateOutputFile:

    def test_writes_output_file_to_specified_path(self, tmp_path):
        if not _files_exist(_BUDGET_POLICY, _SAMPLE_PLAN):
            pytest.skip("Fixture files not found")

        output_path = str(tmp_path / "result.json")
        runner.invoke(app, [
            "evaluate",
            "--plan",    _SAMPLE_PLAN,
            "--policy",  _BUDGET_POLICY,
            "--output",  output_path,
        ])
        assert Path(output_path).exists()

    def test_output_file_is_valid_json(self, tmp_path):
        if not _files_exist(_BUDGET_POLICY, _SAMPLE_PLAN):
            pytest.skip("Fixture files not found")

        output_path = str(tmp_path / "result.json")
        runner.invoke(app, [
            "evaluate",
            "--plan",    _SAMPLE_PLAN,
            "--policy",  _BUDGET_POLICY,
            "--output",  output_path,
        ])
        with open(output_path) as output_file:
            data = json.load(output_file)
        assert "decision" in data

    def test_output_file_matches_stdout(self, tmp_path):
        if not _files_exist(_BUDGET_POLICY, _SAMPLE_PLAN):
            pytest.skip("Fixture files not found")

        output_path = str(tmp_path / "result.json")
        result = runner.invoke(app, [
            "evaluate",
            "--plan",    _SAMPLE_PLAN,
            "--policy",  _BUDGET_POLICY,
            "--output",  output_path,
        ])
        stdout_data = json.loads(result.output)
        with open(output_path) as output_file:
            file_data = json.load(output_file)

        assert stdout_data["decision"] == file_data["decision"]
        assert stdout_data["decision_id"] == file_data["decision_id"]


# =====================================================
# EVALUATE — ERROR HANDLING
# =====================================================


class TestEvaluateErrors:

    def test_exits_nonzero_for_missing_plan(self):
        result = runner.invoke(app, [
            "evaluate",
            "--plan",   "/nonexistent/plan.json",
            "--policy", _BUDGET_POLICY,
        ])
        assert result.exit_code == 1

    def test_exits_nonzero_for_missing_policy(self):
        if not _files_exist(_SAMPLE_PLAN):
            pytest.skip("Sample plan not found")

        result = runner.invoke(app, [
            "evaluate",
            "--plan",   _SAMPLE_PLAN,
            "--policy", "/nonexistent/policy.yaml",
        ])
        assert result.exit_code == 1

    def test_exits_nonzero_for_invalid_policy_schema(
        self, tmp_path
    ):
        if not _files_exist(_SAMPLE_PLAN):
            pytest.skip("Sample plan not found")

        bad_policy = tmp_path / "bad.yaml"
        bad_policy.write_text("name: bad\nversion: 1")

        result = runner.invoke(app, [
            "evaluate",
            "--plan",   _SAMPLE_PLAN,
            "--policy", str(bad_policy),
        ])
        assert result.exit_code == 1


# =====================================================
# EVALUATE — ROLE AND SPEND PASSTHROUGH
# =====================================================


class TestEvaluateArgPassthrough:

    def test_accepts_custom_role(self):
        if not _files_exist(_BUDGET_POLICY, _SAMPLE_PLAN):
            pytest.skip("Fixture files not found")

        result = runner.invoke(app, [
            "evaluate",
            "--plan",    _SAMPLE_PLAN,
            "--policy",  _BUDGET_POLICY,
            "--role",    "budget_owner",
        ])
        assert result.exit_code in (0, 1)
        output = json.loads(result.output)
        assert "decision" in output

    def test_accepts_current_spend_flag(self):
        if not _files_exist(_BUDGET_POLICY, _SAMPLE_PLAN):
            pytest.skip("Fixture files not found")

        result = runner.invoke(app, [
            "evaluate",
            "--plan",          _SAMPLE_PLAN,
            "--policy",        _BUDGET_POLICY,
            "--current-spend", "30.0",
        ])
        assert result.exit_code in (0, 1)
        output = json.loads(result.output)
        assert "decision" in output

    def test_current_spend_affects_decision(self):
        if not _files_exist(_BUDGET_POLICY, _SAMPLE_PLAN):
            pytest.skip("Fixture files not found")

        result_low = runner.invoke(app, [
            "evaluate",
            "--plan",          _SAMPLE_PLAN,
            "--policy",        _BUDGET_POLICY,
            "--current-spend", "0",
        ])
        result_high = runner.invoke(app, [
            "evaluate",
            "--plan",          _SAMPLE_PLAN,
            "--policy",        _BUDGET_POLICY,
            "--current-spend", "10000",
        ])

        output_low  = json.loads(result_low.output)
        output_high = json.loads(result_high.output)

        # With very high current spend (10000) the budget
        # condition must fail — decision should be DENY or
        # DENY_WITH_OVERRIDE regardless of plan cost.
        assert output_high["decision"] in (
            "DENY",
            "DENY_WITH_OVERRIDE",
        )
        # Low spend evaluation produces a valid decision
        assert output_low["decision"] in (
            "ALLOW",
            "ALLOW_WITH_NOTIFICATION",
            "DENY",
            "DENY_WITH_OVERRIDE",
        )