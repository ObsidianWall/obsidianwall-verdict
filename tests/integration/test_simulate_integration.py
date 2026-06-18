
# tests/integration/test_simulate_integration.py
#
# Integration tests for verdict simulate.
#
# Tests the full pipeline: CLI invocation → policy loading
# → synthetic context building → evaluation → output.
# No mocking. Uses real policy files from the repo.

import json
import pytest
from pathlib import Path
from typer.testing import CliRunner

from cli.main import app

runner = CliRunner()

# Path to a known policy file in the repo
_AI_POLICY_PATH = "policies/ai_governance/basic_ai_governance.yaml"
_BUDGET_POLICY_PATH = "policies/cost/basic_budget.yaml"


def _policy_exists(path: str) -> bool:
    return Path(path).exists()


class TestSimulateIntegration:

    def test_simulate_exits_zero_with_valid_policy_no_violations(self):
        if not _policy_exists(_AI_POLICY_PATH):
            pytest.skip(f"Policy fixture not found: {_AI_POLICY_PATH}")

        result = runner.invoke(app, [
            "simulate",
            "--policy", _AI_POLICY_PATH,
            "--set", "ai_gpu_workloads=0",
        ])
        assert result.exit_code == 0

    def test_simulate_exits_nonzero_on_violation(self):
        if not _policy_exists(_AI_POLICY_PATH):
            pytest.skip(f"Policy fixture not found: {_AI_POLICY_PATH}")

        result = runner.invoke(app, [
            "simulate",
            "--policy", _AI_POLICY_PATH,
            "--set", "ai_gpu_workloads=2",
        ])
        assert result.exit_code == 1

    def test_simulate_shows_decision_in_output(self):
        if not _policy_exists(_AI_POLICY_PATH):
            pytest.skip(f"Policy fixture not found: {_AI_POLICY_PATH}")

        result = runner.invoke(app, [
            "simulate",
            "--policy", _AI_POLICY_PATH,
        ])
        assert any(
            decision in result.output
            for decision in ["ALLOW", "DENY", "DENY_WITH_OVERRIDE"]
        )

    def test_simulate_shows_context_values_in_output(self):
        if not _policy_exists(_AI_POLICY_PATH):
            pytest.skip(f"Policy fixture not found: {_AI_POLICY_PATH}")

        result = runner.invoke(app, [
            "simulate",
            "--policy", _AI_POLICY_PATH,
            "--set", "ai_gpu_workloads=3",
        ])
        assert "ai_gpu_workloads" in result.output

    def test_simulate_exits_nonzero_for_missing_policy(self):
        result = runner.invoke(app, [
            "simulate",
            "--policy", "/nonexistent/policy.yaml",
        ])
        assert result.exit_code == 1

    def test_simulate_exits_nonzero_for_invalid_set_format(self):
        if not _policy_exists(_AI_POLICY_PATH):
            pytest.skip(f"Policy fixture not found: {_AI_POLICY_PATH}")

        result = runner.invoke(app, [
            "simulate",
            "--policy", _AI_POLICY_PATH,
            "--set", "no_equals_sign",
        ])
        assert result.exit_code == 1

    def test_simulate_accepts_multiple_set_flags(self):
        if not _policy_exists(_AI_POLICY_PATH):
            pytest.skip(f"Policy fixture not found: {_AI_POLICY_PATH}")

        result = runner.invoke(app, [
            "simulate",
            "--policy", _AI_POLICY_PATH,
            "--set", "ai_gpu_workloads=0",
            "--set", "open_ingress_rules=0",
            "--set", "estimated_cost=50",
        ])
        assert result.exit_code == 0

    def test_simulate_writes_output_file_when_requested(self, tmp_path):
        if not _policy_exists(_AI_POLICY_PATH):
            pytest.skip(f"Policy fixture not found: {_AI_POLICY_PATH}")

        output_file = str(tmp_path / "simulate_result.json")
        result = runner.invoke(app, [
            "simulate",
            "--policy", _AI_POLICY_PATH,
            "--output", output_file,
        ])
        assert result.exit_code == 0
        assert Path(output_file).exists()
        with open(output_file) as result_file:
            data = json.load(result_file)
        assert "decision" in data

    def test_simulate_budget_policy_allow_at_low_cost(self):
        if not _policy_exists(_BUDGET_POLICY_PATH):
            pytest.skip(f"Policy fixture not found: {_BUDGET_POLICY_PATH}")

        result = runner.invoke(app, [
            "simulate",
            "--policy", _BUDGET_POLICY_PATH,
            "--set", "estimated_cost=10",
        ])
        assert result.exit_code == 0

    def test_simulate_budget_policy_deny_at_high_cost(self):
        if not _policy_exists(_BUDGET_POLICY_PATH):
            pytest.skip(f"Policy fixture not found: {_BUDGET_POLICY_PATH}")

        result = runner.invoke(app, [
            "simulate",
            "--policy", _BUDGET_POLICY_PATH,
            "--set", "estimated_cost=99999",
        ])
        assert result.exit_code == 1