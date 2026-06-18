
# tests/integration/test_coverage_integration.py
#
# Integration tests for verdict coverage.
#
# Tests the full pipeline: CLI invocation → policy loading
# → framework lookup → coverage analysis → output.
# No mocking. Uses real policy files from the repo.

import pytest
from pathlib import Path
from typer.testing import CliRunner

from cli.main import app

runner = CliRunner()

_AI_POLICY_PATH = "policies/ai_governance/basic_ai_governance.yaml"
_BUDGET_POLICY_PATH = "policies/cost/basic_budget.yaml"


def _policy_exists(path: str) -> bool:
    return Path(path).exists()


class TestCoverageIntegration:

    def test_coverage_exits_zero_for_valid_policy_and_framework(self):
        if not _policy_exists(_AI_POLICY_PATH):
            pytest.skip(f"Policy fixture not found: {_AI_POLICY_PATH}")

        result = runner.invoke(app, [
            "coverage",
            "--policy", _AI_POLICY_PATH,
            "--framework", "nist_ai_rmf",
        ])
        assert result.exit_code == 0

    def test_coverage_output_shows_policy_name(self):
        if not _policy_exists(_AI_POLICY_PATH):
            pytest.skip(f"Policy fixture not found: {_AI_POLICY_PATH}")

        result = runner.invoke(app, [
            "coverage",
            "--policy", _AI_POLICY_PATH,
            "--framework", "nist_ai_rmf",
        ])
        assert "basic_ai_governance_verdict" in result.output

    def test_coverage_output_shows_framework_name(self):
        if not _policy_exists(_AI_POLICY_PATH):
            pytest.skip(f"Policy fixture not found: {_AI_POLICY_PATH}")

        result = runner.invoke(app, [
            "coverage",
            "--policy", _AI_POLICY_PATH,
            "--framework", "nist_ai_rmf",
        ])
        assert "NIST AI Risk Management Framework" in result.output

    def test_coverage_output_shows_coverage_percentage(self):
        if not _policy_exists(_AI_POLICY_PATH):
            pytest.skip(f"Policy fixture not found: {_AI_POLICY_PATH}")

        result = runner.invoke(app, [
            "coverage",
            "--policy", _AI_POLICY_PATH,
            "--framework", "nist_ai_rmf",
        ])
        assert "Coverage:" in result.output
        assert "%" in result.output

    def test_coverage_output_shows_missing_controls(self):
        if not _policy_exists(_AI_POLICY_PATH):
            pytest.skip(f"Policy fixture not found: {_AI_POLICY_PATH}")

        result = runner.invoke(app, [
            "coverage",
            "--policy", _AI_POLICY_PATH,
            "--framework", "nist_ai_rmf",
        ])
        assert "Missing Controls" in result.output

    def test_coverage_exits_nonzero_for_unknown_framework(self):
        if not _policy_exists(_AI_POLICY_PATH):
            pytest.skip(f"Policy fixture not found: {_AI_POLICY_PATH}")

        result = runner.invoke(app, [
            "coverage",
            "--policy", _AI_POLICY_PATH,
            "--framework", "iso27001",
        ])
        assert result.exit_code == 1

    def test_coverage_exits_nonzero_for_missing_policy(self):
        result = runner.invoke(app, [
            "coverage",
            "--policy", "/nonexistent/policy.yaml",
            "--framework", "hipaa",
        ])
        assert result.exit_code == 1

    def test_coverage_works_with_all_four_frameworks(self):
        if not _policy_exists(_AI_POLICY_PATH):
            pytest.skip(f"Policy fixture not found: {_AI_POLICY_PATH}")

        for framework in ["hipaa", "soc2", "cis", "nist_ai_rmf"]:
            result = runner.invoke(app, [
                "coverage",
                "--policy", _AI_POLICY_PATH,
                "--framework", framework,
            ])
            assert result.exit_code == 0, (
                f"coverage failed for framework: {framework}\n"
                f"Output: {result.output}"
            )

    def test_coverage_budget_policy_against_hipaa(self):
        if not _policy_exists(_BUDGET_POLICY_PATH):
            pytest.skip(f"Policy fixture not found: {_BUDGET_POLICY_PATH}")

        result = runner.invoke(app, [
            "coverage",
            "--policy", _BUDGET_POLICY_PATH,
            "--framework", "hipaa",
        ])
        assert result.exit_code == 0
        assert "Coverage:" in result.output