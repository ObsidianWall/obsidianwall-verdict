# tests/integration/test_cli_wiring.py
#
# Verifies that all CLI commands are correctly registered
# in cli/main.py and respond to --help without error.
#
# These tests catch wiring failures that unit tests miss:
# - Missing import in main.py
# - Command not registered with app.command()
# - Import errors in command modules

import pytest
from typer.testing import CliRunner


from cli.main import app


runner = CliRunner()

class TestCliWiring:

    def test_app_responds_to_help(self):
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0

    def test_app_shows_version(self):
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "Verdict" in result.output or "verdict" in result.output.lower()

    def test_evaluate_command_registered(self):
        result = runner.invoke(app, ["evaluate", "--help"], color=False)
        assert result.exit_code == 0
        assert "--plan" in result.output
        assert "--policy" in result.output

    def test_validate_command_registered(self):
        result = runner.invoke(app, ["validate", "--help"], color=False)
        assert result.exit_code == 0
        assert "--policy" in result.output

    def test_audit_command_registered(self):
        result = runner.invoke(app, ["audit", "--help"])
        assert result.exit_code == 0

    def test_sentinel_command_registered(self):
        result = runner.invoke(app, ["sentinel", "--help"])
        assert result.exit_code == 0

    def test_coverage_command_registered(self):
        result = runner.invoke(app, ["coverage", "--help"], env={"COLUMNS": "200"}, color=False)
        assert result.exit_code == 0
        assert "--policy" in result.output
        assert "--framework" in result.output

    def test_simulate_command_registered(self):
        result = runner.invoke(app, ["simulate", "--help"], env={"COLUMNS": "200"}, color=False)
        assert result.exit_code == 0
        assert "--policy" in result.output
        assert "--set" in result.output

    def test_test_command_registered(self):
        result = runner.invoke(app, ["test", "--help"])
        assert result.exit_code == 0

    def test_evaluate_requires_plan_flag(self):
        result = runner.invoke(app, ["evaluate", "--policy", "some.yaml"])
        assert result.exit_code != 0

    def test_evaluate_requires_policy_flag(self):
        result = runner.invoke(app, ["evaluate", "--plan", "some.json"])
        assert result.exit_code != 0

    def test_coverage_requires_policy_flag(self):
        result = runner.invoke(app, ["coverage", "--framework", "hipaa"])
        assert result.exit_code != 0

    def test_coverage_requires_framework_flag(self):
        result = runner.invoke(app, ["coverage", "--policy", "some.yaml"])
        assert result.exit_code != 0

    def test_simulate_requires_policy_flag(self):
        result = runner.invoke(app, ["simulate"])
        assert result.exit_code != 0
