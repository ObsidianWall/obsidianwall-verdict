# tests/integration/test_cli_wiring.py
#
# Verifies that all CLI commands are correctly registered
# in cli/main.py and respond to --help without error.
#
# These tests catch wiring failures that unit tests miss:
# - Missing import in main.py
# - Command not registered with app.command()
# - Import errors in command modules

import re
import pytest
from typer.testing import CliRunner

from cli.main import app


runner = CliRunner()


def _strip_ansi(text: str) -> str:
    """
    Strip ANSI escape codes from CLI output.

    Rich emits ANSI colour codes in CI environments even when
    color=False is passed to runner.invoke(), because Rich has
    its own terminal detection layer. Flag names like --plan are
    split into \x1b[..]-\x1b[0m\x1b[..-plan\x1b[0m, making a
    plain string search for '--plan' fail.

    Stripping ANSI before asserting is the portable fix.
    """
    return re.compile(r"\x1b\[[0-9;]*m").sub("", text)


class TestCliWiring:

    def test_app_responds_to_help(self):
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0

    def test_app_shows_version(self):
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "Verdict" in result.output or "verdict" in result.output.lower()

    def test_evaluate_command_registered(self):
        result = runner.invoke(app, ["evaluate", "--help"])
        assert result.exit_code == 0
        clean = _strip_ansi(result.output)
        assert "--plan" in clean
        assert "--policy" in clean

    def test_validate_command_registered(self):
        result = runner.invoke(app, ["validate", "--help"])
        assert result.exit_code == 0
        clean = _strip_ansi(result.output)
        assert "--policy" in clean

    def test_audit_command_registered(self):
        result = runner.invoke(app, ["audit", "--help"])
        assert result.exit_code == 0

    def test_sentinel_command_registered(self):
        result = runner.invoke(app, ["sentinel", "--help"])
        assert result.exit_code == 0

    def test_coverage_command_registered(self):
        result = runner.invoke(app, ["coverage", "--help"], env={"COLUMNS": "200"})
        assert result.exit_code == 0
        clean = _strip_ansi(result.output)
        assert "--policy" in clean
        assert "--framework" in clean

    def test_simulate_command_registered(self):
        result = runner.invoke(app, ["simulate", "--help"], env={"COLUMNS": "200"})
        assert result.exit_code == 0
        clean = _strip_ansi(result.output)
        assert "--policy" in clean
        assert "--set" in clean

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
