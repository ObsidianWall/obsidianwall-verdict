
# tests/integration/test_validate_integration.py
#
# Integration tests for verdict validate.
#
# Tests the full pipeline: CLI invocation → policy loading
# → schema validation → output.

import json
import pytest
from pathlib import Path
from typer.testing import CliRunner

from cli.main import app

runner = CliRunner()

_AI_POLICY_PATH = "policies/ai_governance/basic_ai_governance.yaml"


def _policy_exists(path: str) -> bool:
    return Path(path).exists()


class TestValidateIntegration:

    def test_validate_exits_zero_for_valid_policy(self):
        if not _policy_exists(_AI_POLICY_PATH):
            pytest.skip(f"Policy fixture not found: {_AI_POLICY_PATH}")

        result = runner.invoke(app, [
            "validate",
            "--policy", _AI_POLICY_PATH,
        ])
        assert result.exit_code == 0

    def test_validate_output_shows_valid_status(self):
        if not _policy_exists(_AI_POLICY_PATH):
            pytest.skip(f"Policy fixture not found: {_AI_POLICY_PATH}")

        result = runner.invoke(app, [
            "validate",
            "--policy", _AI_POLICY_PATH,
        ])
        output = json.loads(result.output)
        assert output["status"] == "valid"

    def test_validate_output_includes_policy_name(self):
        if not _policy_exists(_AI_POLICY_PATH):
            pytest.skip(f"Policy fixture not found: {_AI_POLICY_PATH}")

        result = runner.invoke(app, [
            "validate",
            "--policy", _AI_POLICY_PATH,
        ])
        output = json.loads(result.output)
        assert "name" in output
        assert output["name"] == "basic_ai_governance_verdict"

    def test_validate_exits_nonzero_for_missing_policy(self):
        result = runner.invoke(app, [
            "validate",
            "--policy", "/nonexistent/policy.yaml",
        ])
        assert result.exit_code == 1

    def test_validate_exits_nonzero_for_invalid_yaml(self, tmp_path):
        bad_policy = tmp_path / "bad.yaml"
        bad_policy.write_text("{ invalid yaml: [[[")
        result = runner.invoke(app, [
            "validate",
            "--policy", str(bad_policy),
        ])
        assert result.exit_code == 1

    def test_validate_exits_nonzero_for_invalid_schema(self, tmp_path):
        bad_policy = tmp_path / "bad_schema.yaml"
        bad_policy.write_text("name: bad\nversion: 1")
        result = runner.invoke(app, [
            "validate",
            "--policy", str(bad_policy),
        ])
        assert result.exit_code == 1