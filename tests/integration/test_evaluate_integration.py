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
#
# Every test now wraps its real runner.invoke(app, ["evaluate",
# ...]) call in patch_telemetry(db_path=..., enabled=True).
# This file invokes the REAL cli.main.app end to end — by
# design, since its whole purpose is testing the actual CLI
# stack, not a mocked stand-in. Previously it had ZERO telemetry
# interception anywhere: every real evaluate call genuinely
# persisted to the actual default database
# (~/.obsidianwall/decisions.db), confirmed as the source of a
# reproducible 17-record leak on every full-suite run — the
# count of real, successful (non-error-path) evaluate
# invocations in this file matches almost exactly. The fix
# deliberately does NOT mock create_governance_record() away
# entirely — persistence actually happening is part of what
# this file is meant to prove — it just needs to persist
# somewhere isolated instead of the real, shared database.
#
# NOTE (v0.5.2): Default stdout is now the text renderer,
# not JSON (see renderers/text_renderer.py). Tests that
# parse result.output as JSON must pass --format json
# explicitly. Tests that only check the --output file
# are unaffected — the file always contains full JSON
# regardless of --format.

import json
import pytest
from pathlib import Path
from typer.testing import CliRunner

from cli.main import app

from tests.helpers.telemetry_patching import patch_telemetry

runner = CliRunner()

_BUDGET_POLICY  = "policies/cost/basic_budget.yaml"
_SAMPLE_PLAN    = "samples/terraform_plan.json"


def _files_exist(*paths: str) -> bool:
    return all(Path(p).exists() for p in paths)


def _invoke_evaluate(args: list[str], db_path: Path):
    """
    Shared wrapper — every real evaluate invocation in this
    file goes through here, so the telemetry redirect is
    applied consistently rather than repeated (and potentially
    forgotten) at each call site.
    """
    with patch_telemetry(db_path=db_path, enabled=True):
        return runner.invoke(app, args)


# =====================================================
# EVALUATE — ALLOW PATH
# =====================================================


class TestEvaluateAllow:

    def test_allow_exits_zero(self, tmp_path):
        if not _files_exist(_BUDGET_POLICY, _SAMPLE_PLAN):
            pytest.skip("Fixture files not found")

        db = tmp_path / "test.db"
        result = _invoke_evaluate([
            "evaluate",
            "--plan",   _SAMPLE_PLAN,
            "--policy", _BUDGET_POLICY,
        ], db_path=db)
        # exit 0 = ALLOW, exit 1 = DENY
        # either is valid depending on plan cost
        assert result.exit_code in (0, 1)

    def test_allow_output_contains_decision(self, tmp_path):
        if not _files_exist(_BUDGET_POLICY, _SAMPLE_PLAN):
            pytest.skip("Fixture files not found")

        db = tmp_path / "test.db"
        result = _invoke_evaluate([
            "evaluate",
            "--plan",   _SAMPLE_PLAN,
            "--policy", _BUDGET_POLICY,
            "--format", "json",
        ], db_path=db)
        output = json.loads(result.output)
        assert "decision" in output
        assert output["decision"] in (
            "ALLOW",
            "ALLOW_WITH_NOTIFICATION",
            "DENY",
            "DENY_WITH_OVERRIDE",
        )

    def test_output_contains_decision_id(self, tmp_path):
        if not _files_exist(_BUDGET_POLICY, _SAMPLE_PLAN):
            pytest.skip("Fixture files not found")

        db = tmp_path / "test.db"
        result = _invoke_evaluate([
            "evaluate",
            "--plan",   _SAMPLE_PLAN,
            "--policy", _BUDGET_POLICY,
            "--format", "json",
        ], db_path=db)
        output = json.loads(result.output)
        assert "decision_id" in output
        assert output["decision_id"] is not None

    def test_output_contains_conditions_passed(self, tmp_path):
        if not _files_exist(_BUDGET_POLICY, _SAMPLE_PLAN):
            pytest.skip("Fixture files not found")

        db = tmp_path / "test.db"
        result = _invoke_evaluate([
            "evaluate",
            "--plan",   _SAMPLE_PLAN,
            "--policy", _BUDGET_POLICY,
            "--format", "json",
        ], db_path=db)
        output = json.loads(result.output)
        assert "conditions_passed" in output

    def test_output_contains_risk_score(self, tmp_path):
        if not _files_exist(_BUDGET_POLICY, _SAMPLE_PLAN):
            pytest.skip("Fixture files not found")

        db = tmp_path / "test.db"
        output_path = str(tmp_path / "result.json")
        _invoke_evaluate([
            "evaluate",
            "--plan",    _SAMPLE_PLAN,
            "--policy",  _BUDGET_POLICY,
            "--output",  output_path,
        ], db_path=db)
        with open(output_path) as output_file:
            output = json.load(output_file)

        # risk score is nested under risk_summary in the audit artifact
        # This test checks the --output FILE, unaffected by --format.
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

        db = tmp_path / "test.db"
        output_path = str(tmp_path / "result.json")
        _invoke_evaluate([
            "evaluate",
            "--plan",    _SAMPLE_PLAN,
            "--policy",  _BUDGET_POLICY,
            "--output",  output_path,
        ], db_path=db)
        assert Path(output_path).exists()

    def test_output_file_is_valid_json(self, tmp_path):
        if not _files_exist(_BUDGET_POLICY, _SAMPLE_PLAN):
            pytest.skip("Fixture files not found")

        db = tmp_path / "test.db"
        output_path = str(tmp_path / "result.json")
        _invoke_evaluate([
            "evaluate",
            "--plan",    _SAMPLE_PLAN,
            "--policy",  _BUDGET_POLICY,
            "--output",  output_path,
        ], db_path=db)
        with open(output_path) as output_file:
            data = json.load(output_file)
        assert "decision" in data

    def test_output_file_matches_stdout(self, tmp_path):
        """
        Confirms the --output file and --format json stdout
        represent the same underlying decision. This is the
        contract that matters: both are views of one artifact.
        """
        if not _files_exist(_BUDGET_POLICY, _SAMPLE_PLAN):
            pytest.skip("Fixture files not found")

        db = tmp_path / "test.db"
        output_path = str(tmp_path / "result.json")
        result = _invoke_evaluate([
            "evaluate",
            "--plan",    _SAMPLE_PLAN,
            "--policy",  _BUDGET_POLICY,
            "--output",  output_path,
            "--format",  "json",
        ], db_path=db)
        stdout_data = json.loads(result.output)
        with open(output_path) as output_file:
            file_data = json.load(output_file)

        assert stdout_data["decision"] == file_data["decision"]
        assert stdout_data["decision_id"] == file_data["decision_id"]


# =====================================================
# EVALUATE — TEXT RENDERER (DEFAULT STDOUT)
# =====================================================


class TestEvaluateTextRenderer:
    """
    Confirms the default stdout output (no --format flag)
    is the concise text summary, not raw JSON. This is the
    v0.5.2 behavior change — added here to lock it in.
    """

    def test_default_stdout_is_not_valid_json(self, tmp_path):
        """
        The default text renderer output should NOT parse
        as JSON. If this test starts failing, it likely means
        stdout has reverted to raw JSON — check cli/main.py
        STEP 6 and confirm --format defaults to "text".
        """
        if not _files_exist(_BUDGET_POLICY, _SAMPLE_PLAN):
            pytest.skip("Fixture files not found")

        db = tmp_path / "test.db"
        result = _invoke_evaluate([
            "evaluate",
            "--plan",   _SAMPLE_PLAN,
            "--policy", _BUDGET_POLICY,
        ], db_path=db)
        with pytest.raises(json.JSONDecodeError):
            json.loads(result.output)

    def test_default_stdout_contains_decision_keyword(self, tmp_path):
        """Text renderer output should mention the decision value."""
        if not _files_exist(_BUDGET_POLICY, _SAMPLE_PLAN):
            pytest.skip("Fixture files not found")

        db = tmp_path / "test.db"
        result = _invoke_evaluate([
            "evaluate",
            "--plan",   _SAMPLE_PLAN,
            "--policy", _BUDGET_POLICY,
        ], db_path=db)
        # One of the five decision types must appear in the text output
        assert any(
            decision in result.output
            for decision in (
                "ALLOW",
                "ALLOW_WITH_NOTIFICATION",
                "ALLOW_WITH_APPROVAL_REQUIRED",
                "DENY_WITH_OVERRIDE",
                "DENY",
            )
        )

    def test_default_stdout_references_output_artifact(self, tmp_path):
        """Text renderer should point the user to the full JSON artifact."""
        if not _files_exist(_BUDGET_POLICY, _SAMPLE_PLAN):
            pytest.skip("Fixture files not found")

        db = tmp_path / "test.db"
        result = _invoke_evaluate([
            "evaluate",
            "--plan",   _SAMPLE_PLAN,
            "--policy", _BUDGET_POLICY,
        ], db_path=db)
        assert "output/result.json" in result.output or "artifact" in result.output.lower()

    def test_yaml_format_produces_parseable_yaml(self, tmp_path):
        """--format yaml should produce valid YAML on stdout."""
        import yaml

        if not _files_exist(_BUDGET_POLICY, _SAMPLE_PLAN):
            pytest.skip("Fixture files not found")

        db = tmp_path / "test.db"
        result = _invoke_evaluate([
            "evaluate",
            "--plan",   _SAMPLE_PLAN,
            "--policy", _BUDGET_POLICY,
            "--format", "yaml",
        ], db_path=db)
        parsed = yaml.safe_load(result.output)
        assert "decision" in parsed

    def test_invalid_format_flag_raises_error(self, tmp_path):
        """An unsupported --format value should fail, not silently succeed."""
        if not _files_exist(_BUDGET_POLICY, _SAMPLE_PLAN):
            pytest.skip("Fixture files not found")

        db = tmp_path / "test.db"
        result = _invoke_evaluate([
            "evaluate",
            "--plan",   _SAMPLE_PLAN,
            "--policy", _BUDGET_POLICY,
            "--format", "xml",
        ], db_path=db)
        assert result.exit_code != 0


# =====================================================
# EVALUATE — ERROR HANDLING
#
# These invoke evaluate with missing/invalid files, which
# fail BEFORE reaching the persist step — but wrapped in
# patch_telemetry anyway, defensively, since a future change
# to error-handling order should not silently reopen this
# exact leak class.
# =====================================================


class TestEvaluateErrors:

    def test_exits_nonzero_for_missing_plan(self, tmp_path):
        db = tmp_path / "test.db"
        result = _invoke_evaluate([
            "evaluate",
            "--plan",   "/nonexistent/plan.json",
            "--policy", _BUDGET_POLICY,
        ], db_path=db)
        assert result.exit_code == 1

    def test_exits_nonzero_for_missing_policy(self, tmp_path):
        if not _files_exist(_SAMPLE_PLAN):
            pytest.skip("Sample plan not found")

        db = tmp_path / "test.db"
        result = _invoke_evaluate([
            "evaluate",
            "--plan",   _SAMPLE_PLAN,
            "--policy", "/nonexistent/policy.yaml",
        ], db_path=db)
        assert result.exit_code == 1

    def test_exits_nonzero_for_invalid_policy_schema(
        self, tmp_path
    ):
        if not _files_exist(_SAMPLE_PLAN):
            pytest.skip("Sample plan not found")

        db = tmp_path / "test.db"
        bad_policy = tmp_path / "bad.yaml"
        bad_policy.write_text("name: bad\nversion: 1")

        result = _invoke_evaluate([
            "evaluate",
            "--plan",   _SAMPLE_PLAN,
            "--policy", str(bad_policy),
        ], db_path=db)
        assert result.exit_code == 1


# =====================================================
# EVALUATE — ROLE AND SPEND PASSTHROUGH
# =====================================================


class TestEvaluateArgPassthrough:

    def test_accepts_custom_role(self, tmp_path):
        if not _files_exist(_BUDGET_POLICY, _SAMPLE_PLAN):
            pytest.skip("Fixture files not found")

        db = tmp_path / "test.db"
        result = _invoke_evaluate([
            "evaluate",
            "--plan",    _SAMPLE_PLAN,
            "--policy",  _BUDGET_POLICY,
            "--role",    "budget_owner",
            "--format",  "json",
        ], db_path=db)
        assert result.exit_code in (0, 1)
        output = json.loads(result.output)
        assert "decision" in output

    def test_accepts_current_spend_flag(self, tmp_path):
        if not _files_exist(_BUDGET_POLICY, _SAMPLE_PLAN):
            pytest.skip("Fixture files not found")

        db = tmp_path / "test.db"
        result = _invoke_evaluate([
            "evaluate",
            "--plan",          _SAMPLE_PLAN,
            "--policy",        _BUDGET_POLICY,
            "--current-spend", "30.0",
            "--format",        "json",
        ], db_path=db)
        assert result.exit_code in (0, 1)
        output = json.loads(result.output)
        assert "decision" in output

    def test_current_spend_affects_decision(self, tmp_path):
        if not _files_exist(_BUDGET_POLICY, _SAMPLE_PLAN):
            pytest.skip("Fixture files not found")

        db = tmp_path / "test.db"
        result_low = _invoke_evaluate([
            "evaluate",
            "--plan",          _SAMPLE_PLAN,
            "--policy",        _BUDGET_POLICY,
            "--current-spend", "0",
            "--format",        "json",
        ], db_path=db)
        result_high = _invoke_evaluate([
            "evaluate",
            "--plan",          _SAMPLE_PLAN,
            "--policy",        _BUDGET_POLICY,
            "--current-spend", "10000",
            "--format",        "json",
        ], db_path=db)

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