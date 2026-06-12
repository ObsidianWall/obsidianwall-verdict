
# tests/unit/test_engine_coverage_final.py
#
# Purpose:
# Targeted tests for the final engine module uncovered lines.
# Together with existing tests, pushes total coverage to 90%+.
#
# Covers:
#   engine/lint_validator.py     12, 15, 18, 21, 26, 29
#     — error append branches for each missing required key
#
#   engine/validator.py          41
#     — logger.error in except block — triggered when
#       normalize_policy raises for an empty dict input
#
#   engine/policy_normalizer.py  160
#     — raise ValueError when policy parameters conflict
#       with runtime context keys

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from engine.lint_validator import lint_policy
from engine.policy_normalizer import build_policy_runtime_context
from engine.validator import validate_policy


# =====================================================
# engine/lint_validator.py — lines 12, 15, 18, 26
#
# lint_policy returns a list of error dicts.
# Each errors.append(...) is a separate uncovered line.
# Passing an empty dict triggers all top-level missing
# key checks simultaneously.
# =====================================================


class TestLintPolicyMissingTopLevelKeys:
    """Covers lines 12, 15, 18, 26."""

    def test_empty_dict_produces_all_top_level_errors(self) -> None:
        """
        Empty dict is missing apiVersion, kind, metadata, and spec.
        Each missing key triggers its errors.append() branch.
        """
        errors = lint_policy({})

        error_fields = [error["field"] for error in errors]

        assert "apiVersion"   in error_fields    # line 12
        assert "kind"         in error_fields    # line 15
        assert "metadata"     in error_fields    # line 18
        assert "spec"         in error_fields    # line 26

    def test_returns_list_of_error_dicts(self) -> None:
        """Each error entry is a dict with field and message keys."""
        errors = lint_policy({})

        for error in errors:
            assert "field"   in error
            assert "message" in error

    def test_no_errors_for_valid_structure(self) -> None:
        """Valid structure produces no lint errors."""
        errors = lint_policy({
            "apiVersion": "obsidianwall.io/v1",
            "kind":       "Policy",
            "metadata":   {"name": "test_policy"},
            "spec":       {"conditions": []},
        })

        assert errors == []


# =====================================================
# engine/lint_validator.py — lines 21, 29
#
# The else branches for metadata and spec are reached
# when the key IS present but the nested required key
# is missing. metadata.name and spec.conditions.
# =====================================================


class TestLintPolicyMissingNestedKeys:
    """Covers lines 21, 29."""

    def test_metadata_present_but_name_missing(self) -> None:
        """
        metadata key present but name not declared.
        Hits the else branch and triggers line 21.
        """
        errors = lint_policy({
            "apiVersion": "obsidianwall.io/v1",
            "kind":       "Policy",
            "metadata":   {},           # ← name missing
            "spec":       {"conditions": []},
        })

        error_fields = [error["field"] for error in errors]
        assert "metadata.name" in error_fields    # line 21

    def test_spec_present_but_conditions_missing(self) -> None:
        """
        spec key present but conditions not declared.
        Hits the else branch and triggers line 29.
        """
        errors = lint_policy({
            "apiVersion": "obsidianwall.io/v1",
            "kind":       "Policy",
            "metadata":   {"name": "test_policy"},
            "spec":       {},           # ← conditions missing
        })

        error_fields = [error["field"] for error in errors]
        assert "spec.conditions" in error_fields  # line 29

    def test_both_nested_keys_missing_in_one_call(self) -> None:
        """Both nested missing keys produce errors in a single call."""
        errors = lint_policy({
            "apiVersion": "obsidianwall.io/v1",
            "kind":       "Policy",
            "metadata":   {},    # missing name
            "spec":       {},    # missing conditions
        })

        error_fields = [error["field"] for error in errors]
        assert "metadata.name"    in error_fields
        assert "spec.conditions"  in error_fields


# =====================================================
# engine/validator.py — line 41
#
# Line 41 is logger.error() inside the except block.
# Reached when normalize_policy raises — empty dict
# input fails the non-empty check immediately.
#
# Flow:
#   validate_policy({})
#     → normalize_policy({}) → ValueError (empty dict)
#     → except Exception as error:
#         logger.error(...)   ← line 41
#         raise
# =====================================================


class TestValidatePolicyExceptionPath:
    """Covers line 41 — logger.error in except block."""

    def test_empty_dict_triggers_exception_logging(self) -> None:
        """
        Empty dict causes normalize_policy to raise ValueError.
        Caught by except block in validate_policy → line 41.
        """
        with pytest.raises(ValueError):
            validate_policy({})

    def test_invalid_format_triggers_exception_logging(self) -> None:
        """
        Dict with unrecognized structure also triggers except path.
        """
        with pytest.raises(ValueError):
            validate_policy({"unknown_key": "unknown_value"})


# =====================================================
# engine/policy_normalizer.py — line 160
#
# build_policy_runtime_context() raises ValueError
# when policy parameters overlap with runtime context
# keys. Line 160 is the raise statement in the
# conflict detection block.
#
# Uses MagicMock to avoid creating a full Policy object.
# =====================================================


class TestBuildPolicyRuntimeContextConflict:
    """Covers line 160 — parameter/context key conflict."""

    def test_raises_when_parameters_conflict_with_context(self) -> None:
        """
        When flattened policy parameters share a key with the
        runtime context, ValueError is raised at line 160.
        """
        mock_policy = MagicMock()
        mock_policy.spec.parameters.model_dump.return_value = {
            "estimated_cost": 100,
        }

        base_context = {
            "estimated_cost": 50,   # ← conflict with policy parameter
            "resource_count":  3,
        }

        with pytest.raises(ValueError, match="conflict"):
            build_policy_runtime_context(mock_policy, base_context)

    def test_error_message_names_conflicting_keys(self) -> None:
        """ValueError message identifies the conflicting key."""
        mock_policy = MagicMock()
        mock_policy.spec.parameters.model_dump.return_value = {
            "monthly_budget": 500,
        }

        base_context = {"monthly_budget": 400}

        with pytest.raises(ValueError) as exception_info:
            build_policy_runtime_context(mock_policy, base_context)

        assert "monthly_budget" in str(exception_info.value)