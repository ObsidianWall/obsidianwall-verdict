
# tests/unit/test_simulate_command.py
#
# Unit tests for cli/commands/simulate.py
#
# Covers:
# - _parse_set_value() type inference
# - _parse_set_overrides() parsing and error handling
# - _build_simulate_context() context assembly

import pytest

from cli.commands.simulate import (
    _build_simulate_context,
    _parse_set_overrides,
    _parse_set_value,
)


# =====================================================
# TYPE INFERENCE
# =====================================================


class TestParseSetValue:

    def test_parses_integer(self):
        assert _parse_set_value("150") == 150
        assert isinstance(_parse_set_value("150"), int)

    def test_parses_zero(self):
        assert _parse_set_value("0") == 0
        assert isinstance(_parse_set_value("0"), int)

    def test_parses_float(self):
        assert _parse_set_value("75.5") == 75.5
        assert isinstance(_parse_set_value("75.5"), float)

    def test_parses_string_when_not_numeric(self):
        assert _parse_set_value("production") == "production"
        assert isinstance(_parse_set_value("production"), str)

    def test_parses_boolean_string_as_string(self):
        assert _parse_set_value("true") == "true"
        assert isinstance(_parse_set_value("true"), str)

    def test_parses_negative_integer(self):
        assert _parse_set_value("-1") == -1

    def test_parses_large_integer(self):
        assert _parse_set_value("1000000") == 1000000


# =====================================================
# SET OVERRIDES PARSING
# =====================================================


class TestParseSetOverrides:

    def test_parses_single_integer_override(self):
        result = _parse_set_overrides(["estimated_cost=150"])
        assert result == {"estimated_cost": 150}

    def test_parses_multiple_overrides(self):
        result = _parse_set_overrides([
            "estimated_cost=150",
            "open_ingress_rules=2",
        ])
        assert result == {
            "estimated_cost": 150,
            "open_ingress_rules": 2,
        }

    def test_parses_float_override(self):
        result = _parse_set_overrides(["estimated_cost=99.99"])
        assert result["estimated_cost"] == 99.99

    def test_parses_string_override(self):
        result = _parse_set_overrides(["environment=production"])
        assert result["environment"] == "production"

    def test_handles_value_with_equals_sign(self):
        result = _parse_set_overrides(["tag=env=prod"])
        assert result["tag"] == "env=prod"

    def test_returns_empty_dict_for_empty_list(self):
        assert _parse_set_overrides([]) == {}

    def test_raises_for_missing_equals_sign(self):
        with pytest.raises(ValueError, match="Invalid --set format"):
            _parse_set_overrides(["no_equals_sign"])

    def test_raises_for_empty_key(self):
        with pytest.raises(ValueError, match="Key cannot be empty"):
            _parse_set_overrides(["=value"])

    def test_strips_whitespace_from_key_and_value(self):
        result = _parse_set_overrides([" estimated_cost = 150 "])
        assert result == {"estimated_cost": 150}


# =====================================================
# SIMULATE CONTEXT BUILDING
# =====================================================


class TestBuildSimulateContext:

    def test_base_context_has_all_standard_keys(self):
        context = _build_simulate_context({})
        expected_keys = {
            "resources",
            "open_ingress_rules",
            "public_storage_buckets",
            "unencrypted_databases",
            "ssl_not_enforced_count",
            "versioning_disabled_count",
            "untagged_resource_count",
            "total_resource_count",
            "compute_instance_count",
            "gpu_instance_count",
            "ai_gpu_workloads",
            "estimated_cost",
            "current_spend",
            "pricing_mode",
        }
        assert expected_keys.issubset(set(context.keys()))

    def test_base_context_integer_keys_default_to_zero(self):
        context = _build_simulate_context({})
        assert context["open_ingress_rules"] == 0
        assert context["unencrypted_databases"] == 0
        assert context["gpu_instance_count"] == 0

    def test_base_context_cost_defaults_to_zero(self):
        context = _build_simulate_context({})
        assert context["estimated_cost"] == 0.0
        assert context["current_spend"] == 0.0

    def test_pricing_mode_set_to_simulate(self):
        context = _build_simulate_context({})
        assert context["pricing_mode"] == "simulate"

    def test_overrides_apply_to_base_context(self):
        context = _build_simulate_context({
            "estimated_cost": 150,
            "open_ingress_rules": 3,
        })
        assert context["estimated_cost"] == 150
        assert context["open_ingress_rules"] == 3

    def test_overrides_do_not_affect_other_keys(self):
        context = _build_simulate_context({"estimated_cost": 150})
        assert context["open_ingress_rules"] == 0
        assert context["unencrypted_databases"] == 0

    def test_custom_keys_can_be_added_via_overrides(self):
        context = _build_simulate_context({"custom_key": "custom_value"})
        assert context["custom_key"] == "custom_value"

    def test_base_context_is_not_mutated_between_calls(self):
        context_one = _build_simulate_context({"estimated_cost": 100})
        context_two = _build_simulate_context({"estimated_cost": 200})
        assert context_one["estimated_cost"] == 100
        assert context_two["estimated_cost"] == 200