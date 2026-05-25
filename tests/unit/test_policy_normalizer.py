
# tests/unit/test_policy_normalizer.py

import pytest
from engine.policy_normalizer import (
    flatten_policy_parameters,
    normalize_policy,
)


# =====================================================
# flatten_policy_parameters
# =====================================================

def test_flat_dict_unchanged():
    params = {"amount": 50, "period": "monthly"}
    result = flatten_policy_parameters(params)
    assert result == {"amount": 50, "period": "monthly"}


def test_nested_dict_flattened():
    params = {
        "budget": {
            "amount":   50,
            "period":   "monthly",
        }
    }
    result = flatten_policy_parameters(params)
    assert result == {
        "budget.amount":    50,
        "budget.period":    "monthly",
    }


def test_deeply_nested_dict_flattened():
    params = {
        "budget": {
            "limits": {
                "monthly": 50,
                "annual":  600,
            }
        }
    }
    result = flatten_policy_parameters(params)
    assert result == {
        "budget.limits.monthly":    50,
        "budget.limits.annual":     600,
    }


def test_mixed_flat_and_nested():
    params = {
        "name":     "test",
        "budget": {
            "amount": 100
        }
    }
    result = flatten_policy_parameters(params)
    assert result["name"] == "test"
    assert result["budget.amount"] == 100


def test_empty_dict_returns_empty():
    assert flatten_policy_parameters({}) == {}


def test_list_values_not_flattened():
    params = {"tags": ["a", "b", "c"]}
    result = flatten_policy_parameters(params)
    assert result["tags"] == ["a", "b", "c"]


def test_mutable_default_arg_not_shared():
    """
    Verify the flattened=None guard prevents
    mutable default argument bug.
    """
    result1 = flatten_policy_parameters({"a": 1})
    result2 = flatten_policy_parameters({"b": 2})
    assert "a" not in result2
    assert "b" not in result1


# =====================================================
# normalize_policy
# =====================================================

def test_canonical_policy_returned_unchanged():
    raw = {
        "apiVersion":   "obsidianwall.io/v1",
        "kind":         "Policy",
        "spec":         {},
        "metadata":     {},
    }
    result = normalize_policy(raw)
    assert result == raw


def test_legacy_policy_converted():
    raw = {
        "policy": {
            "name":         "test_policy",
            "version":      "1.0",
            "description":  "Test",
        },
        "parameters":   {"budget": {"owner": "team-a"}},
        "conditions":   [],
        "decision":     {},
        "override":     {},
        "actions":      [],
        "inputs":       [],
    }
    result = normalize_policy(raw)
    assert result["apiVersion"]     == "obsidianwall.io/v1"
    assert result["kind"]           == "Policy"
    assert result["metadata"]["name"] == "test_policy"
    assert result["metadata"]["owner"] == "team-a"


def test_invalid_format_raises():
    with pytest.raises(ValueError, match="Invalid policy format"):
        normalize_policy({"unknown_key": "value"})


def test_empty_dict_raises():
    with pytest.raises(ValueError):
        normalize_policy({})


def test_none_raises():
    with pytest.raises((ValueError, TypeError)):
        normalize_policy(None)


def test_legacy_owner_extracted_from_budget():
    raw = {
        "policy": {
            "name":     "legacy",
            "version":  "0.1",
        },
        "parameters": {
            "budget": {
                "owner": "finance-team"
            }
        },
        "conditions": [],
        "decision":   {},
        "override":   {},
        "actions":    [],
        "inputs":     [],
    }
    result = normalize_policy(raw)
    assert result["metadata"]["owner"] == "finance-team"


def test_legacy_owner_defaults_to_unknown():
    raw = {
        "policy": {
            "name":     "legacy",
            "version":  "0.1",
        },
        "parameters": {},
        "conditions": [],
        "decision":   {},
        "override":   {},
        "actions":    [],
        "inputs":     [],
    }
    result = normalize_policy(raw)
    assert result["metadata"]["owner"] == "unknown"
