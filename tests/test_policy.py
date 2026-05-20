# tests/test_policy.py

# Purpose:
# Validates that policies load, normalize, and
# validate correctly against the canonical DSL schema.
#
# Ensures:
# - Policies load from YAML without error
# - Schema validation produces correct typed objects
# - Invalid policy structures are rejected


import pytest

from engine.policy_loader import load_policy
from engine.validator import validate_policy


def test_load_policy():
    """
    Policy file loads as a non-empty dict.
    """

    policy = load_policy("policies/cost/basic_budget.yaml")

    assert policy is not None
    assert isinstance(policy, dict)
    assert len(policy) > 0


def test_load_policy_is_canonical_dsl():
    """
    Loaded policy contains canonical DSL top-level keys.
    """

    policy = load_policy("policies/cost/basic_budget.yaml")

    assert "apiVersion" in policy
    assert "kind" in policy
    assert "metadata" in policy
    assert "spec" in policy


def test_validate_policy():
    """
    Validated policy produces correct typed Policy object
    with expected metadata fields.
    """

    policy_dict = load_policy("policies/cost/basic_budget.yaml")
    policy_obj = validate_policy(policy_dict)

    assert policy_obj.metadata.name == "basic_budget_verdict"
    assert policy_obj.metadata.version == "0.2"
    assert policy_obj.metadata.owner == "team-alpha"


def test_validate_policy_spec():
    """
    Validated policy spec contains expected fields.
    """

    policy_dict = load_policy("policies/cost/basic_budget.yaml")
    policy_obj = validate_policy(policy_dict)

    assert len(policy_obj.spec.conditions) > 0
    assert policy_obj.spec.decision.allow is not None
    assert policy_obj.spec.decision.deny is not None


def test_invalid_policy_raises():
    """
    Invalid policy structure raises an exception.
    """

    invalid_policy = {
        "invalid": "structure"
    }

    with pytest.raises(Exception):
        validate_policy(invalid_policy)


def test_strict_budget_loads():
    """
    strict_budget policy loads and validates correctly.
    """

    policy_dict = load_policy("policies/cost/strict_budget.yaml")
    policy_obj = validate_policy(policy_dict)

    assert policy_obj.metadata.name == "strict_budget_verdict"
    assert policy_obj.metadata.owner == "finance-team"