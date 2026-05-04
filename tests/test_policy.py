# tests/test_policy.py

# Purpose: This ensures:
              # policies load correctly
              # schema is valid
              # conditions behave as expected



import pytest
from engine.policy_loader import load_policy
from engine.validator import validate_policy


def test_load_policy():
    policy = load_policy("policies/cost/basic_budget.yaml")
    assert policy is not None
    assert "policy" in policy


def test_validate_policy():
    policy_dict = load_policy("policies/cost/basic_budget.yaml")
    policy_obj = validate_policy(policy_dict)

    assert policy_obj.policy.name == "basic_budget_guardrail"
    assert policy_obj.policy.version == "0.2"


def test_invalid_policy():
    invalid_policy = {
        "invalid": "structure"
    }

    with pytest.raises(Exception):
        validate_policy(invalid_policy)