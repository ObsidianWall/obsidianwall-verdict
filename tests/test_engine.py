# tests/test_engine.py

from engine.evaluator import DecisionEngine


def test_allow():
    engine = DecisionEngine("policies/cost_policy.yaml")

    context = {
        "estimated_cost": 10,
        "current_spend": 10
    }

    result = engine.evaluate(context)
    assert result["decision"] == "ALLOW"


def test_deny():
    engine = DecisionEngine("policies/cost_policy.yaml")

    context = {
        "estimated_cost": 40,
        "current_spend": 20
    }

    result = engine.evaluate(context)
    assert result["decision"] == "DENY"