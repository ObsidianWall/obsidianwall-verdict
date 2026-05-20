# tests/test_engine.py

# Purpose:
# Smoke tests for the full evaluation pipeline
# using the PolicyOrchestrator entry point.
#
# NOTE:
# DecisionEngine was replaced by PolicyOrchestrator
# during the architecture refactor.
# These tests use the current API.


from engine.orchestrator import PolicyOrchestrator


def test_allow():
    """
    Deployment within budget should be ALLOWED.
    estimated_cost (10) + current_spend (10) = 20 <= budget.amount (50)
    """

    orchestrator = PolicyOrchestrator.from_policy_path(
        "policies/cost/basic_budget.yaml"
    )

    context = {
        "estimated_cost":   10,
        "current_spend":    10,
    }

    result = orchestrator.evaluate(context)

    assert result["decision"] == "ALLOW"
    assert result["conditions_passed"] is True


def test_deny():
    """
    Deployment over budget should be DENIED.
    estimated_cost (40) + current_spend (20) = 60 > budget.amount (50)
    """

    orchestrator = PolicyOrchestrator.from_policy_path(
        "policies/cost/basic_budget.yaml"
    )

    context = {
        "estimated_cost":   40,
        "current_spend":    20,
    }

    result = orchestrator.evaluate(context)

    assert result["decision"] in (
        "DENY",
        "DENY_WITH_OVERRIDE",
    )
    assert result["conditions_passed"] is False