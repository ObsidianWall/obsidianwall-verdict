# tests/integration/test_evaluate_pipeline.py

# Purpose:
# Integration tests for the full ObsidianWall Verdict
# evaluation pipeline.
#
# Tests the complete flow:
# context → normalization → evaluation → decision
# → risk scoring → recommendations → explainability
#
# These tests use real modules — no mocks between layers.
# Only I/O boundaries (filesystem) are mocked.


import pytest
from unittest.mock import patch, MagicMock

from engine.condition_evaluator import evaluate_conditions
from engine.decision_resolver import resolve_decision
from engine.policy_normalizer import (
    flatten_policy_parameters,
    build_policy_runtime_context,
)
from engine.risk_scorer import compute_risk_summary
from engine.recommender import generate_suggestions
from schemas.policy_schema import (
    Policy,
    Metadata,
    Spec,
    Condition,
    Action,
    Decision,
    Override,
    Parameters,
    Budget,
    GovernanceConfig,
    GovernanceSeverity,
    NotificationTarget,
)


# =====================================================
# FIXTURES — POLICY CONSTRUCTION
# =====================================================

@pytest.fixture
def basic_budget_policy():
    """
    Construct a basic_budget policy object directly
    without loading from YAML — pure integration test.
    """
    return Policy(
        apiVersion="obsidianwall.io/v1",
        kind="Policy",
        metadata=Metadata(
            name="basic_budget_verdict",
            version="0.2",
            owner="team-alpha",
            description="Test policy",
        ),
        spec=Spec(
            inputs=["estimated_cost", "current_spend"],
            parameters=Parameters(
                budget=Budget(
                    amount=50.0,
                    period="monthly",
                    scope="project:default",
                    owner="team-alpha",
                    flexibility="soft",
                    override_allowed=True,
                )
            ),
            conditions=[
                Condition(
                    id="budget_check",
                    expression=(
                        "(current_spend + estimated_cost) "
                        "<= budget.amount"
                    ),
                    description="Monthly spend cap enforcement",
                )
            ],
            decision=Decision(
                allow="ALLOW",
                deny="DENY_WITH_OVERRIDE",
                warn="ALLOW_WITH_NOTIFICATION",
            ),
            override=Override(
                roles=["budget_owner"],
                requires_approval=False,
            ),
            governance=GovernanceConfig(
                severity=GovernanceSeverity.MEDIUM,
                notifications=[
                    NotificationTarget(
                        role="budget_owner",
                        channel="email"
                    ),
                ],
            ),
            actions=[
                Action(
                    type="notify",
                    message="Budget exceeded",
                    severity="high",
                ),
            ],
        ),
    )


@pytest.fixture
def over_budget_context():
    return {
        "estimated_cost":   100,
        "current_spend":    0,
    }


@pytest.fixture
def within_budget_context():
    return {
        "estimated_cost":   30,
        "current_spend":    0,
    }


# =====================================================
# NORMALIZATION → CONDITION EVALUATION PIPELINE
# =====================================================

def test_normalization_produces_correct_budget_key(
    basic_budget_policy,
    over_budget_context
):
    runtime_context = build_policy_runtime_context(
        basic_budget_policy,
        over_budget_context
    )
    assert "budget.amount" in runtime_context
    assert runtime_context["budget.amount"] == 50.0


def test_over_budget_conditions_fail(
    basic_budget_policy,
    over_budget_context
):
    runtime_context = build_policy_runtime_context(
        basic_budget_policy,
        over_budget_context
    )
    conditions_passed, trace = evaluate_conditions(
        basic_budget_policy,
        runtime_context
    )
    assert conditions_passed is False
    assert len(trace) == 1
    assert trace[0]["condition_id"] == "budget_check"
    assert trace[0]["result"] is False


def test_within_budget_conditions_pass(
    basic_budget_policy,
    within_budget_context
):
    runtime_context = build_policy_runtime_context(
        basic_budget_policy,
        within_budget_context
    )
    conditions_passed, trace = evaluate_conditions(
        basic_budget_policy,
        runtime_context
    )
    assert conditions_passed is True
    assert trace[0]["result"] is True


# =====================================================
# DECISION RESOLUTION PIPELINE
# =====================================================

def test_over_budget_engineer_gets_deny_with_override(
    basic_budget_policy,
    over_budget_context
):
    runtime_context = build_policy_runtime_context(
        basic_budget_policy,
        over_budget_context
    )
    conditions_passed, _ = evaluate_conditions(
        basic_budget_policy,
        runtime_context
    )
    resolution = resolve_decision(
        basic_budget_policy,
        conditions_passed,
        user_role="engineer"
    )
    assert resolution["decision"] == "DENY_WITH_OVERRIDE"
    assert resolution["override_required"] is True


def test_over_budget_budget_owner_gets_deny_with_override(
    basic_budget_policy,
    over_budget_context
):
    runtime_context = build_policy_runtime_context(
        basic_budget_policy,
        over_budget_context
    )
    conditions_passed, _ = evaluate_conditions(
        basic_budget_policy,
        runtime_context
    )
    resolution = resolve_decision(
        basic_budget_policy,
        conditions_passed,
        user_role="budget_owner"
    )
    # budget_owner is in override roles
    assert resolution["decision"] == "DENY_WITH_OVERRIDE"
    assert resolution["override_required"] is True
    assert resolution["requires_approval"] is False


def test_within_budget_gets_allow(
    basic_budget_policy,
    within_budget_context
):
    runtime_context = build_policy_runtime_context(
        basic_budget_policy,
        within_budget_context
    )
    conditions_passed, _ = evaluate_conditions(
        basic_budget_policy,
        runtime_context
    )
    resolution = resolve_decision(
        basic_budget_policy,
        conditions_passed,
        user_role="engineer"
    )
    assert resolution["decision"] == "ALLOW"
    assert resolution["override_required"] is False


# =====================================================
# RISK SCORING PIPELINE
# =====================================================

def test_zero_risk_on_no_findings():
    analyzer_results = {
        "cost_analysis": {
            "risk_score": 0,
            "findings": [],
            "optimization_candidates": [],
        }
    }
    summary = compute_risk_summary(
        analyzer_results,
        policy_severity="medium"
    )
    assert summary["overall_risk_score"] == 0
    assert summary["effective_severity"] == "medium"


def test_high_analyzer_risk_escalates_effective_severity():
    analyzer_results = {
        "cost_analysis": {
            "risk_score": 70,
            "findings": [
                {"type": "x", "severity": "high", "message": "y"}
            ],
            "optimization_candidates": [],
        }
    }
    summary = compute_risk_summary(
        analyzer_results,
        policy_severity="low"
    )
    assert summary["effective_severity"] in ("high", "critical")


# =====================================================
# RECOMMENDATION PIPELINE
# =====================================================

def test_deny_decision_always_has_enforcement_suggestion():
    suggestions = generate_suggestions(
        context={"resources": []},
        decision="DENY_WITH_OVERRIDE",
        analyzer_results={}
    )
    types = [s["type"] for s in suggestions]
    assert "enforcement" in types


def test_suggestions_always_return_list():
    result = generate_suggestions(
        context={"resources": []},
        decision="ALLOW",
        analyzer_results={}
    )
    assert isinstance(result, list)


# =====================================================
# AUDIT ARTIFACT CONTRACT
# =====================================================

def test_resolution_contains_required_fields(
    basic_budget_policy,
    over_budget_context
):
    """
    Contract test: resolution dict must always carry
    these fields regardless of decision path.
    """
    runtime_context = build_policy_runtime_context(
        basic_budget_policy,
        over_budget_context
    )
    conditions_passed, _ = evaluate_conditions(
        basic_budget_policy,
        runtime_context
    )
    resolution = resolve_decision(
        basic_budget_policy,
        conditions_passed,
        user_role="engineer"
    )

    required_fields = {
        "decision",
        "override_required",
        "requires_approval",
        "governance_severity",
        "resolution_reason",
    }

    for field in required_fields:
        assert field in resolution, (
            f"Resolution missing required field: {field}"
        )
