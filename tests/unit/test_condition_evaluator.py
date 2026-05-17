
# tests/unit/test_condition_evaluator.py

import pytest
from engine.condition_evaluator import (
    evaluate_expression,
    evaluate_arithmetic_expression,
)


# =====================================================
# FIXTURES
# =====================================================

@pytest.fixture
def budget_context():
    return {
        "current_spend":    0,
        "estimated_cost":   100,
        "budget.amount":    50.0,
        "budget.period":    "monthly",
    }

@pytest.fixture
def passing_context():
    return {
        "current_spend":    0,
        "estimated_cost":   30,
        "budget.amount":    50.0,
    }


# =====================================================
# evaluate_expression — PASS / FAIL
# =====================================================

def test_budget_check_fails_when_over_budget(budget_context):
    result = evaluate_expression(
        "(current_spend + estimated_cost) <= budget.amount",
        budget_context
    )
    assert result is False


def test_budget_check_passes_when_within_budget(passing_context):
    result = evaluate_expression(
        "(current_spend + estimated_cost) <= budget.amount",
        passing_context
    )
    assert result is True


def test_exact_budget_boundary_passes():
    context = {
        "current_spend":    0,
        "estimated_cost":   50,
        "budget.amount":    50.0,
    }
    result = evaluate_expression(
        "(current_spend + estimated_cost) <= budget.amount",
        context
    )
    assert result is True


def test_one_over_budget_fails():
    context = {
        "current_spend":    0,
        "estimated_cost":   51,
        "budget.amount":    50.0,
    }
    result = evaluate_expression(
        "(current_spend + estimated_cost) <= budget.amount",
        context
    )
    assert result is False


# =====================================================
# evaluate_expression — OPERATORS
# =====================================================

@pytest.mark.parametrize("expression, context, expected", [
    ("a <= b", {"a": 10, "b": 20},  True),
    ("a <= b", {"a": 20, "b": 20},  True),
    ("a <= b", {"a": 21, "b": 20},  False),
    ("a >= b", {"a": 20, "b": 10},  True),
    ("a >= b", {"a": 10, "b": 10},  True),
    ("a >= b", {"a": 9,  "b": 10},  False),
    ("a < b",  {"a": 9,  "b": 10},  True),
    ("a < b",  {"a": 10, "b": 10},  False),
    ("a > b",  {"a": 11, "b": 10},  True),
    ("a > b",  {"a": 10, "b": 10},  False),
    ("a == b", {"a": 10, "b": 10},  True),
    ("a == b", {"a": 10, "b": 11},  False),
])
def test_all_supported_operators(expression, context, expected):
    assert evaluate_expression(expression, context) == expected


# =====================================================
# evaluate_expression — UNSUPPORTED GRAMMAR
# =====================================================

def test_unsupported_operator_raises():
    with pytest.raises(ValueError, match="Unsupported"):
        evaluate_expression(
            "a != b",
            {"a": 1, "b": 2}
        )


def test_injection_attempt_raises():
    with pytest.raises(ValueError):
        evaluate_expression(
            "__import__('os').system('ls')",
            {}
        )


def test_empty_expression_raises():
    with pytest.raises(ValueError):
        evaluate_expression("", {})


# =====================================================
# evaluate_arithmetic_expression
# =====================================================

def test_addition_resolves_from_context():
    result = evaluate_arithmetic_expression(
        "current_spend + estimated_cost",
        {"current_spend": 20, "estimated_cost": 30}
    )
    assert result == 50


def test_single_context_key_resolves():
    result = evaluate_arithmetic_expression(
        "budget.amount",
        {"budget.amount": 75.0}
    )
    assert result == 75.0


def test_numeric_literal_resolves():
    result = evaluate_arithmetic_expression(
        "100",
        {}
    )
    assert result == 100.0


def test_addition_with_literal():
    result = evaluate_arithmetic_expression(
        "current_spend + 50",
        {"current_spend": 25}
    )
    assert result == 75.0


def test_multi_part_addition():
    result = evaluate_arithmetic_expression(
        "a + b + c",
        {"a": 10, "b": 20, "c": 30}
    )
    assert result == 60.0
