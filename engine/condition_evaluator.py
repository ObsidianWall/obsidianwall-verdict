# engine/condition_evaluator.py

# Purpose:
# Deterministic and secure policy condition evaluation.
#
# IMPORTANT:
# - No arbitrary code execution
# - No dynamic eval()
# - Deterministic only
# - Fully auditable
# - Restricted expression grammar

import operator
from typing import Any

from schemas.policy_schema import Policy

SUPPORTED_OPERATORS: dict[str, Any] = {
    "<=": operator.le,
    ">=": operator.ge,
    "<": operator.lt,
    ">": operator.gt,
    "==": operator.eq,
}


def evaluate_expression(
    expression: str,
    evaluation_context: dict[str, Any],
) -> bool:
    """
    Evaluate a restricted deterministic expression.

    Supported grammar:
        (current_spend + estimated_cost) <= budget.amount
        open_ingress_rules <= security.max_open_ingress_rules
        replica_count >= resilience.min_replica_count

    Raises:
        ValueError: if operator is unsupported,
                    expression is empty,
                    injection attempt detected,
                    or context key is missing.
    """

    if not expression or not expression.strip():
        raise ValueError("Expression must not be empty.")

    # ---------------------------------------------------
    # Injection guard
    # Reject any expression containing Python builtins,
    # dunder attributes, or import statements.
    # ---------------------------------------------------

    injection_patterns = (
        "__",
        "import",
        "exec",
        "eval",
        "open(",
        "os.",
        "sys.",
        "subprocess",
    )

    for pattern in injection_patterns:
        if pattern in expression:
            raise ValueError(
                f"Unsupported expression: forbidden pattern '{pattern}' detected."
            )

    # ---------------------------------------------------
    # Normalize expression
    # ---------------------------------------------------

    normalized_expression = expression.replace("(", "").replace(")", "")

    left_side: str | None = None
    right_side: str | None = None
    comparison_operator: str | None = None

    # ---------------------------------------------------
    # Find supported operator
    # Longer operators checked before shorter to prevent
    # "<=" being split on "<" first.
    # ---------------------------------------------------

    for supported_operator in SUPPORTED_OPERATORS:
        if supported_operator in normalized_expression:
            parts = normalized_expression.split(supported_operator)
            left_side = parts[0]
            right_side = parts[1]
            comparison_operator = supported_operator
            break

    if not comparison_operator or left_side is None or right_side is None:
        raise ValueError(
            f"Unsupported expression operator in: '{expression}'. "
            f"Supported operators: {list(SUPPORTED_OPERATORS.keys())}"
        )

    # ---------------------------------------------------
    # Evaluate both sides
    # ---------------------------------------------------

    left_value = evaluate_arithmetic_expression(left_side.strip(), evaluation_context)
    right_value = evaluate_arithmetic_expression(right_side.strip(), evaluation_context)

    # ---------------------------------------------------
    # Deterministic comparison
    # ---------------------------------------------------

    op_fn = SUPPORTED_OPERATORS[comparison_operator]

    return bool(op_fn(left_value, right_value))


def evaluate_arithmetic_expression(
    arithmetic_expression: str,
    evaluation_context: dict[str, Any],
) -> int | float:
    """
    Evaluate restricted arithmetic operations.

    Supported:
        a + b + c        (addition chain)
        a                (single context key)
        100              (numeric literal)

    Raises:
        ValueError: if a token is neither a context key
                    nor a numeric literal. Provides a clear
                    error naming the missing key so engineers
                    know exactly what the plan translator
                    needs to extract.
    """

    # ---------------------------------------------------
    # Addition chain
    # ---------------------------------------------------

    if "+" in arithmetic_expression:
        expression_parts = [part.strip() for part in arithmetic_expression.split("+")]
        resolved_values: list[int | float] = []

        for expression_part in expression_parts:
            resolved_values.append(_resolve_token(expression_part, evaluation_context))

        return sum(resolved_values)

    # ---------------------------------------------------
    # Single token
    # ---------------------------------------------------

    return _resolve_token(arithmetic_expression, evaluation_context)


def _resolve_token(
    token: str,
    evaluation_context: dict[str, Any],
) -> int | float:
    """
    Resolve a single expression token to a numeric value.

    Resolution order:
    1. Context key lookup
    2. Numeric literal

    Raises:
        ValueError: with a clear message naming the missing
                    context key if neither resolves.
    """

    token = token.strip()

    # Context key lookup
    if token in evaluation_context:
        value = evaluation_context[token]
        try:
            return float(value)
        except (TypeError, ValueError) as e:
            raise ValueError(
                f"Context key '{token}' resolved to "
                f"'{value}' (type: {type(value).__name__}) "
                f"which cannot be used in a numeric comparison."
            ) from e

    # Numeric literal
    try:
        return float(token)
    except ValueError:
        raise ValueError(
            f"Context key '{token}' not found in the runtime "
            f"evaluation context. "
            f"Ensure your plan translator extracts this value "
            f"and adds it to the evaluation context before "
            f"policy conditions are evaluated. "
            f"Available context keys: "
            f"{sorted(evaluation_context.keys())}"
        )


def evaluate_conditions(
    policy: Policy,
    evaluation_context: dict[str, Any],
) -> tuple[bool, list[dict[str, Any]]]:
    """
    Evaluate all policy conditions deterministically.

    Returns:
        tuple[bool, list[dict[str, Any]]]
        (
            all_conditions_passed,
            evaluation_trace
        )
    """

    evaluation_results: list[bool] = []
    evaluation_trace: list[dict[str, Any]] = []

    for condition in policy.spec.conditions:
        condition_expression = condition.expression

        condition_result = evaluate_expression(condition_expression, evaluation_context)

        evaluation_trace.append(
            {
                "condition_id": condition.id,
                "expression": condition_expression,
                "result": condition_result,
                "description": condition.description,
            }
        )

        evaluation_results.append(condition_result)

    all_conditions_passed = all(evaluation_results)

    return all_conditions_passed, evaluation_trace
