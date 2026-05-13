
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


SUPPORTED_OPERATORS = {
    "<=": operator.le,
    ">=": operator.ge,
    "<": operator.lt,
    ">": operator.gt,
    "==": operator.eq,
}


def evaluate_expression(expression: str, evaluation_context: dict):
    """
    Evaluate a restricted deterministic expression.

    Example:
        (current_spend + estimated_cost) <= max_budget
    """

    # ---------------------------------------------------
    # Normalize expression
    # ---------------------------------------------------

    normalized_expression = (
        expression
        .replace("(", "")
        .replace(")", "")
    )

    left_side = None
    right_side = None
    comparison_operator = None

    # ---------------------------------------------------
    # Find supported operator
    # ---------------------------------------------------

    for supported_operator in SUPPORTED_OPERATORS.keys():

        if supported_operator in normalized_expression:

            left_side, right_side = normalized_expression.split(
                supported_operator
            )

            comparison_operator = supported_operator
            break

    if not comparison_operator:
        raise ValueError(
            f"Unsupported expression operator in: {expression}"
        )

    # ---------------------------------------------------
    # Evaluate both sides
    # ---------------------------------------------------

    left_value = evaluate_arithmetic_expression(
        left_side.strip(),
        evaluation_context
    )

    right_value = evaluate_arithmetic_expression(
        right_side.strip(),
        evaluation_context
    )

    # ---------------------------------------------------
    # Deterministic comparison
    # ---------------------------------------------------

    return SUPPORTED_OPERATORS[comparison_operator](
        left_value,
        right_value
    )



def evaluate_arithmetic_expression(
    arithmetic_expression: str,
    evaluation_context: dict
):
    """
    Evaluate restricted arithmetic operations.

    Supported:
        a + b
        a
        numeric literals
    """

    # ---------------------------------------------------
    # Addition support
    # ---------------------------------------------------

    if "+" in arithmetic_expression:

        expression_parts = [
            part.strip()
            for part in arithmetic_expression.split("+")
        ]

        resolved_values = []

        for expression_part in expression_parts:

            if expression_part in evaluation_context:
                resolved_value = evaluation_context[
                    expression_part
                ]
            else:
                resolved_value = float(expression_part)

            resolved_values.append(resolved_value)

        return sum(resolved_values)
    


    # ---------------------------------------------------
    # Single value resolution
    # ---------------------------------------------------

    if arithmetic_expression in evaluation_context:
        return evaluation_context[arithmetic_expression]

    return float(arithmetic_expression)



def evaluate_conditions(policy, evaluation_context):
    """
    Evaluate all policy conditions.

    Returns:
        tuple[bool, list]
        (
            all_conditions_passed,
            evaluation_trace
        )
    """

    evaluation_results = []
    evaluation_trace = []


    # ---------------------------------------------------
    # Evaluate each condition
    # ---------------------------------------------------

    for condition in policy.spec.conditions:

        condition_expression = condition.expression

        condition_result = evaluate_expression(
            condition_expression,
            evaluation_context
        )

        evaluation_trace.append({
            "condition_id": condition.id,
            "expression": condition_expression,
            "result": condition_result,
            "description": condition.description
        })

        evaluation_results.append(condition_result)

    # ---------------------------------------------------
    # Deterministic final outcome
    # ---------------------------------------------------

    all_conditions_passed = all(evaluation_results)

    return all_conditions_passed, evaluation_trace