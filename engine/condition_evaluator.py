# engine/condition_evaluator.py

# Purpose: Deterministic, secure expression evaluation

# Purpose: Evaluate policy conditions deterministically

import operator

OPS = {
    "<=": operator.le,
    ">=": operator.ge,
    "<": operator.lt,
    ">": operator.gt,
    "==": operator.eq,
}


def evaluate_expression(expr: str, context: dict):
    """
    Supports simple expressions like:
    (current_spend + estimated_cost) <= max_budget
    """

    # VERY controlled parsing (v0.2 scope)
    expr = expr.replace("(", "").replace(")", "")
    left, op, right = None, None, None

    for symbol in OPS.keys():
        if symbol in expr:
            left, right = expr.split(symbol)
            op = symbol
            break

    if not op:
        raise ValueError("Unsupported expression")

    left_value = eval_arithmetic(left.strip(), context)
    right_value = eval_arithmetic(right.strip(), context)

    return OPS[op](left_value, right_value)


def eval_arithmetic(part: str, context: dict):
    if "+" in part:
        items = [i.strip() for i in part.split("+")]
        return sum(context.get(i, float(i)) for i in items)

    return context.get(part, float(part))


def evaluate_conditions(policy, context):
    results = []
    trace = []

    for condition in policy.spec.conditions:
        expr = cond["expression"]

        result = evaluate_expression(expr, context)

        trace.append({
            "expression": expr,
            "result": result
        })

        results.append(result)

    return all(results), trace