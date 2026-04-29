#engine/condition_evaluator.py

# Purpose -- Executes logic.

def evaluate_conditions(policy, context):
    conditions = policy["policy"]["conditions"]
    parameters = policy["policy"].get("parameters", {})

    results = []

    for condition in conditions:
        expr = condition["expression"]

        env = {**context, **parameters}

        try:
            result = eval(expr, {}, env)
        except Exception:
            result = False

        results.append(result)

    return all(results)