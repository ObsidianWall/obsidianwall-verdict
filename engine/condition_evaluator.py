#

def evaluate_conditions(policy, context):
    results = []

    parameters = policy.get("parameters", {})

    for condition in policy["conditions"]:
        expr = condition

        # inject parameters
        for key, value in parameters.items():
            expr = expr.replace(key, str(value))

        try:
            result = eval(expr, {}, context)
        except Exception:
            result = False

        results.append(result)

    return all(results)