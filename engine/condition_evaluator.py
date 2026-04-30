# engine/condition_evaluator.py

# Purpose: Evaluate policy conditions deterministically

from utils.logger import get_logger

logger = get_logger()


def evaluate_conditions(policy, context):
    results = []
    failures = []

    env = {**context, **policy.parameters}

    for cond in policy.conditions:
        try:
            result = eval(cond.expression, {}, env)
            results.append(result)

            if not result:
                failures.append(cond.message)

        except Exception as e:
            logger.error("Condition evaluation error", extra={"error": str(e)})
            results.append(False)
            failures.append(f"Evaluation error: {str(e)}")

    return all(results), failures