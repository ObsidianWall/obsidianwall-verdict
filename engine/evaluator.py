# engine/evaluator.py

# Purpose:
# Deterministic policy evaluation engine.
#
# Responsibilities:
# - Evaluate policy conditions
# - Resolve deterministic decisions
# - Produce evaluation traces
#
# IMPORTANT:
# This module NEVER:
# - loads policies
# - validates policies
# - generates recommendations
# - performs orchestration


from engine.condition_evaluator import (
    evaluate_conditions
)

from engine.decision_resolver import (
    resolve_decision
)


def evaluate_policy(
    policy:policy,
    runtime_context: dict,
    user_role: str = "engineer"
) -> dict:

    # =================================================
    # CONDITION EVALUATION
    # =================================================

    conditions_passed, trace = (
        evaluate_conditions(
            policy,
            runtime_context
        )
    )

    # =================================================
    # DECISION RESOLUTION
    # =================================================

    decision, override_required = (
        resolve_decision(
            policy,
            conditions_passed,
            user_role
        )
    )

    return {

        "decision": decision,

        "override_required": override_required,

        "conditions_passed": conditions_passed,

        "trace": trace,
    }