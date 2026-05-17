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


from schemas.policy_schema import Policy

from engine.condition_evaluator import (
    evaluate_conditions
)

from engine.decision_resolver import (
    resolve_decision
)

from audit.audit_logger import get_logger


logger = get_logger()


def evaluate_policy(
    policy: Policy,
    runtime_context: dict,
    user_role: str = "engineer"
) -> dict:
    """
    Evaluate a validated policy against runtime context.

    Returns:
        dict containing:
        - decision:             5-level governance decision outcome
        - override_required:    whether an override was applied
        - requires_approval:    whether formal approval is needed
        - governance_severity:  severity level for routing
        - conditions_passed:    boolean outcome of condition evaluation
        - trace:                per-condition evaluation trace
    """

    # =================================================
    # CONDITION EVALUATION
    # =================================================

    conditions_passed, trace = evaluate_conditions(
        policy,
        runtime_context
    )

    # =================================================
    # DECISION RESOLUTION
    # =================================================

    resolution = resolve_decision(
        policy,
        conditions_passed,
        user_role
    )

    result = {

        "decision": resolution[
            "decision"
        ],

        "override_required": resolution[
            "override_required"
        ],

        "requires_approval": resolution[
            "requires_approval"
        ],

        "governance_severity": resolution[
            "governance_severity"
        ],

        "resolution_reason": resolution[
            "resolution_reason"
        ],

        "conditions_passed": conditions_passed,

        "trace": trace,
    }

    logger.info(
        "policy_evaluated",
        extra={
            "extra": {
                "decision":             result["decision"],
                "conditions_passed":    result["conditions_passed"],
                "governance_severity":  result["governance_severity"],
                "override_required":    result["override_required"],
                "requires_approval":    result["requires_approval"],
            }
        }
    )

    return result
