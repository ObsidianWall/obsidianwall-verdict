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


from typing import Any

from audit.audit_logger import get_logger
from engine.condition_evaluator import evaluate_conditions
from engine.decision_resolver import resolve_decision
from schemas.policy_schema import Policy

logger = get_logger()


def evaluate_policy(
    policy: Policy,
    runtime_context: dict[str, Any],
    user_role: str = "engineer",
) -> dict[str, Any]:
    """
    Evaluate a validated policy against runtime context.

    Returns:
        dict containing:
        - decision:             5-level governance decision outcome
        - override_required:    whether an override was applied
        - override_possible:    whether the policy allows any override
        - requires_approval:    whether formal approval is needed
        - governance_severity:  severity level for routing
        - resolution_reason:    why this decision was reached
        - conditions_passed:    boolean outcome of condition evaluation
        - trace:                per-condition evaluation trace
    """

    # =================================================
    # CONDITION EVALUATION
    # =================================================

    conditions_passed, trace = evaluate_conditions(policy, runtime_context)

    # =================================================
    # DECISION RESOLUTION
    # =================================================

    resolution: dict[str, Any] = resolve_decision(policy, conditions_passed, user_role)

    result: dict[str, Any] = {
        "decision": resolution["decision"],
        "override_required": resolution["override_required"],
        "override_possible": resolution["override_possible"],
        "requires_approval": resolution["requires_approval"],
        "governance_severity": resolution["governance_severity"],
        "resolution_reason": resolution["resolution_reason"],
        "conditions_passed": conditions_passed,
        "trace": trace,
    }

    logger.info(
        "policy_evaluated",
        extra={
            "extra": {
                "decision": result["decision"],
                "conditions_passed": result["conditions_passed"],
                "governance_severity": result["governance_severity"],
                "override_required": result["override_required"],
                "override_possible": result["override_possible"],
                "requires_approval": result["requires_approval"],
            }
        },
    )

    return result
