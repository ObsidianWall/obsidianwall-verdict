
# engine/explainability/policy_reasoning.py

# Purpose:
# Generate plain-English governance reasoning artifacts.
#
# Responsibilities:
# - Explain WHY a governance decision was made
# - Translate condition evaluation traces into
#   human-readable causal reasoning chains
# - Produce compliance-ready decision narratives
# - Surface remediation guidance on failed conditions
#
# IMPORTANT:
# This module NEVER influences enforcement decisions.
# Reasoning artifacts are informational only.
# Produced AFTER the deterministic decision is resolved.


from audit.audit_logger import get_logger


logger = get_logger()


# =====================================================
# DECISION NARRATIVES
# =====================================================

DECISION_NARRATIVES = {

    "ALLOW": (
        "All policy conditions were satisfied. "
        "The infrastructure change is within governance boundaries."
    ),

    "ALLOW_WITH_NOTIFICATION": (
        "Policy conditions were satisfied. "
        "However, governance severity warrants stakeholder notification. "
        "Budget owners and engineering leads have been notified."
    ),

    "ALLOW_WITH_APPROVAL_REQUIRED": (
        "Policy conditions were satisfied. "
        "Governance policy requires formal approval before deployment proceeds. "
        "Pending approval from designated governance stakeholders."
    ),

    "DENY_WITH_OVERRIDE": (
        "One or more policy conditions failed. "
        "An authorized override role is present. "
        "Deployment is blocked pending override confirmation or approval."
    ),

    "DENY": (
        "One or more policy conditions failed. "
        "No override authority is available for this role. "
        "Deployment is blocked. Review the evaluation trace for remediation."
    ),
}


# =====================================================
# SEVERITY NARRATIVES
# =====================================================

SEVERITY_NARRATIVES = {

    "informational": (
        "This is an informational governance event. "
        "No action is required."
    ),

    "low": (
        "Low governance severity. "
        "Advisory awareness recommended."
    ),

    "medium": (
        "Medium governance severity. "
        "Budget owner notification has been triggered."
    ),

    "high": (
        "High governance severity. "
        "Immediate stakeholder notification and review required."
    ),

    "critical": (
        "Critical governance severity. "
        "Escalation to senior governance stakeholders required immediately."
    ),
}


# =====================================================
# CONDITION REASONING
# =====================================================

def _explain_condition(
    trace_item: dict
) -> dict:
    """
    Translate a single condition trace item into
    a plain-English reasoning step.
    """

    condition_id    = trace_item.get("condition_id", "unknown")
    expression      = trace_item.get("expression", "")
    result          = trace_item.get("result", False)
    description     = trace_item.get("description", "")

    if result:

        explanation = (
            f"Condition '{condition_id}' passed. "
            f"{description}. "
            f"Expression evaluated to true: {expression}."
        )

        remediation = None

    else:

        explanation = (
            f"Condition '{condition_id}' failed. "
            f"{description}. "
            f"Expression evaluated to false: {expression}."
        )

        remediation = _build_remediation_guidance(
            condition_id,
            expression,
        )

    return {
        "condition_id":     condition_id,
        "passed":           result,
        "explanation":      explanation,
        "remediation":      remediation,
    }


def _build_remediation_guidance(
    condition_id: str,
    expression: str,
) -> str:
    """
    Generate contextual remediation guidance
    for a failed condition.
    """

    # Budget-related conditions
    if "budget" in expression.lower() or "spend" in expression.lower():
        return (
            "Reduce the estimated infrastructure cost to satisfy "
            "the budget constraint, or contact your budget owner "
            "to request a budget adjustment or override authorization."
        )

    # Cost-related conditions
    if "cost" in expression.lower():
        return (
            "Review resource sizing and configuration to reduce "
            "projected costs below the policy threshold."
        )

    # Generic remediation
    return (
        f"Review the condition expression '{expression}' "
        f"and adjust infrastructure configuration to satisfy "
        f"the policy requirement."
    )


# =====================================================
# POLICY REASONING BUILDER
# =====================================================

def build_policy_reasoning(
    decision: str,
    conditions_passed: bool,
    trace: list[dict],
) -> dict:
    """
    Build a plain-English governance reasoning artifact.

    Produces:
    - Decision narrative (why this outcome was reached)
    - Per-condition reasoning chain (what was evaluated)
    - Remediation guidance (what to do next on failure)
    - Governance summary (compliance-readable outcome)

    Raises:
        TypeError:  if trace is not a list.
        ValueError: if decision is not a non-empty string.
    """

    # =================================================
    # BOUNDARY VALIDATION
    # =================================================

    if not isinstance(trace, list):
        raise TypeError("trace must be a list")

    if not isinstance(decision, str) or not decision:
        raise ValueError(
            "decision must be a non-empty string"
        )

    # =================================================
    # DECISION NARRATIVE
    # =================================================

    decision_narrative = DECISION_NARRATIVES.get(
        decision,
        (
            f"Governance decision '{decision}' was reached. "
            f"Review the evaluation trace for details."
        )
    )

    # =================================================
    # CONDITION REASONING CHAIN
    # =================================================

    reasoning_chain = []
    failed_conditions = []
    passed_conditions = []

    for trace_item in trace:

        if not isinstance(trace_item, dict):
            continue

        condition_reasoning = _explain_condition(
            trace_item
        )

        reasoning_chain.append(condition_reasoning)

        if condition_reasoning["passed"]:
            passed_conditions.append(
                condition_reasoning["condition_id"]
            )
        else:
            failed_conditions.append(
                condition_reasoning["condition_id"]
            )

    # =================================================
    # GOVERNANCE SUMMARY
    # =================================================

    if conditions_passed:

        governance_summary = (
            f"All {len(passed_conditions)} policy condition(s) "
            f"passed. Governance boundaries satisfied."
        )

    else:

        governance_summary = (
            f"{len(failed_conditions)} of "
            f"{len(trace)} policy condition(s) failed. "
            f"Failed conditions: "
            f"{', '.join(failed_conditions)}."
        )

    # =================================================
    # REMEDIATION SUMMARY
    # =================================================

    remediations = [
        step["remediation"]
        for step in reasoning_chain
        if step.get("remediation")
    ]

    artifact = {
        "decision_narrative":   decision_narrative,
        "governance_summary":   governance_summary,
        "reasoning_chain":      reasoning_chain,
        "passed_conditions":    passed_conditions,
        "failed_conditions":    failed_conditions,
        "remediation_steps":    remediations,
    }

    logger.info(
        "policy_reasoning_built",
        extra={
            "extra": {
                "decision":             decision,
                "conditions_passed":    conditions_passed,
                "passed_count":         len(passed_conditions),
                "failed_count":         len(failed_conditions),
            }
        }
    )

    return artifact
