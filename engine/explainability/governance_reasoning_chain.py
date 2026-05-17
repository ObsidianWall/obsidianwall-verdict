
# engine/explainability/governance_reasoning_chain.py

# Purpose:
# Build structured governance causal reasoning chains.
#
# Responsibilities:
# - Produce a sequential, stage-by-stage reasoning chain
#   connecting every phase of the governance pipeline
# - Translate technical pipeline outputs into
#   compliance-readable governance narratives
# - Surface the causal logic behind governance decisions
# - Provide a complete audit-defensible reasoning record
#
# IMPORTANT:
# This module NEVER influences enforcement decisions.
# Reasoning chains are produced AFTER the deterministic
# decision is resolved. Informational only.
#
# AUDIENCE:
# - Compliance officers (audit defensibility)
# - Budget owners (decision transparency)
# - Engineering leads (remediation guidance)
# - Governance dashboards (structured display)


from audit.audit_logger import get_logger


logger = get_logger()


# =====================================================
# STAGE DEFINITIONS
# =====================================================

class ReasoningStage:
    POLICY_INTENT           = "policy_intent"
    RUNTIME_NORMALIZATION   = "runtime_normalization"
    CONDITION_EVALUATION    = "condition_evaluation"
    ANALYZER_INTELLIGENCE   = "analyzer_intelligence"
    RISK_SCORING            = "risk_scoring"
    DECISION_RESOLUTION     = "decision_resolution"
    GOVERNANCE_ROUTING      = "governance_routing"


# =====================================================
# DECISION OUTCOME LABELS
# =====================================================

DECISION_OUTCOME_LABELS = {

    "ALLOW": (
        "Deployment authorized within governance boundaries."
    ),

    "ALLOW_WITH_NOTIFICATION": (
        "Deployment authorized. "
        "Governance stakeholders notified due to elevated severity."
    ),

    "ALLOW_WITH_APPROVAL_REQUIRED": (
        "Deployment conditionally authorized. "
        "Formal approval required before proceeding."
    ),

    "DENY_WITH_OVERRIDE": (
        "Deployment blocked. "
        "Override authority available — pending confirmation."
    ),

    "DENY": (
        "Deployment blocked. "
        "No override authority available for this role."
    ),
}


# =====================================================
# STAGE BUILDERS
# =====================================================

def _build_policy_intent_stage(
    policy_name: str,
    evaluation_result: dict,
    policy_governance: dict | None,
) -> dict:
    """
    Stage 1: What the policy is enforcing and why.
    """

    severity = (
        policy_governance.get("severity", "medium")
        if policy_governance
        else evaluation_result.get(
            "governance_severity", "medium"
        )
    )

    reason = (
        f"Policy '{policy_name}' defines governance "
        f"constraints for this infrastructure change. "
        f"Governance severity declared as '{severity}'. "
        f"Conditions will be evaluated deterministically "
        f"against the normalized runtime context."
    )

    return _build_stage(
        sequence=1,
        stage=ReasoningStage.POLICY_INTENT,
        outcome=f"Policy '{policy_name}' applied",
        reason=reason,
        severity=severity,
        governance_relevant=True,
        contributing_factors={
            "policy_name":          policy_name,
            "declared_severity":    severity,
        }
    )


def _build_normalization_stage(
    runtime_context: dict,
) -> dict:
    """
    Stage 2: How policy parameters were resolved
    into the runtime evaluation context.
    """

    # Identify flattened policy parameters
    # (dot-notation keys indicate normalized params)
    policy_params = {
        k: v for k, v in runtime_context.items()
        if "." in k and not isinstance(v, (dict, list))
    }

    infra_keys = {
        k: v for k, v in runtime_context.items()
        if "." not in k and not isinstance(v, (dict, list))
    }

    if policy_params:

        param_summary = ", ".join(
            f"{k}={v}" for k, v in list(policy_params.items())[:5]
        )

        reason = (
            f"Policy parameters normalized into flat "
            f"evaluation context via dot-notation keys. "
            f"Resolved parameters: {param_summary}. "
            f"Infrastructure context keys: "
            f"{', '.join(list(infra_keys.keys())[:5])}."
        )

    else:

        reason = (
            "Runtime context built from infrastructure "
            "context only. No nested policy parameters "
            "required flattening."
        )

    return _build_stage(
        sequence=2,
        stage=ReasoningStage.RUNTIME_NORMALIZATION,
        outcome=f"{len(policy_params)} policy parameter(s) normalized",
        reason=reason,
        severity="informational",
        governance_relevant=False,
        contributing_factors={
            "policy_param_count":   len(policy_params),
            "infra_key_count":      len(infra_keys),
        }
    )


def _build_condition_evaluation_stage(
    evaluation_result: dict,
) -> dict:
    """
    Stage 3: What conditions were checked and
    what the outcome was.
    """

    trace               = evaluation_result.get("trace", [])
    conditions_passed   = evaluation_result.get(
        "conditions_passed", False
    )

    total       = len(trace)
    passed      = sum(1 for t in trace if t.get("result"))
    failed      = total - passed

    if conditions_passed:

        outcome = f"All {total} condition(s) passed"

        reason = (
            f"All {total} policy condition(s) were satisfied. "
            f"Infrastructure configuration is within "
            f"policy-defined governance boundaries."
        )

        severity = "informational"

    else:

        outcome = f"{failed} of {total} condition(s) failed"

        # Build specific failure reasons from trace
        failure_details = []

        for trace_item in trace:
            if not trace_item.get("result"):
                failure_details.append(
                    f"'{trace_item.get('condition_id')}': "
                    f"{trace_item.get('expression')}"
                )

        failures_text = "; ".join(failure_details)

        reason = (
            f"{failed} of {total} policy condition(s) failed. "
            f"Failed condition(s): {failures_text}. "
            f"The infrastructure configuration does not satisfy "
            f"the policy-defined governance boundaries."
        )

        severity = "high"

    # Extract contributing context values referenced
    # in condition expressions
    contributing_factors = {
        "total_conditions":     total,
        "passed_conditions":    passed,
        "failed_conditions":    failed,
        "conditions_passed":    conditions_passed,
    }

    for trace_item in trace:
        contributing_factors[trace_item.get(
            "condition_id", "unknown"
        )] = trace_item.get("result")

    return _build_stage(
        sequence=3,
        stage=ReasoningStage.CONDITION_EVALUATION,
        outcome=outcome,
        reason=reason,
        severity=severity,
        governance_relevant=True,
        contributing_factors=contributing_factors,
    )


def _build_analyzer_intelligence_stage(
    analyzer_results: dict,
    risk_summary: dict,
) -> dict:
    """
    Stage 4: What the analyzers detected and
    the combined intelligence picture.
    """

    total_findings      = risk_summary.get("total_findings", 0)
    highest_analyzer    = risk_summary.get(
        "highest_risk_analyzer"
    )
    failed_analyzers    = risk_summary.get("failed_analyzers", [])
    analyzer_scores     = risk_summary.get("analyzer_scores", {})

    if total_findings == 0:

        outcome = "No significant findings detected"

        reason = (
            "All analyzers completed without detecting "
            "significant infrastructure risk patterns."
        )

        severity = "informational"

    else:

        # Build per-analyzer finding summaries
        finding_summaries = []

        for analyzer_name, analyzer_data in analyzer_results.items():

            if not isinstance(analyzer_data, dict):
                continue

            findings = analyzer_data.get("findings", [])

            if findings:

                finding_summaries.append(
                    f"{analyzer_name}: "
                    f"{len(findings)} finding(s)"
                )

        outcome = (
            f"{total_findings} finding(s) across "
            f"{len(analyzer_results)} analyzer(s)"
        )

        reason = (
            f"Infrastructure analyzers detected "
            f"{total_findings} finding(s). "
            f"{'; '.join(finding_summaries)}. "
        )

        if highest_analyzer:
            reason += (
                f"Highest risk contribution from "
                f"'{highest_analyzer}' "
                f"(score: {analyzer_scores.get(highest_analyzer, 0)})."
            )

        if failed_analyzers:
            reason += (
                f" {len(failed_analyzers)} analyzer(s) "
                f"failed and were excluded: "
                f"{', '.join(failed_analyzers)}."
            )

        severity = risk_summary.get("risk_severity", "medium")

    return _build_stage(
        sequence=4,
        stage=ReasoningStage.ANALYZER_INTELLIGENCE,
        outcome=outcome,
        reason=reason,
        severity=severity,
        governance_relevant=total_findings > 0,
        contributing_factors={
            "total_findings":       total_findings,
            "analyzer_count":       len(analyzer_results),
            "failed_analyzers":     failed_analyzers,
            "analyzer_scores":      analyzer_scores,
        }
    )


def _build_risk_scoring_stage(
    risk_summary: dict,
) -> dict:
    """
    Stage 5: The consolidated risk assessment
    and severity escalation outcome.
    """

    overall_score       = risk_summary.get(
        "overall_risk_score", 0
    )
    risk_severity       = risk_summary.get(
        "risk_severity", "informational"
    )
    policy_severity     = risk_summary.get(
        "policy_severity", "medium"
    )
    effective_severity  = risk_summary.get(
        "effective_severity", "medium"
    )

    outcome = (
        f"Overall risk score: {overall_score}/100 "
        f"({risk_severity})"
    )

    if effective_severity != policy_severity:

        reason = (
            f"Aggregated analyzer risk scores produced "
            f"an overall risk score of {overall_score}/100. "
            f"Risk severity classified as '{risk_severity}'. "
            f"Policy declared severity '{policy_severity}' — "
            f"escalated to '{effective_severity}' based on "
            f"analyzer intelligence. "
            f"The higher severity governs routing and notifications."
        )

    else:

        reason = (
            f"Aggregated analyzer risk scores produced "
            f"an overall risk score of {overall_score}/100. "
            f"Risk severity classified as '{risk_severity}'. "
            f"Effective severity remains '{effective_severity}' "
            f"consistent with declared policy severity."
        )

    return _build_stage(
        sequence=5,
        stage=ReasoningStage.RISK_SCORING,
        outcome=outcome,
        reason=reason,
        severity=effective_severity,
        governance_relevant=True,
        contributing_factors={
            "overall_risk_score":   overall_score,
            "risk_severity":        risk_severity,
            "policy_severity":      policy_severity,
            "effective_severity":   effective_severity,
        }
    )


def _build_decision_resolution_stage(
    evaluation_result: dict,
    user_role: str,
) -> dict:
    """
    Stage 6: How the final governance decision
    was reached and why.
    """

    decision            = evaluation_result.get(
        "decision", "UNKNOWN"
    )
    override_required   = evaluation_result.get(
        "override_required", False
    )
    requires_approval   = evaluation_result.get(
        "requires_approval", False
    )
    resolution_reason   = evaluation_result.get(
        "resolution_reason", ""
    )

    outcome_label = DECISION_OUTCOME_LABELS.get(
        decision,
        f"Governance decision '{decision}' reached."
    )

    reason = outcome_label

    if override_required and requires_approval:
        reason += (
            f" Role '{user_role}' has override authority "
            f"but formal approval is required before "
            f"deployment can proceed."
        )

    elif override_required:
        reason += (
            f" Role '{user_role}' has override authority. "
            f"Override can be confirmed without formal approval."
        )

    elif decision in ("DENY", "DENY_WITH_OVERRIDE"):
        reason += (
            f" Role '{user_role}' does not have override "
            f"authority for this policy. Remediation or "
            f"escalation required."
        )

    return _build_stage(
        sequence=6,
        stage=ReasoningStage.DECISION_RESOLUTION,
        outcome=decision,
        reason=reason,
        severity=evaluation_result.get(
            "governance_severity", "medium"
        ),
        governance_relevant=True,
        contributing_factors={
            "decision":             decision,
            "user_role":            user_role,
            "override_required":    override_required,
            "requires_approval":    requires_approval,
            "resolution_reason":    resolution_reason,
        }
    )


def _build_governance_routing_stage(
    evaluation_result: dict,
    policy_governance: dict | None,
    risk_summary: dict,
) -> dict:
    """
    Stage 7: What happens next — who gets notified,
    what approvals are needed, and what the
    governance workflow state is.
    """

    decision            = evaluation_result.get(
        "decision", "UNKNOWN"
    )
    requires_approval   = evaluation_result.get(
        "requires_approval", False
    )
    effective_severity  = risk_summary.get(
        "effective_severity", "medium"
    )

    # Extract notification targets from governance config
    notifications = []

    if policy_governance:
        for target in policy_governance.get(
            "notifications", []
        ):
            role    = target.get("role", "unknown")
            channel = target.get("channel", "email")
            notifications.append(
                f"{role} via {channel}"
            )

    # Build routing narrative
    routing_parts = []

    if notifications:
        routing_parts.append(
            f"Stakeholder notifications triggered: "
            f"{', '.join(notifications)}."
        )
    else:
        routing_parts.append(
            "No stakeholder notification targets configured."
        )

    if requires_approval:

        approval_roles = []

        if policy_governance:
            approvals = policy_governance.get(
                "approvals", {}
            )
            approval_roles = approvals.get("required", [])

        if approval_roles:
            routing_parts.append(
                f"Approval required from: "
                f"{', '.join(approval_roles)}. "
                f"Deployment is pending approval."
            )
        else:
            routing_parts.append(
                "Approval required. "
                "No approval roles configured — "
                "contact governance administrator."
            )

    if decision == "ALLOW":
        routing_parts.append(
            "Deployment may proceed. "
            "Audit record created."
        )

    elif decision in ("DENY", "DENY_WITH_OVERRIDE"):
        routing_parts.append(
            "Deployment is blocked. "
            "Engineer should review evaluation trace "
            "and remediation guidance."
        )

    reason = " ".join(routing_parts)

    outcome = (
        f"{len(notifications)} notification target(s)"
        if notifications
        else "No notifications configured"
    )

    return _build_stage(
        sequence=7,
        stage=ReasoningStage.GOVERNANCE_ROUTING,
        outcome=outcome,
        reason=reason,
        severity=effective_severity,
        governance_relevant=True,
        contributing_factors={
            "notification_targets": notifications,
            "requires_approval":    requires_approval,
            "effective_severity":   effective_severity,
            "decision":             decision,
        }
    )


# =====================================================
# STAGE FACTORY
# =====================================================

def _build_stage(
    sequence: int,
    stage: str,
    outcome: str,
    reason: str,
    severity: str,
    governance_relevant: bool,
    contributing_factors: dict,
) -> dict:
    """
    Build a single standardized reasoning chain stage.
    """

    return {
        "sequence":             sequence,
        "stage":                stage,
        "outcome":              outcome,
        "reason":               reason,
        "severity":             severity,
        "governance_relevant":  governance_relevant,
        "contributing_factors": contributing_factors,
    }


# =====================================================
# CHAIN SUMMARY
# =====================================================

def _build_chain_summary(
    chain: list[dict],
    evaluation_result: dict,
    risk_summary: dict,
) -> str:
    """
    Build a single-paragraph compliance-readable
    summary of the complete reasoning chain.
    """

    decision            = evaluation_result.get(
        "decision", "UNKNOWN"
    )
    conditions_passed   = evaluation_result.get(
        "conditions_passed", False
    )
    total_findings      = risk_summary.get(
        "total_findings", 0
    )
    overall_risk        = risk_summary.get(
        "overall_risk_score", 0
    )
    effective_severity  = risk_summary.get(
        "effective_severity", "medium"
    )
    requires_approval   = evaluation_result.get(
        "requires_approval", False
    )

    condition_summary = (
        "All policy conditions were satisfied."
        if conditions_passed
        else "One or more policy conditions failed."
    )

    finding_summary = (
        f"Infrastructure analysis identified "
        f"{total_findings} finding(s) with an overall "
        f"risk score of {overall_risk}/100."
        if total_findings > 0
        else "No significant infrastructure risk findings detected."
    )

    decision_summary = DECISION_OUTCOME_LABELS.get(
        decision,
        f"Governance decision: {decision}."
    )

    approval_summary = (
        "Formal approval is required before deployment can proceed."
        if requires_approval
        else ""
    )

    parts = [
        condition_summary,
        finding_summary,
        f"Effective governance severity: {effective_severity}.",
        decision_summary,
    ]

    if approval_summary:
        parts.append(approval_summary)

    return " ".join(parts)


# =====================================================
# MAIN REASONING CHAIN BUILDER
# =====================================================

def build_governance_reasoning_chain(
    evaluation_result: dict,
    analyzer_results: dict,
    risk_summary: dict,
    runtime_context: dict,
    policy_name: str,
    user_role: str = "engineer",
    policy_governance: dict | None = None,
) -> dict:
    """
    Build the complete structured governance reasoning chain.

    Connects every pipeline stage into a sequential,
    compliance-readable causal narrative.

    Stages:
        1. policy_intent          - what the policy enforces
        2. runtime_normalization  - how parameters resolved
        3. condition_evaluation   - what was checked
        4. analyzer_intelligence  - what was detected
        5. risk_scoring           - combined risk assessment
        6. decision_resolution    - how decision was reached
        7. governance_routing     - what happens next

    Args:
        evaluation_result:  Output from evaluate_policy()
        analyzer_results:   Output from all analyzers
        risk_summary:       Output from compute_risk_summary()
        runtime_context:    Normalized runtime context
        policy_name:        Name of the evaluated policy
        user_role:          Role of the requesting user
        policy_governance:  Serialized governance config
                            from policy.spec.governance.
                            None if policy has no governance block.

    Raises:
        TypeError:  if required inputs are not dicts.
        ValueError: if policy_name is empty.
    """

    # =================================================
    # BOUNDARY VALIDATION
    # =================================================

    if not isinstance(evaluation_result, dict):
        raise TypeError("evaluation_result must be a dict")

    if not isinstance(analyzer_results, dict):
        raise TypeError("analyzer_results must be a dict")

    if not isinstance(risk_summary, dict):
        raise TypeError("risk_summary must be a dict")

    if not isinstance(runtime_context, dict):
        raise TypeError("runtime_context must be a dict")

    if not policy_name:
        raise ValueError("policy_name must be a non-empty string")

    # =================================================
    # BUILD REASONING CHAIN
    # =================================================

    chain = [

        _build_policy_intent_stage(
            policy_name=policy_name,
            evaluation_result=evaluation_result,
            policy_governance=policy_governance,
        ),

        _build_normalization_stage(
            runtime_context=runtime_context,
        ),

        _build_condition_evaluation_stage(
            evaluation_result=evaluation_result,
        ),

        _build_analyzer_intelligence_stage(
            analyzer_results=analyzer_results,
            risk_summary=risk_summary,
        ),

        _build_risk_scoring_stage(
            risk_summary=risk_summary,
        ),

        _build_decision_resolution_stage(
            evaluation_result=evaluation_result,
            user_role=user_role,
        ),

        _build_governance_routing_stage(
            evaluation_result=evaluation_result,
            policy_governance=policy_governance,
            risk_summary=risk_summary,
        ),
    ]

    # =================================================
    # CHAIN SUMMARY
    # =================================================

    chain_summary = _build_chain_summary(
        chain=chain,
        evaluation_result=evaluation_result,
        risk_summary=risk_summary,
    )

    # =================================================
    # GOVERNANCE-RELEVANT STAGES ONLY
    # For compliance export — filter to stages that
    # directly influenced the governance decision.
    # =================================================

    governance_stages = [
        stage for stage in chain
        if stage.get("governance_relevant")
    ]

    artifact = {
        "reasoning_chain":          chain,
        "governance_stages":        governance_stages,
        "chain_summary":            chain_summary,
        "total_stages":             len(chain),
        "governance_stage_count":   len(governance_stages),
    }

    logger.info(
        "governance_reasoning_chain_built",
        extra={
            "extra": {
                "policy_name":          policy_name,
                "total_stages":         len(chain),
                "governance_stages":    len(governance_stages),
                "decision":             evaluation_result.get(
                    "decision"
                ),
                "effective_severity":   risk_summary.get(
                    "effective_severity"
                ),
            }
        }
    )

    return artifact
