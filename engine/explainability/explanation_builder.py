# engine/explainability/explanation_builder.py

# Purpose:
# Build top-level governance explainability artifacts.
#
# Responsibilities:
# - Orchestrate explainability sub-modules
# - Assemble the complete explanation artifact
# - Surface consolidated risk summary
# - Build governance reasoning chain
# - Summarize decisions, reasoning, findings,
#   recommendations
#
# IMPORTANT:
# Explainability NEVER influences enforcement decisions.
# This layer is informational and audit-support only.


from engine.explainability.policy_reasoning import (
    build_policy_reasoning
)

from engine.explainability.recommendation_explainer import (
    explain_recommendations
)

from engine.explainability.trace_graph import (
    build_trace_graph
)

from engine.explainability.governance_reasoning_chain import (
    build_governance_reasoning_chain
)

from audit.audit_logger import get_logger


logger = get_logger()


def build_explanation_artifact(
    evaluation_result: dict,
    analyzer_results: dict,
    recommendations: list[dict],
    runtime_context: dict,
    risk_summary: dict | None = None,
    policy_name: str = "unknown",
    user_role: str = "engineer",
    policy_governance: dict | None = None,
) -> dict:
    """
    Build the complete governance explainability artifact.

    Assembles:
    - Governance reasoning chain (causal pipeline narrative)
    - Consolidated risk summary
    - Policy reasoning (condition-level explanation)
    - Analyzer findings summary
    - Explained recommendations
    - Evaluation trace graph

    Args:
        evaluation_result:  Output from evaluate_policy()
        analyzer_results:   Output from all analyzer executions
        recommendations:    Output from generate_suggestions()
        runtime_context:    Normalized runtime evaluation context
        risk_summary:       Pre-computed from compute_risk_summary()
        policy_name:        Name of the evaluated policy
        user_role:          Role of the requesting user
        policy_governance:  Serialized governance config from
                            policy.spec.governance.model_dump()
                            None if policy has no governance block.

    Raises:
        TypeError:  if inputs are not expected types.
        ValueError: if evaluation_result is missing required keys.
    """

    # =================================================
    # BOUNDARY VALIDATION
    # =================================================

    if not isinstance(evaluation_result, dict):
        raise TypeError(
            "evaluation_result must be a dict"
        )

    if not isinstance(analyzer_results, dict):
        raise TypeError(
            "analyzer_results must be a dict"
        )

    if not isinstance(recommendations, list):
        raise TypeError(
            "recommendations must be a list"
        )

    if not isinstance(runtime_context, dict):
        raise TypeError(
            "runtime_context must be a dict"
        )

    required_keys = {
        "decision",
        "conditions_passed",
        "trace"
    }

    missing_keys = required_keys - evaluation_result.keys()

    if missing_keys:
        raise ValueError(
            f"evaluation_result missing required keys: "
            f"{missing_keys}"
        )

    # =================================================
    # GOVERNANCE REASONING CHAIN
    # Built first — provides the complete causal
    # narrative connecting all pipeline stages.
    # =================================================

    governance_reasoning = build_governance_reasoning_chain(
        evaluation_result=evaluation_result,
        analyzer_results=analyzer_results,
        risk_summary=risk_summary or {},
        runtime_context=runtime_context,
        policy_name=policy_name,
        user_role=user_role,
        policy_governance=policy_governance,
    )

    # =================================================
    # POLICY REASONING
    # Condition-level explanation — WHY each
    # condition passed or failed.
    # =================================================

    policy_reasoning = build_policy_reasoning(
        decision=evaluation_result.get(
            "decision", "UNKNOWN"
        ),
        conditions_passed=evaluation_result.get(
            "conditions_passed", False
        ),
        trace=evaluation_result.get("trace", []),
    )

    # =================================================
    # ANALYZER FINDINGS SUMMARY
    # =================================================

    analyzer_findings = _summarize_analyzer_findings(
        analyzer_results
    )

    # =================================================
    # EXPLAINED RECOMMENDATIONS
    # =================================================

    explained_recommendations = explain_recommendations(
        recommendations=recommendations,
        decision=evaluation_result.get(
            "decision", "UNKNOWN"
        ),
    )

    # =================================================
    # TRACE GRAPH
    # Pre-computed risk_summary passed in —
    # no internal recomputation.
    # =================================================

    trace_graph = build_trace_graph(
        evaluation_result=evaluation_result,
        analyzer_results=analyzer_results,
        runtime_context=runtime_context,
        risk_summary=risk_summary,
    )

    # =================================================
    # ASSEMBLE ARTIFACT
    # =================================================

    artifact = {

        "decision": evaluation_result.get("decision"),

        "conditions_passed": evaluation_result.get(
            "conditions_passed"
        ),

        # -----------------------------------------
        # RISK SUMMARY
        # Consolidated across all analyzers.
        # Surfaces at top level for readability.
        # -----------------------------------------
        "risk_summary": risk_summary,

        # -----------------------------------------
        # GOVERNANCE REASONING CHAIN
        # Complete causal pipeline narrative.
        # Primary compliance artifact.
        # -----------------------------------------
        "governance_reasoning": governance_reasoning,

        # -----------------------------------------
        # CONDITION-LEVEL REASONING
        # -----------------------------------------
        "policy_reasoning": policy_reasoning,

        # -----------------------------------------
        # INTELLIGENCE SUMMARIES
        # -----------------------------------------
        "analyzer_findings":            analyzer_findings,

        "explained_recommendations":    explained_recommendations,

        # -----------------------------------------
        # EXECUTION LINEAGE GRAPH
        # -----------------------------------------
        "trace_graph":                  trace_graph,
    }

    logger.info(
        "explanation_artifact_built",
        extra={
            "extra": {
                "decision":             artifact["decision"],
                "policy_name":          policy_name,
                "reasoning_stages":     governance_reasoning.get(
                    "total_stages", 0
                ),
                "governance_stages":    governance_reasoning.get(
                    "governance_stage_count", 0
                ),
                "analyzer_findings":    len(analyzer_findings),
                "recommendation_count": len(
                    explained_recommendations.get(
                        "all_recommendations", []
                    )
                ),
                "overall_risk_score": (
                    risk_summary.get("overall_risk_score", 0)
                    if risk_summary else 0
                ),
                "effective_severity": (
                    risk_summary.get("effective_severity", "unknown")
                    if risk_summary else "unknown"
                ),
            }
        }
    )

    return artifact


# =====================================================
# INTERNAL HELPERS
# =====================================================

def _summarize_analyzer_findings(
    analyzer_results: dict
) -> list[dict]:
    """
    Flatten and summarize findings across all analyzers.
    Skips malformed analyzer outputs defensively.
    """

    summary = []

    for analyzer_name, analyzer_data in analyzer_results.items():

        if not isinstance(analyzer_data, dict):
            continue

        findings = analyzer_data.get("findings", [])

        for finding in findings:

            message = finding.get("message")
            if not message:
                continue

            summary.append({
                "analyzer":     analyzer_name,
                "type":         finding.get("type", "unknown"),
                "severity":     finding.get("severity", "medium"),
                "message":      message,
            })

    return summary
