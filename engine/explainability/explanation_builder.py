
# engine/explainability/explanation_builder.py


# Purpose:
# Build top-level governance explainability artifacts.
#
# Responsibilities:
# - Orchestrate explainability sub-modules
# - Assemble the complete explanation artifact
# - Summarize decisions, reasoning, findings, recommendations
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

from audit.audit_logger import get_logger


logger = get_logger()


def build_explanation_artifact(
    evaluation_result: dict,
    analyzer_results: dict,
    recommendations: list[dict],
    runtime_context: dict,
) -> dict:
    """
    Build the complete governance explainability artifact.

    Assembles:
    - Policy reasoning chain (why the decision was made)
    - Analyzer findings summary (what was detected)
    - Explained recommendations (what to do and why)
    - Evaluation trace graph (how the decision was reached)

    Raises:
        TypeError:  if inputs are not expected types.
        ValueError: if evaluation_result is missing required keys.
    """

    # =================================================
    # BOUNDARY VALIDATION
    # =================================================

    if not isinstance(evaluation_result, dict):
        raise TypeError("evaluation_result must be a dict")

    if not isinstance(analyzer_results, dict):
        raise TypeError("analyzer_results must be a dict")

    if not isinstance(recommendations, list):
        raise TypeError("recommendations must be a list")

    if not isinstance(runtime_context, dict):
        raise TypeError("runtime_context must be a dict")

    required_keys = {"decision", "conditions_passed", "trace"}
    missing_keys = required_keys - evaluation_result.keys()

    if missing_keys:
        raise ValueError(
            f"evaluation_result missing required keys: {missing_keys}"
        )

    # =================================================
    # POLICY REASONING
    # =================================================

    policy_reasoning = build_policy_reasoning(
        decision=evaluation_result.get("decision", "UNKNOWN"),
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
        decision=evaluation_result.get("decision", "UNKNOWN"),
    )

    # =================================================
    # TRACE GRAPH
    # =================================================

    trace_graph = build_trace_graph(
        evaluation_result=evaluation_result,
        analyzer_results=analyzer_results,
        runtime_context=runtime_context,
    )

    # =================================================
    # ASSEMBLE ARTIFACT
    # =================================================

    artifact = {
        "decision":                     evaluation_result.get("decision"),
        "conditions_passed":            evaluation_result.get("conditions_passed"),
        "policy_reasoning":             policy_reasoning,
        "analyzer_findings":            analyzer_findings,
        "explained_recommendations":    explained_recommendations,
        "trace_graph":                  trace_graph,
    }

    logger.info(
        "explanation_artifact_built",
        extra={
            "extra": {
                "decision":                 artifact["decision"],
                "reasoning_steps":          len(
                    policy_reasoning.get("reasoning_chain", [])
                ),
                "analyzer_finding_count":   len(analyzer_findings),
                "recommendation_count":     len(
                    explained_recommendations
                ),
            }
        }
    )

    return artifact


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
