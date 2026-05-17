# engine/analyzers/architecture_analyzer.py

# Purpose:
# Analyze infrastructure architecture patterns.
#
# Responsibilities:
# - Architecture anti-pattern detection
# - Resilience assessment
# - Deployment structure analysis
# - Architecture risk scoring
#
# IMPORTANT:
# This analyzer NEVER performs enforcement.
# Findings are advisory only.


# =====================================================
# ANALYZER CONSTANTS
# =====================================================

# TODO:
# Replace with centralized scoring engine.
SINGLE_RESOURCE_RISK_WEIGHT = 20


def analyze_architecture(
    runtime_context: dict
) -> dict:
    """
    Analyze infrastructure architecture posture.
    """

    findings = []

    resources = runtime_context.get(
        "resources",
        []
    )

    # =================================================
    # SINGLE RESOURCE DETECTION
    # =================================================

    # NOTE:
    # Currently flags all single-resource deployments.
    #
    # Future:
    # Weight by:
    # - resource_class
    # - environment
    # - redundancy expectations
    #
    # Example:
    # - single S3 bucket → probably acceptable
    # - single production DB → higher concern

    if len(resources) == 1:

        findings.append({

            "type": "single_resource_architecture",

            "severity": "medium",

            "message": (
                "Single-resource deployment detected."
            )
        })

    risk_score = (
        SINGLE_RESOURCE_RISK_WEIGHT
        if findings
        else 0
    )

    return {

        "analyzer": "architecture_analyzer",

        "risk_score": risk_score,

        "findings": findings,

        "optimization_candidates": []
    }