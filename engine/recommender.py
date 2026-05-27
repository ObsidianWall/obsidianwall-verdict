# engine/recommender.py

# Purpose:
# Deterministic recommendation intelligence engine.
#
# Responsibilities:
# - Semantic recommendation generation
# - Analyzer recommendation enrichment
# - Recommendation deduplication
# - Recommendation scoring metadata propagation
#
# IMPORTANT:
# Recommendations NEVER influence enforcement decisions.
# Advisory systems are isolated from governance authority.


from audit.audit_logger import get_logger
from engine.optimization_catalog import OPTIMIZATION_RULES, RESOURCE_CLASSES

logger = get_logger()


# =====================================================
# RESOURCE CLASSIFICATION
# =====================================================


def classify_resource(resource_type: str) -> str:
    """
    Resolve semantic resource classification.

    Returns "unknown" for unrecognized resource types
    and emits a warning for observability.
    """

    classification = RESOURCE_CLASSES.get(resource_type)

    if classification is None:
        logger.warning(
            "unclassified_resource_type",
            extra={"extra": {"resource_type": resource_type}},
        )

        return "unknown"

    return classification


# =====================================================
# RULE MATCHING
# =====================================================


def match_rule_conditions(rule_conditions: dict, context: dict) -> bool:
    """
    Evaluate optimization rule applicability.

    Returns False for malformed rule conditions
    rather than raising.
    """

    if not isinstance(rule_conditions, dict):
        return False

    for key, expected_value in rule_conditions.items():
        actual_value = context.get(key)

        if actual_value != expected_value:
            return False

    return True


# =====================================================
# SEMANTIC RECOMMENDATIONS
# =====================================================


def generate_semantic_recommendations(resource_class: str, context: dict) -> list[dict]:
    """
    Generate semantic optimization recommendations
    from the optimization catalog.
    """

    recommendations = []

    for rule in OPTIMIZATION_RULES:
        if rule["resource_class"] != resource_class:
            continue

        if not match_rule_conditions(rule["conditions"], context):
            continue

        recommendations.extend(rule["recommendations"])

    return recommendations


# =====================================================
# ANALYZER ENRICHMENT
# =====================================================


def enrich_from_analyzers(analyzer_results: dict) -> list[dict]:
    """
    Convert analyzer findings and optimization candidates
    into structured recommendation objects.

    Skips malformed analyzer outputs defensively.
    """

    enriched_recommendations = []

    for analyzer_name, analyzer_data in analyzer_results.items():
        # -----------------------------------------
        # GUARD: malformed analyzer output
        # -----------------------------------------

        if not isinstance(analyzer_data, dict):
            logger.warning(
                "malformed_analyzer_output",
                extra={
                    "extra": {
                        "analyzer": analyzer_name,
                        "received_type": type(analyzer_data).__name__,
                    }
                },
            )

            continue

        findings = analyzer_data.get("findings", [])

        optimization_candidates = analyzer_data.get("optimization_candidates", [])

        # -----------------------------------------
        # FINDINGS
        # -----------------------------------------

        for finding in findings:
            enriched_recommendations.append(
                {
                    "type": finding.get("type", "analyzer_finding"),
                    "message": finding.get("message", "Analyzer finding detected."),
                    "severity": finding.get("severity", "medium"),
                    # TODO: Replace with scoring engine output.
                    "priority_score": 70,
                    # TODO: Derive from analyzer confidence signal.
                    "confidence": 0.85,
                    "estimated_savings_percent": 0,
                }
            )

        # -----------------------------------------
        # OPTIMIZATION CANDIDATES
        # -----------------------------------------

        for candidate in optimization_candidates:
            enriched_recommendations.append(
                {
                    "type": candidate.get("type", "optimization_candidate"),
                    "message": candidate.get(
                        "message", "Optimization opportunity identified."
                    ),
                    "severity": candidate.get("severity", "medium"),
                    "estimated_savings_percent": candidate.get(
                        "estimated_savings_percent", 0
                    ),
                    # TODO: Replace with scoring engine output.
                    "priority_score": 85,
                    # TODO: Derive from analyzer confidence signal.
                    "confidence": 0.90,
                }
            )

    return enriched_recommendations


# =====================================================
# DEDUPLICATION
# =====================================================


def deduplicate_recommendations(recommendations: list[dict]) -> list[dict]:
    """
    Remove duplicate recommendations by message.
    Preserves original ordering.
    Skips malformed recommendation objects defensively.
    """

    seen_messages = set()

    deduped = []

    for recommendation in recommendations:
        # -----------------------------------------
        # GUARD: missing message key
        # -----------------------------------------

        message = recommendation.get("message")

        if not message:
            logger.warning(
                "recommendation_missing_message",
                extra={"extra": {"recommendation": recommendation}},
            )

            continue

        if message in seen_messages:
            continue

        seen_messages.add(message)

        deduped.append(recommendation)

    return deduped


# =====================================================
# MAIN RECOMMENDATION PIPELINE
# =====================================================


def generate_suggestions(
    context: dict, decision: str, analyzer_results: dict
) -> list[dict]:
    """
    Generate deterministic infrastructure recommendations.

    Pipeline:
    1. Semantic catalog recommendations by resource class
    2. Analyzer enrichment from findings and candidates
    3. Enforcement guidance on DENY decisions
    4. Final deduplication

    Raises:
        TypeError:  if context or analyzer_results
                    are not dicts.
        ValueError: if decision is not a non-empty string.
    """

    # =================================================
    # BOUNDARY VALIDATION
    # =================================================

    if not isinstance(context, dict):
        raise TypeError("context must be a dict")

    if not isinstance(decision, str) or not decision:
        raise ValueError("decision must be a non-empty string")

    if not isinstance(analyzer_results, dict):
        raise TypeError("analyzer_results must be a dict")

    suggestions = []

    resources = context.get("resources", [])

    # =================================================
    # SEMANTIC RESOURCE RECOMMENDATIONS
    # =================================================

    seen_resource_classes = set()

    for resource in resources:
        resource_type = resource.get("type", "")

        resource_class = classify_resource(resource_type)

        if resource_class in seen_resource_classes:
            continue

        seen_resource_classes.add(resource_class)

        semantic_recommendations = generate_semantic_recommendations(
            resource_class, context
        )

        suggestions.extend(semantic_recommendations)

    # =================================================
    # ANALYZER ENRICHMENT
    # =================================================

    analyzer_recommendations = enrich_from_analyzers(analyzer_results)

    suggestions.extend(analyzer_recommendations)

    # =================================================
    # ENFORCEMENT GUIDANCE
    # =================================================

    if decision.startswith("DENY"):
        suggestions.append(
            {
                "type": "enforcement",
                "message": (
                    "Deployment blocked by policy enforcement. "
                    "Review evaluation trace for remediation guidance."
                ),
                "severity": "high",
                "priority_score": 95,
                "confidence": 1.0,
                "estimated_savings_percent": 0,
            }
        )

    # =================================================
    # FINAL DEDUPLICATION
    # =================================================

    deduped = deduplicate_recommendations(suggestions)

    # =================================================
    # AUDIT OBSERVABILITY
    # =================================================

    logger.info(
        "recommendations_generated",
        extra={
            "extra": {
                "decision": decision,
                "recommendation_count": len(deduped),
                "resource_classes": list(seen_resource_classes),
            }
        },
    )

    return deduped
