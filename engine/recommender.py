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

from typing import Any

from audit.audit_logger import get_logger
from engine.optimization_catalog import OPTIMIZATION_RULES, RESOURCE_CLASSES

logger = get_logger()


# =====================================================
# RESOURCE CLASSIFICATION
# =====================================================


def classify_resource(resource_type: str) -> str:
    """
    Resolve semantic resource classification.
    Returns "unknown" for unrecognized resource types.
    """

    classification: str | None = RESOURCE_CLASSES.get(resource_type)

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


def match_rule_conditions(
    rule_conditions: dict[str, Any],
    context: dict[str, Any],
) -> bool:
    """
    Evaluate optimization rule applicability.
    Returns False for malformed rule conditions.
    """

    if not isinstance(rule_conditions, dict):
        return False

    for key, expected_value in rule_conditions.items():
        if context.get(key) != expected_value:
            return False

    return True


# =====================================================
# SEMANTIC RECOMMENDATIONS
# =====================================================


def generate_semantic_recommendations(
    resource_class: str,
    context: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Generate semantic optimization recommendations
    from the optimization catalog.
    """

    recommendations: list[dict[str, Any]] = []

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


def enrich_from_analyzers(
    analyzer_results: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Convert analyzer findings and optimization candidates
    into structured recommendation objects.
    Skips malformed analyzer outputs defensively.
    """

    enriched: list[dict[str, Any]] = []

    for analyzer_name, analyzer_data in analyzer_results.items():
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

        findings: list[Any] = analyzer_data.get("findings", [])
        optimization_candidates: list[Any] = analyzer_data.get(
            "optimization_candidates", []
        )

        for finding in findings:
            enriched.append(
                {
                    "type": finding.get("type", "analyzer_finding"),
                    "message": finding.get("message", "Analyzer finding detected."),
                    "severity": finding.get("severity", "medium"),
                    "priority_score": 70,
                    "confidence": 0.85,
                    "estimated_savings_percent": 0,
                }
            )

        for candidate in optimization_candidates:
            enriched.append(
                {
                    "type": candidate.get("type", "optimization_candidate"),
                    "message": candidate.get(
                        "message", "Optimization opportunity identified."
                    ),
                    "severity": candidate.get("severity", "medium"),
                    "estimated_savings_percent": candidate.get(
                        "estimated_savings_percent", 0
                    ),
                    "priority_score": 85,
                    "confidence": 0.90,
                }
            )

    return enriched


# =====================================================
# DEDUPLICATION
# =====================================================


def deduplicate_recommendations(
    recommendations: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Remove duplicate recommendations by message.
    Preserves original ordering.
    """

    seen_messages: set[str] = set()
    deduped: list[dict[str, Any]] = []

    for recommendation in recommendations:
        message: str | None = recommendation.get("message")

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
    context: dict[str, Any],
    decision: str,
    analyzer_results: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Generate deterministic infrastructure recommendations.

    Pipeline:
    1. Semantic catalog recommendations by resource class
    2. Analyzer enrichment from findings and candidates
    3. Enforcement guidance on DENY decisions
    4. Final deduplication

    Raises:
        TypeError:  if context or analyzer_results are not dicts.
        ValueError: if decision is not a non-empty string.
    """

    if not isinstance(context, dict):
        raise TypeError("context must be a dict")

    if not isinstance(decision, str) or not decision:
        raise ValueError("decision must be a non-empty string")

    if not isinstance(analyzer_results, dict):
        raise TypeError("analyzer_results must be a dict")

    suggestions: list[dict[str, Any]] = []
    resources: list[Any] = context.get("resources", [])

    seen_resource_classes: set[str] = set()

    for resource in resources:
        resource_type: str = resource.get("type", "")
        resource_class: str = classify_resource(resource_type)

        if resource_class in seen_resource_classes:
            continue

        seen_resource_classes.add(resource_class)
        suggestions.extend(generate_semantic_recommendations(resource_class, context))

    suggestions.extend(enrich_from_analyzers(analyzer_results))

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

    deduped: list[dict[str, Any]] = deduplicate_recommendations(suggestions)

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
