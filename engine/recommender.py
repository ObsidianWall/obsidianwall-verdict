# engine/recommender.py
#
# Purpose:
# Deterministic recommendation intelligence engine.
#
# Responsibilities:
# - Semantic recommendation generation
# - Analyzer recommendation enrichment
# - Recommendation deduplication
# - Recommendation scoring metadata propagation
#
# recommendation_confidence explained:
#   A deterministic rule-based score (0.0–1.0) expressing
#   how directly this recommendation addresses the specific
#   finding that triggered it. This is NOT probabilistic and
#   NOT AI-generated confidence. It is a domain-authored
#   score that reflects:
#     - Direct match: recommendation directly resolves finding (0.90–0.95)
#     - Partial match: recommendation improves the situation (0.70–0.85)
#     - Weak match:   recommendation is generic guidance    (0.50–0.69)
#   Scores increase over time as outcome telemetry from
#   Sentinel allows effectiveness correlation via Compass.
#
# IMPORTANT:
# Recommendations NEVER influence enforcement decisions.
# Advisory systems are isolated from governance authority.

from typing import Any

from audit.audit_logger import get_logger
from engine.optimization_catalog import OPTIMIZATION_RULES, RESOURCE_CLASSES

logger = get_logger()


# =====================================================
# RECOMMENDATION CONFIDENCE SCORES
#
# Rule-based confidence per finding type.
# Reflects how directly a recommendation addresses
# the specific finding — not probabilistic, not AI.
#
# Scale:
#   0.90–1.00  Direct: recommendation resolves finding
#   0.75–0.89  Strong: recommendation significantly improves
#   0.60–0.74  Partial: recommendation partially addresses
#   0.40–0.59  Weak:    recommendation is generic guidance
# =====================================================

_FINDING_CONFIDENCE: dict[str, float] = {
    # Cost findings — direct remediation paths exist
    "budget_exceeded": 0.95,
    "elevated_projected_cost": 0.80,
    "cost_anomaly": 0.75,
    # Security findings — direct remediation paths exist
    "open_ingress_rules": 0.92,
    "unencrypted_databases": 0.95,
    "public_storage_buckets": 0.90,
    "ssl_not_enforced": 0.93,
    "versioning_disabled": 0.88,
    # Network findings
    "missing_network_segmentation": 0.75,
    # Identity findings
    "missing_mfa": 0.92,
    "excessive_permissions": 0.78,
    # Operational findings
    "missing_tags": 0.85,
    "untagged_resources": 0.85,
    "missing_monitoring": 0.80,
    # Architecture findings
    "no_redundancy": 0.72,
    "single_region": 0.68,
    "missing_backup": 0.82,
    # Utilization findings
    "oversized_instance": 0.85,
    "burstable_candidate": 0.78,
    "gpu_underutilization": 0.70,
}

# Default confidence when finding type is not in the map.
# Represents a generic recommendation with no specific match.
_DEFAULT_FINDING_CONFIDENCE: float = 0.65

# Optimization candidates have lower default confidence
# because they are opportunities, not direct finding responses.
_OPTIMIZATION_CANDIDATE_CONFIDENCE: float = 0.72

# Enforcement guidance is always certain — the deployment
# was blocked by deterministic policy evaluation.
_ENFORCEMENT_CONFIDENCE: float = 1.0


def _get_finding_confidence(finding_type: str) -> float:
    """
    Return the recommendation confidence score for a finding type.

    Looks up the finding type in the domain-authored confidence map.
    Falls back to the default confidence for unknown finding types.
    Never raises — unknown types return the default, not an error.
    """
    return _FINDING_CONFIDENCE.get(finding_type, _DEFAULT_FINDING_CONFIDENCE)


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
        # Demoted from WARNING to DEBUG — an unclassified
        # resource type during normal operation is routine
        # (new Terraform resource types appear constantly),
        # not evidence of a real problem. This was the second
        # source (alongside cost_estimator.py's fallback
        # warning) of the JSON noise flooding a real
        # `verdict evaluate` run tonight.
        logger.debug(
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

    recommendation_confidence is assigned per finding type
    from the domain-authored _FINDING_CONFIDENCE map rather
    than hardcoded. This reflects how directly each
    recommendation addresses the specific finding.

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
            finding_type = finding.get("type", "analyzer_finding")
            enriched.append(
                {
                    "type": finding_type,
                    "message": finding.get("message", "Analyzer finding detected."),
                    "severity": finding.get("severity", "medium"),
                    "priority_score": 70,
                    # Rule-based confidence: how directly does this
                    # recommendation address this specific finding type.
                    # Not probabilistic — see _FINDING_CONFIDENCE map.
                    "recommendation_confidence": _get_finding_confidence(finding_type),
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
                    # Optimization candidates use a fixed confidence
                    # because they are opportunities rather than direct
                    # responses to a specific detected finding.
                    "recommendation_confidence": _OPTIMIZATION_CANDIDATE_CONFIDENCE,
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

    All recommendation_confidence scores are rule-based and
    deterministic. They are NOT AI-generated or probabilistic.
    See _FINDING_CONFIDENCE for the domain-authored score map.

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
                # Enforcement guidance is always certain — the block
                # is the result of deterministic policy evaluation,
                # not an inferred recommendation.
                "recommendation_confidence": _ENFORCEMENT_CONFIDENCE,
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
