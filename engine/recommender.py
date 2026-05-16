# engine/recommender.py

# Purpose:
# Deterministic recommendation intelligence engine.
#
# IMPORTANT:
# Recommendations NEVER influence enforcement decisions.
# Advisory systems are isolated from governance authority.


from engine.optimization_catalog import (
    RESOURCE_CLASSES,
    OPTIMIZATION_RULES
)


# =====================================================
# RESOURCE CLASSIFICATION
# =====================================================

def classify_resource(
    resource_type: str
) -> str:

    return RESOURCE_CLASSES.get(
        resource_type,
        "unknown"
    )


# =====================================================
# RULE CONDITION MATCHING
# =====================================================

def match_rule_conditions(
    rule_conditions: dict,
    context: dict
) -> bool:

    for key, expected_value in rule_conditions.items():

        actual_value = context.get(key)

        if actual_value != expected_value:
            return False

    return True


# =====================================================
# SEMANTIC CATALOG RECOMMENDATIONS
# =====================================================

def generate_semantic_recommendations(
    resource_class: str,
    context: dict
) -> list[dict]:

    recommendations = []

    for rule in OPTIMIZATION_RULES:

        if rule["resource_class"] != resource_class:
            continue

        if not match_rule_conditions(
            rule["conditions"],
            context
        ):
            continue

        recommendations.extend(
            rule["recommendations"]
        )

    return recommendations


# =====================================================
# ANALYZER RECOMMENDATION ENRICHMENT
# =====================================================

def enrich_from_analyzers(
    analyzer_results: dict
) -> list[dict]:

    enriched_recommendations = []

    for analyzer_name, analyzer_data in analyzer_results.items():

        findings = analyzer_data.get(
            "findings",
            []
        )

        optimization_candidates = analyzer_data.get(
            "optimization_candidates",
            []
        )

        # -------------------------------------------------
        # FINDING-BASED RECOMMENDATIONS
        # -------------------------------------------------

        for finding in findings:

            enriched_recommendations.append({

                "type": finding.get(
                    "type",
                    "analyzer_finding"
                ),

                "message": finding.get(
                    "message",
                    "Analyzer finding detected."
                ),

                "severity": finding.get(
                    "severity",
                    "medium"
                ),

                "priority_score": 70,  # TODO: replace with scoring engine output

                "confidence": 0.85,  # TODO: derive from analyzer confidence signal

                "estimated_savings_percent": 0,
            })

        # -------------------------------------------------
        # OPTIMIZATION CANDIDATES
        # -------------------------------------------------

        for candidate in optimization_candidates:

            enriched_recommendations.append({

                "type": candidate.get(
                    "type",
                    "optimization"
                ),

                "message": (
                    "Optimization opportunity identified."
                ),

                "severity": "medium",

                "priority_score": 85,  # TODO: replace with scoring engine output

                "confidence": 0.90,   # TODO: derive from analyzer confidence signal

                "estimated_savings_percent": (
                    candidate.get(
                        "estimated_savings_percent",
                        0
                    )
                ),
            })

    return enriched_recommendations


# =====================================================
# RECOMMENDATION DEDUPLICATION
# =====================================================

def deduplicate_recommendations(
    recommendations: list[dict]
) -> list[dict]:

    seen_messages = set()

    deduped = []

    for recommendation in recommendations:

        message = recommendation["message"]

        if message not in seen_messages:

            seen_messages.add(message)

            deduped.append(recommendation)

    return deduped


# =====================================================
# MAIN RECOMMENDATION PIPELINE
# =====================================================

def generate_suggestions(
    context: dict,
    decision: str,
    analyzer_results: dict
) -> list[dict]:

    suggestions = []

    resources = context.get(
        "resources",
        []
    )

    # =================================================
    # SEMANTIC RESOURCE RECOMMENDATIONS
    # =================================================

    for resource in resources:

        resource_type = resource.get(
            "type",
            ""
        )

        resource_class = classify_resource(
            resource_type
        )

        semantic_recommendations = (
            generate_semantic_recommendations(
                resource_class,
                context
            )
        )

        suggestions.extend(
            semantic_recommendations
        )

    # =================================================
    # ANALYZER ENRICHMENT
    # =================================================

    analyzer_recommendations = (
        enrich_from_analyzers(
            analyzer_results
        )
    )

    suggestions.extend(
        analyzer_recommendations
    )

    # =================================================
    # ENFORCEMENT GUIDANCE
    # =================================================

    if decision.startswith("DENY"):

        suggestions.append({

            "type": "enforcement",

            "message": (
                "Deployment blocked by policy enforcement. "
                "Review evaluation trace for remediation guidance."
            ),

            "severity": "high",

            "priority_score": 95,  # TODO: replace with scoring engine output

            "confidence": 1.0,    # TODO: derive from analyzer confidence signal

            "estimated_savings_percent": 0,
        })

    # =================================================
    # FINAL DEDUPLICATION
    # =================================================

    return deduplicate_recommendations(
        suggestions
    )