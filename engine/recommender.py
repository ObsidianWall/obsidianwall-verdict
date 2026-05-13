
# engine/recommender.py

# Responsibilities: optimization intelligence.


# Purpose:
# Generate NON-authoritative optimization recommendations.
#
# IMPORTANT:
# Suggestions NEVER influence enforcement decisions.
#
# This layer provides:
# - cost optimization
# - architecture recommendations
# - infrastructure right-sizing
# - operational guidance


# Purpose:
# Deterministic recommendation orchestration engine.
#
# IMPORTANT:
# Recommendations NEVER influence enforcement decisions.
# Recommendations are advisory only.


from engine.optimization_catalog import (
    RESOURCE_CLASSES,
    OPTIMIZATION_RULES
)


def classify_resource(resource_type: str) -> str:
    """
    Resolve semantic resource classification.
    """

    return RESOURCE_CLASSES.get(
        resource_type,
        "unknown"
    )


def match_rule_conditions(
    rule_conditions: dict,
    context: dict
) -> bool:
    """
    Evaluate optimization rule applicability.
    """

    for key, expected_value in rule_conditions.items():

        actual_value = context.get(key)

        if actual_value != expected_value:
            return False

    return True


def generate_semantic_recommendations(
    resource_class: str,
    context: dict
) -> list[dict]:
    """
    Generate semantic optimization recommendations.
    """

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


def generate_suggestions(
    context: dict,
    decision: str
) ->list[str]:
    """
    Generate deterministic infrastructure recommendations.
    """

    suggestions = []

    resources = context.get("resources", [])

    # -------------------------------------------------
    # RESOURCE ANALYSIS
    # -------------------------------------------------

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

        for recommendation in semantic_recommendations:

            suggestions.append(
                recommendation
            )


    # -------------------------------------------------
    # DECISION GUIDANCE
    # -------------------------------------------------

    # Change to suggestions.append(recommendation) — full dict
    # Fix the DENY guidance to match:
    if decision.startswith("DENY"):
        suggestions.append({
            "type": "enforcement",
            "message": (
                "Deployment blocked by policy enforcement. "
                "Review evaluation trace for remediation guidance."
            ),
            "estimated_savings_percent": 0
        })

    # Then dict deduplication works correctly
    seen_messages = set()
    deduped = []
    for suggestion in suggestions:
        message = suggestion["message"]
        if message not in seen_messages:
            seen_messages.add(message)
            deduped.append(suggestion)
    return deduped