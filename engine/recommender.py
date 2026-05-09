
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


def generate_suggestions(context: dict, decision: str):
    """
    Generate advisory optimization suggestions.

    Parameters:
        context (dict): Parsed infrastructure context
        decision (str): Final engine decision

    Returns:
        list[str]
    """

    suggestions = []

    estimated_cost = context.get("estimated_cost", 0)
    resource_count = context.get("resource_count", 0)
    resources = context.get("resources", [])

    # ---------------------------------------------------
    # COST OPTIMIZATION
    # ---------------------------------------------------

    if estimated_cost > 50:
        suggestions.append(
            "Projected infrastructure cost exceeds recommended budget threshold."
        )

        suggestions.append(
            "Consider migrating burst workloads to serverless infrastructure."
        )

        suggestions.append(
            "Evaluate smaller compute instance sizes for non-production workloads."
        )

    # ---------------------------------------------------
    # RESOURCE FOOTPRINT OPTIMIZATION
    # ---------------------------------------------------

    if resource_count > 10:
        suggestions.append(
            "Large infrastructure footprint detected. Consider workload consolidation."
        )

    # ---------------------------------------------------
    # SECURITY + ARCHITECTURE RECOMMENDATIONS
    # ---------------------------------------------------

    for resource in resources:

        resource_type = resource.get("type", "").lower()

        # VM optimization
        if "aws_instance" in resource_type:
            suggestions.append(
                "EC2 instances detected. Evaluate autoscaling or spot instances for cost efficiency."
            )

        # Storage optimization
        if "s3" in resource_type:
            suggestions.append(
                "S3 resources detected. Review lifecycle policies for storage cost optimization."
            )

        # Database optimization
        if "db" in resource_type:
            suggestions.append(
                "Database resources detected. Review reserved capacity options."
            )

    # ---------------------------------------------------
    # DENY-SPECIFIC GUIDANCE
    # ---------------------------------------------------

    if decision.startswith("DENY"):
        suggestions.append(
            "Deployment blocked by policy enforcement. Review trace output for remediation guidance."
        )

    return suggestions