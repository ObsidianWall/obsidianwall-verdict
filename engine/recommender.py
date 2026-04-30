# egine/recommender.py

# Purpose: Provide actionable alternatives (AI-lite layer)

# Purpose: Generate recommendations based on the evaluated conditions and context

# This module provides recommendations based on the context of the Terraform plan.

def generate_suggestions(context):
    suggestions = []

    if context["estimated_cost"] > 50:
        suggestions.append("Use smaller VM instance")
        suggestions.append("Switch to serverless architecture")

    return suggestions