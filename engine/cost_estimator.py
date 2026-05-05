
# engine/cost_estimator.py

# Purpose: Estimate costs based on parsed Terraform plan data


# 🎯 Purpose: Convert resources → estimated monthly cost

# ⚠️ Design Decision
  # We use:
  # deterministic pricing table
  # simple heuristics
  # extensible model

# This module provides a cost estimation function that takes the structured context produced by the Terraform parser and applies a simple pricing model to estimate monthly costs. The estimation is based on resource types and key configuration parameters, using predefined pricing tables for common resources.

# The `estimate_cost` function iterates through the parsed resources, applies the pricing logic based on resource type and configuration, and returns a total estimated cost along with a breakdown by resource. This allows for a clear understanding of which resources contribute most to the overall cost, enabling informed decision-making in the guardrail evaluation process.

# Note: This is a simplified cost estimation model for demonstration purposes. In a production system, you would likely want to integrate with real pricing APIs from cloud providers and consider additional factors such as usage patterns, discounts, and regional pricing variations.

# Note: 🧠 What i just built

    # This is the first financial intelligence layer
    # Not perfect—but:
    #👉 deterministic
    #👉 testable
    #👉 extensible




def estimate_cost(context: dict) -> dict:
    """
    Estimate cost based on parsed Terraform resources.

    Returns:
        dict with estimated_cost and breakdown
    """

    resources = context.get("resources", [])

    total_cost = 0
    breakdown = []

    for r in resources:
        r_type = r["type"]
        values = r["values"]

        cost = 0

        # AWS EC2
        if r_type == "aws_instance":
            instance_type = values.get("instance_type", "t2.micro")

            pricing = {
                "t2.micro": 10,
                "t2.small": 20,
                "t2.medium": 40
            }

            cost = pricing.get(instance_type, 25)

        # Azure VM
        elif r_type == "azurerm_virtual_machine":
            size = values.get("vm_size", "Standard_B1s")

            pricing = {
                "Standard_B1s": 12,
                "Standard_B2s": 25,
                "Standard_D2s_v3": 50
            }

            cost = pricing.get(size, 30)

        # Azure Sentinel (simplified)
        elif r_type == "azurerm_sentinel_log_analytics_workspace":
            cost = 50

        # AWS S3 (basic assumption)
        elif r_type == "aws_s3_bucket":
            cost = 5

        # Default fallback
        else:
            cost = 10

        total_cost += cost

        breakdown.append({
            "resource": r["name"],
            "type": r_type,
            "estimated_cost": cost
        })

    return {
        "estimated_cost": total_cost,
        "cost_breakdown": breakdown
    }