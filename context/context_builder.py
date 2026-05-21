
# context/context_builder.py
#
# Purpose:
# Assemble the full decision context from a Terraform plan.
#
# Responsibilities:
# - Parse Terraform plan into structured resource data
# - Estimate costs from parsed resources
# - Merge infrastructure context with spend data
# - Produce the runtime context consumed by the evaluator

from typing import Any

from context.terraform_parser import parse_terraform_plan
from engine.cost_estimator import estimate_cost


def build_context(
    plan_path: str,
    current_spend: float = 0.0,
) -> dict[str, Any]:
    """
    Build the full decision context from a Terraform plan.

    Args:
        plan_path:      path to the Terraform plan JSON file
        current_spend:  current period spend to date

    Returns:
        dict containing:
        - resources:        parsed resource list
        - estimated_cost:   estimated monthly cost
        - cost_breakdown:   per-resource cost breakdown
        - current_spend:    current spend passed through
    """

    parsed: dict[str, Any] = parse_terraform_plan(plan_path)

    cost_data: dict[str, Any] = estimate_cost(parsed)

    return {
        "resources":        parsed["resources"],
        "estimated_cost":   cost_data["estimated_cost"],
        "cost_breakdown":   cost_data["cost_breakdown"],
        "current_spend":    current_spend,
    }
