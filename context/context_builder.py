# context/context_builder.py
#
# Purpose:
# Assemble the full decision context from a Terraform plan.

from typing import Any

from context.terraform_parser import parse_terraform_plan
from engine.cost_estimator import estimate_cost


def build_context(
    plan_path: str,
    current_spend: float = 0.0,
    pricing_mode: str = "table",
    region: str = "eastus",
) -> dict[str, Any]:
    """
    Build the full decision context from a Terraform plan.

    Args:
        plan_path:      path to Terraform plan JSON
        current_spend:  current period spend to date
        pricing_mode:   "table" (default) or "live" (Azure API)
        region:         cloud region for live pricing

    Returns:
        dict with resources, estimated_cost, cost_breakdown,
        current_spend, pricing_mode
    """

    parsed: dict[str, Any] = parse_terraform_plan(plan_path)

    cost_data: dict[str, Any] = estimate_cost(
        context=parsed,
        pricing_mode=pricing_mode,
        region=region,
    )

    return {
        "resources": parsed["resources"],
        "estimated_cost": cost_data["estimated_cost"],
        "cost_breakdown": cost_data["cost_breakdown"],
        "current_spend": current_spend,
        "pricing_mode": pricing_mode,
    }
