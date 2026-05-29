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

    parsed: dict[str, Any] = parse_terraform_plan(plan_path)

    cost_data: dict[str, Any] = estimate_cost(
        context=parsed,
        pricing_mode=pricing_mode,
        region=region,
    )

    # Start from the full parsed context so all keys extracted
    # by the parser (security, compliance, resource limits)
    # flow through to the evaluation context automatically.
    # Any new keys added to the parser require no changes here.
    context: dict[str, Any] = dict(parsed)
    context["estimated_cost"] = cost_data["estimated_cost"]
    context["cost_breakdown"]  = cost_data["cost_breakdown"]
    context["current_spend"]   = current_spend
    context["pricing_mode"]    = pricing_mode

    return context
