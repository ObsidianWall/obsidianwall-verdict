# context/context_builder.py
#
# Purpose:
# Assemble the full decision context from an infrastructure
# plan file. Auto-detects whether the plan is a Terraform
# JSON plan or an AWS CloudFormation template — no --format
# flag required.
#
# The orchestrator does not parse plans itself. It dispatches
# to the correct Translation Layer implementation via
# _parse_plan(), then enriches the resulting context with
# cost estimation and runtime parameters.

from typing import Any

from context.translators.cloudformation_parser import (
    CloudFormationParser,
    is_cloudformation_template,
)
from context.translators.terraform_parser import parse_terraform_plan
from engine.cost_estimator import estimate_cost


def _parse_plan(plan_path: str) -> dict[str, Any]:
    """
    Auto-detect the infrastructure plan format and dispatch
    to the correct Translation Layer implementation.

    Detection order:
    1. Check for CloudFormation indicators
       (AWSTemplateFormatVersion key or AWS:: type prefixes)
    2. Default to Terraform JSON plan

    Args:
        plan_path: path to the infrastructure plan file

    Returns:
        Normalized context dict from the appropriate translator.

    Raises:
        FileNotFoundError: if plan_path does not exist
        ValueError:        if plan format is invalid
    """
    if is_cloudformation_template(plan_path):
        return CloudFormationParser().parse(plan_path)
    return parse_terraform_plan(plan_path)


def build_context(
    plan_path: str,
    current_spend: float = 0.0,
    pricing_mode: str = "table",
    region: str = "eastus",
) -> dict[str, Any]:
    """
    Assemble the full decision context for policy evaluation.

    Auto-detects the plan format (Terraform or CloudFormation),
    parses it into the normalized context, then enriches that
    context with cost estimation and runtime parameters.

    Args:
        plan_path:     path to the infrastructure plan file
                       (Terraform JSON or CloudFormation
                       JSON/YAML — auto-detected)
        current_spend: current spend baseline for cost
                       comparison
        pricing_mode:  cost estimation mode ("table" or
                       another supported pricing strategy)
        region:        cloud region used for cost estimation

    Returns:
        Full decision context dict containing all parser
        keys plus cost estimation fields, ready for policy
        evaluation.
    """
    parsed_context: dict[str, Any] = _parse_plan(plan_path)

    cost_data: dict[str, Any] = estimate_cost(
        context=parsed_context,
        pricing_mode=pricing_mode,
        region=region,
    )

    # Start from the full parsed context so all keys extracted
    # by the translator (security, compliance, resource limits)
    # flow through to the evaluation context automatically.
    # Any new keys added to a translator require no changes here.
    context: dict[str, Any] = dict(parsed_context)
    context["estimated_cost"] = cost_data["estimated_cost"]
    context["cost_breakdown"] = cost_data["cost_breakdown"]
    context["current_spend"] = current_spend
    context["pricing_mode"] = pricing_mode

    return context
