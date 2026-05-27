# context/terraform_parser.py
#
# Purpose:
# Convert Terraform plan JSON into a normalized
# decision context for policy evaluation.
#
# What it extracts:
# - Resource types, names, and configuration values
# - Nested module resources (child_modules)
#
# Usage:
#   Generate plan:  terraform plan -out=tfplan
#   Export JSON:    terraform show -json tfplan > plan.json
#   Parse:          parse_terraform_plan("plan.json")
#
# IMPORTANT:
# This parser targets the standard Terraform plan JSON
# structure produced by terraform show -json.
# Adjust if using third-party plan formats.

import json
from pathlib import Path
from typing import Any


def parse_terraform_plan(
    plan_path: str,
) -> dict[str, Any]:
    """
    Parse a Terraform plan JSON file and extract
    resource-level data for cost estimation and
    policy evaluation.

    Args:
        plan_path:  path to the Terraform plan JSON file

    Returns:
        dict containing:
        - resources:    list of parsed resource dicts

    Raises:
        FileNotFoundError:  if plan_path does not exist
        ValueError:         if plan format is invalid
    """

    path = Path(plan_path)

    if not path.exists():
        raise FileNotFoundError(f"Terraform plan not found: {plan_path}")

    with path.open("r", encoding="utf-8") as f:
        try:
            plan: dict[str, Any] = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in Terraform plan: {plan_path}") from e

    raw_resources: list[dict[str, Any]] = []

    try:
        root: dict[str, Any] = plan.get("planned_values", {}).get("root_module", {})

        raw_resources.extend(root.get("resources", []))

        for child in root.get("child_modules", []):
            raw_resources.extend(child.get("resources", []))

    except (AttributeError, TypeError) as e:
        raise ValueError(
            "Invalid Terraform plan structure — "
            "expected planned_values.root_module.resources"
        ) from e

    parsed_resources: list[dict[str, Any]] = []

    for resource in raw_resources:
        resource_type: str | None = resource.get("type")
        resource_name: str | None = resource.get("name")
        resource_values: dict[str, Any] = resource.get("values", {})

        if resource_type is None or resource_name is None:
            continue

        parsed_resources.append(
            {
                "type": resource_type,
                "name": resource_name,
                "values": resource_values,
            }
        )

    return {
        "resources": parsed_resources,
    }
