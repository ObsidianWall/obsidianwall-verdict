# context/terraform_parser.py

# Purpose:Convert Terraform plan → normalized decision context

# This module focuses on parsing Terraform plan JSON output to extract relevant resource information for cost estimation and guardrail evaluation. It handles the structure of Terraform plans, including nested modules, to ensure comprehensive data extraction.

# The main function `parse_terraform_plan` reads a Terraform plan from a specified file path, processes the JSON structure to gather resource details, and returns a structured dictionary that can be used for further analysis in the guardrail evaluation process.

# Note: This parser assumes a specific structure of the Terraform plan output. It may need adjustments if the Terraform version or output format changes. Always ensure that the plan is generated with the `-out` option and then converted to JSON using `terraform show -json` for compatibility with this parser.

# 🎯 Purpose: Convert Terraform plan JSON → structured decision context


# ✅ What it extracts
    # resource types, resource counts, and basic configuration signals

# Note: This parser is designed to be simple and focused on extracting key information relevant for cost estimation and guardrail evaluation. It does not attempt to capture every detail of the Terraform plan, but rather focuses on the most impactful data points for guardrail evaluation.

# Note: 🧠 What i have just built, I now understand infrastructure BEFORE deployment - That’s step 1 of control.


import json


def parse_terraform_plan(plan_path: str) -> dict:
    """
    Parses Terraform plan JSON and extracts resource-level data.
    
    Returns:
        dict with resource summary used for cost estimation.
    """

    with open(plan_path, "r") as f:
        plan = json.load(f)

    resources = []

    # Terraform plan structure: planned_values.root_module.resources
    try:
        root = plan.get("planned_values", {}).get("root_module", {})
        resources.extend(root.get("resources", []))

        # Handle child modules if present
        for child in root.get("child_modules", []):
            resources.extend(child.get("resources", []))

    except Exception:
        raise ValueError("Invalid Terraform plan format")

    parsed_resources = []

    for r in resources:
        parsed_resources.append({
            "type": r.get("type"),
            "name": r.get("name"),
            "values": r.get("values", {})
        })

    return {
        "resources": parsed_resources
    }