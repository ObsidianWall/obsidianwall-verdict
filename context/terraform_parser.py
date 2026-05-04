# context/terraform_parser.py

# Purpose:Convert Terraform plan → normalized decision context

# context/terraform_parser.py

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