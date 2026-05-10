
# context/context_builder.py


from context.terraform_parser import parse_terraform_plan
from engine.cost_estimator import estimate_cost


def build_context(plan_path: str, current_spend: float = 0) -> dict:
    """
    Build full decision context:
    - parsed resources
    - estimated cost
    - current spend
    """

    parsed = parse_terraform_plan(plan_path)

    cost_data = estimate_cost(parsed)

    return {
        "resources": parsed["resources"],
        "estimated_cost": cost_data["estimated_cost"],
        "cost_breakdown": cost_data["cost_breakdown"],
        "current_spend": current_spend
    }