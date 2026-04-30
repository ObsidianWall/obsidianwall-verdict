# context/terraform_parser.py

# Purpose:Convert Terraform plan → normalized decision context


import json
from utils.logger import get_logger

logger = get_logger()


def parse_terraform_plan(path: str) -> dict:
    with open(path, "r") as f:
        plan = json.load(f)

    # v0.1 simplified mapping
    estimated_cost = plan.get("estimated_cost", 0)
    current_spend = plan.get("current_spend", 0)

    context = {
        "estimated_cost": estimated_cost,
        "current_spend": current_spend
    }

    logger.info("Context built", extra=context)

    return context