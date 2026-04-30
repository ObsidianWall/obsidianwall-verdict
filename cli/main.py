# cli/main.py

# Purpose: User interface → runs the engine


import typer
import json
from pathlib import Path

from engine.evaluator import DecisionEngine
from engine.policy_loader import load_policy
from engine.validator import validate_policy
from context.terraform_parser import parse_terraform_plan
from utils.logger import get_logger

app = typer.Typer()
logger = get_logger()

@app.command()
def evaluate(plan: str, policy: str, output: str = "output/result.json"):
    """
    Evaluate Terraform plan against policy.
    """

    logger.info("Starting evaluation", extra={"plan": plan, "policy": policy})

    # Load + validate policy
    policy_dict = load_policy(policy)
    policy_obj = validate_policy(policy_dict)

    # Build context
    context = parse_terraform_plan(plan)

    # Run engine
    engine = DecisionEngine(policy_obj, context)
    result = engine.evaluate()

    # Write output
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    with open(output, "w") as f:
        json.dump(result, f, indent=2)

    logger.info("Evaluation complete", extra={"decision": result["decision"]})

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    app()