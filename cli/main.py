# cli/main.py

# Purpose: User interface → runs the engine



import typer
import json
from pathlib import Path

from engine.evaluator import DecisionEngine
from context.terraform_parser import parse_terraform_plan
from engine.policy_loader import load_policy
from engine.validator import validate_policy
from audit.audit_logger import get_logger

app = typer.Typer()
logger = get_logger()


@app.command()
def evaluate(
    plan: str,
    policy: str,
    role: str = "engineer",
    output: str = "output/result.json"
):
    """
    Evaluate Terraform plan against policy.
    """

    try:
        logger.info("evaluation_started", extra={
            "extra": {"plan": plan, "policy": policy, "role": role}
        })

        # 1. Load + validate policy (CRITICAL for compliance)
        policy_dict = load_policy(policy)
        validate_policy(policy_dict)

        # 2. Parse Terraform plan
        context = parse_terraform_plan(plan)

        # 3. Run engine
        engine = DecisionEngine(policy_path=policy)
        result = engine.evaluate(context, user_role=role)

        # 4. Persist audit artifact
        Path(output).parent.mkdir(parents=True, exist_ok=True)
        with open(output, "w") as f:
            json.dump(result, f, indent=2)

        logger.info("evaluation_completed", extra={
            "extra": {
                "decision": result["decision"],
                "decision_id": result["decision_id"]
            }
        })

        print(json.dumps(result, indent=2))

    except Exception as e:
        logger.error("evaluation_failed", extra={
            "extra": {"error": str(e)}
        })
        raise typer.Exit(code=1)


@app.command()
def validate(policy: str):
    """
    Validate policy schema only.
    """
    try:
        policy_dict = load_policy(policy)
        validate_policy(policy_dict)

        print(json.dumps({
            "status": "valid",
            "policy": policy
        }, indent=2))

    except Exception as e:
        print(json.dumps({
            "status": "invalid",
            "error": str(e)
        }, indent=2))
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()