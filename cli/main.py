# cli/main.py

# Purpose: User interface → runs the engine


import typer
import json
from pathlib import Path

from engine.evaluator import DecisionEngine
from context.terraform_parser import parse_terraform_plan
from logging.audit_logger import get_logger

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
    Evaluate Terraform plan against policy with audit logging.
    """

    logger.info("evaluation_started", extra={
        "extra": {"plan": plan, "policy": policy, "role": role}
    })

    # 1. Parse Terraform plan → context
    context = parse_terraform_plan(plan)


    # 2. Run decision engine (PROTECTED BLOCK)
    try:
        engine = DecisionEngine(policy_path=policy)
        result = engine.evaluate(context, user_role=role)

    except Exception as e:
        logger.error("evaluation_failed", extra={
            "extra": {
                "error": str(e),
                "plan": plan,
                "policy": policy,
                "role": role
            }
        })
        raise typer.Exit(code=1)

    # 3. Persist result (audit artifact)
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    with open(output, "w") as f:
        json.dump(result, f, indent=2)

    logger.info("evaluation_completed", extra={
        "extra": {"decision": result["decision"], "decision_id": result["decision_id"]}
    })

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    app()