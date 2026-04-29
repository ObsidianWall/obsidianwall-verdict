# cli/main.py

# Purpose: User interface → runs the engine


import typer
import json
from engine.evaluator import DecisionEngine

app = typer.Typer()

@app.command()
def evaluate(plan: str, policy: str):
    """
    Evaluate Terraform plan against policy
    """

    engine = DecisionEngine(policy_path=policy)

    with open(plan, "r") as f:
        context = json.load(f)

    result = engine.evaluate(context)

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    app()