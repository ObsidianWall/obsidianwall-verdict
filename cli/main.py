# cli/main.py

import typer
from packages.decision_engine.engine import DecisionEngine
from packages.policy_engine.loader import load_policy
from packages.context_engine.context import build_context

app = typer.Typer()

@app.command()
def evaluate(plan: str, policy: str):
    """
    Evaluate a Terraform plan against a policy.
    
    plan: path to plan.json
    policy: path to policy.yaml
    """

    # 1. Load policy (intent)
    policy_data = load_policy(policy)

    # 2. Build context (reality)
    context = build_context(plan)

    # 3. Run decision engine
    engine = DecisionEngine(policy_data, context)
    result = engine.evaluate()

    # 4. Output result
    print(result)

if __name__ == "__main__":
    app()