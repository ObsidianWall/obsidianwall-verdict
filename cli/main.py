# cli/main.py
#
# Purpose:
# User-facing CLI for ObsidianWall Verdict.
#
# Commands:
#   evaluate   Evaluate a Terraform plan against a policy
#   validate   Validate a policy schema only
#
# Enterprise design:
#   Validation explicit      ← compliance requirement
#   Audit logging intact     ← security requirement
#   Deterministic execution  ← core architecture
#   Command separation       ← platform scalability

import json
from pathlib import Path
from typing import Any

import typer

from audit.audit_logger import get_logger
from context.context_builder import build_context
from engine.orchestrator import PolicyOrchestrator
from engine.policy_loader import load_policy
from engine.validator import validate_policy


app = typer.Typer(
    name="verdict",
    help="ObsidianWall Verdict — pre-deployment infrastructure governance.",
    add_completion=False,
)

logger = get_logger()


@app.command()
def evaluate(
    plan: str = typer.Option(
        ...,
        "--plan",
        help="Path to Terraform plan JSON file.",
    ),
    policy: str = typer.Option(
        ...,
        "--policy",
        help="Path to ObsidianWall policy YAML file.",
    ),
    role: str = typer.Option(
        "engineer",
        "--role",
        help="Role of the user triggering the evaluation.",
    ),
    output: str = typer.Option(
        "output/result.json",
        "--output",
        help="Path to write the audit artifact JSON.",
    ),
    pricing: str = typer.Option(
        "table",
        "--pricing",
        help=(
            "Pricing mode. "
            "'table' uses deterministic hardcoded prices (default, offline-safe). "
            "'live' fetches real-time prices from the Azure Retail Prices API."
        ),
    ),
    region: str = typer.Option(
        "eastus",
        "--region",
        help=(
            "Cloud region for live pricing. "
            "Only used when --pricing live is set. "
            "Examples: eastus, westeurope, eastasia."
        ),
    ),
    current_spend: float = typer.Option(
        0.0,
        "--current-spend",
        help=(
            "Current period spend in USD already incurred this month. "
            "Combined with estimated_cost to check total projected spend "
            "against your budget limit. "
            "Example: --current-spend 30.0 means $30 already spent this month. "
            "Defaults to 0.0. Connect to Azure Cost Management API in future "
            "versions for automatic current spend detection."
        ),
    ),
) -> None:
    """
    Evaluate a Terraform plan against an ObsidianWall policy.

    Produces a governance decision with full audit trail,
    risk summary, notification manifest, and explainability artifact.

    Exit codes:
      0   ALLOW or ALLOW_WITH_NOTIFICATION
      1   DENY, DENY_WITH_OVERRIDE, or evaluation error

    Examples:

      Basic evaluation:
        verdict evaluate --plan plan.json --policy budget.yaml

      With current month spend:
        verdict evaluate --plan plan.json --policy budget.yaml --current-spend 30.0

      With live Azure pricing:
        verdict evaluate --plan plan.json --policy budget.yaml --pricing live --region eastus

      Full example:
        verdict evaluate \\
          --plan          terraform_plan.json \\
          --policy        policies/cost/basic_budget.yaml \\
          --role          engineer \\
          --current-spend 30.0 \\
          --pricing       live \\
          --region        eastus
    """

    try:

        logger.info(
            "evaluation_started",
            extra={
                "extra": {
                    "plan":          plan,
                    "policy":        policy,
                    "role":          role,
                    "pricing":       pricing,
                    "region":        region,
                    "current_spend": current_spend,
                }
            }
        )

        # ---------------------------------------------
        # STEP 1 — Validate policy schema
        # Explicit validation before execution.
        # Compliance requirement: policy must be valid
        # before any evaluation begins.
        # ---------------------------------------------

        policy_dict: dict[str, Any] = load_policy(policy)
        validate_policy(policy_dict)

        # ---------------------------------------------
        # STEP 2 — Build decision context
        # Parse Terraform plan and estimate costs.
        # Pricing mode and region are applied here.
        # current_spend is passed through so the
        # budget condition evaluates total projected
        # spend, not just this deployment's cost.
        # ---------------------------------------------

        context: dict[str, Any] = build_context(
            plan_path=plan,
            current_spend=current_spend,
            pricing_mode=pricing,
            region=region,
        )

        # ---------------------------------------------
        # STEP 3 — Execute governance pipeline
        # ---------------------------------------------

        engine = PolicyOrchestrator.from_policy_path(policy)
        result: dict[str, Any] = engine.evaluate(
            context=context,
            user_role=role,
        )

        # ---------------------------------------------
        # STEP 4 — Persist audit artifact
        # ---------------------------------------------

        output_path = Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with output_path.open("w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, default=str)

        logger.info(
            "evaluation_completed",
            extra={
                "extra": {
                    "decision":     result["decision"],
                    "decision_id":  result["decision_id"],
                }
            }
        )

        # ---------------------------------------------
        # STEP 5 — Print audit artifact to stdout
        # Structured logs go to stderr via audit_logger.
        # The final JSON artifact goes to stdout.
        # This separation allows shell piping and
        # GitHub Actions output parsing.
        # ---------------------------------------------

        print(json.dumps(result, indent=2, default=str))

        # ---------------------------------------------
        # STEP 6 — Exit code based on decision
        # Non-zero exit blocks CI/CD pipelines
        # automatically on DENY decisions.
        # ---------------------------------------------

        deny_decisions = {"DENY", "DENY_WITH_OVERRIDE"}

        if result["decision"] in deny_decisions:
            raise typer.Exit(code=1)

    except typer.Exit:
        raise

    except Exception as e:
        logger.error(
            "evaluation_failed",
            extra={"extra": {"error": str(e)}}
        )
        raise typer.Exit(code=1)


@app.command()
def validate(
    policy: str = typer.Option(
        ...,
        "--policy",
        help="Path to the ObsidianWall policy YAML file to validate.",
    ),
) -> None:
    """
    Validate an ObsidianWall policy schema.

    Checks that the policy file is valid YAML and conforms
    to the canonical ObsidianWall policy DSL schema.
    Does not execute any evaluation.

    Exit codes:
      0   Policy is valid
      1   Policy is invalid
    """

    try:
        policy_dict: dict[str, Any] = load_policy(policy)
        policy_obj = validate_policy(policy_dict)

        print(json.dumps({
            "status":   "valid",
            "policy":   policy,
            "name":     policy_obj.metadata.name,
            "version":  policy_obj.metadata.version,
            "owner":    policy_obj.metadata.owner,
        }, indent=2))

    except Exception as e:
        print(json.dumps({
            "status":   "invalid",
            "policy":   policy,
            "error":    str(e),
        }, indent=2))
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()