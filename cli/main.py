# cli/main.py
#
# Purpose:
# User-facing CLI for ObsidianWall Verdict.
#
# Commands:
#   evaluate   Evaluate a Terraform plan against a policy
#   validate   Validate a policy schema only
#   audit      Governance risk summary across recorded decisions
#   test       Assert expected governance decision
#   sentinel   Post-deployment reality verification
#   explain    Show full reasoning chain for a past decision
#
# v0.6.0: governance storage moved from telemetry/store.py
# (decisions/overrides/approvals/outcomes/decision_artifacts)
# to telemetry/governance_store.py (governance_records +
# governance_history + governance_evidence). Migration from
# the old schema runs automatically on first invocation via
# telemetry/migration.py — no manual steps required for
# pip-installed users with existing local history.

import importlib.metadata
import json
import logging
from pathlib import Path
from typing import Any

import typer

from audit.audit_logger import get_logger
from cli.commands.audit import audit_app
from cli.commands.coverage import coverage
from cli.commands.explain import explain_app
from cli.commands.ledger import ledger_app
from cli.commands.override import override_app
from cli.commands.sentinel import sentinel_app
from cli.commands.simulate import simulate
from cli.commands.test_command import test_command
from context.context_builder import build_context
from engine.governance_objective import compute_governance_objective
from engine.orchestrator import PolicyOrchestrator
from engine.policy_loader import load_policy
from engine.validator import validate_policy
from renderers import SUPPORTED_FORMATS, render
from telemetry.governance_store import (
    create_governance_record,
    record_governance_evidence,
)
from telemetry.migration import migrate_if_needed
from telemetry.notice import show_first_run_notice_if_needed

app = typer.Typer(
    name="verdict",
    help="ObsidianWall Verdict — pre-deployment infrastructure governance.",
    add_completion=False,
)

# ── Register commands ──────────────────────────────
app.add_typer(audit_app, name="audit")
app.add_typer(sentinel_app, name="sentinel")
app.add_typer(explain_app, name="explain")
app.add_typer(ledger_app, name="ledger")
app.add_typer(override_app, name="override")
app.command(name="coverage")(coverage)
app.command(name="simulate")(simulate)
app.command(name="test")(test_command)


def _version_callback(value: bool) -> None:
    if value:
        version = importlib.metadata.version("obsidianwall-verdict")
        typer.echo(f"ObsidianWall Verdict v{version}")
        raise typer.Exit()


@app.callback()
def _main(
    version: bool = typer.Option(
        False,
        "--version",
        "-v",
        help="Show version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    """ObsidianWall Verdict — pre-deployment infrastructure governance."""
    # Runs before any command. migrate_if_needed() is a no-op
    # after the first successful run or when no old-schema
    # database is present — safe on every invocation.
    migrate_if_needed()
    show_first_run_notice_if_needed()


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
    fmt: str = typer.Option(
        "text",
        "--format",
        help=(
            "Output format printed to stdout. "
            "'text' prints a concise human-readable summary (default). "
            "'json' prints the full JSON artifact. "
            "'yaml' prints the full YAML artifact. "
            f"Supported: {', '.join(SUPPORTED_FORMATS)}"
        ),
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
    current_spend: float | None = typer.Option(
        None,
        "--current-spend",
        help=(
            "Current period spend in USD already incurred this month. "
            "Combined with estimated_cost to check total projected spend "
            "against your budget limit. "
            "Example: --current-spend 30.0 means $30 already spent this month. "
            "If omitted, treated as $0 but marked in the evidence artifact "
            "as unverified rather than indistinguishable from an explicit "
            "'--current-spend 0' claim — see context_builder.py."
        ),
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        help=(
            "Show structured INFO-level evaluation logs on stderr "
            "in addition to the governance decision output. "
            "Default (off) shows only the decision — matching the "
            "same logging.disable(logging.INFO) pattern already "
            "used by verdict sentinel scan."
        ),
    ),
) -> None:
    """
    Evaluate a Terraform plan against an ObsidianWall policy.

    Produces a governance decision with full audit trail,
    risk summary, notification manifest, and explainability artifact.

    By default, prints a concise human-readable summary to stdout.
    Use --format json for the full machine-readable artifact
    (required for CI/CD pipelines and scripts that parse output).
    The full artifact is always written to the --output file
    regardless of --format.

    Exit codes:
      0   ALLOW or ALLOW_WITH_NOTIFICATION
      1   DENY, DENY_WITH_OVERRIDE, or evaluation error

    Examples:

      Basic evaluation (human-readable summary):
        verdict evaluate --plan plan.json --policy budget.yaml

      Full JSON for CI/CD pipelines:
        verdict evaluate --plan plan.json --policy budget.yaml --format json

      With current month spend:
        verdict evaluate --plan plan.json --policy budget.yaml --current-spend 30.0

      With live Azure pricing:
        verdict evaluate --plan plan.json --policy budget.yaml --pricing live --region eastus

      Full example:
        verdict evaluate \\
          --plan          terraform_plan.json \\
          --policy        policies/cost/basic_budget.yaml \\
          --role          engineer \\
          --format        json \\
          --current-spend 30.0 \\
          --pricing       live \\
          --region        eastus
    """

    # Suppress structured INFO-level logs by default — the
    # governance decision output is the point, not the internal
    # pipeline trace. Same pattern already used by
    # verdict sentinel scan. --verbose restores full logging.
    if not verbose:
        logging.disable(logging.INFO)

    try:
        logger.info(
            "evaluation_started",
            extra={
                "extra": {
                    "plan": plan,
                    "policy": policy,
                    "role": role,
                    "pricing": pricing,
                    "region": region,
                    "current_spend": current_spend,
                }
            },
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
        # STEP 3b — Compute governance objective
        # Optional. Only present if the policy declares
        # metadata.governance_objective.statement. Shifts
        # the artifact from reporting technical facts to
        # reporting whether an organizational governance
        # objective was upheld or violated. Never influences
        # the decision — purely explanatory, computed after
        # the decision is already final.
        # ---------------------------------------------

        governance_objective = compute_governance_objective(
            policy_dict=policy_dict,
            decision=result.get("decision", ""),
        )
        if governance_objective is not None:
            result["governance_objective"] = governance_objective

        # ---------------------------------------------
        # STEP 4 — Persist audit artifact
        # Full artifact always written to file
        # regardless of --format used for stdout.
        # ---------------------------------------------

        output_path = Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with output_path.open("w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, default=str)

        # ---------------------------------------------
        # STEP 5 — Record governance decision + evidence
        #
        # v0.6.0: create_governance_record() replaces
        # record_decision() from v0.5.x — writes the
        # governance_records row and its first (CREATED)
        # history entry in one call. policy_content_hash
        # and policy_family are auto-computed internally
        # from policy_path, matching the old function's
        # call simplicity.
        #
        # record_governance_evidence() replaces
        # record_artifact() from v0.5.2 — stores the full
        # artifact, retrievable later by verdict explain
        # regardless of whether the --output file still
        # exists on disk.
        #
        # Both never raise — governance recording must not
        # crash the CLI.
        # ---------------------------------------------

        create_governance_record(
            result=result,
            plan_path=plan,
            policy_path=policy,
        )

        record_governance_evidence(
            record_id=result.get("decision_id", ""),
            evidence=result,
            evidence_type="evaluation",
        )

        # ---------------------------------------------
        # STEP 6 — Render governance decision to stdout
        #
        # text:  concise human-readable summary (default)
        #        ~15 lines — decision, failed conditions,
        #        remediation, decision ID
        # json:  full artifact — current/legacy behavior,
        #        required for CI/CD pipelines and scripts
        # yaml:  full artifact in YAML format
        #
        # The full JSON artifact is always written to the
        # --output file (STEP 4) regardless of this choice.
        # Structured logs go to stderr via audit_logger,
        # keeping stdout clean for the chosen renderer.
        # ---------------------------------------------

        render(result, fmt=fmt, output_path=output)

        # ---------------------------------------------
        # STEP 7 — Exit code based on decision
        # Non-zero exit blocks CI/CD pipelines
        # automatically on DENY decisions.
        # ---------------------------------------------

        deny_decisions = {"DENY", "DENY_WITH_OVERRIDE"}

        if result["decision"] in deny_decisions:
            raise typer.Exit(code=1)

    except typer.Exit:
        raise

    except Exception as e:
        logger.error("evaluation_failed", extra={"extra": {"error": str(e)}})
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

        print(
            json.dumps(
                {
                    "status": "valid",
                    "policy": policy,
                    "name": policy_obj.metadata.name,
                    "version": policy_obj.metadata.version,
                    "owner": policy_obj.metadata.owner,
                },
                indent=2,
            )
        )

    except Exception as e:
        print(
            json.dumps(
                {
                    "status": "invalid",
                    "policy": policy,
                    "error": str(e),
                },
                indent=2,
            )
        )
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
