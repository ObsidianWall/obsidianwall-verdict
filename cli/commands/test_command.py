# cli/commands/test_command.py
#
# Purpose:
# verdict test command — assert that a Terraform plan
# produces an expected governance decision.
#
# Usage:
#   verdict test \
#     --plan   terraform_plan.json \
#     --policy policies/cost/basic_budget.yaml \
#     --expect DENY_WITH_OVERRIDE
#
# Exit codes:
#   0   Decision matches expected — test passed
#   1   Decision does not match  — test failed
#   2   Evaluation error         — test could not run
#
# Why this matters:
#   Policy authors need to verify their policies behave
#   correctly before deploying them. Infrastructure teams
#   need regression tests when policies change.
#   CI/CD pipelines need policy correctness gates.
#
#   verdict test enables all three — it is the unit
#   testing layer for ObsidianWall policies.
#
# Examples:
#   # Assert a budget violation is caught
#   verdict test \
#     --plan   samples/terraform_plan.json \
#     --policy policies/cost/basic_budget.yaml \
#     --expect DENY_WITH_OVERRIDE
#
#   # Assert a compliant plan is allowed
#   verdict test \
#     --plan   samples/compliant_plan.json \
#     --policy policies/security/basic_security.yaml \
#     --expect ALLOW
#
#   # Use in CI/CD — fails pipeline if policy breaks
#   verdict test \
#     --plan   terraform_plan.json \
#     --policy policies/cost/strict_budget.yaml \
#     --expect DENY

from __future__ import annotations

import json
import logging
from typing import Any

import typer

from context.context_builder import build_context
from engine.orchestrator import PolicyOrchestrator
from engine.policy_loader import load_policy
from engine.validator import validate_policy

# Valid governance decision values for --expect validation
_VALID_DECISIONS: frozenset[str] = frozenset(
    {
        "ALLOW",
        "ALLOW_WITH_NOTIFICATION",
        "ALLOW_WITH_APPROVAL_REQUIRED",
        "DENY_WITH_OVERRIDE",
        "DENY",
    }
)


def test_command(
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
    expect: str = typer.Option(
        ...,
        "--expect",
        help=(
            "Expected governance decision. "
            "One of: ALLOW, ALLOW_WITH_NOTIFICATION, "
            "ALLOW_WITH_APPROVAL_REQUIRED, "
            "DENY_WITH_OVERRIDE, DENY."
        ),
    ),
    role: str = typer.Option(
        "engineer",
        "--role",
        help="Role of the user triggering the evaluation.",
    ),
    pricing: str = typer.Option(
        "table",
        "--pricing",
        help="Pricing mode: table (default) or live.",
    ),
    region: str = typer.Option(
        "eastus",
        "--region",
        help="Cloud region for live pricing.",
    ),
    current_spend: float = typer.Option(
        0.0,
        "--current-spend",
        help="Current period spend in USD.",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Show full evaluation output on failure.",
    ),
) -> None:
    """
    Assert that a Terraform plan produces the expected
    governance decision against a policy.

    Runs a full evaluation and compares the decision
    against the expected value. Exits 0 on match,
    exits 1 on mismatch, exits 2 on evaluation error.

    Use this to write policy regression tests and
    verify policy correctness in CI/CD pipelines.

    Examples:

      Assert budget violation is caught:
        verdict test \\
          --plan   samples/terraform_plan.json \\
          --policy policies/cost/basic_budget.yaml \\
          --expect DENY_WITH_OVERRIDE

      Assert compliant plan is allowed:
        verdict test \\
          --plan   samples/compliant_plan.json \\
          --policy policies/security/basic_security.yaml \\
          --expect ALLOW
    """
    logging.disable(logging.INFO)

    # ── Validate --expect value ───────────────────────
    expect_upper: str = expect.upper().strip()

    if expect_upper not in _VALID_DECISIONS:
        typer.echo(
            f"\n  ✗ Invalid --expect value: '{expect}'\n\n"
            f"  Valid values:\n"
            + "\n".join(f"    {d}" for d in sorted(_VALID_DECISIONS))
            + "\n"
        )
        raise typer.Exit(code=2)

    # ── Run evaluation ────────────────────────────────
    try:
        policy_dict: dict[str, Any] = load_policy(policy)
        validate_policy(policy_dict)

        context: dict[str, Any] = build_context(
            plan_path=plan,
            current_spend=current_spend,
            pricing_mode=pricing,
            region=region,
        )

        engine = PolicyOrchestrator.from_policy_path(policy)
        result: dict[str, Any] = engine.evaluate(
            context=context,
            user_role=role,
        )

    except Exception as e:
        typer.echo(
            f"\n  ✗ Evaluation error\n\n"
            f"  Could not evaluate plan against policy.\n"
            f"  Error: {e}\n"
        )
        raise typer.Exit(code=2)

    # ── Compare decision to expected ──────────────────
    actual: str = str(result.get("decision", ""))
    matched: bool = actual == expect_upper

    if matched:
        typer.echo(
            f"\n  ✅ Test passed\n\n"
            f"  Policy:   {policy}\n"
            f"  Plan:     {plan}\n"
            f"  Expected: {expect_upper}\n"
            f"  Actual:   {actual}\n"
        )
        raise typer.Exit(code=0)

    else:
        risk_score: int = int(
            result.get("risk_summary", {}).get("overall_risk_score", 0)
        )
        effective_severity: str = str(result.get("effective_severity", ""))

        # Extract failed conditions for context
        trace: list[dict[str, Any]] = result.get("trace", [])
        failed: list[str] = [
            t["condition_id"] for t in trace if not t.get("result", True)
        ]
        passed: list[str] = [t["condition_id"] for t in trace if t.get("result", True)]

        typer.echo(
            f"\n  ✗ Test failed\n\n"
            f"  Policy:   {policy}\n"
            f"  Plan:     {plan}\n"
            f"  Expected: {expect_upper}\n"
            f"  Actual:   {actual}\n\n"
            f"  Risk score:  {risk_score}/100\n"
            f"  Severity:    {effective_severity}\n"
        )

        if failed:
            typer.echo(
                "  Failed conditions:\n"
                + "\n".join(f"    ✗ {c}" for c in failed)
                + "\n"
            )

        if passed:
            typer.echo(
                "  Passed conditions:\n"
                + "\n".join(f"    ✓ {c}" for c in passed)
                + "\n"
            )

        if verbose:
            typer.echo("  Full evaluation output:")
            typer.echo(json.dumps(result, indent=2, default=str))

        raise typer.Exit(code=1)
