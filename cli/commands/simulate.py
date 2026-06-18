# cli/commands/simulate.py
#
# Purpose:
# CLI command: verdict simulate
#
# Evaluates a policy against a synthetic context built
# from --set key=value pairs. No Terraform plan or
# CloudFormation template required.
#
# Use cases:
#   Policy authoring      Test a policy while writing it
#   Threshold calibration Find the exact value that triggers DENY
#   Team onboarding       Show what a policy evaluates
#   CI policy testing     Assert expected decisions without
#                         generating real infrastructure plans
#
# Usage:
#   verdict simulate \
#     --policy policies/cost/basic_budget.yaml \
#     --set estimated_cost=150 \
#     --set open_ingress_rules=2 \
#     --set unencrypted_databases=1
#
# Exit codes:
#   0   ALLOW or ALLOW_WITH_NOTIFICATION
#   1   DENY or DENY_WITH_OVERRIDE
#
# Output dimensions:
#   Technical Risk    infrastructure findings risk score (0-100)
#                     open ingress, unencrypted databases, cost
#   Governance Risk   policy severity and intent
#                     determined by policy_type and governance config
#
#   These are distinct. A governance DENY can occur at
#   Technical Risk 0 — it means the policy condition failed,
#   not that infrastructure is misconfigured.

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from engine.orchestrator import PolicyOrchestrator

console = Console()

_SEPARATOR = "─" * 64

_BASE_SIMULATE_CONTEXT: dict[str, Any] = {
    "resources": [],
    "open_ingress_rules": 0,
    "public_storage_buckets": 0,
    "unencrypted_databases": 0,
    "ssl_not_enforced_count": 0,
    "versioning_disabled_count": 0,
    "untagged_resource_count": 0,
    "total_resource_count": 0,
    "compute_instance_count": 0,
    "gpu_instance_count": 0,
    "ai_gpu_workloads": 0,
    "estimated_cost": 0.0,
    "current_spend": 0.0,
    "pricing_mode": "simulate",
}


# =====================================================
# CONTEXT BUILDER
# =====================================================


def _parse_set_value(raw_value: str) -> int | float | str:
    """
    Infer the type of a --set value string.

    Tries int first, then float, then returns as string.

    Examples:
        "150"    → 150   (int)
        "75.5"   → 75.5  (float)
        "true"   → "true" (str — policy engine handles booleans)
        "prod"   → "prod" (str)
    """
    try:
        return int(raw_value)
    except ValueError:
        pass

    try:
        return float(raw_value)
    except ValueError:
        pass

    return raw_value


def _parse_set_overrides(
    set_values: list[str],
) -> dict[str, Any]:
    """
    Parse --set key=value pairs into a context override dict.

    Args:
        set_values: list of "key=value" strings from --set flags

    Returns:
        dict of parsed key → typed value pairs

    Raises:
        ValueError: if any entry is not in key=value format
    """
    overrides: dict[str, Any] = {}

    for entry in set_values:
        if "=" not in entry:
            raise ValueError(
                f"Invalid --set format: '{entry}'. "
                f"Expected key=value (example: --set estimated_cost=150)"
            )

        key, raw_value = entry.split("=", 1)
        key = key.strip()
        raw_value = raw_value.strip()

        if not key:
            raise ValueError(f"Invalid --set entry: '{entry}'. Key cannot be empty.")

        overrides[key] = _parse_set_value(raw_value)

    return overrides


def _build_simulate_context(
    overrides: dict[str, Any],
) -> dict[str, Any]:
    """
    Build the synthetic evaluation context.

    Starts from a base context with all standard keys set
    to safe defaults (zero / empty), then applies user
    overrides from --set flags.

    Args:
        overrides: parsed --set key=value pairs

    Returns:
        Complete context dict ready for policy evaluation.
    """
    context = dict(_BASE_SIMULATE_CONTEXT)
    context.update(overrides)
    return context


# =====================================================
# DISPLAY
# =====================================================


def _display_simulate_result(
    result: dict[str, Any],
    context: dict[str, Any],
) -> None:
    """
    Print the simulation result to the console.

    Shows Technical Risk and Governance Risk as separate
    dimensions. A governance DENY at Technical Risk 0 means
    the policy condition failed — not that infrastructure is
    misconfigured. Displaying both prevents misreading the
    risk score as the reason for the decision.
    """
    decision: str = result.get("decision", "UNKNOWN")

    # Technical risk — infrastructure findings (open ingress,
    # unencrypted databases, cost overruns, GPU sizing, etc.)
    risk_summary: dict[str, Any] = result.get("risk_summary", {})
    technical_risk: int = risk_summary.get("overall_risk_score", 0)

    # Governance risk — policy severity and intent
    # Distinct from technical risk: a governance DENY can occur
    # at technical risk 0 when a policy condition fails.
    governance_severity: str = result.get("governance_severity", "unknown")

    resolution_reason: str = result.get("resolution_reason", "")

    console.print()
    console.print(_SEPARATOR)
    console.print("  ObsidianWall Verdict — Simulate")
    console.print(_SEPARATOR)
    console.print()

    # ── Context used ─────────────────────────────────
    console.print("  Context")
    console.print(_SEPARATOR)

    non_default_keys = {
        key: value
        for key, value in context.items()
        if key != "resources"
        and key != "pricing_mode"
        and value != 0
        and value != 0.0
        and value != []
    }

    if non_default_keys:
        for key, value in non_default_keys.items():
            console.print(f"  {key:<32} {value}")
    else:
        console.print("  All context values at defaults (zero)")

    console.print()

    # ── Decision ─────────────────────────────────────
    console.print("  Decision")
    console.print(_SEPARATOR)

    decision_icon = {
        "ALLOW": "✅",
        "ALLOW_WITH_NOTIFICATION": "✅",
        "DENY_WITH_OVERRIDE": "⚠️ ",
        "DENY": "🚫",
    }.get(decision, "❓")

    console.print(f"  {decision_icon}  {decision}")
    console.print()

    # ── Risk dimensions ───────────────────────────────
    # Shown separately so a governance DENY at risk 0
    # is not misread as a technical finding.
    console.print(f"  Technical Risk:    {technical_risk}/100")
    console.print(f"  Governance Risk:   {governance_severity}")

    if resolution_reason:
        human_readable_reason = resolution_reason.replace("_", " ")
        console.print(f"  Reason:            {human_readable_reason}")

    console.print()
    console.print(_SEPARATOR)
    console.print()


# =====================================================
# SIMULATE COMMAND
# =====================================================


def simulate(
    policy: str = typer.Option(
        ...,
        "--policy",
        help="Path to the ObsidianWall policy YAML file.",
    ),
    set_values: list[str] = typer.Option(
        [],
        "--set",
        help=(
            "Set a context key to a specific value. "
            "Repeatable. Format: key=value. "
            "Example: --set estimated_cost=150 --set open_ingress_rules=2"
        ),
    ),
    role: str = typer.Option(
        "engineer",
        "--role",
        help="Role of the user triggering the simulation.",
    ),
    output: str = typer.Option(
        "",
        "--output",
        help=(
            "Optional path to write the simulation result JSON. "
            "If not set, result is printed to stdout only."
        ),
    ),
) -> None:
    """
    Evaluate a policy against synthetic context values.

    Builds a context from --set key=value pairs and evaluates
    the policy without requiring a real infrastructure plan.

    Exit codes:
      0   ALLOW or ALLOW_WITH_NOTIFICATION
      1   DENY or DENY_WITH_OVERRIDE

    Examples:

      Test a budget policy at a specific cost:
        verdict simulate \\
          --policy policies/cost/basic_budget.yaml \\
          --set estimated_cost=150

      Test a security policy with violations:
        verdict simulate \\
          --policy policies/security/nsg_policy.yaml \\
          --set open_ingress_rules=3 \\
          --set unencrypted_databases=1

      Test AI governance with GPU workloads:
        verdict simulate \\
          --policy policies/ai_governance/basic_ai_governance.yaml \\
          --set ai_gpu_workloads=2
    """
    policy_path = Path(policy)

    if not policy_path.exists():
        console.print(f"[red]Policy file not found: {policy}[/red]")
        raise typer.Exit(code=1)

    # ── Parse --set overrides ─────────────────────────
    try:
        overrides: dict[str, Any] = _parse_set_overrides(set_values)
    except ValueError as parse_error:
        console.print(f"[red]{parse_error}[/red]")
        raise typer.Exit(code=1)

    # ── Build synthetic context ───────────────────────
    context: dict[str, Any] = _build_simulate_context(overrides)

    # ── Run evaluation ────────────────────────────────
    try:
        engine = PolicyOrchestrator.from_policy_path(policy)
        result: dict[str, Any] = engine.evaluate(
            context=context,
            user_role=role,
        )

    except Exception as evaluation_error:
        console.print(f"[red]Simulation failed: {evaluation_error}[/red]")
        raise typer.Exit(code=1)

    # ── Display result ────────────────────────────────
    _display_simulate_result(result, context)

    # ── Optional output file ──────────────────────────
    if output:
        output_path = Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8") as output_file:
            json.dump(result, output_file, indent=2, default=str)

    # ── Exit code based on decision ───────────────────
    deny_decisions = {"DENY", "DENY_WITH_OVERRIDE"}
    if result.get("decision") in deny_decisions:
        raise typer.Exit(code=1)
