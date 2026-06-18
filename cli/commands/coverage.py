# cli/commands/coverage.py
#
# Purpose:
# CLI command: verdict coverage
#
# Maps a policy's conditions to a compliance framework
# and reports which controls are covered and which are
# missing.
#
# Usage:
#   verdict coverage \
#     --policy policies/hipaa/data_governance.yaml \
#     --framework hipaa
#
# Supported frameworks:
#   hipaa        → HIPAA Security Rule
#   soc2         → SOC 2 Trust Service Criteria
#   cis          → CIS Controls v8
#   nist_ai_rmf  → NIST AI Risk Management Framework

from __future__ import annotations

from pathlib import Path
from typing import Any

import typer
import yaml
from rich.console import Console

from engine.coverage.coverage_engine import analyze_coverage
from schemas.policy_schema import Policy

console = Console()

_SEPARATOR = "─" * 64
_COVERED_ICON = "✅"
_MISSING_ICON = "❌"


# =====================================================
# DISPLAY HELPERS
# =====================================================


def _display_coverage_report(results: dict[str, Any]) -> None:
    """
    Print the compliance coverage report to the console.
    """
    coverage_percent: float = results["coverage_percent"]
    covered_count: int = results["covered_count"]
    total_controls: int = results["total_controls"]
    missing_count: int = results["missing_count"]

    console.print()
    console.print(_SEPARATOR)
    console.print("  ObsidianWall — Compliance Coverage Report")
    console.print(_SEPARATOR)
    console.print()
    console.print(f"  Policy:     {results['policy_name']}")
    console.print(f"  Framework:  {results['framework_name']}")
    console.print(
        f"  Coverage:   {coverage_percent}%  "
        f"({covered_count} of {total_controls} controls)"
    )
    console.print()

    # ── Covered controls ─────────────────────────────────────
    if results["covered_controls"]:
        console.print("  Covered Controls")
        console.print(_SEPARATOR)
        for control_id, control_data in results["covered_controls"].items():
            console.print(
                f"  {_COVERED_ICON}  {control_id:<22} {control_data['title']}"
            )
            matching_conditions: list[str] = results["condition_map"].get(
                control_id, []
            )
            for condition_id in matching_conditions:
                console.print(f"               → {condition_id}")
        console.print()

    # ── Missing controls ─────────────────────────────────────
    if results["missing_controls"]:
        console.print("  Missing Controls")
        console.print(_SEPARATOR)
        for control_id, control_data in results["missing_controls"].items():
            console.print(
                f"  {_MISSING_ICON}  {control_id:<22} {control_data['title']}"
            )
        console.print()

    # ── Summary footer ────────────────────────────────────────
    console.print(_SEPARATOR)

    if missing_count > 0:
        console.print(
            f"  {missing_count} control(s) not addressed. "
            f"Add conditions covering the missing areas to improve coverage."
        )
    else:
        console.print("  All framework controls are addressed by this policy.")

    console.print(_SEPARATOR)
    console.print()


# =====================================================
# COVERAGE COMMAND
# =====================================================


def coverage(
    policy: str = typer.Option(
        ...,
        "--policy",
        help="Path to the policy YAML file to analyze.",
    ),
    framework: str = typer.Option(
        ...,
        "--framework",
        help=(
            "Compliance framework to map against. "
            "Supported: hipaa, soc2, cis, nist_ai_rmf"
        ),
    ),
) -> None:
    """
    Map a policy's conditions to a compliance framework.

    Reports which framework controls are addressed by the
    policy's conditions and which controls are missing.

    Examples:

      verdict coverage --policy policies/hipaa/phi.yaml --framework hipaa
      verdict coverage --policy policies/ai/governance.yaml --framework nist_ai_rmf
    """
    policy_path = Path(policy)

    if not policy_path.exists():
        console.print(f"[red]Policy file not found: {policy}[/red]")
        raise typer.Exit(code=1)

    # ── Load and validate policy ─────────────────────────────
    try:
        with policy_path.open(encoding="utf-8") as policy_file:
            policy_data: dict[str, Any] = yaml.safe_load(policy_file)

        loaded_policy = Policy(**policy_data)

    except yaml.YAMLError as yaml_error:
        console.print(f"[red]Invalid YAML in policy file: {yaml_error}[/red]")
        raise typer.Exit(code=1)

    except Exception as validation_error:
        console.print(f"[red]Policy validation failed: {validation_error}[/red]")
        raise typer.Exit(code=1)

    # ── Run coverage analysis ─────────────────────────────────
    try:
        coverage_results: dict[str, Any] = analyze_coverage(
            policy=loaded_policy,
            framework=framework,
        )

    except ValueError as value_error:
        console.print(f"[red]{value_error}[/red]")
        raise typer.Exit(code=1)

    # ── Display results ───────────────────────────────────────
    _display_coverage_report(coverage_results)
