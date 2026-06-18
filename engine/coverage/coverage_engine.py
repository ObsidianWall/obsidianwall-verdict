# engine/coverage/coverage_engine.py

# engine/coverage/coverage_engine.py
#
# Purpose:
# Map policy conditions to compliance framework controls
# using pattern matching on condition identifiers,
# expressions, and descriptions.
#
# How it works:
#   For each control in the target framework, the engine
#   searches every policy condition for keywords associated
#   with that control. A condition matches a control if any
#   keyword appears in the combined text of:
#     condition.id + condition.expression + condition.description
#
#   A control is "covered" if at least one condition matches.
#   A control is "missing" if no condition matches.
#
# This approach requires no policy annotations.
# Existing policies evaluate automatically.
#
# Usage:
#   from engine.coverage.coverage_engine import analyze_coverage
#   results = analyze_coverage(policy, "hipaa")

from __future__ import annotations

from typing import Any

from engine.coverage.frameworks import FRAMEWORK_REGISTRY
from schemas.policy_schema import Condition, Policy

# =====================================================
# FRAMEWORK DISPLAY NAMES
# =====================================================

_FRAMEWORK_DISPLAY_NAMES: dict[str, str] = {
    "hipaa": "HIPAA Security Rule",
    "soc2": "SOC 2 Trust Service Criteria",
    "cis": "CIS Controls v8",
    "nist_ai_rmf": "NIST AI Risk Management Framework",
}


# =====================================================
# PATTERN MATCHING
# =====================================================


def _condition_matches_control(
    condition: Condition,
    keywords: list[str],
) -> bool:
    """
    Return True if any keyword appears in the combined
    text of the condition identifier, expression, and
    description.

    Matching is case-insensitive. A single keyword match
    is sufficient to consider the condition relevant to
    the control.

    Args:
        condition: the policy condition to inspect
        keywords:  list of keyword strings for the control

    Returns:
        True if the condition addresses the control.
    """
    searchable_text: str = (
        f"{condition.id} {condition.expression} {condition.description}"
    ).lower()

    return any(keyword.lower() in searchable_text for keyword in keywords)


# =====================================================
# COVERAGE ANALYSIS
# =====================================================


def analyze_coverage(
    policy: Policy,
    framework: str,
) -> dict[str, Any]:
    """
    Map policy conditions to compliance framework controls.

    For each control in the target framework, searches all
    policy conditions for keyword matches. Reports which
    controls are covered, which are missing, and which
    specific conditions address each covered control.

    Args:
        policy:    loaded and validated Policy object
        framework: framework identifier. One of:
                   "hipaa", "soc2", "cis", "nist_ai_rmf"

    Returns:
        dict containing:
            framework           framework identifier (normalized)
            framework_name      human-readable framework name
            policy_name         policy metadata.name
            total_controls      total controls in the framework
            covered_count       controls addressed by the policy
            missing_count       controls not addressed
            coverage_percent    float — percentage covered
            covered_controls    dict[control_id, control_data]
            missing_controls    dict[control_id, control_data]
            condition_map       dict[control_id, list[condition_id]]
                                maps each covered control to the
                                conditions that address it

    Raises:
        ValueError: if framework identifier is not recognized
    """
    normalized_framework: str = framework.lower()

    framework_controls: dict[str, dict[str, Any]] | None = FRAMEWORK_REGISTRY.get(
        normalized_framework
    )

    if framework_controls is None:
        supported_frameworks: str = ", ".join(FRAMEWORK_REGISTRY.keys())
        raise ValueError(
            f"Unknown framework: '{framework}'. "
            f"Supported frameworks: {supported_frameworks}"
        )

    conditions: list[Condition] = policy.spec.conditions

    covered_controls: dict[str, dict[str, Any]] = {}
    missing_controls: dict[str, dict[str, Any]] = {}
    condition_map: dict[str, list[str]] = {}

    for control_id, control_data in framework_controls.items():
        keywords: list[str] = control_data.get("keywords", [])
        matching_condition_ids: list[str] = []

        for condition in conditions:
            if _condition_matches_control(condition, keywords):
                matching_condition_ids.append(condition.id)

        if matching_condition_ids:
            covered_controls[control_id] = control_data
            condition_map[control_id] = matching_condition_ids
        else:
            missing_controls[control_id] = control_data

    total_controls: int = len(framework_controls)
    covered_count: int = len(covered_controls)
    missing_count: int = len(missing_controls)

    coverage_percent: float = (
        round((covered_count / total_controls) * 100, 1) if total_controls > 0 else 0.0
    )

    return {
        "framework": normalized_framework,
        "framework_name": _FRAMEWORK_DISPLAY_NAMES.get(normalized_framework, framework),
        "policy_name": policy.metadata.name,
        "total_controls": total_controls,
        "covered_count": covered_count,
        "missing_count": missing_count,
        "coverage_percent": coverage_percent,
        "covered_controls": covered_controls,
        "missing_controls": missing_controls,
        "condition_map": condition_map,
    }
