# engine/analyzers/cost_analyzer.py

# Purpose:
# Deterministic infrastructure cost analysis.
#
# Responsibilities:
# - Multi-threshold cost detection
# - Budget utilization analysis
# - Per-resource cost distribution analysis
# - Cost anomaly identification
# - Optimization candidate generation
# - Cost risk scoring
#
# IMPORTANT:
# This analyzer NEVER performs enforcement.
# Findings are advisory only.


from audit.audit_logger import get_logger

logger = get_logger()


# =====================================================
# COST THRESHOLDS
# =====================================================

# USD — tiered cost detection thresholds
# TODO: Make configurable via policy parameters.

COST_THRESHOLD_LOW = 50
COST_THRESHOLD_MEDIUM = 100
COST_THRESHOLD_HIGH = 500
COST_THRESHOLD_CRITICAL = 1000

# TODO: Replace with centralized scoring engine.
RISK_WEIGHT_MEDIUM = 20
RISK_WEIGHT_HIGH = 40
RISK_WEIGHT_CRITICAL = 70

# Budget utilization warning threshold (percentage)
BUDGET_UTILIZATION_WARNING = 0.80  # 80%
BUDGET_UTILIZATION_CRITICAL = 1.0  # 100% — over budget


# =====================================================
# COST ANALYZER
# =====================================================


def analyze_cost(runtime_context: dict) -> dict:
    """
    Analyze infrastructure cost posture.

    Detects:
    - Cost threshold breaches (tiered)
    - Budget utilization percentage
    - Per-resource cost concentration
    - High single-resource cost dominance
    """

    estimated_cost = runtime_context.get("estimated_cost", 0)
    current_spend = runtime_context.get("current_spend", 0)
    budget_amount = runtime_context.get("budget.amount")
    cost_breakdown = runtime_context.get("cost_breakdown", [])

    findings = []
    optimization_candidates = []
    risk_score = 0

    # =================================================
    # TIERED COST THRESHOLD DETECTION
    # =================================================

    if estimated_cost >= COST_THRESHOLD_CRITICAL:
        risk_score += RISK_WEIGHT_CRITICAL

        findings.append(
            {
                "type": "critical_projected_cost",
                "severity": "critical",
                "message": (
                    f"Projected infrastructure cost (${estimated_cost}) "
                    f"exceeds critical threshold (${COST_THRESHOLD_CRITICAL})."
                ),
            }
        )

        optimization_candidates.append(
            {
                "type": "cost_optimization",
                "message": (
                    "Critical cost detected. Immediate resource "
                    "rightsizing and reserved capacity review required."
                ),
                "estimated_savings_percent": 40,
            }
        )

    elif estimated_cost >= COST_THRESHOLD_HIGH:
        risk_score += RISK_WEIGHT_HIGH

        findings.append(
            {
                "type": "high_projected_cost",
                "severity": "high",
                "message": (
                    f"Projected infrastructure cost (${estimated_cost}) "
                    f"exceeds high threshold (${COST_THRESHOLD_HIGH})."
                ),
            }
        )

        optimization_candidates.append(
            {
                "type": "cost_optimization",
                "message": (
                    "Review resource sizing and evaluate "
                    "reserved capacity pricing models."
                ),
                "estimated_savings_percent": 30,
            }
        )

    elif estimated_cost >= COST_THRESHOLD_MEDIUM:
        risk_score += RISK_WEIGHT_MEDIUM

        findings.append(
            {
                "type": "elevated_projected_cost",
                "severity": "medium",
                "message": (
                    f"Projected infrastructure cost (${estimated_cost}) "
                    f"exceeds recommended threshold (${COST_THRESHOLD_MEDIUM})."
                ),
            }
        )

        optimization_candidates.append(
            {
                "type": "cost_optimization",
                "message": (
                    "Review resource sizing and consider "
                    "reserved capacity pricing models."
                ),
                "estimated_savings_percent": 25,
            }
        )

    # =================================================
    # BUDGET UTILIZATION ANALYSIS
    # =================================================

    if budget_amount and budget_amount > 0:
        projected_total = current_spend + estimated_cost
        utilization_ratio = projected_total / budget_amount

        if utilization_ratio >= BUDGET_UTILIZATION_CRITICAL:
            risk_score += 30

            findings.append(
                {
                    "type": "budget_exceeded",
                    "severity": "critical",
                    "message": (
                        f"Projected total spend (${projected_total:.2f}) "
                        f"exceeds budget (${budget_amount:.2f}). "
                        f"Utilization: {utilization_ratio * 100:.1f}%."
                    ),
                }
            )

        elif utilization_ratio >= BUDGET_UTILIZATION_WARNING:
            risk_score += 15

            findings.append(
                {
                    "type": "budget_utilization_warning",
                    "severity": "medium",
                    "message": (
                        f"Projected spend reaches "
                        f"{utilization_ratio * 100:.1f}% of budget. "
                        f"Approaching budget limit."
                    ),
                }
            )

    # =================================================
    # PER-RESOURCE COST CONCENTRATION
    # =================================================

    if cost_breakdown and estimated_cost > 0:
        for resource in cost_breakdown:
            resource_cost = resource.get("estimated_cost", 0)
            resource_name = resource.get("resource", "unknown")
            concentration = resource_cost / estimated_cost

            # Flag resources consuming more than 70% of total cost
            if concentration >= 0.70:
                findings.append(
                    {
                        "type": "cost_concentration",
                        "severity": "medium",
                        "message": (
                            f"Resource '{resource_name}' accounts for "
                            f"{concentration * 100:.1f}% of projected cost. "
                            f"High cost concentration detected."
                        ),
                    }
                )

                optimization_candidates.append(
                    {
                        "type": "resource_rightsizing",
                        "message": (
                            f"Evaluate rightsizing options for "
                            f"'{resource_name}' to reduce cost concentration."
                        ),
                        "estimated_savings_percent": 20,
                    }
                )

    logger.info(
        "cost_analysis_complete",
        extra={
            "extra": {
                "estimated_cost": estimated_cost,
                "risk_score": risk_score,
                "finding_count": len(findings),
            }
        },
    )

    return {
        "analyzer": "cost_analyzer",
        "risk_score": risk_score,
        "findings": findings,
        "optimization_candidates": optimization_candidates,
        "metadata": {
            "estimated_cost": estimated_cost,
            "current_spend": current_spend,
            "budget_amount": budget_amount,
        },
    }
