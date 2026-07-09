# engine/explainability/recommendation_explainer.py

# Purpose:
# Generate plain-English recommendation explanations.
#
# Responsibilities:
# - Enrich recommendations with human-readable rationale
# - Group recommendations by priority
# - Surface actionable remediation guidance
# - Produce compliance-readable advisory summaries
#
# IMPORTANT:
# This module NEVER influences enforcement decisions.
# Recommendation explanations are advisory only.
# Explainability artifacts are produced AFTER
# the deterministic decision is resolved.

from typing import Any

from audit.audit_logger import get_logger

logger = get_logger()


# =====================================================
# RECOMMENDATION TYPE RATIONALE
# =====================================================

# Maps recommendation types to plain-English rationale.
# Extends as new recommendation types are added to
# the optimization catalog.

RECOMMENDATION_RATIONALE: dict[str, str] = {
    "rightsizing": (
        "The detected resource configuration appears "
        "oversized for its workload profile and environment. "
        "Rightsizing reduces unnecessary spend without "
        "impacting workload performance."
    ),
    "serverless_candidate": (
        "The workload pattern suggests event-driven or "
        "intermittent execution. Serverless architectures "
        "eliminate idle compute cost and scale automatically."
    ),
    "lifecycle_policy": (
        "Storage resources accumulate data over time. "
        "Lifecycle policies automatically migrate infrequently "
        "accessed data to lower-cost storage tiers."
    ),
    "reserved_capacity": (
        "Predictable production workloads benefit from "
        "reserved capacity pricing, which offers significant "
        "discounts over on-demand rates for committed usage."
    ),
    "autoscaling": (
        "Container workloads with variable demand benefit "
        "from autoscaling, which right-sizes capacity "
        "dynamically and eliminates over-provisioning."
    ),
    "cost_optimization": (
        "The projected infrastructure cost exceeds recommended "
        "thresholds. Review resource configurations for "
        "rightsizing, reserved pricing, or architecture "
        "optimization opportunities."
    ),
    "resource_rightsizing": (
        "A single resource accounts for a disproportionate "
        "share of projected cost. Review this resource's "
        "configuration for overprovisioning."
    ),
    "network_segmentation": (
        "Public-facing resources without network segmentation "
        "present an elevated security risk. Adding firewall "
        "rules or security groups reduces the attack surface."
    ),
    "load_balancer_coverage": (
        "Production compute resources without load balancer "
        "coverage represent a single point of failure. "
        "A load balancer improves resilience and availability."
    ),
    "database_redundancy": (
        "A single database instance in production without "
        "replica or failover configuration creates data "
        "availability risk. Redundancy ensures continuity."
    ),
    "compute_redundancy": (
        "Single compute resources in production cannot "
        "tolerate instance failure. Horizontal redundancy "
        "ensures deployment continuity."
    ),
    "observability": (
        "Production deployments without monitoring and "
        "alerting reduce operational visibility. Observability "
        "tooling enables faster incident detection and response."
    ),
    "burstable_migration": (
        "Burstable instance types provide baseline compute "
        "with burst capacity for development and test workloads, "
        "at significantly lower cost than fixed-performance instances."
    ),
    "cost_anomaly_review": (
        "A resource cost significantly exceeds the deployment "
        "average. This may indicate misconfiguration, "
        "overprovisioning, or an unintended resource type."
    ),
    "analyzer_finding": (
        "An infrastructure analyzer detected a configuration "
        "pattern that warrants review. See the finding details "
        "for specific context."
    ),
    "optimization_candidate": (
        "An optimization opportunity was identified during "
        "infrastructure analysis. Implementing this change "
        "may reduce cost or improve architecture quality."
    ),
    "enforcement": (
        "This deployment was blocked by deterministic policy "
        "enforcement. The evaluation trace identifies the "
        "specific condition that failed and the values "
        "that triggered the governance decision."
    ),
}


# =====================================================
# PRIORITY TIERS
# =====================================================


def _priority_tier(priority_score: int) -> str:
    """
    Map a numeric priority score to a human-readable tier.
    """
    if priority_score >= 90:
        return "critical"
    elif priority_score >= 75:
        return "high"
    elif priority_score >= 50:
        return "medium"
    else:
        return "low"


# =====================================================
# SINGLE RECOMMENDATION EXPLAINER
# =====================================================


def _explain_single(recommendation: dict[str, Any]) -> dict[str, Any]:
    """
    Enrich a single recommendation with plain-English
    rationale and priority context.
    Skips malformed recommendations defensively.

    Reads recommendation_confidence (v0.5.2+ field name).
    Falls back to the legacy "confidence" key for any
    recommendation objects produced by code not yet
    migrated to the new field name, so nothing silently
    defaults to 0.0 during the transition.
    """

    rec_type: str = recommendation.get("type", "unknown")
    message: str = recommendation.get("message", "")
    severity: str = recommendation.get("severity", "medium")
    priority_score: int = recommendation.get("priority_score", 50)

    # v0.5.2: recommendation_confidence replaced confidence.
    # Check both keys during the migration window so no
    # recommendation silently reports 0.0.
    recommendation_confidence: float = recommendation.get(
        "recommendation_confidence",
        recommendation.get("confidence", 0.65),
    )

    savings_percent: int = recommendation.get("estimated_savings_percent", 0)

    rationale: str = RECOMMENDATION_RATIONALE.get(
        rec_type,
        (
            "This recommendation was generated based on "
            "infrastructure analysis patterns. Review the "
            "finding details for specific guidance."
        ),
    )

    priority_tier: str = _priority_tier(priority_score)

    explained: dict[str, Any] = {
        "type": rec_type,
        "message": message,
        "rationale": rationale,
        "severity": severity,
        "priority_tier": priority_tier,
        "priority_score": priority_score,
        "recommendation_confidence": recommendation_confidence,
        "estimated_savings_percent": savings_percent,
    }

    # Add savings narrative if meaningful
    if savings_percent > 0:
        explained["savings_narrative"] = (
            f"Estimated cost reduction of up to {savings_percent}% if implemented."
        )

    return explained


# =====================================================
# RECOMMENDATION EXPLAINER
# =====================================================


def explain_recommendations(
    recommendations: list[dict[str, Any]],
    decision: str,
) -> dict[str, Any]:
    """
    Generate plain-English explanation for all recommendations.

    Produces:
    - Per-recommendation rationale and priority context
    - Grouped recommendations by priority tier
    - Advisory summary narrative
    - Total estimated savings potential

    Raises:
        TypeError:  if recommendations is not a list.
        ValueError: if decision is not a non-empty string.
    """

    # =================================================
    # BOUNDARY VALIDATION
    # =================================================

    if not isinstance(recommendations, list):
        raise TypeError("recommendations must be a list")

    if not isinstance(decision, str) or not decision:
        raise ValueError("decision must be a non-empty string")

    # =================================================
    # EXPLAIN EACH RECOMMENDATION
    # =================================================

    explained_recommendations: list[dict[str, Any]] = []

    for recommendation in recommendations:
        if not isinstance(recommendation, dict):
            continue

        message = recommendation.get("message")
        if not message:
            continue

        explained = _explain_single(recommendation)
        explained_recommendations.append(explained)

    # =================================================
    # GROUP BY PRIORITY TIER
    # =================================================

    grouped: dict[str, list[dict[str, Any]]] = {
        "critical": [],
        "high": [],
        "medium": [],
        "low": [],
    }

    for rec in explained_recommendations:
        tier: str = rec.get("priority_tier", "low")
        if tier in grouped:
            grouped[tier].append(rec)

    # =================================================
    # TOTAL SAVINGS POTENTIAL
    # =================================================

    savings_values: list[int] = [
        rec.get("estimated_savings_percent", 0)
        for rec in explained_recommendations
        if rec.get("estimated_savings_percent", 0) > 0
    ]

    max_savings: int = max(savings_values) if savings_values else 0

    # =================================================
    # ADVISORY SUMMARY
    # =================================================

    total_count: int = len(explained_recommendations)
    critical_count: int = len(grouped["critical"])
    high_count: int = len(grouped["high"])

    advisory_summary: str

    if total_count == 0:
        advisory_summary = (
            "No optimization recommendations were generated "
            "for this infrastructure configuration."
        )

    elif decision == "ALLOW":
        advisory_summary = (
            f"{total_count} advisory recommendation(s) identified. "
            f"Deployment is within governance boundaries. "
            f"Implementing recommendations may improve cost posture."
        )

    elif decision in ("DENY", "DENY_WITH_OVERRIDE"):
        advisory_summary = (
            f"Deployment blocked by governance policy. "
            f"{total_count} recommendation(s) available to "
            f"help resolve the governance violation and "
            f"optimize infrastructure configuration."
        )

    else:
        advisory_summary = (
            f"{total_count} recommendation(s) identified. "
            f"{critical_count + high_count} require immediate attention."
        )

    artifact: dict[str, Any] = {
        "advisory_summary": advisory_summary,
        "total_recommendations": total_count,
        "max_estimated_savings_percent": max_savings,
        "recommendations_by_priority": grouped,
        "all_recommendations": explained_recommendations,
    }

    logger.info(
        "recommendations_explained",
        extra={
            "extra": {
                "decision": decision,
                "total_count": total_count,
                "critical_count": critical_count,
                "high_count": high_count,
                "max_savings_percent": max_savings,
            }
        },
    )

    return artifact
