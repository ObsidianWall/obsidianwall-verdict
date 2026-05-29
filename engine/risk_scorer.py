# engine/risk_scorer.py

# Purpose:
# Centralized consolidated risk scoring engine.
#
# Responsibilities:
# - Aggregate risk scores across all analyzers
# - Produce consolidated governance risk summary
# - Map overall risk to governance severity
# - Compute effective governance severity
#   (policy severity vs analyzer severity — higher wins)
# - Surface finding counts and risk distribution
#
# IMPORTANT:
# Risk scores are advisory intelligence.
# They NEVER override deterministic enforcement decisions.
# Risk scoring informs governance routing only.

from typing import Any

from audit.audit_logger import get_logger
from schemas.policy_schema import GovernanceSeverity

logger = get_logger()


# =====================================================
# SEVERITY THRESHOLDS
# =====================================================

RISK_SEVERITY_THRESHOLDS: dict[str, int] = {
    "critical": 70,
    "high":     40,
    "medium":   15,
    "low":       1,
}

SEVERITY_ORDER: dict[GovernanceSeverity, int] = {
    GovernanceSeverity.INFORMATIONAL: 0,
    GovernanceSeverity.LOW:           1,
    GovernanceSeverity.MEDIUM:        2,
    GovernanceSeverity.HIGH:          3,
    GovernanceSeverity.CRITICAL:      4,
}


# =====================================================
# SEVERITY NARRATIVES
# =====================================================

RISK_SEVERITY_NARRATIVES: dict[str, str] = {
    "critical": (
        "Critical infrastructure risk detected. "
        "Multiple high-severity findings require "
        "immediate governance review."
    ),
    "high": (
        "Elevated infrastructure risk detected. "
        "Significant findings identified across "
        "one or more analyzers."
    ),
    "medium": (
        "Moderate infrastructure risk detected. "
        "Advisory findings identified that warrant review."
    ),
    "low": (
        "Low infrastructure risk detected. "
        "Minor findings identified for awareness."
    ),
    "informational": (
        "No significant infrastructure risk detected. "
        "Infrastructure configuration is within "
        "acceptable governance parameters."
    ),
}


# =====================================================
# SEVERITY RESOLUTION
# =====================================================


def _score_to_severity(overall_score: int) -> str:
    """Map an aggregated risk score to a severity level."""

    if overall_score >= RISK_SEVERITY_THRESHOLDS["critical"]:
        return "critical"
    elif overall_score >= RISK_SEVERITY_THRESHOLDS["high"]:
        return "high"
    elif overall_score >= RISK_SEVERITY_THRESHOLDS["medium"]:
        return "medium"
    elif overall_score >= RISK_SEVERITY_THRESHOLDS["low"]:
        return "low"
    return "informational"


def compute_effective_severity(
    policy_severity: str,
    risk_severity: str,
) -> str:
    """
    Compute effective governance severity.

    Returns the higher of policy-declared severity
    and analyzer-computed risk severity.
    """

    try:
        policy_level = SEVERITY_ORDER.get(GovernanceSeverity(policy_severity), 2)
    except ValueError:
        policy_level = 2

    try:
        risk_level = SEVERITY_ORDER.get(GovernanceSeverity(risk_severity), 2)
    except ValueError:
        risk_level = 2

    if risk_level > policy_level:
        logger.info(
            "severity_escalated",
            extra={
                "extra": {
                    "policy_severity": policy_severity,
                    "risk_severity":   risk_severity,
                    "effective":       risk_severity,
                }
            },
        )
        return risk_severity

    return policy_severity


# =====================================================
# RISK SCORER
# =====================================================


def compute_risk_summary(
    analyzer_results: dict[str, Any],
    policy_severity: str = "medium",
) -> dict[str, Any]:
    """
    Compute a consolidated governance risk summary
    across all analyzer results.

    Raises:
        TypeError: if analyzer_results is not a dict.
    """

    if not isinstance(analyzer_results, dict):
        raise TypeError("analyzer_results must be a dict")

    total_risk_score:       int              = 0
    highest_risk_analyzer:  str | None       = None
    highest_risk_score:     int              = 0
    total_findings:         int              = 0

    analyzer_scores:         dict[str, int]  = {}
    analyzer_finding_counts: dict[str, int]  = {}
    failed_analyzers:        list[str]       = []

    for analyzer_name, analyzer_data in analyzer_results.items():

        if not isinstance(analyzer_data, dict):
            failed_analyzers.append(analyzer_name)
            analyzer_scores[analyzer_name]         = 0
            analyzer_finding_counts[analyzer_name] = 0
            continue

        if analyzer_data.get("status") == "failed":
            failed_analyzers.append(analyzer_name)
            analyzer_scores[analyzer_name]         = 0
            analyzer_finding_counts[analyzer_name] = 0
            continue

        score:    int       = analyzer_data.get("risk_score", 0)
        findings: list[Any] = analyzer_data.get("findings", [])
        count:    int       = len(findings)

        analyzer_scores[analyzer_name]         = score
        analyzer_finding_counts[analyzer_name] = count

        total_risk_score += score
        total_findings   += count

        if score > highest_risk_score:
            highest_risk_score    = score
            highest_risk_analyzer = analyzer_name

    overall_risk_score: int = min(total_risk_score, 100)

    risk_severity: str = _score_to_severity(overall_risk_score)

    effective_severity: str = compute_effective_severity(
        policy_severity=policy_severity,
        risk_severity=risk_severity,
    )

    risk_narrative: str = RISK_SEVERITY_NARRATIVES.get(
        effective_severity, RISK_SEVERITY_NARRATIVES["informational"]
    )

    if failed_analyzers:
        risk_narrative += (
            f" Note: {len(failed_analyzers)} analyzer(s) "
            f"failed and were excluded from scoring: "
            f"{', '.join(failed_analyzers)}."
        )

    summary: dict[str, Any] = {
        "overall_risk_score":      overall_risk_score,
        "risk_severity":           risk_severity,
        "effective_severity":      effective_severity,
        "policy_severity":         policy_severity,
        "highest_risk_analyzer":   highest_risk_analyzer,
        "highest_risk_score":      highest_risk_score,
        "total_findings":          total_findings,
        "analyzer_scores":         analyzer_scores,
        "analyzer_finding_counts": analyzer_finding_counts,
        "failed_analyzers":        failed_analyzers,
        "risk_narrative":          risk_narrative,
    }

    logger.info(
        "risk_summary_computed",
        extra={
            "extra": {
                "overall_risk_score": overall_risk_score,
                "risk_severity":      risk_severity,
                "effective_severity": effective_severity,
                "policy_severity":    policy_severity,
                "highest_risk_analyzer": highest_risk_analyzer,
                "total_findings":     total_findings,
                "failed_analyzers":   failed_analyzers,
            }
        },
    )

    return summary
