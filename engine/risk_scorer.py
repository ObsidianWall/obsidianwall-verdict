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


from audit.audit_logger import get_logger
from schemas.policy_schema import GovernanceSeverity

logger = get_logger()


# =====================================================
# SEVERITY THRESHOLDS
# =====================================================

# Overall risk score → governance severity mapping.
# Scores are aggregated across all analyzers and
# capped at 100.
# TODO: Replace with configurable scoring engine.

RISK_SEVERITY_THRESHOLDS = {
    "critical": 70,
    "high": 40,
    "medium": 15,
    "low": 1,
}

# Severity ordering for escalation comparison.
SEVERITY_ORDER = {
    GovernanceSeverity.INFORMATIONAL: 0,
    GovernanceSeverity.LOW: 1,
    GovernanceSeverity.MEDIUM: 2,
    GovernanceSeverity.HIGH: 3,
    GovernanceSeverity.CRITICAL: 4,
}


# =====================================================
# SEVERITY NARRATIVES
# =====================================================

RISK_SEVERITY_NARRATIVES = {
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
        "Low infrastructure risk detected. Minor findings identified for awareness."
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
    """
    Map an aggregated risk score to a severity level.
    """

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

    Rationale:
    A policy may declare medium severity but analyzers
    may detect critical risk. The effective severity
    must escalate to critical to ensure appropriate
    governance routing — the higher severity always wins.
    """

    try:
        policy_level = SEVERITY_ORDER.get(GovernanceSeverity(policy_severity), 2)
    except ValueError:
        policy_level = 2  # default to medium

    try:
        risk_level = SEVERITY_ORDER.get(GovernanceSeverity(risk_severity), 2)
    except ValueError:
        risk_level = 2  # default to medium

    if risk_level > policy_level:
        logger.info(
            "severity_escalated",
            extra={
                "extra": {
                    "policy_severity": policy_severity,
                    "risk_severity": risk_severity,
                    "effective": risk_severity,
                }
            },
        )

        return risk_severity

    return policy_severity


# =====================================================
# RISK SCORER
# =====================================================


def compute_risk_summary(
    analyzer_results: dict,
    policy_severity: str = "medium",
) -> dict:
    """
    Compute a consolidated governance risk summary
    across all analyzer results.

    Produces:
    - overall_risk_score (0-100, aggregated + capped)
    - risk_severity (informational → critical)
    - effective_severity (max of policy + risk severity)
    - highest_risk_analyzer
    - per-analyzer scores and finding counts
    - risk narrative (plain-English summary)

    Raises:
        TypeError: if analyzer_results is not a dict.
    """

    # =================================================
    # BOUNDARY VALIDATION
    # =================================================

    if not isinstance(analyzer_results, dict):
        raise TypeError("analyzer_results must be a dict")

    # =================================================
    # AGGREGATE SCORES
    # =================================================

    total_risk_score = 0
    highest_risk_analyzer = None
    highest_risk_score = 0
    total_findings = 0

    analyzer_scores = {}
    analyzer_finding_counts = {}
    failed_analyzers = []

    for analyzer_name, analyzer_data in analyzer_results.items():
        # -------------------------------------------------
        # GUARD: failed or malformed analyzer
        # -------------------------------------------------

        if not isinstance(analyzer_data, dict):
            failed_analyzers.append(analyzer_name)
            analyzer_scores[analyzer_name] = 0
            analyzer_finding_counts[analyzer_name] = 0
            continue

        if analyzer_data.get("status") == "failed":
            failed_analyzers.append(analyzer_name)
            analyzer_scores[analyzer_name] = 0
            analyzer_finding_counts[analyzer_name] = 0
            continue

        score = analyzer_data.get("risk_score", 0)
        findings = analyzer_data.get("findings", [])
        count = len(findings)

        analyzer_scores[analyzer_name] = score
        analyzer_finding_counts[analyzer_name] = count

        total_risk_score += score
        total_findings += count

        if score > highest_risk_score:
            highest_risk_score = score
            highest_risk_analyzer = analyzer_name

    # =================================================
    # NORMALIZE SCORE
    # =================================================

    # Cap at 100 — sum can exceed 100 across analyzers.
    # TODO: Replace with weighted scoring model.
    overall_risk_score = min(total_risk_score, 100)

    # =================================================
    # SEVERITY RESOLUTION
    # =================================================

    risk_severity = _score_to_severity(overall_risk_score)

    effective_severity = compute_effective_severity(
        policy_severity=policy_severity,
        risk_severity=risk_severity,
    )

    # =================================================
    # RISK NARRATIVE
    # =================================================

    risk_narrative = RISK_SEVERITY_NARRATIVES.get(
        effective_severity, RISK_SEVERITY_NARRATIVES["informational"]
    )

    if failed_analyzers:
        risk_narrative += (
            f" Note: {len(failed_analyzers)} analyzer(s) "
            f"failed and were excluded from scoring: "
            f"{', '.join(failed_analyzers)}."
        )

    # =================================================
    # ASSEMBLE SUMMARY
    # =================================================

    summary = {
        "overall_risk_score": overall_risk_score,
        "risk_severity": risk_severity,
        "effective_severity": effective_severity,
        "policy_severity": policy_severity,
        "highest_risk_analyzer": highest_risk_analyzer,
        "highest_risk_score": highest_risk_score,
        "total_findings": total_findings,
        "analyzer_scores": analyzer_scores,
        "analyzer_finding_counts": analyzer_finding_counts,
        "failed_analyzers": failed_analyzers,
        "risk_narrative": risk_narrative,
    }

    logger.info(
        "risk_summary_computed",
        extra={
            "extra": {
                "overall_risk_score": overall_risk_score,
                "risk_severity": risk_severity,
                "effective_severity": effective_severity,
                "policy_severity": policy_severity,
                "highest_risk_analyzer": highest_risk_analyzer,
                "total_findings": total_findings,
                "failed_analyzers": failed_analyzers,
            }
        },
    )

    return summary
