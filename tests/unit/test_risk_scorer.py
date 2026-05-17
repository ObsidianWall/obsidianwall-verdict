
# tests/unit/test_risk_scorer.py

import pytest
from engine.risk_scorer import (
    compute_risk_summary,
    compute_effective_severity,
)


# =====================================================
# FIXTURES
# =====================================================

@pytest.fixture
def clean_analyzers():
    """All analyzers pass with zero findings."""
    return {
        "cost_analysis": {
            "analyzer":     "cost_analyzer",
            "risk_score":   0,
            "findings":     [],
            "optimization_candidates": [],
        },
        "topology_analysis": {
            "analyzer":     "topology_analyzer",
            "risk_score":   0,
            "findings":     [],
            "optimization_candidates": [],
        },
        "architecture_analysis": {
            "analyzer":     "architecture_analyzer",
            "risk_score":   0,
            "findings":     [],
            "optimization_candidates": [],
        },
        "utilization_analysis": {
            "analyzer":     "utilization_analyzer",
            "risk_score":   0,
            "findings":     [],
            "optimization_candidates": [],
        },
    }


@pytest.fixture
def high_risk_analyzers():
    """Analyzers with significant risk scores."""
    return {
        "cost_analysis": {
            "analyzer":     "cost_analyzer",
            "risk_score":   40,
            "findings": [
                {"type": "high_projected_cost", "severity": "high",
                 "message": "Cost exceeds threshold."}
            ],
            "optimization_candidates": [],
        },
        "architecture_analysis": {
            "analyzer":     "architecture_analyzer",
            "risk_score":   40,
            "findings": [
                {"type": "single_database_no_replica",
                 "severity": "high", "message": "Single DB."}
            ],
            "optimization_candidates": [],
        },
    }


# =====================================================
# compute_risk_summary
# =====================================================

def test_zero_risk_all_clean(clean_analyzers):
    summary = compute_risk_summary(clean_analyzers)
    assert summary["overall_risk_score"] == 0
    assert summary["risk_severity"] == "informational"
    assert summary["total_findings"] == 0


def test_risk_score_aggregates_across_analyzers(high_risk_analyzers):
    summary = compute_risk_summary(high_risk_analyzers)
    assert summary["overall_risk_score"] == 80
    assert summary["risk_severity"] == "critical"


def test_risk_score_capped_at_100():
    analyzers = {
        "a": {"risk_score": 80, "findings": [], "optimization_candidates": []},
        "b": {"risk_score": 80, "findings": [], "optimization_candidates": []},
    }
    summary = compute_risk_summary(analyzers)
    assert summary["overall_risk_score"] == 100


def test_highest_risk_analyzer_identified(high_risk_analyzers):
    summary = compute_risk_summary(high_risk_analyzers)
    assert summary["highest_risk_analyzer"] in high_risk_analyzers


def test_total_findings_counted(high_risk_analyzers):
    summary = compute_risk_summary(high_risk_analyzers)
    assert summary["total_findings"] == 2


def test_failed_analyzer_excluded():
    analyzers = {
        "cost_analysis": {"status": "failed", "error": "timeout"},
        "architecture_analysis": {
            "risk_score": 20,
            "findings":   [{"type": "x", "severity": "low", "message": "y"}],
            "optimization_candidates": [],
        },
    }
    summary = compute_risk_summary(analyzers)
    assert "cost_analysis" in summary["failed_analyzers"]
    assert summary["total_findings"] == 1


def test_malformed_analyzer_output_skipped():
    analyzers = {
        "bad_analyzer": None,
        "good_analyzer": {
            "risk_score": 10,
            "findings":   [],
            "optimization_candidates": [],
        },
    }
    summary = compute_risk_summary(analyzers)
    assert summary["overall_risk_score"] == 10


def test_invalid_input_raises():
    with pytest.raises(TypeError):
        compute_risk_summary("not a dict")


def test_effective_severity_uses_policy_when_higher(clean_analyzers):
    summary = compute_risk_summary(
        clean_analyzers,
        policy_severity="high"
    )
    assert summary["effective_severity"] == "high"


def test_effective_severity_escalates_to_risk_when_higher(high_risk_analyzers):
    summary = compute_risk_summary(
        high_risk_analyzers,
        policy_severity="low"
    )
    assert summary["effective_severity"] in ("high", "critical")


@pytest.mark.parametrize("risk_score, expected_severity", [
    (0,   "informational"),
    (1,   "low"),
    (15,  "medium"),
    (40,  "high"),
    (70,  "critical"),
    (100, "critical"),
])
def test_severity_thresholds(risk_score, expected_severity):
    analyzers = {
        "test": {
            "risk_score":   risk_score,
            "findings":     [],
            "optimization_candidates": [],
        }
    }
    summary = compute_risk_summary(analyzers)
    assert summary["risk_severity"] == expected_severity


# =====================================================
# compute_effective_severity
# =====================================================

@pytest.mark.parametrize("policy_sev, risk_sev, expected", [
    ("low",     "high",     "high"),
    ("high",    "low",      "high"),
    ("medium",  "medium",   "medium"),
    ("critical","low",      "critical"),
    ("low",     "critical", "critical"),
])
def test_effective_severity_returns_higher(
    policy_sev, risk_sev, expected
):
    result = compute_effective_severity(policy_sev, risk_sev)
    assert result == expected
