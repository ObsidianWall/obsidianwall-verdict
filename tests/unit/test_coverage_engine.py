
# tests/unit/test_coverage_engine.py
#
# Test suite for engine/coverage/coverage_engine.py
#
# Covers:
# - _condition_matches_control() keyword matching
# - analyze_coverage() full analysis
# - Coverage across all four frameworks
# - Edge cases: empty conditions, full coverage,
#   unknown framework, case-insensitive matching

import pytest
from unittest.mock import MagicMock

from engine.coverage.coverage_engine import (
    _condition_matches_control,
    analyze_coverage,
)
from schemas.policy_schema import Condition


# =====================================================
# HELPERS
# =====================================================


def _make_condition(condition_id, expression, description=""):
    return Condition(
        id=condition_id,
        expression=expression,
        description=description,
    )


def _make_mock_policy(conditions_data, name="test_policy"):
    """Create a minimal mock policy for coverage engine tests."""
    mock_policy = MagicMock()
    mock_policy.metadata.name = name
    mock_policy.spec.conditions = [
        _make_condition(
            condition_id=condition["id"],
            expression=condition.get("expression", ""),
            description=condition.get("description", ""),
        )
        for condition in conditions_data
    ]
    return mock_policy


# =====================================================
# CONDITION MATCHING
# =====================================================


class TestConditionMatchesControl:

    def test_matches_keyword_in_condition_id(self):
        condition = _make_condition(
            "mfa_required",
            "mfa_violations == 0",
            "MFA must be enabled",
        )
        assert _condition_matches_control(condition, ["mfa"]) is True

    def test_matches_keyword_in_expression(self):
        condition = _make_condition(
            "budget_check",
            "unencrypted_databases <= 0",
            "All databases must be encrypted",
        )
        assert _condition_matches_control(condition, ["encrypt"]) is True

    def test_matches_keyword_in_description(self):
        condition = _make_condition(
            "data_protection",
            "resource_count <= 10",
            "TLS must be enforced for all endpoints",
        )
        assert _condition_matches_control(condition, ["tls"]) is True

    def test_returns_false_when_no_keyword_matches(self):
        condition = _make_condition(
            "budget_check",
            "estimated_cost <= 100",
            "Cost must stay within budget",
        )
        assert _condition_matches_control(condition, ["mfa", "encryption"]) is False

    def test_matching_is_case_insensitive(self):
        condition = _make_condition(
            "SSL_CHECK",
            "SSL_ENFORCEMENT == true",
            "SSL must be enforced",
        )
        assert _condition_matches_control(condition, ["ssl"]) is True

    def test_partial_keyword_match_works(self):
        condition = _make_condition(
            "versioning_disabled_check",
            "versioning_disabled_count <= 0",
            "Versioning must be enabled",
        )
        assert _condition_matches_control(condition, ["versioning"]) is True

    def test_empty_keywords_returns_false(self):
        condition = _make_condition(
            "any_check",
            "some_value <= 0",
            "Some description",
        )
        assert _condition_matches_control(condition, []) is False


# =====================================================
# ANALYZE COVERAGE — STRUCTURE
# =====================================================


class TestAnalyzeCoverageStructure:

    def test_returns_all_required_keys(self):
        policy = _make_mock_policy([
            {
                "id": "gpu_check",
                "expression": "ai_gpu_workloads <= 0",
                "description": "GPU workloads require approval",
            }
        ])
        result = analyze_coverage(policy, "nist_ai_rmf")

        expected_keys = {
            "framework",
            "framework_name",
            "policy_name",
            "total_controls",
            "covered_count",
            "missing_count",
            "coverage_percent",
            "covered_controls",
            "missing_controls",
            "condition_map",
        }
        assert expected_keys.issubset(set(result.keys()))

    def test_returns_correct_policy_name(self):
        policy = _make_mock_policy([], name="my_hipaa_policy")
        result = analyze_coverage(policy, "hipaa")
        assert result["policy_name"] == "my_hipaa_policy"

    def test_returns_normalized_framework_name(self):
        policy = _make_mock_policy([])
        result = analyze_coverage(policy, "HIPAA")
        assert result["framework"] == "hipaa"

    def test_returns_human_readable_framework_name_hipaa(self):
        policy = _make_mock_policy([])
        result = analyze_coverage(policy, "hipaa")
        assert result["framework_name"] == "HIPAA Security Rule"

    def test_returns_human_readable_framework_name_soc2(self):
        policy = _make_mock_policy([])
        result = analyze_coverage(policy, "soc2")
        assert result["framework_name"] == "SOC 2 Trust Service Criteria"

    def test_returns_human_readable_framework_name_cis(self):
        policy = _make_mock_policy([])
        result = analyze_coverage(policy, "cis")
        assert result["framework_name"] == "CIS Controls v8"

    def test_returns_human_readable_framework_name_nist_ai_rmf(self):
        policy = _make_mock_policy([])
        result = analyze_coverage(policy, "nist_ai_rmf")
        assert result["framework_name"] == "NIST AI Risk Management Framework"

    def test_raises_for_unknown_framework(self):
        policy = _make_mock_policy([])
        with pytest.raises(ValueError, match="Unknown framework"):
            analyze_coverage(policy, "iso27001")


# =====================================================
# ANALYZE COVERAGE — EMPTY CONDITIONS
# =====================================================


class TestAnalyzeCoverageEmptyConditions:

    def test_all_controls_missing_with_no_conditions(self):
        policy = _make_mock_policy([])
        result = analyze_coverage(policy, "hipaa")
        assert result["covered_count"] == 0
        assert result["missing_count"] == result["total_controls"]
        assert result["coverage_percent"] == 0.0
        assert result["covered_controls"] == {}

    def test_covered_controls_empty_with_no_conditions(self):
        policy = _make_mock_policy([])
        result = analyze_coverage(policy, "soc2")
        assert len(result["covered_controls"]) == 0

    def test_condition_map_empty_with_no_conditions(self):
        policy = _make_mock_policy([])
        result = analyze_coverage(policy, "cis")
        assert result["condition_map"] == {}


# =====================================================
# ANALYZE COVERAGE — HIPAA
# =====================================================


class TestAnalyzeCoverageHipaa:

    def test_encryption_condition_covers_hipaa_164_312_a2iv(self):
        policy = _make_mock_policy([
            {
                "id": "phi_encryption_at_rest",
                "expression": "unencrypted_databases <= 0",
                "description": "PHI databases must be encrypted at rest",
            }
        ])
        result = analyze_coverage(policy, "hipaa")
        assert "164.312(a)(2)(iv)" in result["covered_controls"]

    def test_mfa_condition_covers_hipaa_access_control(self):
        policy = _make_mock_policy([
            {
                "id": "mfa_required",
                "expression": "mfa_violations == 0",
                "description": "MFA required for all access",
            }
        ])
        result = analyze_coverage(policy, "hipaa")
        assert "164.312(a)(1)" in result["covered_controls"]

    def test_ssl_condition_covers_hipaa_transmission_security(self):
        policy = _make_mock_policy([
            {
                "id": "ssl_enforcement_required",
                "expression": "ssl_not_enforced_count <= 0",
                "description": "SSL must be enforced for all data transmission",
            }
        ])
        result = analyze_coverage(policy, "hipaa")
        assert "164.312(e)(1)" in result["covered_controls"]

    def test_versioning_condition_covers_hipaa_integrity_controls(self):
        policy = _make_mock_policy([
            {
                "id": "versioning_required",
                "expression": "versioning_disabled_count <= 0",
                "description": "Storage versioning must be enabled",
            }
        ])
        result = analyze_coverage(policy, "hipaa")
        assert "164.312(c)(1)" in result["covered_controls"]

    def test_condition_map_lists_matching_condition_ids(self):
        policy = _make_mock_policy([
            {
                "id": "audit_logging_check",
                "expression": "audit_log_count > 0",
                "description": "Audit logging must be enabled",
            }
        ])
        result = analyze_coverage(policy, "hipaa")
        assert "164.312(b)" in result["covered_controls"]
        assert "audit_logging_check" in result["condition_map"]["164.312(b)"]

    def test_coverage_percent_calculated_correctly(self):
        policy = _make_mock_policy([
            {
                "id": "mfa_check",
                "expression": "mfa_violations == 0",
                "description": "MFA required",
            }
        ])
        result = analyze_coverage(policy, "hipaa")
        total = result["total_controls"]
        covered = result["covered_count"]
        expected_percent = round((covered / total) * 100, 1)
        assert result["coverage_percent"] == expected_percent


# =====================================================
# ANALYZE COVERAGE — NIST AI RMF
# =====================================================


class TestAnalyzeCoverageNistAiRmf:

    def test_gpu_workload_condition_covers_map_1_1(self):
        policy = _make_mock_policy([
            {
                "id": "gpu_governance_check",
                "expression": "ai_gpu_workloads <= 0",
                "description": "GPU deployments require AI governance approval",
            }
        ])
        result = analyze_coverage(policy, "nist_ai_rmf")
        assert "MAP-1.1" in result["covered_controls"]

    def test_ai_guardrails_condition_covers_manage_1_1(self):
        policy = _make_mock_policy([
            {
                "id": "ai_guardrails_required",
                "expression": "ai_guardrails_enabled == true",
                "description": "AI guardrails must be configured",
            }
        ])
        result = analyze_coverage(policy, "nist_ai_rmf")
        assert "MANAGE-1.1" in result["covered_controls"]

    def test_ai_governance_condition_covers_govern_1_1(self):
        policy = _make_mock_policy([
            {
                "id": "ai_governance_policy_check",
                "expression": "ai_governance_required == true",
                "description": "AI governance policy must be in place",
            }
        ])
        result = analyze_coverage(policy, "nist_ai_rmf")
        assert "GOVERN-1.1" in result["covered_controls"]


# =====================================================
# ANALYZE COVERAGE — SOC 2
# =====================================================


class TestAnalyzeCoverageSoc2:

    def test_network_condition_covers_cc6_6(self):
        policy = _make_mock_policy([
            {
                "id": "open_ingress_check",
                "expression": "open_ingress_rules <= 0",
                "description": "No open ingress rules allowed",
            }
        ])
        result = analyze_coverage(policy, "soc2")
        assert "CC6.6" in result["covered_controls"]

    def test_encryption_condition_covers_cc6_7(self):
        policy = _make_mock_policy([
            {
                "id": "encryption_at_rest",
                "expression": "unencrypted_databases <= 0",
                "description": "All databases must be encrypted",
            }
        ])
        result = analyze_coverage(policy, "soc2")
        assert "CC6.7" in result["covered_controls"]


# =====================================================
# ANALYZE COVERAGE — CIS CONTROLS
# =====================================================


class TestAnalyzeCoverageCis:

    def test_ingress_condition_covers_cis_12(self):
        policy = _make_mock_policy([
            {
                "id": "open_ingress_check",
                "expression": "open_ingress_rules == 0",
                "description": "Network ingress must be restricted",
            }
        ])
        result = analyze_coverage(policy, "cis")
        assert "CIS.12" in result["covered_controls"]

    def test_tagging_condition_covers_cis_1(self):
        policy = _make_mock_policy([
            {
                "id": "tagging_compliance",
                "expression": "untagged_resource_count == 0",
                "description": "All resources must be tagged",
            }
        ])
        result = analyze_coverage(policy, "cis")
        assert "CIS.1" in result["covered_controls"]

    def test_total_controls_matches_framework_size(self):
        from engine.coverage.frameworks import CIS_CONTROLS
        policy = _make_mock_policy([])
        result = analyze_coverage(policy, "cis")
        assert result["total_controls"] == len(CIS_CONTROLS)

    def test_covered_plus_missing_equals_total(self):
        policy = _make_mock_policy([
            {
                "id": "some_check",
                "expression": "open_ingress_rules == 0",
                "description": "",
            }
        ])
        result = analyze_coverage(policy, "cis")
        assert (
            result["covered_count"] + result["missing_count"]
            == result["total_controls"]
        )