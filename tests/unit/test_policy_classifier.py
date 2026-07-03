# tests/unit/test_policy_classifier.py
#
# Tests for telemetry/policy_classifier.py
#
# Verifies:
# - Correct family classification for each family type
# - Falls back to "custom" for unrecognizable content
# - Handles missing/empty policy dicts gracefully
# - Prefers highest-scoring family when keywords overlap

import pytest

from telemetry.policy_classifier import classify_policy_family


# =====================================================
# FIXTURES
# =====================================================


def _make_policy(name: str = "", description: str = "", framework: str = "") -> dict:
    """Build a minimal policy dict for testing."""
    return {
        "metadata": {
            "name": name,
            "description": description,
        },
        "spec": {
            "governance": {
                "framework_mapping": framework,
            }
        },
    }


# =====================================================
# COST GOVERNANCE
# =====================================================


class TestCostGovernance:
    def test_budget_in_name(self):
        policy = _make_policy(name="basic_budget_verdict")
        assert classify_policy_family(policy) == "cost_governance"

    def test_cost_in_name(self):
        policy = _make_policy(name="cost_control_policy")
        assert classify_policy_family(policy) == "cost_governance"

    def test_spend_in_description(self):
        policy = _make_policy(description="Controls monthly spend limits")
        assert classify_policy_family(policy) == "cost_governance"

    def test_billing_keyword(self):
        policy = _make_policy(name="billing_governance")
        assert classify_policy_family(policy) == "cost_governance"

    def test_financial_keyword(self):
        policy = _make_policy(description="Financial exposure limits for cloud")
        assert classify_policy_family(policy) == "cost_governance"


# =====================================================
# SECURITY COMPLIANCE
# =====================================================


class TestSecurityCompliance:
    def test_hipaa_framework(self):
        policy = _make_policy(framework="HIPAA §164.312")
        assert classify_policy_family(policy) == "security_compliance"

    def test_soc2_name(self):
        policy = _make_policy(name="soc2_controls")
        assert classify_policy_family(policy) == "security_compliance"

    def test_nist_framework(self):
        policy = _make_policy(framework="NIST SP 800-53")
        assert classify_policy_family(policy) == "security_compliance"

    def test_cis_name(self):
        policy = _make_policy(name="cis_aws_benchmark")
        assert classify_policy_family(policy) == "security_compliance"

    def test_compliance_keyword(self):
        policy = _make_policy(description="Regulatory compliance enforcement")
        assert classify_policy_family(policy) == "security_compliance"

    def test_pci_framework(self):
        policy = _make_policy(framework="PCI-DSS v4.0")
        assert classify_policy_family(policy) == "security_compliance"


# =====================================================
# INFRASTRUCTURE SECURITY
# =====================================================


class TestInfrastructureSecurity:
    def test_encryption_keyword(self):
        policy = _make_policy(description="Enforce encryption at rest")
        assert classify_policy_family(policy) == "infrastructure_security"

    def test_public_access_keyword(self):
        policy = _make_policy(name="deny_public_s3_buckets")
        assert classify_policy_family(policy) == "infrastructure_security"

    def test_ingress_keyword(self):
        policy = _make_policy(description="Block open ingress on port 22")
        assert classify_policy_family(policy) == "infrastructure_security"

    def test_tls_keyword(self):
        policy = _make_policy(name="require_tls_endpoints")
        assert classify_policy_family(policy) == "infrastructure_security"


# =====================================================
# IDENTITY GOVERNANCE
# =====================================================


class TestIdentityGovernance:
    def test_iam_keyword(self):
        policy = _make_policy(name="iam_role_constraints")
        assert classify_policy_family(policy) == "identity_governance"

    def test_mfa_keyword(self):
        policy = _make_policy(description="Require MFA for all production roles")
        assert classify_policy_family(policy) == "identity_governance"

    def test_privilege_keyword(self):
        policy = _make_policy(name="least_privilege_enforcement")
        assert classify_policy_family(policy) == "identity_governance"

    def test_access_keyword(self):
        policy = _make_policy(description="Access control for sensitive resources")
        assert classify_policy_family(policy) == "identity_governance"


# =====================================================
# OPERATIONAL GOVERNANCE
# =====================================================


class TestOperationalGovernance:
    def test_tagging_keyword(self):
        policy = _make_policy(name="required_resource_tags")
        assert classify_policy_family(policy) == "operational_governance"

    def test_naming_keyword(self):
        policy = _make_policy(description="Enforce naming conventions")
        assert classify_policy_family(policy) == "operational_governance"

    def test_region_keyword(self):
        policy = _make_policy(name="approved_regions_policy")
        assert classify_policy_family(policy) == "operational_governance"

    def test_retention_keyword(self):
        policy = _make_policy(description="Log retention policy enforcement")
        assert classify_policy_family(policy) == "operational_governance"


# =====================================================
# AI GOVERNANCE
# =====================================================


class TestAIGovernance:
    def test_ai_keyword(self):
        policy = _make_policy(name="ai_workload_controls")
        assert classify_policy_family(policy) == "ai_governance"

    def test_nist_ai_framework(self):
        policy = _make_policy(framework="NIST AI RMF")
        assert classify_policy_family(policy) == "ai_governance"

    def test_llm_keyword(self):
        policy = _make_policy(description="LLM deployment governance controls")
        assert classify_policy_family(policy) == "ai_governance"

    def test_model_keyword(self):
        policy = _make_policy(name="model_deployment_gate")
        assert classify_policy_family(policy) == "ai_governance"


# =====================================================
# CUSTOM / FALLBACK
# =====================================================


class TestCustomFallback:
    def test_empty_policy_returns_custom(self):
        assert classify_policy_family({}) == "custom"

    def test_no_recognizable_keywords(self):
        policy = _make_policy(
            name="alpha_bravo_charlie",
            description="Delta echo foxtrot"
        )
        assert classify_policy_family(policy) == "custom"

    def test_none_metadata_returns_custom(self):
        policy = {"metadata": None, "spec": None}
        assert classify_policy_family(policy) == "custom"

    def test_missing_all_fields(self):
        policy = {"irrelevant_key": "irrelevant_value"}
        assert classify_policy_family(policy) == "custom"

    def test_empty_strings_returns_custom(self):
        policy = _make_policy(name="", description="", framework="")
        assert classify_policy_family(policy) == "custom"


# =====================================================
# HIGHEST-SCORING FAMILY WINS
# =====================================================


class TestScoringResolution:
    def test_multiple_cost_keywords_beat_single_security(self):
        """
        "budget spend financial" (3 cost hits) should beat
        "hipaa" (1 security hit).
        """
        policy = _make_policy(
            name="budget_spend_financial",
            description="hipaa"
        )
        assert classify_policy_family(policy) == "cost_governance"

    def test_framework_and_name_combine_for_same_family(self):
        """
        Keywords from different fields should accumulate
        for the same family.
        """
        policy = _make_policy(
            name="nist_controls",
            framework="HIPAA"
        )
        # Both nist and hipaa hit security_compliance
        assert classify_policy_family(policy) == "security_compliance"