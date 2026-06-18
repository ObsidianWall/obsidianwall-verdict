
# tests/unit/test_coverage_frameworks.py
#
# Test suite for engine/coverage/frameworks/
#
# Covers:
# - FRAMEWORK_REGISTRY contains all four frameworks
# - Each framework has the required structure
# - HIPAA integrity and transmission controls have
#   the new context key keywords
# - NIST AI RMF MANAGE-1.1 includes ai_guardrails
# - All controls have required keys

import pytest

from engine.coverage.frameworks import (
    CIS_CONTROLS,
    FRAMEWORK_REGISTRY,
    HIPAA_CONTROLS,
    NIST_AI_RMF_CONTROLS,
    SOC2_CONTROLS,
)


# =====================================================
# FRAMEWORK REGISTRY
# =====================================================


class TestFrameworkRegistry:

    def test_registry_contains_hipaa(self):
        assert "hipaa" in FRAMEWORK_REGISTRY

    def test_registry_contains_soc2(self):
        assert "soc2" in FRAMEWORK_REGISTRY

    def test_registry_contains_cis(self):
        assert "cis" in FRAMEWORK_REGISTRY

    def test_registry_contains_nist_ai_rmf(self):
        assert "nist_ai_rmf" in FRAMEWORK_REGISTRY

    def test_registry_has_exactly_four_frameworks(self):
        assert len(FRAMEWORK_REGISTRY) == 4

    def test_registry_values_are_dicts(self):
        for framework_name, controls in FRAMEWORK_REGISTRY.items():
            assert isinstance(controls, dict), (
                f"{framework_name} controls should be a dict"
            )

    def test_registry_maps_to_correct_objects(self):
        assert FRAMEWORK_REGISTRY["hipaa"] is HIPAA_CONTROLS
        assert FRAMEWORK_REGISTRY["soc2"] is SOC2_CONTROLS
        assert FRAMEWORK_REGISTRY["cis"] is CIS_CONTROLS
        assert FRAMEWORK_REGISTRY["nist_ai_rmf"] is NIST_AI_RMF_CONTROLS


# =====================================================
# CONTROL STRUCTURE VALIDATION
# =====================================================


class TestControlStructure:

    @pytest.mark.parametrize("framework_name,controls", [
        ("hipaa", HIPAA_CONTROLS),
        ("soc2", SOC2_CONTROLS),
        ("cis", CIS_CONTROLS),
        ("nist_ai_rmf", NIST_AI_RMF_CONTROLS),
    ])
    def test_all_controls_have_title(self, framework_name, controls):
        for control_id, control_data in controls.items():
            assert "title" in control_data, (
                f"{framework_name} control {control_id} missing 'title'"
            )

    @pytest.mark.parametrize("framework_name,controls", [
        ("hipaa", HIPAA_CONTROLS),
        ("soc2", SOC2_CONTROLS),
        ("cis", CIS_CONTROLS),
        ("nist_ai_rmf", NIST_AI_RMF_CONTROLS),
    ])
    def test_all_controls_have_description(self, framework_name, controls):
        for control_id, control_data in controls.items():
            assert "description" in control_data, (
                f"{framework_name} control {control_id} missing 'description'"
            )

    @pytest.mark.parametrize("framework_name,controls", [
        ("hipaa", HIPAA_CONTROLS),
        ("soc2", SOC2_CONTROLS),
        ("cis", CIS_CONTROLS),
        ("nist_ai_rmf", NIST_AI_RMF_CONTROLS),
    ])
    def test_all_controls_have_keywords_list(self, framework_name, controls):
        for control_id, control_data in controls.items():
            assert "keywords" in control_data, (
                f"{framework_name} control {control_id} missing 'keywords'"
            )
            assert isinstance(control_data["keywords"], list), (
                f"{framework_name} control {control_id} 'keywords' must be a list"
            )

    @pytest.mark.parametrize("framework_name,controls", [
        ("hipaa", HIPAA_CONTROLS),
        ("soc2", SOC2_CONTROLS),
        ("cis", CIS_CONTROLS),
        ("nist_ai_rmf", NIST_AI_RMF_CONTROLS),
    ])
    def test_all_controls_have_at_least_one_keyword(
        self, framework_name, controls
    ):
        for control_id, control_data in controls.items():
            assert len(control_data["keywords"]) > 0, (
                f"{framework_name} control {control_id} has no keywords"
            )


# =====================================================
# HIPAA — SPECIFIC CONTROL VALIDATION
# =====================================================


class TestHipaaControls:

    def test_hipaa_has_integrity_control(self):
        assert "164.312(c)(1)" in HIPAA_CONTROLS

    def test_hipaa_integrity_control_has_versioning_keyword(self):
        control = HIPAA_CONTROLS["164.312(c)(1)"]
        assert "versioning_disabled" in control["keywords"], (
            "HIPAA 164.312(c)(1) must include 'versioning_disabled' "
            "to match versioning_disabled_count context key"
        )

    def test_hipaa_has_transmission_security_control(self):
        assert "164.312(e)(1)" in HIPAA_CONTROLS

    def test_hipaa_transmission_control_has_ssl_keyword(self):
        control = HIPAA_CONTROLS["164.312(e)(1)"]
        assert "ssl_not_enforced" in control["keywords"], (
            "HIPAA 164.312(e)(1) must include 'ssl_not_enforced' "
            "to match ssl_not_enforced_count context key"
        )

    def test_hipaa_has_access_control(self):
        assert "164.312(a)(1)" in HIPAA_CONTROLS

    def test_hipaa_has_encryption_control(self):
        assert "164.312(a)(2)(iv)" in HIPAA_CONTROLS

    def test_hipaa_has_audit_controls(self):
        assert "164.312(b)" in HIPAA_CONTROLS

    def test_hipaa_has_authentication_control(self):
        assert "164.312(d)" in HIPAA_CONTROLS

    def test_hipaa_access_control_has_mfa_keyword(self):
        control = HIPAA_CONTROLS["164.312(a)(1)"]
        assert "mfa" in control["keywords"]

    def test_hipaa_encryption_control_has_encrypt_keyword(self):
        control = HIPAA_CONTROLS["164.312(a)(2)(iv)"]
        assert "encrypt" in control["keywords"]

    def test_hipaa_has_minimum_required_controls(self):
        assert len(HIPAA_CONTROLS) >= 7


# =====================================================
# SOC 2 — SPECIFIC CONTROL VALIDATION
# =====================================================


class TestSoc2Controls:

    def test_soc2_has_logical_access_control(self):
        assert "CC6.1" in SOC2_CONTROLS

    def test_soc2_has_network_security_control(self):
        assert "CC6.6" in SOC2_CONTROLS

    def test_soc2_has_encryption_control(self):
        assert "CC6.7" in SOC2_CONTROLS

    def test_soc2_cc6_7_has_ssl_keyword(self):
        control = SOC2_CONTROLS["CC6.7"]
        assert "ssl_not_enforced" in control["keywords"]

    def test_soc2_has_minimum_required_controls(self):
        assert len(SOC2_CONTROLS) >= 8


# =====================================================
# CIS CONTROLS — SPECIFIC VALIDATION
# =====================================================


class TestCisControls:

    def test_cis_has_data_protection(self):
        assert "CIS.3" in CIS_CONTROLS

    def test_cis_has_access_control(self):
        assert "CIS.6" in CIS_CONTROLS

    def test_cis_has_audit_log_management(self):
        assert "CIS.8" in CIS_CONTROLS

    def test_cis_has_network_infrastructure(self):
        assert "CIS.12" in CIS_CONTROLS

    def test_cis_has_minimum_required_controls(self):
        assert len(CIS_CONTROLS) >= 8


# =====================================================
# NIST AI RMF — SPECIFIC VALIDATION
# =====================================================


class TestNistAiRmfControls:

    def test_nist_has_govern_1_1(self):
        assert "GOVERN-1.1" in NIST_AI_RMF_CONTROLS

    def test_nist_has_map_1_1(self):
        assert "MAP-1.1" in NIST_AI_RMF_CONTROLS

    def test_nist_has_manage_1_1(self):
        assert "MANAGE-1.1" in NIST_AI_RMF_CONTROLS

    def test_nist_manage_1_1_has_ai_guardrails_keyword(self):
        control = NIST_AI_RMF_CONTROLS["MANAGE-1.1"]
        assert "ai_guardrails" in control["keywords"], (
            "NIST AI RMF MANAGE-1.1 must include 'ai_guardrails' keyword"
        )

    def test_nist_map_1_1_has_gpu_workloads_keyword(self):
        control = NIST_AI_RMF_CONTROLS["MAP-1.1"]
        assert "ai_gpu_workloads" in control["keywords"]

    def test_nist_govern_1_1_has_ai_governance_keyword(self):
        control = NIST_AI_RMF_CONTROLS["GOVERN-1.1"]
        assert "ai_governance" in control["keywords"]

    def test_nist_has_minimum_required_controls(self):
        assert len(NIST_AI_RMF_CONTROLS) >= 10