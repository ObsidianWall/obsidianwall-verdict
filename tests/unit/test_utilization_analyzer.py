
# tests/unit/test_utilization_analyzer.py
#
# Purpose:
# Unit tests for engine/analyzers/utilization_analyzer.py.
# Covers: pattern-based classifiers, analyze_utilization(),
#         GPU detection, oversizing, burstable candidates,
#         cost anomaly detection.

from __future__ import annotations

from typing import Any

import pytest

from engine.analyzers.utilization_analyzer import (
    _azure_vcpu_count,
    _extract_vm_size,
    _is_aws_burstable,
    _is_aws_gpu,
    _is_aws_oversized_for_dev,
    _is_azure_burstable,
    _is_azure_gpu,
    _is_azure_oversized_for_dev,
    _is_burstable_candidate,
    _is_gpu_instance,
    _is_oversized_for_environment,
    _parse_aws_instance,
    analyze_utilization,
)


# =====================================================
# FIXTURES
# =====================================================


def _make_resource(
    resource_type: str,
    name: str,
    vm_size: str | None = None,
    instance_type: str | None = None,
) -> dict[str, Any]:
    """Build a minimal resource dict for testing."""
    values: dict[str, Any] = {}
    if vm_size:
        values["vm_size"] = vm_size
    if instance_type:
        values["instance_type"] = instance_type
    return {"type": resource_type, "name": name, "values": values}


def _make_context(
    resources: list[dict[str, Any]],
    environment: str = "development",
    estimated_cost: float = 0.0,
    cost_breakdown: list[dict[str, Any]] | None = None,
    gpu_instance_count: int = 0,
    ai_gpu_workloads: int = 0,
) -> dict[str, Any]:
    """Build a minimal context dict for testing."""
    return {
        "resources":          resources,
        "environment":        environment,
        "estimated_cost":     estimated_cost,
        "cost_breakdown":     cost_breakdown or [],
        "gpu_instance_count": gpu_instance_count,
        "ai_gpu_workloads":   ai_gpu_workloads,
    }


# =====================================================
# Azure vCPU count extractor
# =====================================================


class TestAzureVcpuCount:

    def test_extracts_vcpu_from_standard_d_series(self) -> None:
        assert _azure_vcpu_count("Standard_D2s_v3")  == 2
        assert _azure_vcpu_count("Standard_D4s_v3")  == 4
        assert _azure_vcpu_count("Standard_D16s_v3") == 16

    def test_extracts_vcpu_from_b_series(self) -> None:
        assert _azure_vcpu_count("Standard_B2ms") == 2
        assert _azure_vcpu_count("Standard_B4ms") == 4

    def test_extracts_vcpu_from_nc_series(self) -> None:
        assert _azure_vcpu_count("Standard_NC6")  == 6
        assert _azure_vcpu_count("Standard_NC12") == 12

    def test_returns_zero_for_non_matching_name(self) -> None:
        assert _azure_vcpu_count("unknown_format") == 0

    def test_returns_zero_for_empty_string(self) -> None:
        assert _azure_vcpu_count("") == 0


# =====================================================
# Azure GPU classifier
# =====================================================


class TestIsAzureGpu:

    def test_nc_series_is_gpu(self) -> None:
        assert _is_azure_gpu("Standard_NC6")     is True
        assert _is_azure_gpu("Standard_NC6s_v3") is True
        assert _is_azure_gpu("Standard_NC12")    is True

    def test_nd_series_is_gpu(self) -> None:
        assert _is_azure_gpu("Standard_ND6s")    is True
        assert _is_azure_gpu("Standard_ND40rs_v2") is True

    def test_nv_series_is_gpu(self) -> None:
        assert _is_azure_gpu("Standard_NV6")  is True
        assert _is_azure_gpu("Standard_NV12") is True

    def test_d_series_is_not_gpu(self) -> None:
        assert _is_azure_gpu("Standard_D2s_v3") is False

    def test_b_series_is_not_gpu(self) -> None:
        assert _is_azure_gpu("Standard_B2s") is False

    def test_e_series_is_not_gpu(self) -> None:
        assert _is_azure_gpu("Standard_E4s_v3") is False


# =====================================================
# Azure burstable classifier
# =====================================================


class TestIsAzureBurstable:

    def test_b_series_is_burstable(self) -> None:
        assert _is_azure_burstable("Standard_B1s")  is True
        assert _is_azure_burstable("Standard_B2s")  is True
        assert _is_azure_burstable("Standard_B4ms") is True

    def test_d_series_is_not_burstable(self) -> None:
        assert _is_azure_burstable("Standard_D2s_v3") is False

    def test_nc_series_is_not_burstable(self) -> None:
        assert _is_azure_burstable("Standard_NC6") is False


# =====================================================
# Azure oversized for dev
# =====================================================


class TestIsAzureOversizedForDev:

    def test_gpu_is_always_oversized(self) -> None:
        assert _is_azure_oversized_for_dev("Standard_NC6")  is True
        assert _is_azure_oversized_for_dev("Standard_ND6s") is True

    def test_large_vcpu_count_is_oversized(self) -> None:
        assert _is_azure_oversized_for_dev("Standard_D8s_v3")  is True
        assert _is_azure_oversized_for_dev("Standard_D16s_v3") is True

    def test_small_vcpu_count_is_not_oversized(self) -> None:
        assert _is_azure_oversized_for_dev("Standard_D2s_v3") is False
        assert _is_azure_oversized_for_dev("Standard_D4s_v3") is False

    def test_burstable_b2_is_not_oversized(self) -> None:
        assert _is_azure_oversized_for_dev("Standard_B2s") is False


# =====================================================
# AWS instance parser
# =====================================================


class TestParseAwsInstance:

    def test_parses_m5_xlarge(self) -> None:
        family, rank = _parse_aws_instance("m5.xlarge")
        assert family == "m"
        assert rank   == 6

    def test_parses_t3_micro(self) -> None:
        family, rank = _parse_aws_instance("t3.micro")
        assert family == "t"
        assert rank   == 2

    def test_parses_p3_2xlarge(self) -> None:
        family, rank = _parse_aws_instance("p3.2xlarge")
        assert family == "p"
        assert rank   == 7

    def test_parses_trn1_2xlarge(self) -> None:
        family, rank = _parse_aws_instance("trn1.2xlarge")
        assert family == "trn"
        assert rank   == 7

    def test_returns_empty_for_invalid_format(self) -> None:
        family, rank = _parse_aws_instance("invalid")
        assert family == ""
        assert rank   == 0

    def test_unknown_size_returns_zero_rank(self) -> None:
        _, rank = _parse_aws_instance("m5.unknown_size")
        assert rank == 0


# =====================================================
# AWS GPU classifier
# =====================================================


class TestIsAwsGpu:

    def test_p_family_is_gpu(self) -> None:
        assert _is_aws_gpu("p3.2xlarge") is True
        assert _is_aws_gpu("p4d.24xlarge") is True

    def test_g_family_is_gpu(self) -> None:
        assert _is_aws_gpu("g5.xlarge")  is True
        assert _is_aws_gpu("g4dn.xlarge") is True

    def test_trn_family_is_gpu(self) -> None:
        assert _is_aws_gpu("trn1.2xlarge") is True

    def test_inf_family_is_gpu(self) -> None:
        assert _is_aws_gpu("inf1.xlarge") is True

    def test_m_family_is_not_gpu(self) -> None:
        assert _is_aws_gpu("m5.xlarge") is False

    def test_t_family_is_not_gpu(self) -> None:
        assert _is_aws_gpu("t3.micro") is False

    def test_c_family_is_not_gpu(self) -> None:
        assert _is_aws_gpu("c5.large") is False


# =====================================================
# AWS burstable classifier
# =====================================================


class TestIsAwsBurstable:

    def test_t_series_is_burstable(self) -> None:
        assert _is_aws_burstable("t3.micro")  is True
        assert _is_aws_burstable("t2.medium") is True
        assert _is_aws_burstable("t4g.small") is True

    def test_m_series_is_not_burstable(self) -> None:
        assert _is_aws_burstable("m5.xlarge") is False

    def test_p_series_is_not_burstable(self) -> None:
        assert _is_aws_burstable("p3.2xlarge") is False


# =====================================================
# AWS oversized for dev
# =====================================================


class TestIsAwsOversizedForDev:

    def test_gpu_is_always_oversized(self) -> None:
        assert _is_aws_oversized_for_dev("p3.2xlarge") is True
        assert _is_aws_oversized_for_dev("g5.xlarge")  is True

    def test_2xlarge_is_oversized(self) -> None:
        assert _is_aws_oversized_for_dev("m5.2xlarge") is True
        assert _is_aws_oversized_for_dev("c5.4xlarge") is True

    def test_xlarge_is_not_oversized(self) -> None:
        assert _is_aws_oversized_for_dev("m5.xlarge") is False

    def test_micro_is_not_oversized(self) -> None:
        assert _is_aws_oversized_for_dev("t3.micro") is False


# =====================================================
# _extract_vm_size
# =====================================================


class TestExtractVmSize:

    def test_extracts_azure_vm_size(self) -> None:
        resource = _make_resource("azurerm_virtual_machine", "vm", vm_size="Standard_B2s")
        assert _extract_vm_size(resource) == "Standard_B2s"

    def test_extracts_aws_instance_type(self) -> None:
        resource = _make_resource("aws_instance", "ec2", instance_type="t3.micro")
        assert _extract_vm_size(resource) == "t3.micro"

    def test_returns_none_for_non_compute_resource(self) -> None:
        resource = {"type": "aws_s3_bucket", "name": "bucket", "values": {}}
        assert _extract_vm_size(resource) is None


# =====================================================
# _is_gpu_instance
# =====================================================


class TestIsGpuInstance:

    def test_azure_gpu_instance(self) -> None:
        assert _is_gpu_instance("azurerm_virtual_machine", "Standard_NC6") is True

    def test_azure_non_gpu_instance(self) -> None:
        assert _is_gpu_instance("azurerm_virtual_machine", "Standard_B2s") is False

    def test_aws_gpu_instance(self) -> None:
        assert _is_gpu_instance("aws_instance", "p3.2xlarge") is True

    def test_aws_non_gpu_instance(self) -> None:
        assert _is_gpu_instance("aws_instance", "t3.micro") is False

    def test_unknown_provider_returns_false(self) -> None:
        assert _is_gpu_instance("google_compute_instance", "n1-standard-8") is False


# =====================================================
# _is_oversized_for_environment
# =====================================================


class TestIsOversizedForEnvironment:

    def test_azure_oversized_in_dev(self) -> None:
        assert _is_oversized_for_environment(
            "azurerm_virtual_machine", "Standard_D16s_v3", "development"
        ) is True

    def test_azure_not_oversized_in_dev(self) -> None:
        assert _is_oversized_for_environment(
            "azurerm_virtual_machine", "Standard_D2s_v3", "development"
        ) is False

    def test_azure_oversized_in_test(self) -> None:
        assert _is_oversized_for_environment(
            "azurerm_virtual_machine", "Standard_D8s_v3", "test"
        ) is True

    def test_azure_oversized_in_production_returns_false(self) -> None:
        """Production sizing is outside this analyzer's scope."""
        assert _is_oversized_for_environment(
            "azurerm_virtual_machine", "Standard_D16s_v3", "production"
        ) is False

    def test_aws_oversized_in_dev(self) -> None:
        assert _is_oversized_for_environment(
            "aws_instance", "m5.2xlarge", "development"
        ) is True

    def test_aws_not_oversized_in_dev(self) -> None:
        assert _is_oversized_for_environment(
            "aws_instance", "t3.micro", "development"
        ) is False

    def test_unknown_provider_returns_false(self) -> None:
        assert _is_oversized_for_environment(
            "google_compute_instance", "n1-standard-8", "development"
        ) is False

    def test_unknown_environment_returns_false(self) -> None:
        assert _is_oversized_for_environment(
            "aws_instance", "m5.2xlarge", "staging"
        ) is False


# =====================================================
# _is_burstable_candidate
# =====================================================


class TestIsBurstableCandidate:

    def test_aws_non_burstable_in_dev_is_candidate(self) -> None:
        assert _is_burstable_candidate("aws_instance", "m5.xlarge", "development") is True

    def test_aws_already_burstable_is_not_candidate(self) -> None:
        assert _is_burstable_candidate("aws_instance", "t3.micro", "development") is False

    def test_aws_non_burstable_in_production_is_not_candidate(self) -> None:
        assert _is_burstable_candidate("aws_instance", "m5.xlarge", "production") is False

    def test_azure_is_not_candidate(self) -> None:
        """Azure burstable migration logic is not implemented in this analyzer."""
        assert _is_burstable_candidate(
            "azurerm_virtual_machine", "Standard_D2s_v3", "development"
        ) is False

    def test_unknown_environment_is_not_candidate(self) -> None:
        assert _is_burstable_candidate("aws_instance", "m5.xlarge", "staging") is False


# =====================================================
# analyze_utilization — main function
# =====================================================


class TestAnalyzeUtilization:

    def test_returns_zero_risk_for_empty_context(self) -> None:
        """Empty context returns zero risk and no findings."""
        result = analyze_utilization(_make_context([]))
        assert result["risk_score"]  == 0
        assert result["findings"]    == []

    def test_returns_analyzer_name(self) -> None:
        result = analyze_utilization(_make_context([]))
        assert result["analyzer"] == "utilization_analyzer"

    def test_detects_ai_gpu_workloads_in_dev(self) -> None:
        """ai_gpu_workloads > 0 in dev triggers high-severity finding."""
        context = _make_context([], environment="development", ai_gpu_workloads=1)
        result  = analyze_utilization(context)

        finding_types = [f["type"] for f in result["findings"]]
        assert "gpu_workload_in_dev_environment" in finding_types
        assert result["risk_score"] > 0

    def test_ai_gpu_risk_capped_at_two_workloads(self) -> None:
        """Risk is capped at 2× GPU weight regardless of workload count."""
        context_two  = _make_context([], environment="development", ai_gpu_workloads=2)
        context_many = _make_context([], environment="development", ai_gpu_workloads=10)

        result_two  = analyze_utilization(context_two)
        result_many = analyze_utilization(context_many)

        assert result_two["risk_score"] == result_many["risk_score"]

    def test_detects_gpu_instance_count_in_dev(self) -> None:
        """gpu_instance_count > 0 in dev triggers medium-severity finding."""
        context = _make_context([], environment="development", gpu_instance_count=1)
        result  = analyze_utilization(context)

        finding_types = [f["type"] for f in result["findings"]]
        assert "gpu_instance_in_dev_environment" in finding_types

    def test_no_gpu_findings_outside_dev_environment(self) -> None:
        """GPU findings are not raised for production deployments."""
        context = _make_context([], environment="production", ai_gpu_workloads=2)
        result  = analyze_utilization(context)

        finding_types = [f["type"] for f in result["findings"]]
        assert "gpu_workload_in_dev_environment" not in finding_types

    def test_detects_oversized_azure_vm_in_dev(self) -> None:
        """Oversized Azure VM in development triggers finding."""
        resource = _make_resource(
            "azurerm_virtual_machine", "big_vm", vm_size="Standard_D16s_v3"
        )
        context = _make_context([resource], environment="development")
        result  = analyze_utilization(context)

        finding_types = [f["type"] for f in result["findings"]]
        assert "oversized_for_environment" in finding_types
        assert result["risk_score"] > 0

    def test_detects_oversized_aws_instance_in_dev(self) -> None:
        """Oversized AWS instance in development triggers finding."""
        resource = _make_resource(
            "aws_instance", "big_ec2", instance_type="m5.2xlarge"
        )
        context = _make_context([resource], environment="development")
        result  = analyze_utilization(context)

        finding_types = [f["type"] for f in result["findings"]]
        assert "oversized_for_environment" in finding_types

    def test_detects_burstable_candidate(self) -> None:
        """Non-burstable AWS instance in dev triggers burstable candidate finding."""
        resource = _make_resource(
            "aws_instance", "medium_ec2", instance_type="m5.large"
        )
        context = _make_context([resource], environment="development")
        result  = analyze_utilization(context)

        finding_types = [f["type"] for f in result["findings"]]
        assert "burstable_candidate" in finding_types

    def test_no_findings_for_appropriately_sized_dev_instance(self) -> None:
        """Appropriately sized T-series instance in dev has no findings."""
        resource = _make_resource(
            "aws_instance", "small_ec2", instance_type="t3.micro"
        )
        context = _make_context([resource], environment="development")
        result  = analyze_utilization(context)

        assert result["risk_score"] == 0
        assert result["findings"]   == []

    def test_detects_per_resource_gpu_in_dev(self) -> None:
        """GPU instance found via resource scan (no context key) triggers finding."""
        resource = _make_resource(
            "aws_instance", "gpu_ec2", instance_type="p3.2xlarge"
        )
        # gpu_instance_count=0 and ai_gpu_workloads=0 forces per-resource path
        context = _make_context(
            [resource],
            environment="development",
            gpu_instance_count=0,
            ai_gpu_workloads=0,
        )
        result = analyze_utilization(context)

        finding_types = [f["type"] for f in result["findings"]]
        assert "gpu_instance_in_dev_environment" in finding_types

    def test_detects_cost_anomaly(self) -> None:
        """Resource costing significantly more than average triggers anomaly."""
        resources = [
            _make_resource("aws_instance", "cheap_a", instance_type="t3.micro"),
            _make_resource("aws_instance", "cheap_b", instance_type="t3.micro"),
            _make_resource("aws_instance", "expensive", instance_type="t3.micro"),
        ]
        cost_breakdown = [
            {"resource": "cheap_a",   "estimated_cost": 5.0},
            {"resource": "cheap_b",   "estimated_cost": 5.0},
            {"resource": "expensive", "estimated_cost": 500.0},
        ]
        context = _make_context(
            resources,
            environment="production",
            estimated_cost=510.0,
            cost_breakdown=cost_breakdown,
        )
        result = analyze_utilization(context)

        finding_types = [f["type"] for f in result["findings"]]
        assert "cost_anomaly" in finding_types

    def test_no_cost_anomaly_for_single_resource(self) -> None:
        """Cost anomaly detection requires more than one resource."""
        resource = _make_resource("aws_instance", "only_resource", instance_type="t3.micro")
        context  = _make_context(
            [resource],
            estimated_cost=500.0,
            cost_breakdown=[{"resource": "only_resource", "estimated_cost": 500.0}],
        )
        result = analyze_utilization(context)

        finding_types = [f["type"] for f in result["findings"]]
        assert "cost_anomaly" not in finding_types

    def test_metadata_includes_environment(self) -> None:
        """Metadata block includes the environment."""
        context = _make_context([], environment="production")
        result  = analyze_utilization(context)
        assert result["metadata"]["environment"] == "production"

    def test_skips_resources_without_vm_size(self) -> None:
        """Resources without vm_size or instance_type are skipped."""
        resource = {"type": "aws_s3_bucket", "name": "bucket", "values": {}}
        context  = _make_context([resource], environment="development")
        result   = analyze_utilization(context)
        assert result["risk_score"] == 0
        assert result["findings"]   == []