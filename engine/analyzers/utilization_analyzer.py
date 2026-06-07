# engine/analyzers/utilization_analyzer.py
#
# Purpose:
# Analyze infrastructure utilization patterns.
#
# Responsibilities:
# - Resource overprovisioning detection
# - Environment-appropriate sizing analysis
# - GPU workload environment validation
# - Cost-per-resource anomaly detection
# - Utilization risk scoring
#
# Classification approach (v0.3.5):
# Instance types are classified by parsing the
# naming convention rather than matching against
# hardcoded sets. This covers all current and
# future instance families without maintenance.
#
# Azure naming convention:
#   Standard_{Family}{vCPUs}{tier}_v{version}
#   Standard_D2s_v3   → D family, 2 vCPUs
#   Standard_D16s_v3  → D family, 16 vCPUs
#   Standard_NC6s_v3  → NC family (GPU)
#   Standard_B2ms     → B family (burstable)
#
# AWS naming convention:
#   {family}{generation}.{size}
#   m5.xlarge   → M family, xlarge
#   t3.micro    → T family (burstable), micro
#   p3.2xlarge  → P family (GPU)
#   g5.xlarge   → G family (GPU)
#
# Enrichment (v0.3.5):
# - Fixed dead code: cost_lookup now assigned and used
# - Added GPU detection via ai_gpu_workloads and
#   gpu_instance_count context keys
# - Replaced hardcoded instance type frozensets with
#   pattern-based classifiers
#
# IMPORTANT:
# This analyzer NEVER performs enforcement.
# Findings are advisory only.

from __future__ import annotations

import re
from typing import Any

from audit.audit_logger import get_logger

logger = get_logger()


# =====================================================
# RISK WEIGHTS
# =====================================================

# TODO: Replace with centralized scoring engine.
RISK_WEIGHT_OVERPROVISIONED = 25
RISK_WEIGHT_WRONG_ENV_SIZING = 20
RISK_WEIGHT_BURSTABLE_CANDIDATE = 10
RISK_WEIGHT_GPU_IN_DEV = 30


# =====================================================
# THRESHOLDS
# =====================================================

# Azure: vCPU count at or above this threshold is
# considered oversized for development environments.
AZURE_DEV_VCPU_THRESHOLD = 8

# AWS: size ranks above this threshold are oversized
# for development. xlarge = rank 6.
AWS_DEV_SIZE_RANK_THRESHOLD = 6

# Cost anomaly: flag resources costing more than
# this multiple of the deployment average.
COST_ANOMALY_MULTIPLIER = 3.0


# =====================================================
# PATTERN-BASED INSTANCE CLASSIFIERS
#
# These functions parse the provider's naming
# convention rather than matching against lists.
# They work for all current and future instance
# families from AWS and Azure without maintenance.
# =====================================================


def _azure_vcpu_count(vm_size: str) -> int:
    """
    Extract vCPU count from Azure VM size name.

    Azure naming: Standard_{Family}{vCPUs}{tier}_v{n}
      Standard_D2s_v3  → 2 vCPUs
      Standard_D16s_v3 → 16 vCPUs
      Standard_B2ms    → 2 vCPUs
      Standard_NC6s_v3 → 6 vCPUs

    Returns 0 if the pattern does not match.
    """
    match = re.search(r"_[A-Za-z]+(\d+)", vm_size)
    return int(match.group(1)) if match else 0


def _is_azure_gpu(vm_size: str) -> bool:
    """
    Return True if the Azure VM is a GPU instance.

    Azure GPU families use NC, ND, or NV prefix.
    This pattern covers all current and future
    versions (NC6, NC6s_v3, NDv2, NVv4, etc.)
    without requiring per-version list maintenance.
    """
    return bool(re.match(r"Standard_N[CDV]", vm_size, re.IGNORECASE))


def _is_azure_burstable(vm_size: str) -> bool:
    """
    Return True if the Azure VM is a burstable
    instance. Azure burstable family is B series.
    """
    return bool(re.match(r"Standard_B", vm_size, re.IGNORECASE))


def _is_azure_oversized_for_dev(vm_size: str) -> bool:
    """
    Return True if the Azure VM is oversized for
    a development or test environment.

    GPU instances are always oversized for dev.
    Non-GPU instances with vCPUs >= threshold
    are considered oversized.
    """
    if _is_azure_gpu(vm_size):
        return True
    return _azure_vcpu_count(vm_size) >= AZURE_DEV_VCPU_THRESHOLD


# AWS size names mapped to ordinal rank.
# Used to compare relative size across instance types.
_AWS_SIZE_RANK: dict[str, int] = {
    "nano": 1,
    "micro": 2,
    "small": 3,
    "medium": 4,
    "large": 5,
    "xlarge": 6,
    "2xlarge": 7,
    "4xlarge": 8,
    "8xlarge": 9,
    "12xlarge": 10,
    "16xlarge": 11,
    "24xlarge": 12,
    "32xlarge": 13,
    "48xlarge": 14,
    "metal": 15,
}

# AWS families that are GPU compute.
# Stable family prefixes — covers all generations
# of P, G, Trn (Trainium), and Inf (Inferentia).
_AWS_GPU_FAMILIES: frozenset[str] = frozenset(
    {
        "p",  # P family  — NVIDIA Tesla / A100
        "g",  # G family  — NVIDIA T4 / A10G
        "trn",  # Trainium  — AWS custom AI training
        "inf",  # Inferentia — AWS custom inference
    }
)

# AWS families that are burstable (T series).
_AWS_BURSTABLE_FAMILIES: frozenset[str] = frozenset({"t"})


def _parse_aws_instance(instance_type: str) -> tuple[str, int]:
    """
    Parse an AWS instance type into (family, size_rank).

    AWS naming: {family}{generation}.{size}
      m5.xlarge   → ("m",   6)
      t3.micro    → ("t",   2)
      p3.2xlarge  → ("p",   7)
      trn1.2xlarge → ("trn", 7)
      g5.xlarge   → ("g",   6)

    Returns ("", 0) if the pattern does not match.
    """
    parts = instance_type.split(".")
    if len(parts) != 2:
        return ("", 0)

    family_match = re.match(r"([a-z]+)\d*", parts[0])
    family = family_match.group(1) if family_match else ""
    size_rank = _AWS_SIZE_RANK.get(parts[1], 0)
    return (family, size_rank)


def _is_aws_gpu(instance_type: str) -> bool:
    """
    Return True if the AWS instance is a GPU or
    AI accelerator type.

    Covers P, G, Trn, and Inf families across all
    current and future generations.
    """
    family, _ = _parse_aws_instance(instance_type)
    return family in _AWS_GPU_FAMILIES


def _is_aws_burstable(instance_type: str) -> bool:
    """Return True if the AWS instance is T series."""
    family, _ = _parse_aws_instance(instance_type)
    return family in _AWS_BURSTABLE_FAMILIES


def _is_aws_oversized_for_dev(instance_type: str) -> bool:
    """
    Return True if the AWS instance is oversized
    for a development or test environment.

    GPU instances are always oversized for dev.
    Non-GPU instances with size rank above the
    threshold (larger than xlarge) are oversized.
    """
    if _is_aws_gpu(instance_type):
        return True
    _, size_rank = _parse_aws_instance(instance_type)
    return size_rank > AWS_DEV_SIZE_RANK_THRESHOLD


# =====================================================
# RESOURCE-LEVEL HELPERS
# =====================================================


def _extract_vm_size(resource: dict[str, Any]) -> str | None:
    """
    Extract VM or instance size from resource values.
    Supports Azure and AWS naming conventions.
    """
    values: dict[str, Any] = resource.get("values", {})
    return values.get("vm_size") or values.get("instance_type")


def _is_gpu_instance(
    resource_type: str,
    vm_size: str,
) -> bool:
    """
    Return True if the resource is a GPU instance.
    Delegates to provider-specific classifiers.
    """
    if resource_type.startswith("azurerm_"):
        return _is_azure_gpu(vm_size)
    if resource_type.startswith("aws_"):
        return _is_aws_gpu(vm_size)
    return False


def _is_oversized_for_environment(
    resource_type: str,
    vm_size: str,
    environment: str,
) -> bool:
    """
    Return True if the resource is oversized for
    its declared environment. Only evaluates
    development, dev, and test — production
    sizing is outside this analyzer's scope.
    """
    if environment not in ("development", "dev", "test"):
        return False
    if resource_type.startswith("azurerm_"):
        return _is_azure_oversized_for_dev(vm_size)
    if resource_type.startswith("aws_"):
        return _is_aws_oversized_for_dev(vm_size)
    return False


def _is_burstable_candidate(
    resource_type: str,
    vm_size: str,
    environment: str,
) -> bool:
    """
    Return True if the resource is a candidate for
    migration to a burstable instance type.
    Only applicable to AWS development workloads.
    """
    if environment not in ("development", "dev", "test"):
        return False
    if resource_type.startswith("aws_"):
        return not _is_aws_burstable(vm_size)
    return False


# =====================================================
# UTILIZATION ANALYZER
# =====================================================


def analyze_utilization(runtime_context: dict[str, Any]) -> dict[str, Any]:
    """
    Analyze infrastructure utilization posture.

    Uses pattern-based instance classification to
    detect overprovisioning and rightsizing
    opportunities across all current and future
    AWS and Azure instance families.

    Uses per-resource cost data from the Translation
    Layer to identify cost anomalies.

    GPU workload detection uses pre-computed context
    keys from the parser for confirmed counts.

    Detects:
    - GPU workloads in development environments
    - Oversized compute for environment
    - Burstable instance candidates
    - Cost-per-resource anomalies
    """

    resources: list[dict[str, Any]] = runtime_context.get("resources", [])
    environment: str = runtime_context.get("environment", "unknown")
    cost_breakdown: list[dict[str, Any]] = runtime_context.get("cost_breakdown", [])
    estimated_cost: float = float(runtime_context.get("estimated_cost", 0.0))

    # GPU workload context keys from Translation Layer
    gpu_instance_count: int = int(runtime_context.get("gpu_instance_count", 0))
    ai_gpu_workloads: int = int(runtime_context.get("ai_gpu_workloads", 0))

    findings: list[dict[str, Any]] = []
    optimization_candidates: list[dict[str, Any]] = []
    risk_score: int = 0

    # Build cost lookup by resource name.
    # Used in per-resource analysis and anomaly detection.
    cost_lookup: dict[str, float] = {
        str(item.get("resource", "")): float(item.get("estimated_cost", 0.0))
        for item in cost_breakdown
    }

    # =================================================
    # GPU WORKLOAD DETECTION
    # Uses pre-computed context keys from the
    # Translation Layer. GPU instances in development
    # or test environments are almost always oversized
    # and significantly more expensive than needed.
    # =================================================

    if ai_gpu_workloads > 0 and environment in ("development", "dev", "test"):
        risk_score += RISK_WEIGHT_GPU_IN_DEV * min(ai_gpu_workloads, 2)

        findings.append(
            {
                "type": "gpu_workload_in_dev_environment",
                "severity": "high",
                "message": (
                    f"{ai_gpu_workloads} AI/GPU workload(s) detected "
                    f"in {environment} environment. GPU instances are "
                    f"significantly more expensive than standard compute "
                    f"and are rarely justified for non-production workloads."
                ),
            }
        )

        optimization_candidates.append(
            {
                "type": "gpu_rightsizing",
                "message": (
                    f"Replace {ai_gpu_workloads} GPU instance(s) with "
                    f"standard compute for {environment} workloads. "
                    f"Reserve GPU instances for production inference "
                    f"or training pipelines."
                ),
                "estimated_savings_percent": 60,
            }
        )

    elif gpu_instance_count > 0 and environment in ("development", "dev", "test"):
        risk_score += RISK_WEIGHT_WRONG_ENV_SIZING * min(gpu_instance_count, 2)

        findings.append(
            {
                "type": "gpu_instance_in_dev_environment",
                "severity": "medium",
                "message": (
                    f"{gpu_instance_count} GPU instance(s) detected "
                    f"in {environment} environment. "
                    f"Validate whether GPU capacity is required "
                    f"for this workload."
                ),
            }
        )

        optimization_candidates.append(
            {
                "type": "gpu_validation",
                "message": (
                    f"Review {gpu_instance_count} GPU instance(s) in "
                    f"{environment} and replace with standard compute "
                    f"if GPU acceleration is not required."
                ),
                "estimated_savings_percent": 50,
            }
        )

    # =================================================
    # PER-RESOURCE UTILIZATION ANALYSIS
    # Pattern-based classifiers cover all instance
    # families without hardcoded type lists.
    # =================================================

    for resource in resources:
        resource_type: str = resource.get("type", "")
        resource_name: str = resource.get("name", "unknown")
        vm_size: str | None = _extract_vm_size(resource)

        if not vm_size:
            continue

        resource_cost: float = cost_lookup.get(resource_name, 0.0)
        cost_note: str = f" (${resource_cost:.2f}/mo)" if resource_cost > 0.0 else ""

        # -------------------------------------------------
        # GPU INSTANCE — PER RESOURCE
        # Avoid duplicate findings if already flagged
        # via the context key checks above.
        # -------------------------------------------------

        if _is_gpu_instance(resource_type, vm_size):
            if (
                environment in ("development", "dev", "test")
                and ai_gpu_workloads == 0
                and gpu_instance_count == 0
            ):
                risk_score += RISK_WEIGHT_GPU_IN_DEV

                findings.append(
                    {
                        "type": "gpu_instance_in_dev_environment",
                        "severity": "high",
                        "message": (
                            f"Resource '{resource_name}' ({vm_size})"
                            f"{cost_note} is a GPU instance in "
                            f"{environment}. GPU capacity is rarely "
                            f"justified for non-production workloads."
                        ),
                    }
                )

        # -------------------------------------------------
        # ENVIRONMENT-INAPPROPRIATE SIZING
        # -------------------------------------------------

        elif _is_oversized_for_environment(resource_type, vm_size, environment):
            risk_score += RISK_WEIGHT_WRONG_ENV_SIZING

            findings.append(
                {
                    "type": "oversized_for_environment",
                    "severity": "medium",
                    "message": (
                        f"Resource '{resource_name}' ({vm_size})"
                        f"{cost_note} appears oversized for "
                        f"{environment} environment. "
                        f"Consider a smaller instance size."
                    ),
                }
            )

            optimization_candidates.append(
                {
                    "type": "rightsizing",
                    "message": (
                        f"Downsize '{resource_name}' from {vm_size} "
                        f"to a {environment}-appropriate instance size."
                    ),
                    "estimated_savings_percent": 35,
                }
            )

        # -------------------------------------------------
        # BURSTABLE INSTANCE CANDIDATE
        # -------------------------------------------------

        elif _is_burstable_candidate(resource_type, vm_size, environment):
            risk_score += RISK_WEIGHT_BURSTABLE_CANDIDATE

            findings.append(
                {
                    "type": "burstable_candidate",
                    "severity": "low",
                    "message": (
                        f"Resource '{resource_name}' ({vm_size}) "
                        f"may be a candidate for a burstable "
                        f"instance type in {environment} environment."
                    ),
                }
            )

            optimization_candidates.append(
                {
                    "type": "burstable_migration",
                    "message": (
                        f"Consider migrating '{resource_name}' to a "
                        f"burstable instance type (e.g. t3.medium) "
                        f"for {environment} workloads."
                    ),
                    "estimated_savings_percent": 30,
                }
            )

    # =================================================
    # COST-PER-RESOURCE ANOMALY
    # Uses cost_lookup built from Translation Layer
    # cost_breakdown data to identify resources that
    # cost disproportionately more than the average.
    # =================================================

    if estimated_cost > 0.0 and len(resources) > 1:
        average_cost: float = estimated_cost / len(resources)

        for item in cost_breakdown:
            item_cost: float = float(item.get("estimated_cost", 0.0))
            item_resource: str = str(item.get("resource", "unknown"))

            if item_cost > (average_cost * COST_ANOMALY_MULTIPLIER):
                risk_score += RISK_WEIGHT_OVERPROVISIONED

                findings.append(
                    {
                        "type": "cost_anomaly",
                        "severity": "medium",
                        "message": (
                            f"Resource '{item_resource}' "
                            f"(${item_cost:.2f}) costs significantly "
                            f"more than the deployment average "
                            f"(${average_cost:.2f}). "
                            f"Potential overprovisioning."
                        ),
                    }
                )

                optimization_candidates.append(
                    {
                        "type": "cost_anomaly_review",
                        "message": (
                            f"Review '{item_resource}' configuration "
                            f"for overprovisioning or unexpected cost."
                        ),
                        "estimated_savings_percent": 20,
                    }
                )

    logger.info(
        "utilization_analysis_complete",
        extra={
            "extra": {
                "resource_count": len(resources),
                "risk_score": risk_score,
                "finding_count": len(findings),
                "environment": environment,
                "gpu_instance_count": gpu_instance_count,
                "ai_gpu_workloads": ai_gpu_workloads,
            }
        },
    )

    return {
        "analyzer": "utilization_analyzer",
        "risk_score": risk_score,
        "findings": findings,
        "optimization_candidates": optimization_candidates,
        "metadata": {
            "environment": environment,
            "resource_count": len(resources),
            "estimated_cost": estimated_cost,
            "gpu_instance_count": gpu_instance_count,
            "ai_gpu_workloads": ai_gpu_workloads,
        },
    }
