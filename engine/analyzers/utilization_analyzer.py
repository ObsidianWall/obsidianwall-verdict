# engine/analyzers/utilization_analyzer.py
#
# Purpose:
# Analyze infrastructure utilization patterns.
#
# Responsibilities:
# - Resource overprovisioning detection
# - Environment-appropriate sizing analysis
# - Idle resource identification
# - Cost-per-resource anomaly detection
# - GPU workload environment validation
# - Utilization risk scoring
#
# Enrichment (v0.3.5):
# - Fixed dead code: cost_lookup dict is now assigned
#   and used in per-resource cost analysis.
# - Added GPU workload detection using ai_gpu_workloads
#   and gpu_instance_count context keys.
# - Added environment-aware GPU cost risk scoring.
#
# IMPORTANT:
# This analyzer NEVER performs enforcement.
# Findings are advisory only.

from __future__ import annotations

from typing import Any

from audit.audit_logger import get_logger

logger = get_logger()


# =====================================================
# UTILIZATION CONSTANTS
# =====================================================

# TODO: Replace with centralized scoring engine.
RISK_WEIGHT_OVERPROVISIONED      = 25
RISK_WEIGHT_WRONG_ENV_SIZING     = 20
RISK_WEIGHT_BURSTABLE_CANDIDATE  = 10
RISK_WEIGHT_GPU_IN_DEV           = 30

# Azure VM sizes considered oversized for development
# NOTE:
# Full pricing intelligence will replace this lookup.
# Currently pattern-based on size tier naming conventions.
AZURE_OVERSIZED_FOR_DEV: frozenset[str] = frozenset({
    "Standard_D4s_v3",
    "Standard_D8s_v3",
    "Standard_D16s_v3",
    "Standard_D32s_v3",
    "Standard_E4s_v3",
    "Standard_E8s_v3",
    "Standard_F4s_v2",
    "Standard_F8s_v2",
})

# Azure VM sizes appropriate for development
AZURE_DEV_APPROPRIATE: frozenset[str] = frozenset({
    "Standard_B1s",
    "Standard_B1ms",
    "Standard_B2s",
    "Standard_B2ms",
    "Standard_D2s_v3",
    "Standard_D2as_v4",
})

# Azure GPU VM sizes — always flag in dev/test
AZURE_GPU_SIZES: frozenset[str] = frozenset({
    "Standard_NC6",
    "Standard_NC12",
    "Standard_NC24",
    "Standard_NC6s_v3",
    "Standard_NC12s_v3",
    "Standard_NC24s_v3",
    "Standard_ND40rs_v2",
    "Standard_NV6",
    "Standard_NV12",
    "Standard_NV24",
})

# AWS instance types considered oversized for development
AWS_OVERSIZED_FOR_DEV: frozenset[str] = frozenset({
    "m5.xlarge",
    "m5.2xlarge",
    "m5.4xlarge",
    "c5.xlarge",
    "c5.2xlarge",
    "r5.xlarge",
    "r5.2xlarge",
})

# AWS instance types that are burstable (good for dev)
AWS_BURSTABLE_TYPES: frozenset[str] = frozenset({
    "t3.micro",
    "t3.small",
    "t3.medium",
    "t3.large",
    "t3a.micro",
    "t3a.small",
    "t3a.medium",
})

# AWS GPU instance types — always flag in dev/test
AWS_GPU_TYPES: frozenset[str] = frozenset({
    "p2.xlarge",
    "p2.8xlarge",
    "p2.16xlarge",
    "p3.2xlarge",
    "p3.8xlarge",
    "p3.16xlarge",
    "p4d.24xlarge",
    "g4dn.xlarge",
    "g4dn.2xlarge",
    "g4dn.4xlarge",
    "g5.xlarge",
    "g5.2xlarge",
})


# =====================================================
# HELPERS
# =====================================================


def _extract_vm_size(resource: dict[str, Any]) -> str | None:
    """
    Extract VM or instance size from resource values.
    Supports Azure and AWS naming conventions.
    """
    values: dict[str, Any] = resource.get("values", {})

    # Azure
    vm_size: str | None = values.get("vm_size")
    if vm_size:
        return vm_size

    # AWS
    instance_type: str | None = values.get("instance_type")
    if instance_type:
        return instance_type

    return None


def _is_oversized_for_environment(
    resource_type: str,
    vm_size:       str,
    environment:   str,
) -> bool:
    """
    Return True if the resource is oversized for
    its declared environment.
    Only evaluates development, dev, and test
    environments — production sizing is out of scope.
    """
    if environment not in ("development", "dev", "test"):
        return False

    if resource_type.startswith("azurerm_"):
        return vm_size in AZURE_OVERSIZED_FOR_DEV

    if resource_type.startswith("aws_"):
        return vm_size in AWS_OVERSIZED_FOR_DEV

    return False


def _is_burstable_candidate(
    resource_type: str,
    vm_size:       str,
    environment:   str,
) -> bool:
    """
    Return True if the resource is a candidate for
    a burstable instance type.
    Only applicable to AWS development workloads.
    """
    if environment not in ("development", "dev", "test"):
        return False

    if resource_type.startswith("aws_"):
        return vm_size not in AWS_BURSTABLE_TYPES

    return False


def _is_gpu_instance(
    resource_type: str,
    vm_size:       str,
) -> bool:
    """
    Return True if the resource is a GPU instance.
    Covers Azure NC/ND/NV series and AWS P/G families.
    """
    if resource_type.startswith("azurerm_"):
        return vm_size in AZURE_GPU_SIZES

    if resource_type.startswith("aws_"):
        return vm_size in AWS_GPU_TYPES

    return False


# =====================================================
# UTILIZATION ANALYZER
# =====================================================


def analyze_utilization(runtime_context: dict[str, Any]) -> dict[str, Any]:
    """
    Analyze infrastructure utilization posture.

    Uses per-resource cost data from the Translation
    Layer to identify anomalies and rightsizing
    opportunities. GPU workload detection uses
    pre-computed context keys from the parser.

    Detects:
    - Oversized compute resources for environment
    - Burstable instance candidates in development
    - GPU workloads in development environments
    - Cost-per-resource anomalies
    - Environment-inappropriate sizing patterns
    """

    resources:      list[dict[str, Any]] = runtime_context.get("resources", [])
    environment:    str                   = runtime_context.get("environment", "unknown")
    cost_breakdown: list[dict[str, Any]] = runtime_context.get("cost_breakdown", [])
    estimated_cost: float                 = float(runtime_context.get("estimated_cost", 0.0))

    # GPU workload context keys from Translation Layer
    gpu_instance_count: int = int(runtime_context.get("gpu_instance_count", 0))
    ai_gpu_workloads:   int = int(runtime_context.get("ai_gpu_workloads", 0))

    findings:               list[dict[str, Any]] = []
    optimization_candidates: list[dict[str, Any]] = []
    risk_score: int = 0

    # Build cost lookup by resource name.
    # Used in per-resource cost anomaly detection below.
    # Previously this dict was built and discarded (dead code).
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

        findings.append({
            "type":     "gpu_workload_in_dev_environment",
            "severity": "high",
            "message": (
                f"{ai_gpu_workloads} AI/GPU workload(s) detected "
                f"in {environment} environment. GPU instances are "
                f"significantly more expensive than standard compute "
                f"and are rarely justified for non-production workloads."
            ),
        })

        optimization_candidates.append({
            "type":    "gpu_rightsizing",
            "message": (
                f"Replace {ai_gpu_workloads} GPU instance(s) with "
                f"standard compute for {environment} workloads. "
                f"Reserve GPU instances for production inference "
                f"or training pipelines."
            ),
            "estimated_savings_percent": 60,
        })

    elif gpu_instance_count > 0 and environment in ("development", "dev", "test"):
        # GPU instances detected from resource types
        # but not flagged as AI workloads by parser
        risk_score += RISK_WEIGHT_WRONG_ENV_SIZING * min(gpu_instance_count, 2)

        findings.append({
            "type":     "gpu_instance_in_dev_environment",
            "severity": "medium",
            "message": (
                f"{gpu_instance_count} GPU instance(s) detected "
                f"in {environment} environment. "
                f"Validate whether GPU capacity is required "
                f"for this workload."
            ),
        })

        optimization_candidates.append({
            "type":    "gpu_validation",
            "message": (
                f"Review {gpu_instance_count} GPU instance(s) in "
                f"{environment} and replace with standard compute "
                f"if GPU acceleration is not required."
            ),
            "estimated_savings_percent": 50,
        })

    # =================================================
    # PER-RESOURCE UTILIZATION ANALYSIS
    # =================================================

    for resource in resources:
        resource_type: str       = resource.get("type", "")
        resource_name: str       = resource.get("name", "unknown")
        vm_size:       str | None = _extract_vm_size(resource)

        if not vm_size:
            continue

        # Look up per-resource cost from Translation Layer
        resource_cost: float = cost_lookup.get(resource_name, 0.0)

        # -------------------------------------------------
        # GPU INSTANCE DETECTION — PER RESOURCE
        # Cross-reference resource-level GPU detection
        # with environment context.
        # -------------------------------------------------

        if _is_gpu_instance(resource_type, vm_size):
            if environment in ("development", "dev", "test"):
                # Already flagged via context key above if
                # ai_gpu_workloads > 0 — avoid duplicate findings
                if ai_gpu_workloads == 0 and gpu_instance_count == 0:
                    risk_score += RISK_WEIGHT_GPU_IN_DEV

                    findings.append({
                        "type":     "gpu_instance_in_dev_environment",
                        "severity": "high",
                        "message": (
                            f"Resource '{resource_name}' ({vm_size}) "
                            f"is a GPU instance in {environment}. "
                            f"GPU capacity is rarely justified for "
                            f"non-production workloads."
                        ),
                    })

        # -------------------------------------------------
        # ENVIRONMENT-INAPPROPRIATE SIZING
        # -------------------------------------------------

        elif _is_oversized_for_environment(resource_type, vm_size, environment):
            risk_score += RISK_WEIGHT_WRONG_ENV_SIZING

            cost_note: str = (
                f" (${resource_cost:.2f}/mo)" if resource_cost > 0.0 else ""
            )

            findings.append({
                "type":     "oversized_for_environment",
                "severity": "medium",
                "message": (
                    f"Resource '{resource_name}' ({vm_size}){cost_note} "
                    f"appears oversized for {environment} environment. "
                    f"Consider a smaller instance size."
                ),
            })

            optimization_candidates.append({
                "type":    "rightsizing",
                "message": (
                    f"Downsize '{resource_name}' from {vm_size} "
                    f"to a {environment}-appropriate instance size."
                ),
                "estimated_savings_percent": 35,
            })

        # -------------------------------------------------
        # BURSTABLE INSTANCE CANDIDATE
        # -------------------------------------------------

        elif _is_burstable_candidate(resource_type, vm_size, environment):
            risk_score += RISK_WEIGHT_BURSTABLE_CANDIDATE

            findings.append({
                "type":     "burstable_candidate",
                "severity": "low",
                "message": (
                    f"Resource '{resource_name}' ({vm_size}) "
                    f"may be a candidate for a burstable instance "
                    f"type in {environment} environment."
                ),
            })

            optimization_candidates.append({
                "type":    "burstable_migration",
                "message": (
                    f"Consider migrating '{resource_name}' to a "
                    f"burstable instance type (e.g. t3.medium) "
                    f"for {environment} workloads."
                ),
                "estimated_savings_percent": 30,
            })

    # =================================================
    # COST-PER-RESOURCE ANOMALY
    # Uses the cost_lookup built from Translation Layer
    # cost_breakdown data.
    # =================================================

    if estimated_cost > 0.0 and len(resources) > 1:
        average_cost: float = estimated_cost / len(resources)

        for item in cost_breakdown:
            item_cost:     float = float(item.get("estimated_cost", 0.0))
            item_resource: str   = str(item.get("resource", "unknown"))

            # Flag if a resource costs more than 3x the average
            if item_cost > (average_cost * 3.0):
                risk_score += RISK_WEIGHT_OVERPROVISIONED

                findings.append({
                    "type":     "cost_anomaly",
                    "severity": "medium",
                    "message": (
                        f"Resource '{item_resource}' "
                        f"(${item_cost:.2f}) costs significantly "
                        f"more than the deployment average "
                        f"(${average_cost:.2f}). "
                        f"Potential overprovisioning."
                    ),
                })

                optimization_candidates.append({
                    "type":    "cost_anomaly_review",
                    "message": (
                        f"Review '{item_resource}' configuration "
                        f"for overprovisioning or unexpected cost."
                    ),
                    "estimated_savings_percent": 20,
                })

    logger.info(
        "utilization_analysis_complete",
        extra={
            "extra": {
                "resource_count":    len(resources),
                "risk_score":        risk_score,
                "finding_count":     len(findings),
                "environment":       environment,
                "gpu_instance_count": gpu_instance_count,
                "ai_gpu_workloads":  ai_gpu_workloads,
            }
        },
    )

    return {
        "analyzer":               "utilization_analyzer",
        "risk_score":             risk_score,
        "findings":               findings,
        "optimization_candidates": optimization_candidates,
        "metadata": {
            "environment":       environment,
            "resource_count":    len(resources),
            "estimated_cost":    estimated_cost,
            "gpu_instance_count": gpu_instance_count,
            "ai_gpu_workloads":  ai_gpu_workloads,
        },
    }
