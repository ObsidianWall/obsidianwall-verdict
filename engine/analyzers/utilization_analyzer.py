# engine/analyzers/utilization_analyzer.py

# Purpose:
# Analyze infrastructure utilization patterns.
#
# Responsibilities:
# - Resource overprovisioning detection
# - Environment-appropriate sizing analysis
# - Idle resource identification
# - CPU/memory allocation mismatch detection
# - Utilization risk scoring
#
# IMPORTANT:
# This analyzer NEVER performs enforcement.
# Findings are advisory only.


from audit.audit_logger import get_logger

logger = get_logger()


# =====================================================
# UTILIZATION CONSTANTS
# =====================================================

# TODO: Replace with centralized scoring engine.
RISK_WEIGHT_OVERPROVISIONED = 25
RISK_WEIGHT_WRONG_ENV_SIZING = 20
RISK_WEIGHT_BURSTABLE_CANDIDATE = 10

# Azure VM sizes considered oversized for development
# NOTE:
# Full pricing intelligence will replace this lookup.
# Currently pattern-based on size tier naming conventions.
AZURE_OVERSIZED_FOR_DEV = {
    "Standard_D4s_v3",
    "Standard_D8s_v3",
    "Standard_D16s_v3",
    "Standard_D32s_v3",
    "Standard_E4s_v3",
    "Standard_E8s_v3",
    "Standard_F4s_v2",
    "Standard_F8s_v2",
}

# Azure VM sizes appropriate for development
AZURE_DEV_APPROPRIATE = {
    "Standard_B1s",
    "Standard_B1ms",
    "Standard_B2s",
    "Standard_B2ms",
    "Standard_D2s_v3",
    "Standard_D2as_v4",
}

# AWS instance types considered oversized for development
AWS_OVERSIZED_FOR_DEV = {
    "m5.xlarge",
    "m5.2xlarge",
    "m5.4xlarge",
    "c5.xlarge",
    "c5.2xlarge",
    "r5.xlarge",
    "r5.2xlarge",
}

# AWS instance types that are burstable (good for dev)
AWS_BURSTABLE_TYPES = {
    "t3.micro",
    "t3.small",
    "t3.medium",
    "t3.large",
    "t3a.micro",
    "t3a.small",
    "t3a.medium",
}


def _extract_vm_size(resource: dict) -> str | None:
    """
    Extract VM/instance size from resource values.
    Supports Azure and AWS naming conventions.
    """
    values = resource.get("values", {})

    # Azure
    vm_size = values.get("vm_size")
    if vm_size:
        return vm_size

    # AWS
    instance_type = values.get("instance_type")
    if instance_type:
        return instance_type

    return None


def _is_oversized_for_environment(
    resource_type: str, vm_size: str, environment: str
) -> bool:
    """
    Determine if a resource is oversized for its environment.
    """
    if environment not in ("development", "dev", "test"):
        return False

    if resource_type.startswith("azurerm_"):
        return vm_size in AZURE_OVERSIZED_FOR_DEV

    if resource_type.startswith("aws_"):
        return vm_size in AWS_OVERSIZED_FOR_DEV

    return False


def _is_burstable_candidate(resource_type: str, vm_size: str, environment: str) -> bool:
    """
    Determine if a compute resource is a candidate
    for burstable/smaller instance sizing.
    """
    if environment not in ("development", "dev", "test"):
        return False

    if resource_type.startswith("aws_"):
        return vm_size not in AWS_BURSTABLE_TYPES

    return False


# =====================================================
# UTILIZATION ANALYZER
# =====================================================


def analyze_utilization(runtime_context: dict) -> dict:
    """
    Analyze infrastructure utilization posture.

    Detects:
    - Oversized compute resources for environment
    - Burstable instance candidates in development
    - Cost-per-resource anomalies
    - Environment-inappropriate sizing patterns
    """

    resources = runtime_context.get("resources", [])
    environment = runtime_context.get("environment", "unknown")
    cost_breakdown = runtime_context.get("cost_breakdown", [])
    estimated_cost = runtime_context.get("estimated_cost", 0)

    findings = []
    optimization_candidates = []
    risk_score = 0

    # Build cost lookup by resource name
    {item.get("resource"): item.get("estimated_cost", 0) for item in cost_breakdown}

    # =================================================
    # PER-RESOURCE UTILIZATION ANALYSIS
    # =================================================

    for resource in resources:
        resource_type = resource.get("type", "")
        resource_name = resource.get("name", "unknown")
        vm_size = _extract_vm_size(resource)

        if not vm_size:
            continue

        # -------------------------------------------------
        # ENVIRONMENT-INAPPROPRIATE SIZING
        # -------------------------------------------------

        if _is_oversized_for_environment(resource_type, vm_size, environment):
            risk_score += RISK_WEIGHT_WRONG_ENV_SIZING

            findings.append(
                {
                    "type": "oversized_for_environment",
                    "severity": "medium",
                    "message": (
                        f"Resource '{resource_name}' ({vm_size}) "
                        f"appears oversized for {environment} environment. "
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
                        f"may be a candidate for a burstable instance "
                        f"type in {environment} environment."
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
    # =================================================

    # Flag resources with disproportionately high cost
    # relative to the total estimated cost
    if estimated_cost > 0 and len(resources) > 1:
        average_cost = estimated_cost / len(resources)

        for item in cost_breakdown:
            resource_cost = item.get("estimated_cost", 0)
            resource_name = item.get("resource", "unknown")

            # Flag if a resource costs more than 3x average
            if resource_cost > (average_cost * 3):
                risk_score += RISK_WEIGHT_OVERPROVISIONED

                findings.append(
                    {
                        "type": "cost_anomaly",
                        "severity": "medium",
                        "message": (
                            f"Resource '{resource_name}' "
                            f"(${resource_cost}) costs significantly "
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
                            f"Review '{resource_name}' configuration "
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
        },
    }
