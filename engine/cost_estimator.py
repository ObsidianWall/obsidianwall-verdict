
# engine/cost_estimator.py
#
# Purpose:
# Deterministic cost estimation from parsed Terraform resources.
#
# Design:
# - Deterministic pricing tables (no external API calls)
# - Deterministic, testable, extensible
# - Unknown resource types emit a warning and use a
#   conservative fallback — they are NEVER silently ignored
#
# IMPORTANT:
# This is the first financial intelligence layer.
# Pricing tables are intentionally simple at this stage.
# Future versions will integrate cloud provider pricing APIs
# and usage-pattern intelligence from telemetry data.

from typing import Any

from audit.audit_logger import get_logger


logger = get_logger()


# =====================================================
# PRICING TABLES
# =====================================================

AWS_EC2_PRICING: dict[str, float] = {
    "t2.micro":   10.0,
    "t2.small":   20.0,
    "t2.medium":  40.0,
    "t3.micro":   11.0,
    "t3.small":   22.0,
    "t3.medium":  42.0,
    "m5.large":   85.0,
    "m5.xlarge":  170.0,
}

AZURE_VM_PRICING: dict[str, float] = {
    "Standard_B1s":    12.0,
    "Standard_B2s":    25.0,
    "Standard_B4ms":   50.0,
    "Standard_D2s_v3": 50.0,
    "Standard_D4s_v3": 100.0,
    "Standard_D8s_v3": 200.0,
}

FIXED_RESOURCE_PRICING: dict[str, float] = {
    "azurerm_sentinel_log_analytics_workspace": 50.0,
    "azurerm_log_analytics_workspace":          30.0,
    "aws_s3_bucket":                             5.0,
    "aws_rds_instance":                         80.0,
    "azurerm_mssql_server":                    100.0,
    "google_storage_bucket":                     5.0,
    "google_sql_database_instance":             90.0,
    "aws_ecs_cluster":                          20.0,
    "azurerm_kubernetes_cluster":              150.0,
    "google_container_cluster":               120.0,
}

DEFAULT_FALLBACK_COST: float = 10.0


# =====================================================
# COST ESTIMATOR
# =====================================================

def estimate_cost(
    context: dict[str, Any],
) -> dict[str, Any]:
    """
    Estimate monthly cost from parsed Terraform resources.

    Returns:
        dict containing:
        - estimated_cost:   total estimated monthly cost
        - cost_breakdown:   per-resource cost breakdown
    """

    resources: list[dict[str, Any]] = context.get("resources", [])

    total_cost: float = 0.0
    breakdown:  list[dict[str, Any]] = []

    for resource in resources:

        resource_type: str  = resource.get("type", "")
        resource_name: str  = resource.get("name", "")
        values: dict[str, Any] = resource.get("values", {})

        cost = _estimate_resource_cost(
            resource_type,
            resource_name,
            values,
        )

        total_cost += cost

        breakdown.append({
            "resource":         resource_name,
            "type":             resource_type,
            "estimated_cost":   cost,
        })

    return {
        "estimated_cost":   total_cost,
        "cost_breakdown":   breakdown,
    }


def _estimate_resource_cost(
    resource_type: str,
    resource_name: str,
    values: dict[str, Any],
) -> float:
    """
    Estimate cost for a single resource.
    Emits a warning for unknown resource types.
    """

    # -------------------------------------------------
    # AWS EC2 — instance_type aware pricing
    # -------------------------------------------------

    if resource_type == "aws_instance":
        instance_type: str = values.get("instance_type", "t2.micro")
        cost = AWS_EC2_PRICING.get(instance_type)
        if cost is None:
            logger.warning(
                "unknown_instance_type",
                extra={"extra": {
                    "resource_type": resource_type,
                    "instance_type": instance_type,
                    "fallback_cost": DEFAULT_FALLBACK_COST,
                }}
            )
            return DEFAULT_FALLBACK_COST
        return cost

    # -------------------------------------------------
    # Azure VM — vm_size aware pricing
    # -------------------------------------------------

    if resource_type == "azurerm_virtual_machine":
        vm_size: str = values.get("vm_size", "Standard_B1s")
        cost = AZURE_VM_PRICING.get(vm_size)
        if cost is None:
            logger.warning(
                "unknown_vm_size",
                extra={"extra": {
                    "resource_type": resource_type,
                    "vm_size": vm_size,
                    "fallback_cost": DEFAULT_FALLBACK_COST,
                }}
            )
            return DEFAULT_FALLBACK_COST
        return cost

    # -------------------------------------------------
    # Fixed-price resources
    # -------------------------------------------------

    if resource_type in FIXED_RESOURCE_PRICING:
        return FIXED_RESOURCE_PRICING[resource_type]

    # -------------------------------------------------
    # Unknown resource type — log and use fallback
    # -------------------------------------------------

    logger.warning(
        "unknown_resource_type_cost_fallback",
        extra={"extra": {
            "resource_type": resource_type,
            "resource_name": resource_name,
            "fallback_cost": DEFAULT_FALLBACK_COST,
        }}
    )

    return DEFAULT_FALLBACK_COST
