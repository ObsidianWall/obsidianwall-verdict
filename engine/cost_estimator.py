# engine/cost_estimator.py
#
# Purpose:
# Deterministic cost estimation from parsed Terraform resources.
#
# Pricing modes:
#   table  — deterministic hardcoded tables (default, offline-safe)
#   live   — real-time Azure Retail Prices API (requires network)
#
# Azure Retail Prices API:
#   https://prices.azure.com/api/retail/prices
#   Free, no authentication required.
#   Always returns prices in USD.
#
# AWS pricing:
#   Requires boto3 and AWS credentials.
#   Planned for Phase 2.
#
# IMPORTANT:
# This is the financial intelligence layer.
# Pricing tables are the safe default.
# Live pricing provides real-time accuracy.
# Neither makes enforcement decisions — only recommendations.


from __future__ import annotations

import json
import urllib.parse
import urllib.request
from typing import Any

from audit.audit_logger import get_logger

logger = get_logger()


# =====================================================
# PRICING TABLES — deterministic fallback
# All prices are in USD per month.
# =====================================================

AWS_EC2_PRICING: dict[str, float] = {
    "t2.micro": 10.0,
    "t2.small": 20.0,
    "t2.medium": 40.0,
    "t3.micro": 11.0,
    "t3.small": 22.0,
    "t3.medium": 42.0,
    "t3.large": 80.0,
    "m5.large": 85.0,
    "m5.xlarge": 170.0,
    "m5.2xlarge": 340.0,
    "c5.large": 78.0,
    "c5.xlarge": 156.0,
}

AZURE_VM_PRICING: dict[str, float] = {
    "Standard_B1s": 12.0,
    "Standard_B2s": 25.0,
    "Standard_B4ms": 50.0,
    "Standard_D2s_v3": 70.0,
    "Standard_D4s_v3": 140.0,
    "Standard_D8s_v3": 280.0,
    "Standard_E2s_v3": 96.0,
    "Standard_E4s_v3": 192.0,
    # GPU instances
    "Standard_NC6": 657.0,
    "Standard_NC12": 1314.0,
    "Standard_ND96asr_v4": 21792.0,  # A100 x8
}

FIXED_RESOURCE_PRICING: dict[str, float] = {
    # Azure
    "azurerm_sentinel_log_analytics_workspace": 50.0,
    "azurerm_log_analytics_workspace": 30.0,
    "azurerm_mssql_server": 100.0,
    "azurerm_kubernetes_cluster": 150.0,
    "azurerm_storage_account": 20.0,
    # AWS
    "aws_s3_bucket": 5.0,
    "aws_db_instance": 80.0,
    "aws_ecs_cluster": 20.0,
    "aws_eks_cluster": 150.0,
    # GCP
    "google_storage_bucket": 5.0,
    "google_sql_database_instance": 90.0,
    "google_container_cluster": 120.0,
}

DEFAULT_FALLBACK_COST: float = 10.0

# Azure VM SKU name map for the Retail Prices API.
# Maps Terraform vm_size values to Azure API SKU names.
AZURE_SKU_MAP: dict[str, str] = {
    "Standard_B1s": "B1s",
    "Standard_B2s": "B2s",
    "Standard_B4ms": "B4ms",
    "Standard_D2s_v3": "D2s v3",
    "Standard_D4s_v3": "D4s v3",
    "Standard_D8s_v3": "D8s v3",
    "Standard_E2s_v3": "E2s v3",
    "Standard_E4s_v3": "E4s v3",
    "Standard_NC6": "NC6",
}

# Monthly hours — standard for cloud billing calculations
HOURS_PER_MONTH: float = 730.0

# All prices are in USD.
# Azure Retail Prices API always returns USD.
CURRENCY: str = "USD"


# =====================================================
# PUBLIC API
# =====================================================


def estimate_cost(
    context: dict[str, Any],
    pricing_mode: str = "table",
    region: str = "eastus",
) -> dict[str, Any]:
    """
    Estimate monthly cost from parsed Terraform resources.

    Args:
        context:        parsed Terraform context
        pricing_mode:   "table" (default, offline-safe)
                        "live"  (real-time Azure Retail Prices API)
        region:         Azure region for live pricing (default: eastus)

    Returns:
        dict containing:
        - estimated_cost:   total estimated monthly cost (USD)
        - cost_breakdown:   per-resource cost breakdown
        - pricing_mode:     which mode was used
        - currency:         always USD
    """

    resources: list[dict[str, Any]] = context.get("resources", [])

    total_cost: float = 0.0
    breakdown: list[dict[str, Any]] = []

    for resource in resources:
        resource_type: str = resource.get("type", "")
        resource_name: str = resource.get("name", "")
        values: dict[str, Any] = resource.get("values", {})

        cost, source = _estimate_resource_cost(
            resource_type=resource_type,
            resource_name=resource_name,
            values=values,
            pricing_mode=pricing_mode,
            region=region,
        )

        total_cost += cost

        breakdown.append(
            {
                "resource": resource_name,
                "type": resource_type,
                "estimated_cost": cost,
                "pricing_source": source,
                "currency": CURRENCY,
            }
        )

    logger.info(
        "cost_estimation_complete",
        extra={
            "extra": {
                "resource_count": len(resources),
                "total_cost": total_cost,
                "pricing_mode": pricing_mode,
                "region": region,
                "currency": CURRENCY,
            }
        },
    )

    return {
        "estimated_cost": total_cost,
        "cost_breakdown": breakdown,
        "pricing_mode": pricing_mode,
        "currency": CURRENCY,
    }


# =====================================================
# INTERNAL ESTIMATION
# =====================================================


def _estimate_resource_cost(
    resource_type: str,
    resource_name: str,
    values: dict[str, Any],
    pricing_mode: str,
    region: str,
) -> tuple[float, str]:
    """
    Returns (cost, source) where source identifies
    how the cost was determined.
    """

    # -------------------------------------------------
    # AWS EC2
    # -------------------------------------------------

    if resource_type == "aws_instance":
        instance_type: str = values.get("instance_type", "t2.micro")
        cost = AWS_EC2_PRICING.get(instance_type)
        if cost is None:
            logger.warning(
                "unknown_aws_instance_type",
                extra={
                    "extra": {
                        "instance_type": instance_type,
                        "fallback_cost": DEFAULT_FALLBACK_COST,
                    }
                },
            )
            return DEFAULT_FALLBACK_COST, "fallback"
        return cost, "table"

    # -------------------------------------------------
    # Azure VM — supports live pricing
    # -------------------------------------------------

    if resource_type == "azurerm_virtual_machine":
        vm_size: str = values.get("vm_size", "Standard_B1s")

        if pricing_mode == "live":
            live_cost = _fetch_azure_vm_price(vm_size, region)
            if live_cost is not None:
                return live_cost, f"azure_api:{region}"

            logger.warning(
                "azure_live_pricing_unavailable",
                extra={
                    "extra": {
                        "vm_size": vm_size,
                        "region": region,
                        "fallback": "table",
                    }
                },
            )

        cost = AZURE_VM_PRICING.get(vm_size)
        if cost is None:
            logger.warning(
                "unknown_azure_vm_size",
                extra={
                    "extra": {
                        "vm_size": vm_size,
                        "fallback_cost": DEFAULT_FALLBACK_COST,
                    }
                },
            )
            return DEFAULT_FALLBACK_COST, "fallback"
        return cost, "table"

    # -------------------------------------------------
    # Fixed-price resources
    # -------------------------------------------------

    if resource_type in FIXED_RESOURCE_PRICING:
        return FIXED_RESOURCE_PRICING[resource_type], "table"

    # -------------------------------------------------
    # Unknown resource — log and use fallback
    # -------------------------------------------------

    logger.warning(
        "unknown_resource_type_cost_fallback",
        extra={
            "extra": {
                "resource_type": resource_type,
                "resource_name": resource_name,
                "fallback_cost": DEFAULT_FALLBACK_COST,
            }
        },
    )

    return DEFAULT_FALLBACK_COST, "fallback"


# =====================================================
# AZURE RETAIL PRICES API
# =====================================================


def _fetch_azure_vm_price(
    vm_size: str,
    region: str = "eastus",
) -> float | None:
    """
    Fetch real-time Azure VM price from the Retail Prices API.

    Azure Retail Prices API:
    https://prices.azure.com/api/retail/prices

    Free, no authentication required.
    Always returns prices in USD.
    Returns estimated monthly cost (hourly price × 730 hours).
    Returns None if the price cannot be fetched.
    """

    sku_name = AZURE_SKU_MAP.get(vm_size)

    if sku_name is None:
        sku_name = vm_size.replace("Standard_", "").replace("_", " ")

    filter_expr = (
        f"skuName eq '{sku_name}' "
        f"and armRegionName eq '{region}' "
        f"and priceType eq 'Consumption' "
        f"and serviceName eq 'Virtual Machines'"
    )

    params = urllib.parse.urlencode(
        {
            "api-version": "2021-10-01-preview",
            "$filter": filter_expr,
        }
    )

    url = f"https://prices.azure.com/api/retail/prices?{params}"

    try:
        req = urllib.request.Request(
            url,
            headers={"Accept": "application/json"},
        )

        with urllib.request.urlopen(req, timeout=5) as response:
            data: dict[str, Any] = json.loads(response.read().decode("utf-8"))

        items: list[dict[str, Any]] = data.get("Items", [])

        if not items:
            return None

        # Prefer Linux pricing over Windows
        linux_items = [i for i in items if "Windows" not in i.get("productName", "")]

        target = linux_items[0] if linux_items else items[0]

        # Currency is captured here, inside the function,
        # after target is defined — not as a default parameter.
        currency_code: str = str(target.get("currencyCode", CURRENCY))
        hourly_price: float = float(target.get("retailPrice", 0))

        if hourly_price == 0:
            return None

        monthly_estimate = hourly_price * HOURS_PER_MONTH

        logger.info(
            "azure_live_price_fetched",
            extra={
                "extra": {
                    "vm_size": vm_size,
                    "sku_name": sku_name,
                    "region": region,
                    "currency": currency_code,
                    "hourly_price": hourly_price,
                    "monthly_estimate": monthly_estimate,
                }
            },
        )

        return monthly_estimate

    except Exception as e:
        logger.warning(
            "azure_pricing_api_error",
            extra={
                "extra": {
                    "vm_size": vm_size,
                    "region": region,
                    "error": str(e),
                }
            },
        )
        return None
