# context/terraform_parser.py
#
# Purpose:
# Convert Terraform plan JSON into a normalized
# decision context for policy evaluation.
#
# What it extracts:
# - Resource types, names, and configuration values
# - Nested module resources (child_modules)
# - Security context (open ingress, public storage,
#   unencrypted databases)
# - Compliance context (untagged resources)
# - Resource limit context (compute counts, GPU counts)
# - AI governance context (ai_gpu_workloads)
#
# Context key domains:
# - open_ingress_rules        → security domain
# - public_storage_buckets    → security domain
# - unencrypted_databases     → security domain
# - untagged_resource_count   → compliance domain
# - total_resource_count      → compliance domain
# - compute_instance_count    → resource_limits domain
# - gpu_instance_count        → resource_limits domain
# - ai_gpu_workloads          → ai_governance domain
#   (same count as gpu_instance_count but semantically
#    distinct — AI governance treats GPU instances as
#    AI deployment signals, not sizing concerns)

import json
from pathlib import Path
from typing import Any

# =====================================================
# RESOURCE CLASSIFICATION CONSTANTS
# =====================================================

_AZURE_GPU_VM_SIZES: frozenset[str] = frozenset(
    {
        "Standard_NC6",
        "Standard_NC12",
        "Standard_NC24",
        "Standard_NC6s_v3",
        "Standard_NC12s_v3",
        "Standard_NC24s_v3",
        "Standard_ND6s",
        "Standard_ND12s",
        "Standard_ND24s",
        "Standard_NV6",
        "Standard_NV12",
        "Standard_NV24",
        "Standard_NV6s_v2",
        "Standard_NV12s_v2",
        "Standard_NV24s_v2",
    }
)

_AWS_GPU_INSTANCE_PREFIXES: tuple[str, ...] = (
    "p2.",
    "p3.",
    "p4.",
    "p5.",
    "g3.",
    "g4dn.",
    "g5.",
    "inf1.",
    "inf2.",
    "trn1.",
)

_AZURE_COMPUTE_TYPES: frozenset[str] = frozenset(
    {
        "azurerm_virtual_machine",
        "azurerm_linux_virtual_machine",
        "azurerm_windows_virtual_machine",
        "azurerm_virtual_machine_scale_set",
    }
)

_AWS_COMPUTE_TYPES: frozenset[str] = frozenset(
    {
        "aws_instance",
        "aws_launch_template",
        "aws_autoscaling_group",
    }
)

_OPEN_INGRESS_SOURCES: frozenset[str] = frozenset(
    {
        "*",
        "Internet",
        "0.0.0.0/0",
        "::/0",
        "Any",
    }
)


# =====================================================
# SECURITY CONTEXT EXTRACTION
# =====================================================


def _count_open_ingress_rules(
    resources: list[dict[str, Any]],
) -> int:
    """
    Count network security rules that allow
    unrestricted inbound traffic.
    Domain: security
    """

    count: int = 0

    for resource in resources:
        rtype: str = resource.get("type", "")
        values: dict[str, Any] = resource.get("values", {})

        if rtype == "azurerm_network_security_group":
            for rule in values.get("security_rule", []):
                if (
                    rule.get("direction") == "Inbound"
                    and rule.get("access") == "Allow"
                    and rule.get("source_address_prefix") in _OPEN_INGRESS_SOURCES
                ):
                    count += 1

        if rtype == "azurerm_network_security_rule":
            if (
                values.get("direction") == "Inbound"
                and values.get("access") == "Allow"
                and values.get("source_address_prefix") in _OPEN_INGRESS_SOURCES
            ):
                count += 1

        if rtype == "aws_security_group":
            for rule in values.get("ingress", []):
                cidr_blocks: list[str] = rule.get("cidr_blocks", [])
                if "0.0.0.0/0" in cidr_blocks or "::/0" in cidr_blocks:
                    count += 1

        if rtype == "aws_vpc_security_group_ingress_rule":
            cidr = values.get("cidr_ipv4", "") or values.get("cidr_ipv6", "")
            if cidr in ("0.0.0.0/0", "::/0"):
                count += 1

    return count


def _count_public_storage(
    resources: list[dict[str, Any]],
) -> int:
    """
    Count storage resources with public access enabled.
    Domain: security
    """

    count: int = 0

    for resource in resources:
        rtype: str = resource.get("type", "")
        values: dict[str, Any] = resource.get("values", {})

        if rtype == "azurerm_storage_account":
            if values.get("allow_blob_public_access") is True:
                count += 1
            if values.get("public_network_access_enabled") is True:
                count += 1

        if rtype == "aws_s3_bucket":
            count += 1

        if rtype == "aws_s3_bucket_public_access_block":
            if (
                values.get("block_public_acls") is True
                and values.get("block_public_policy") is True
                and values.get("ignore_public_acls") is True
                and values.get("restrict_public_buckets") is True
            ):
                count = max(0, count - 1)

    return count


def _count_unencrypted_databases(
    resources: list[dict[str, Any]],
) -> int:
    """
    Count database resources without encryption enabled.
    Domain: security
    """

    count: int = 0

    for resource in resources:
        rtype: str = resource.get("type", "")
        values: dict[str, Any] = resource.get("values", {})

        if rtype in ("azurerm_sql_database", "azurerm_mssql_database"):
            if values.get("transparent_data_encryption_enabled") is not True:
                count += 1

        if rtype in (
            "azurerm_postgresql_server",
            "azurerm_mysql_server",
            "azurerm_postgresql_flexible_server",
            "azurerm_mysql_flexible_server",
        ):
            if values.get("ssl_enforcement_enabled") is False:
                count += 1

        if rtype in ("aws_db_instance", "aws_rds_cluster"):
            if values.get("storage_encrypted") is not True:
                count += 1

    return count


# =====================================================
# COMPLIANCE CONTEXT EXTRACTION
# =====================================================


def _count_untagged_resources(
    resources: list[dict[str, Any]],
) -> int:
    """
    Count resources with no tags defined.
    Domain: compliance
    """

    return sum(1 for r in resources if not r.get("values", {}).get("tags"))


# =====================================================
# RESOURCE LIMIT CONTEXT EXTRACTION
# =====================================================


def _count_compute_instances(
    resources: list[dict[str, Any]],
) -> int:
    """
    Count total compute instances across Azure and AWS.
    Domain: resource_limits
    """

    return sum(
        1
        for r in resources
        if r.get("type") in _AZURE_COMPUTE_TYPES | _AWS_COMPUTE_TYPES
    )


def _count_gpu_instances(
    resources: list[dict[str, Any]],
) -> int:
    """
    Count compute instances using GPU hardware.
    Domain: resource_limits
    Context key: gpu_instance_count
    Concerned with: infrastructure sizing and capacity
    """

    count: int = 0

    for resource in resources:
        rtype: str = resource.get("type", "")
        values: dict[str, Any] = resource.get("values", {})

        if rtype in _AZURE_COMPUTE_TYPES:
            if values.get("vm_size", "") in _AZURE_GPU_VM_SIZES:
                count += 1

        if rtype == "aws_instance":
            instance_type: str = values.get("instance_type", "")
            if any(
                instance_type.startswith(prefix)
                for prefix in _AWS_GPU_INSTANCE_PREFIXES
            ):
                count += 1

    return count


# =====================================================
# AI GOVERNANCE CONTEXT EXTRACTION
# =====================================================


def _count_ai_gpu_workloads(
    resources: list[dict[str, Any]],
) -> int:
    """
    Count GPU compute resources as AI deployment signals.
    Domain: ai_governance
    Context key: ai_gpu_workloads

    Semantically distinct from gpu_instance_count:
    - gpu_instance_count (resource_limits): counts GPU instances
      as an infrastructure sizing and capacity concern.
    - ai_gpu_workloads (ai_governance): counts GPU instances as
      AI deployment signals requiring governance review — model
      training, inference, and AI workload authorization.

    Same underlying hardware, different governance concern.
    """

    return _count_gpu_instances(resources)


# =====================================================
# PLAN PARSER
# =====================================================


def parse_terraform_plan(
    plan_path: str,
) -> dict[str, Any]:
    """
    Parse a Terraform plan JSON file and extract
    resource-level data for cost estimation and
    policy evaluation.

    Returns a context dict containing all keys needed
    by the governance policy evaluation engine across
    all supported governance domains.

    Args:
        plan_path: path to the Terraform plan JSON file

    Raises:
        FileNotFoundError: if plan_path does not exist
        ValueError:        if plan format is invalid
    """

    path = Path(plan_path)

    if not path.exists():
        raise FileNotFoundError(f"Terraform plan not found: {plan_path}")

    with path.open("r", encoding="utf-8") as f:
        try:
            plan: dict[str, Any] = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in Terraform plan: {plan_path}") from e

    raw_resources: list[dict[str, Any]] = []

    try:
        root: dict[str, Any] = plan.get("planned_values", {}).get("root_module", {})
        raw_resources.extend(root.get("resources", []))
        for child in root.get("child_modules", []):
            raw_resources.extend(child.get("resources", []))

    except (AttributeError, TypeError) as e:
        raise ValueError(
            "Invalid Terraform plan structure — "
            "expected planned_values.root_module.resources"
        ) from e

    parsed_resources: list[dict[str, Any]] = []

    for resource in raw_resources:
        resource_type: str | None = resource.get("type")
        resource_name: str | None = resource.get("name")
        resource_values: dict[str, Any] = resource.get("values", {})

        if resource_type is None or resource_name is None:
            continue

        parsed_resources.append(
            {
                "type": resource_type,
                "name": resource_name,
                "values": resource_values,
            }
        )

    return {
        # Core resource list
        "resources": parsed_resources,
        # Security domain context keys
        "open_ingress_rules": _count_open_ingress_rules(parsed_resources),
        "public_storage_buckets": _count_public_storage(parsed_resources),
        "unencrypted_databases": _count_unencrypted_databases(parsed_resources),
        # Compliance domain context keys
        "untagged_resource_count": _count_untagged_resources(parsed_resources),
        "total_resource_count": len(parsed_resources),
        # Resource limits domain context keys
        "compute_instance_count": _count_compute_instances(parsed_resources),
        "gpu_instance_count": _count_gpu_instances(parsed_resources),
        # AI governance domain context key
        # Semantically distinct from gpu_instance_count —
        # treats GPU instances as AI deployment signals,
        # not infrastructure sizing concerns.
        "ai_gpu_workloads": _count_ai_gpu_workloads(parsed_resources),
    }
