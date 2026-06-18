# context/translators/terraform_parser.py
#
# Purpose:
# Convert Terraform plan JSON into a normalized
# decision context for policy evaluation.
#
# What it extracts:
# - Resource types, names, and configuration values
# - Nested module resources (child_modules)
# - Security context (open ingress, public storage,
#   unencrypted databases, SSL enforcement, versioning)
# - Compliance context (untagged resources)
# - Resource limit context (compute counts, GPU counts)
# - AI governance context (ai_gpu_workloads)
#
# Context key domains:
# - open_ingress_rules        → security domain
# - public_storage_buckets    → security domain
# - unencrypted_databases     → security domain
# - ssl_not_enforced_count    → security domain (transmission)
# - versioning_disabled_count → security domain (integrity)
# - untagged_resource_count   → compliance domain
# - total_resource_count      → compliance domain
# - compute_instance_count    → resource_limits domain
# - gpu_instance_count        → resource_limits domain
# - ai_gpu_workloads          → ai_governance domain
#   (same count as gpu_instance_count but semantically
#    distinct — AI governance treats GPU instances as
#    AI deployment signals, not sizing concerns)
#
# Resource classification constants (GPU VM sizes, GPU
# instance prefixes, compute resource types, open ingress
# source values) are loaded from
# terraform_resource_classification.yaml — add new Azure
# VM sizes, AWS instance families, or resource types there
# without modifying this file.

import json
from pathlib import Path
from typing import Any

import yaml

# =====================================================
# RESOURCE CLASSIFICATION LOADER
#
# Loads GPU hardware classifications, compute resource
# types, and open ingress source values from the YAML
# config file that lives alongside this module.
# =====================================================

_RESOURCE_CLASSIFICATION_PATH = (
    Path(__file__).parent / "terraform_resource_classification.yaml"
)


def _load_resource_classification() -> dict[str, Any]:
    """
    Load resource classification data from the YAML config
    file.

    Returns:
        Parsed config dict containing all classification
        lists defined in terraform_resource_classification.yaml.

    Raises:
        FileNotFoundError: if the YAML config file is missing
        ValueError:        if the YAML structure is invalid
    """
    if not _RESOURCE_CLASSIFICATION_PATH.exists():
        raise FileNotFoundError(
            f"Terraform resource classification file not found: "
            f"{_RESOURCE_CLASSIFICATION_PATH}"
        )

    with _RESOURCE_CLASSIFICATION_PATH.open(encoding="utf-8") as config_file:
        config: dict[str, Any] = yaml.safe_load(config_file)

    if not isinstance(config, dict):
        raise ValueError(
            f"Invalid terraform resource classification file: "
            f"{_RESOURCE_CLASSIFICATION_PATH}"
        )

    return config


# Loaded once at import time — no file I/O on each evaluation.
_RESOURCE_CLASSIFICATION: dict[str, Any] = _load_resource_classification()

_AZURE_GPU_VM_SIZES: frozenset[str] = frozenset(
    _RESOURCE_CLASSIFICATION.get("azure_gpu_vm_sizes", [])
)

_AWS_GPU_INSTANCE_TYPE_PREFIXES: tuple[str, ...] = tuple(
    _RESOURCE_CLASSIFICATION.get("aws_gpu_instance_type_prefixes", [])
)

_AZURE_COMPUTE_RESOURCE_TYPES: frozenset[str] = frozenset(
    _RESOURCE_CLASSIFICATION.get("azure_compute_resource_types", [])
)

_AWS_COMPUTE_RESOURCE_TYPES: frozenset[str] = frozenset(
    _RESOURCE_CLASSIFICATION.get("aws_compute_resource_types", [])
)

_OPEN_INGRESS_SOURCE_VALUES: frozenset[str] = frozenset(
    _RESOURCE_CLASSIFICATION.get("open_ingress_source_values", [])
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
        resource_type: str = resource.get("type", "")
        values: dict[str, Any] = resource.get("values", {})

        if resource_type == "azurerm_network_security_group":
            for security_rule in values.get("security_rule", []):
                if (
                    security_rule.get("direction") == "Inbound"
                    and security_rule.get("access") == "Allow"
                    and security_rule.get("source_address_prefix")
                    in _OPEN_INGRESS_SOURCE_VALUES
                ):
                    count += 1

        if resource_type == "azurerm_network_security_rule":
            if (
                values.get("direction") == "Inbound"
                and values.get("access") == "Allow"
                and values.get("source_address_prefix") in _OPEN_INGRESS_SOURCE_VALUES
            ):
                count += 1

        if resource_type == "aws_security_group":
            for ingress_rule in values.get("ingress", []):
                cidr_blocks: list[str] = ingress_rule.get("cidr_blocks", [])
                if "0.0.0.0/0" in cidr_blocks or "::/0" in cidr_blocks:
                    count += 1

        if resource_type == "aws_vpc_security_group_ingress_rule":
            cidr_block = values.get("cidr_ipv4", "") or values.get("cidr_ipv6", "")
            if cidr_block in ("0.0.0.0/0", "::/0"):
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
        resource_type: str = resource.get("type", "")
        values: dict[str, Any] = resource.get("values", {})

        if resource_type == "azurerm_storage_account":
            if values.get("allow_blob_public_access") is True:
                count += 1
            if values.get("public_network_access_enabled") is True:
                count += 1

        if resource_type == "aws_s3_bucket":
            count += 1

        if resource_type == "aws_s3_bucket_public_access_block":
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
        resource_type: str = resource.get("type", "")
        values: dict[str, Any] = resource.get("values", {})

        if resource_type in ("azurerm_sql_database", "azurerm_mssql_database"):
            if values.get("transparent_data_encryption_enabled") is not True:
                count += 1

        if resource_type in (
            "azurerm_postgresql_server",
            "azurerm_mysql_server",
            "azurerm_postgresql_flexible_server",
            "azurerm_mysql_flexible_server",
        ):
            if values.get("ssl_enforcement_enabled") is False:
                count += 1

        if resource_type in ("aws_db_instance", "aws_rds_cluster"):
            if values.get("storage_encrypted") is not True:
                count += 1

    return count


def _count_ssl_not_enforced(
    resources: list[dict[str, Any]],
) -> int:
    """
    Count resources that transmit data without enforcing
    SSL/TLS encryption in transit.

    Covers Azure and AWS resources:
    - Azure app services without HTTPS-only enforcement
    - Azure databases without SSL enforcement enabled
    - Azure storage accounts below minimum TLS 1.2
    - AWS load balancer listeners using plain HTTP
    - AWS ElastiCache without transit encryption
    - AWS RDS instances that are publicly accessible

    Domain: security (transmission)
    Context key: ssl_not_enforced_count
    HIPAA: 164.312(e)(1) Transmission Security
    SOC 2: CC6.7 Encryption in Transit
    """
    count: int = 0

    for resource in resources:
        resource_type: str = resource.get("type", "")
        values: dict[str, Any] = resource.get("values", {})

        if resource_type in (
            "azurerm_mysql_server",
            "azurerm_postgresql_server",
        ):
            if values.get("ssl_enforcement_enabled") is False:
                count += 1

        if resource_type in (
            "azurerm_app_service",
            "azurerm_linux_web_app",
            "azurerm_windows_web_app",
        ):
            if values.get("https_only") is not True:
                count += 1

        if resource_type == "azurerm_storage_account":
            minimum_tls_version: str = values.get("min_tls_version", "TLS1_0")
            if minimum_tls_version in ("TLS1_0", "TLS1_1"):
                count += 1

        if resource_type == "aws_lb_listener":
            if values.get("protocol", "").upper() == "HTTP":
                count += 1

        if resource_type == "aws_elasticache_replication_group":
            if values.get("transit_encryption_enabled") is not True:
                count += 1

        if resource_type == "aws_db_instance":
            if values.get("publicly_accessible") is True:
                count += 1

    return count


def _count_versioning_disabled(
    resources: list[dict[str, Any]],
) -> int:
    """
    Count storage resources without versioning or
    point-in-time recovery enabled.

    Covers Azure and AWS resources:
    - Azure storage accounts without blob versioning
    - Azure key vaults without soft delete enabled
    - AWS S3 buckets without versioning configured
    - AWS DynamoDB tables without point-in-time recovery

    Domain: security (integrity)
    Context key: versioning_disabled_count
    HIPAA: 164.312(c)(1) Integrity Controls
    SOC 2: CC9.1 Risk Mitigation
    """
    count: int = 0

    for resource in resources:
        resource_type: str = resource.get("type", "")
        values: dict[str, Any] = resource.get("values", {})

        if resource_type == "azurerm_storage_account":
            blob_properties: dict[str, Any] = values.get("blob_properties", {})
            if isinstance(blob_properties, dict):
                if blob_properties.get("versioning_enabled") is not True:
                    count += 1
            else:
                count += 1

        if resource_type == "azurerm_key_vault":
            if values.get("soft_delete_enabled") is not True:
                count += 1

        if resource_type == "aws_s3_bucket_versioning":
            versioning_configuration: dict[str, Any] = values.get(
                "versioning_configuration", {}
            )
            if isinstance(versioning_configuration, dict):
                if versioning_configuration.get("status", "").lower() != "enabled":
                    count += 1
            else:
                count += 1

        if resource_type == "aws_dynamodb_table":
            point_in_time_recovery: list[dict[str, Any]] = values.get(
                "point_in_time_recovery", []
            )
            if isinstance(point_in_time_recovery, list) and point_in_time_recovery:
                if not point_in_time_recovery[0].get("enabled", False):
                    count += 1
            else:
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

    return sum(
        1 for resource in resources if not resource.get("values", {}).get("tags")
    )


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

    compute_resource_types: frozenset[str] = (
        _AZURE_COMPUTE_RESOURCE_TYPES | _AWS_COMPUTE_RESOURCE_TYPES
    )

    return sum(
        1 for resource in resources if resource.get("type") in compute_resource_types
    )


def _count_gpu_instances(
    resources: list[dict[str, Any]],
) -> int:
    """
    Count compute instances using GPU hardware.
    Classified by matching VM size (Azure) or instance
    type prefix (AWS) against classifications loaded
    from YAML config.
    Domain: resource_limits
    Context key: gpu_instance_count
    Concerned with: infrastructure sizing and capacity
    """

    count: int = 0

    for resource in resources:
        resource_type: str = resource.get("type", "")
        values: dict[str, Any] = resource.get("values", {})

        if resource_type in _AZURE_COMPUTE_RESOURCE_TYPES:
            if values.get("vm_size", "") in _AZURE_GPU_VM_SIZES:
                count += 1

        if resource_type == "aws_instance":
            instance_type: str = values.get("instance_type", "")
            if any(
                instance_type.startswith(prefix)
                for prefix in _AWS_GPU_INSTANCE_TYPE_PREFIXES
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

    with path.open("r", encoding="utf-8") as plan_file:
        try:
            plan: dict[str, Any] = json.load(plan_file)
        except json.JSONDecodeError as json_error:
            raise ValueError(
                f"Invalid JSON in Terraform plan: {plan_path}"
            ) from json_error

    raw_resources: list[dict[str, Any]] = []

    try:
        root_module: dict[str, Any] = plan.get("planned_values", {}).get(
            "root_module", {}
        )
        raw_resources.extend(root_module.get("resources", []))
        for child_module in root_module.get("child_modules", []):
            raw_resources.extend(child_module.get("resources", []))

    except (AttributeError, TypeError) as structure_error:
        raise ValueError(
            "Invalid Terraform plan structure — "
            "expected planned_values.root_module.resources"
        ) from structure_error

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
        "ssl_not_enforced_count": _count_ssl_not_enforced(parsed_resources),
        "versioning_disabled_count": _count_versioning_disabled(parsed_resources),
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
