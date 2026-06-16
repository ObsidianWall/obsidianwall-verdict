# context/translators/cloudformation_parser.py
#
# Purpose:
# Convert AWS CloudFormation templates into a normalized
# decision context for policy evaluation.
#
# Supported formats:
#   JSON  (.json)
#   YAML  (.yaml, .yml)
#
# Auto-detection:
#   Identified by presence of AWSTemplateFormatVersion
#   or Resources section with AWS:: type prefixes.
#   The --plan flag accepts CloudFormation templates
#   directly — no --format flag required.
#
# What it extracts:
#   Same standard context keys as terraform_parser.py
#   so all existing policies work without modification.
#
# Context key domains:
#   open_ingress_rules        → security domain
#   public_storage_buckets    → security domain
#   unencrypted_databases     → security domain
#   ssl_not_enforced_count    → security domain (transmission)
#   versioning_disabled_count → security domain (integrity)
#   untagged_resource_count   → compliance domain
#   total_resource_count      → compliance domain
#   compute_instance_count    → resource_limits domain
#   gpu_instance_count        → resource_limits domain
#   ai_gpu_workloads          → ai_governance domain
#
# Resource type normalization:
#   CloudFormation types (AWS::EC2::Instance) are mapped
#   to their Terraform-equivalent names (aws_instance) using
#   cloudformation_resource_type_map.yaml so existing analyzers
#   and policies work transparently. Add new resource type
#   mappings in that file — no Python changes required.

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from .base_translator import BaseTranslator

# =====================================================
# RESOURCE TYPE MAP LOADER
#
# Loads CloudFormation → Terraform type mappings and
# GPU instance type prefixes from the YAML config file
# that lives alongside this module.
#
# Keeping mappings in YAML means new AWS resource types
# and GPU instance families can be added without
# modifying Python code.
# =====================================================

_RESOURCE_TYPE_MAP_PATH = (
    Path(__file__).parent / "cloudformation_resource_type_map.yaml"
)


def _load_cloudformation_resource_type_map() -> dict[str, str]:
    """
    Load and flatten the CloudFormation to Terraform resource
    type mapping from the YAML config file.

    The YAML file organizes mappings by category (compute,
    storage, networking, etc.) for readability. This function
    flattens all categories into a single lookup dict.

    Returns:
        Flat dict mapping CloudFormation type strings to
        their Terraform provider equivalents.

    Raises:
        FileNotFoundError: if the YAML config file is missing
        ValueError:        if the YAML structure is invalid
    """
    if not _RESOURCE_TYPE_MAP_PATH.exists():
        raise FileNotFoundError(
            f"CloudFormation resource type map not found: "
            f"{_RESOURCE_TYPE_MAP_PATH}"
        )

    with _RESOURCE_TYPE_MAP_PATH.open(encoding="utf-8") as config_file:
        config: dict[str, Any] = yaml.safe_load(config_file)

    if not isinstance(config, dict):
        raise ValueError(
            f"Invalid CloudFormation resource type map: "
            f"{_RESOURCE_TYPE_MAP_PATH}"
        )

    flattened_type_map: dict[str, str] = {}

    for category_mappings in config.get("resource_type_mappings", {}).values():
        if isinstance(category_mappings, dict):
            flattened_type_map.update(category_mappings)

    return flattened_type_map


def _load_gpu_instance_type_prefixes() -> tuple[str, ...]:
    """
    Load GPU instance type prefixes from the YAML config file.

    Returns:
        Tuple of instance type prefix strings. An EC2 instance
        whose type starts with any of these prefixes is
        classified as a GPU workload.
    """
    if not _RESOURCE_TYPE_MAP_PATH.exists():
        return ()

    with _RESOURCE_TYPE_MAP_PATH.open(encoding="utf-8") as config_file:
        config: dict[str, Any] = yaml.safe_load(config_file)

    if not isinstance(config, dict):
        return ()

    return tuple(config.get("gpu_instance_type_prefixes", []))


# Loaded once at import time — no file I/O on each evaluation.
_CLOUDFORMATION_TO_TERRAFORM_RESOURCE_TYPE_MAP: dict[str, str] = (
    _load_cloudformation_resource_type_map()
)

_AWS_GPU_INSTANCE_TYPE_PREFIXES: tuple[str, ...] = (
    _load_gpu_instance_type_prefixes()
)

# =====================================================
# COMPUTE RESOURCE TYPES (after CF→TF normalization)
# =====================================================

_COMPUTE_TERRAFORM_RESOURCE_TYPES: frozenset[str] = frozenset(
    {
        "aws_instance",
        "aws_autoscaling_group",
        "aws_ecs_service",
        "aws_ecs_task_definition",
        "aws_batch_compute_environment",
    }
)

# =====================================================
# OPEN INGRESS CIDR RANGES
# =====================================================

_OPEN_INGRESS_CIDR_RANGES: frozenset[str] = frozenset(
    {
        "0.0.0.0/0",
        "::/0",
    }
)


# =====================================================
# TEMPLATE LOADER
# =====================================================


def _load_template(plan_path: str) -> dict[str, Any]:
    """
    Load a CloudFormation template from JSON or YAML.

    Raises:
        FileNotFoundError: if plan_path does not exist
        ValueError:        if template cannot be parsed
    """
    path = Path(plan_path)

    if not path.exists():
        raise FileNotFoundError(
            f"CloudFormation template not found: {plan_path}"
        )

    raw_content: str = path.read_text(encoding="utf-8")

    if path.suffix.lower() == ".json":
        try:
            return json.loads(raw_content)
        except json.JSONDecodeError as json_error:
            raise ValueError(
                f"Invalid JSON in CloudFormation template: {plan_path}"
            ) from json_error

    try:
        parsed = yaml.safe_load(raw_content)
        if not isinstance(parsed, dict):
            raise ValueError(
                f"CloudFormation template must be a YAML mapping: {plan_path}"
            )
        return parsed
    except yaml.YAMLError as yaml_error:
        raise ValueError(
            f"Invalid YAML in CloudFormation template: {plan_path}"
        ) from yaml_error


# =====================================================
# RESOURCE EXTRACTOR
# =====================================================


def _extract_resources(
    template: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Extract and normalize resources from a CloudFormation
    template into the standard context resource format.

    Converts CloudFormation type names to Terraform
    equivalents where a mapping exists in the YAML config.
    Unknown types are retained as-is with the AWS:: prefix
    preserved so they can be identified for future mapping.

    Returns:
        list of normalized resource dicts, each containing:
            type:      Terraform-equivalent type name
            name:      CloudFormation logical resource ID
            values:    CloudFormation Properties dict
            _cf_type:  original CloudFormation type (preserved
                       for diagnostics and future mapping)
    """
    raw_resources: Any = template.get("Resources", {})

    if not isinstance(raw_resources, dict):
        return []

    normalized_resources: list[dict[str, Any]] = []

    for logical_resource_id, resource_definition in raw_resources.items():
        if not isinstance(resource_definition, dict):
            continue

        cloudformation_type: str    = resource_definition.get("Type", "")
        properties: dict[str, Any]  = resource_definition.get("Properties", {})

        if not cloudformation_type:
            continue

        if not isinstance(properties, dict):
            properties = {}

        terraform_type: str = _CLOUDFORMATION_TO_TERRAFORM_RESOURCE_TYPE_MAP.get(
            cloudformation_type,
            cloudformation_type,
        )

        # Normalize CloudFormation Tags list to a dict.
        # CloudFormation: [{Key: "env", Value: "prod"}, ...]
        # Terraform:      {"env": "prod", ...}
        raw_tags: Any = properties.get("Tags", {})
        normalized_tags: dict[str, str] = {}

        if isinstance(raw_tags, list):
            normalized_tags = {
                tag.get("Key", ""): tag.get("Value", "")
                for tag in raw_tags
                if isinstance(tag, dict)
            }
        elif isinstance(raw_tags, dict):
            normalized_tags = raw_tags

        normalized_resources.append(
            {
                "type":     terraform_type,
                "name":     logical_resource_id,
                "values":   {**properties, "tags": normalized_tags},
                "_cf_type": cloudformation_type,
            }
        )

    return normalized_resources


# =====================================================
# SECURITY CONTEXT EXTRACTION
# =====================================================


def _count_open_ingress_rules(
    resources: list[dict[str, Any]],
) -> int:
    """
    Count security group rules that allow unrestricted
    inbound traffic from any source.
    Domain: security
    """
    count: int = 0

    for resource in resources:
        terraform_type: str    = resource.get("type", "")
        values: dict[str, Any] = resource.get("values", {})

        if terraform_type == "aws_security_group":
            for ingress_rule in values.get("SecurityGroupIngress", []):
                if not isinstance(ingress_rule, dict):
                    continue
                cidr_ip: str   = ingress_rule.get("CidrIp", "")
                cidr_ipv6: str = ingress_rule.get("CidrIpv6", "")
                if (
                    cidr_ip   in _OPEN_INGRESS_CIDR_RANGES
                    or cidr_ipv6 in _OPEN_INGRESS_CIDR_RANGES
                ):
                    count += 1

        if terraform_type == "aws_vpc_security_group_ingress_rule":
            cidr_ip   = values.get("CidrIp", "")
            cidr_ipv6 = values.get("CidrIpv6", "")
            if (
                cidr_ip   in _OPEN_INGRESS_CIDR_RANGES
                or cidr_ipv6 in _OPEN_INGRESS_CIDR_RANGES
            ):
                count += 1

    return count


def _count_public_storage(
    resources: list[dict[str, Any]],
) -> int:
    """
    Count S3 buckets without full public access blocking.
    Domain: security
    """
    count: int = 0

    for resource in resources:
        if resource.get("type") != "aws_s3_bucket":
            continue

        values: dict[str, Any]              = resource.get("values", {})
        public_access_block: dict[str, Any] = values.get(
            "PublicAccessBlockConfiguration", {}
        )

        if not isinstance(public_access_block, dict):
            count += 1
            continue

        fully_blocked: bool = all(
            [
                public_access_block.get("BlockPublicAcls")      is True,
                public_access_block.get("BlockPublicPolicy")     is True,
                public_access_block.get("IgnorePublicAcls")      is True,
                public_access_block.get("RestrictPublicBuckets") is True,
            ]
        )

        if not fully_blocked:
            count += 1

    return count


def _count_unencrypted_databases(
    resources: list[dict[str, Any]],
) -> int:
    """
    Count database resources without at-rest encryption.
    Domain: security
    """
    count: int = 0

    for resource in resources:
        terraform_type: str    = resource.get("type", "")
        values: dict[str, Any] = resource.get("values", {})

        if terraform_type in ("aws_db_instance", "aws_rds_cluster"):
            if values.get("StorageEncrypted") is not True:
                count += 1

        if terraform_type == "aws_dynamodb_table":
            sse_specification: dict[str, Any] = values.get(
                "SSESpecification", {}
            )
            if not isinstance(sse_specification, dict):
                count += 1
            elif sse_specification.get("SSEEnabled") is not True:
                count += 1

        if terraform_type == "aws_elasticache_replication_group":
            if values.get("AtRestEncryptionEnabled") is not True:
                count += 1

        if terraform_type == "aws_redshift_cluster":
            if values.get("Encrypted") is not True:
                count += 1

    return count


def _count_ssl_not_enforced(
    resources: list[dict[str, Any]],
) -> int:
    """
    Count resources that transmit data without enforcing
    SSL/TLS encryption in transit.

    Covers:
    - Load balancer listeners using plain HTTP
    - ElastiCache without transit encryption
    - RDS instances that are publicly accessible
    - CloudFront without HTTPS redirect

    Domain: security (transmission)
    Context key: ssl_not_enforced_count
    HIPAA: 164.312(e)(1) Transmission Security
    SOC 2: CC6.7 Encryption in Transit
    """
    count: int = 0

    for resource in resources:
        terraform_type: str    = resource.get("type", "")
        values: dict[str, Any] = resource.get("values", {})

        if terraform_type == "aws_lb_listener":
            if values.get("Protocol", "").upper() == "HTTP":
                count += 1

        if terraform_type == "aws_elasticache_replication_group":
            if values.get("TransitEncryptionEnabled") is not True:
                count += 1

        if terraform_type == "aws_db_instance":
            if values.get("PubliclyAccessible") is True:
                count += 1

        if terraform_type == "aws_cloudfront_distribution":
            default_cache_behavior: dict[str, Any] = values.get(
                "DefaultCacheBehavior", {}
            )
            viewer_protocol_policy: str = default_cache_behavior.get(
                "ViewerProtocolPolicy", ""
            )
            if viewer_protocol_policy.lower() in ("allow-all", "http-only"):
                count += 1

    return count


def _count_versioning_disabled(
    resources: list[dict[str, Any]],
) -> int:
    """
    Count storage resources without versioning or
    point-in-time recovery enabled.

    Covers:
    - S3 buckets without versioning enabled
    - DynamoDB tables without point-in-time recovery

    Domain: security (integrity)
    Context key: versioning_disabled_count
    HIPAA: 164.312(c)(1) Integrity Controls
    SOC 2: CC9.1 Risk Mitigation
    """
    count: int = 0

    for resource in resources:
        terraform_type: str    = resource.get("type", "")
        values: dict[str, Any] = resource.get("values", {})

        if terraform_type == "aws_s3_bucket":
            versioning_configuration: dict[str, Any] = values.get(
                "VersioningConfiguration", {}
            )
            if not isinstance(versioning_configuration, dict):
                count += 1
            elif versioning_configuration.get("Status", "").lower() != "enabled":
                count += 1

        if terraform_type == "aws_dynamodb_table":
            pitr_specification: dict[str, Any] = values.get(
                "PointInTimeRecoverySpecification", {}
            )
            if not isinstance(pitr_specification, dict):
                count += 1
            elif pitr_specification.get("PointInTimeRecoveryEnabled") is not True:
                count += 1

    return count


# =====================================================
# COMPLIANCE CONTEXT EXTRACTION
# =====================================================


def _count_untagged_resources(
    resources: list[dict[str, Any]],
) -> int:
    """
    Count resources with no Tags property defined.
    Domain: compliance
    """
    return sum(
        1
        for resource in resources
        if not resource.get("values", {}).get("tags")
    )


# =====================================================
# RESOURCE LIMIT CONTEXT EXTRACTION
# =====================================================


def _count_compute_instances(
    resources: list[dict[str, Any]],
) -> int:
    """
    Count compute instances across all AWS compute types.
    Domain: resource_limits
    """
    return sum(
        1
        for resource in resources
        if resource.get("type") in _COMPUTE_TERRAFORM_RESOURCE_TYPES
    )


def _count_gpu_instances(
    resources: list[dict[str, Any]],
) -> int:
    """
    Count compute instances using GPU hardware.
    Classified by matching instance type against the
    GPU instance type prefixes loaded from YAML config.
    Domain: resource_limits
    Context key: gpu_instance_count
    """
    count: int = 0

    for resource in resources:
        if resource.get("type") != "aws_instance":
            continue

        instance_type: str = resource.get("values", {}).get(
            "InstanceType", ""
        )
        if any(
            instance_type.startswith(prefix)
            for prefix in _AWS_GPU_INSTANCE_TYPE_PREFIXES
        ):
            count += 1

    return count


def _count_ai_gpu_workloads(
    resources: list[dict[str, Any]],
) -> int:
    """
    Count GPU compute resources as AI deployment signals.
    Domain: ai_governance
    Context key: ai_gpu_workloads

    Semantically distinct from gpu_instance_count:
    ai_gpu_workloads treats GPU instances as AI deployment
    signals requiring governance review — not infrastructure
    sizing concerns.
    """
    return _count_gpu_instances(resources)


# =====================================================
# AUTO-DETECTION
# =====================================================


def is_cloudformation_template(plan_path: str) -> bool:
    """
    Return True if the file at plan_path is a
    CloudFormation template.

    Detection heuristics (in order):
    1. Contains AWSTemplateFormatVersion key
    2. Contains Resources section with AWS:: type prefixes

    Returns False on any parsing error — caller falls
    back to Terraform parser.
    """
    path = Path(plan_path)

    if not path.exists():
        return False

    try:
        raw_content = path.read_text(encoding="utf-8")

        if path.suffix.lower() == ".json":
            data: Any = json.loads(raw_content)
        else:
            data = yaml.safe_load(raw_content)

        if not isinstance(data, dict):
            return False

        if "AWSTemplateFormatVersion" in data:
            return True

        raw_resources: Any = data.get("Resources", {})
        if isinstance(raw_resources, dict):
            return any(
                str(definition.get("Type", "")).startswith("AWS::")
                for definition in raw_resources.values()
                if isinstance(definition, dict)
            )

    except Exception:
        pass

    return False


# =====================================================
# CLOUDFORMATION PARSER
# =====================================================


class CloudFormationParser(BaseTranslator):
    """
    Translation Layer implementation for AWS CloudFormation
    templates (JSON and YAML).

    Normalizes CloudFormation resource definitions into
    the same context dict format produced by terraform_parser.py,
    allowing all existing policies and analyzers to evaluate
    CloudFormation-defined infrastructure without modification.

    Resource type mappings are loaded from
    cloudformation_resource_type_map.yaml — add new
    AWS resource types there without modifying this file.
    """

    @property
    def plan_format(self) -> str:
        return "cloudformation"

    @property
    def supported_extensions(self) -> tuple[str, ...]:
        return (".json", ".yaml", ".yml")

    def parse(self, plan_path: str) -> dict[str, Any]:
        """
        Parse a CloudFormation template and return a
        normalized runtime context dict.

        Supports JSON and YAML CloudFormation templates.
        Resource types are normalized to Terraform equivalents
        so existing analyzers work transparently.

        Args:
            plan_path: path to the CloudFormation template

        Returns:
            Normalized context dict with all standard keys.

        Raises:
            FileNotFoundError: if plan_path does not exist
            ValueError:        if template format is invalid
        """
        template: dict[str, Any]        = _load_template(plan_path)
        resources: list[dict[str, Any]] = _extract_resources(template)

        return {
            # Core resource list
            "resources":                 resources,
            # Security domain context keys
            "open_ingress_rules":        _count_open_ingress_rules(resources),
            "public_storage_buckets":    _count_public_storage(resources),
            "unencrypted_databases":     _count_unencrypted_databases(resources),
            "ssl_not_enforced_count":    _count_ssl_not_enforced(resources),
            "versioning_disabled_count": _count_versioning_disabled(resources),
            # Compliance domain context keys
            "untagged_resource_count":   _count_untagged_resources(resources),
            "total_resource_count":      len(resources),
            # Resource limits domain context keys
            "compute_instance_count":    _count_compute_instances(resources),
            "gpu_instance_count":        _count_gpu_instances(resources),
            # AI governance domain context key
            # Semantically distinct from gpu_instance_count —
            # treats GPU instances as AI deployment signals,
            # not infrastructure sizing concerns.
            "ai_gpu_workloads":          _count_ai_gpu_workloads(resources),
        }


# =====================================================
# MODULE-LEVEL CONVENIENCE FUNCTION
# =====================================================


def parse_cloudformation_template(
    plan_path: str,
) -> dict[str, Any]:
    """
    Parse a CloudFormation template and return a
    normalized context dict.

    Convenience wrapper around CloudFormationParser.parse()
    that mirrors the parse_terraform_plan() interface in
    terraform_parser.py.

    Args:
        plan_path: path to the CloudFormation template

    Returns:
        Normalized context dict with all standard keys.
    """
    return CloudFormationParser().parse(plan_path)
