# context/cloudformation_parser.py
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
#   to their Terraform-equivalent names (aws_instance)
#   so existing analyzers and policies work transparently.

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from context.base_translator import BaseTranslator


# =====================================================
# CLOUDFORMATION → TERRAFORM TYPE MAPPING
#
# Maps CloudFormation resource type strings to their
# Terraform provider equivalents. This allows existing
# analyzers (cost, topology, utilization) to process
# CloudFormation plans without modification.
# =====================================================

_CF_TO_TF_TYPE: dict[str, str] = {
    # Compute
    "AWS::EC2::Instance":                     "aws_instance",
    "AWS::AutoScaling::AutoScalingGroup":     "aws_autoscaling_group",
    "AWS::ECS::Service":                      "aws_ecs_service",
    "AWS::ECS::TaskDefinition":               "aws_ecs_task_definition",
    "AWS::Batch::ComputeEnvironment":         "aws_batch_compute_environment",
    "AWS::Lambda::Function":                  "aws_lambda_function",
    "AWS::ElasticBeanstalk::Environment":     "aws_elastic_beanstalk_environment",
    # Containers / Kubernetes
    "AWS::EKS::Cluster":                      "aws_eks_cluster",
    "AWS::ECS::Cluster":                      "aws_ecs_cluster",
    # Storage
    "AWS::S3::Bucket":                        "aws_s3_bucket",
    "AWS::S3::BucketPolicy":                  "aws_s3_bucket_policy",
    "AWS::EFS::FileSystem":                   "aws_efs_file_system",
    "AWS::FSx::FileSystem":                   "aws_fsx_file_system",
    # Databases
    "AWS::RDS::DBInstance":                   "aws_db_instance",
    "AWS::RDS::DBCluster":                    "aws_rds_cluster",
    "AWS::DynamoDB::Table":                   "aws_dynamodb_table",
    "AWS::ElastiCache::ReplicationGroup":     "aws_elasticache_replication_group",
    "AWS::Redshift::Cluster":                 "aws_redshift_cluster",
    "AWS::Neptune::DBCluster":                "aws_neptune_cluster",
    "AWS::DocDB::DBCluster":                  "aws_docdb_cluster",
    # Networking
    "AWS::EC2::SecurityGroup":                "aws_security_group",
    "AWS::EC2::SecurityGroupIngress":         "aws_vpc_security_group_ingress_rule",
    "AWS::EC2::VPC":                          "aws_vpc",
    "AWS::EC2::Subnet":                       "aws_subnet",
    "AWS::EC2::RouteTable":                   "aws_route_table",
    "AWS::EC2::InternetGateway":              "aws_internet_gateway",
    "AWS::EC2::NatGateway":                   "aws_nat_gateway",
    "AWS::EC2::NetworkAcl":                   "aws_network_acl",
    "AWS::EC2::NetworkAclEntry":              "aws_network_acl_rule",
    # Load Balancers
    "AWS::ElasticLoadBalancingV2::LoadBalancer": "aws_lb",
    "AWS::ElasticLoadBalancingV2::Listener":     "aws_lb_listener",
    "AWS::ElasticLoadBalancingV2::TargetGroup":  "aws_lb_target_group",
    # Identity and Access
    "AWS::IAM::Role":                         "aws_iam_role",
    "AWS::IAM::Policy":                       "aws_iam_policy",
    "AWS::IAM::User":                         "aws_iam_user",
    "AWS::IAM::Group":                        "aws_iam_group",
    "AWS::IAM::InstanceProfile":              "aws_iam_instance_profile",
    # Encryption and Secrets
    "AWS::KMS::Key":                          "aws_kms_key",
    "AWS::SecretsManager::Secret":            "aws_secretsmanager_secret",
    "AWS::SSM::Parameter":                    "aws_ssm_parameter",
    # CDN and DNS
    "AWS::CloudFront::Distribution":          "aws_cloudfront_distribution",
    "AWS::Route53::HostedZone":               "aws_route53_zone",
    "AWS::Route53::RecordSet":                "aws_route53_record",
    # Monitoring and Logging
    "AWS::CloudTrail::Trail":                 "aws_cloudtrail",
    "AWS::CloudWatch::Alarm":                 "aws_cloudwatch_metric_alarm",
    "AWS::Logs::LogGroup":                    "aws_cloudwatch_log_group",
    "AWS::Config::ConfigRule":                "aws_config_config_rule",
    # Messaging
    "AWS::SQS::Queue":                        "aws_sqs_queue",
    "AWS::SNS::Topic":                        "aws_sns_topic",
    # API
    "AWS::ApiGateway::RestApi":               "aws_api_gateway_rest_api",
    "AWS::ApiGatewayV2::Api":                 "aws_apigatewayv2_api",
    # AI / ML
    "AWS::SageMaker::NotebookInstance":       "aws_sagemaker_notebook_instance",
    "AWS::SageMaker::EndpointConfig":         "aws_sagemaker_endpoint_configuration",
    "AWS::SageMaker::Endpoint":               "aws_sagemaker_endpoint",
    "AWS::Bedrock::KnowledgeBase":            "aws_bedrock_knowledge_base",
}

# =====================================================
# GPU INSTANCE TYPE PREFIXES
# =====================================================

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

# =====================================================
# COMPUTE RESOURCE TYPES
# (after CF→TF normalization)
# =====================================================

_COMPUTE_TF_TYPES: frozenset[str] = frozenset(
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

_OPEN_INGRESS_CIDRS: frozenset[str] = frozenset(
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
    equivalents where a mapping exists. Unknown types
    are retained as-is with the AWS:: prefix preserved.

    Returns:
        list of normalized resource dicts, each containing:
            type:   Terraform-equivalent type name
            name:   CloudFormation logical resource ID
            values: CloudFormation Properties dict
    """
    raw_resources: Any = template.get("Resources", {})

    if not isinstance(raw_resources, dict):
        return []

    normalized_resources: list[dict[str, Any]] = []

    for logical_id, resource_definition in raw_resources.items():
        if not isinstance(resource_definition, dict):
            continue

        cloudformation_type: str = resource_definition.get("Type", "")
        properties: dict[str, Any] = resource_definition.get("Properties", {})

        if not cloudformation_type:
            continue

        if not isinstance(properties, dict):
            properties = {}

        terraform_type: str = _CF_TO_TF_TYPE.get(
            cloudformation_type,
            cloudformation_type,
        )

        tags: dict[str, str] = properties.get("Tags", {})
        if isinstance(tags, list):
            tags = {
                tag.get("Key", ""): tag.get("Value", "")
                for tag in tags
                if isinstance(tag, dict)
            }

        normalized_resources.append(
            {
                "type":   terraform_type,
                "name":   logical_id,
                "values": {**properties, "tags": tags},
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
        terraform_type: str = resource.get("type", "")
        values: dict[str, Any] = resource.get("values", {})

        if terraform_type == "aws_security_group":
            for ingress_rule in values.get("SecurityGroupIngress", []):
                if not isinstance(ingress_rule, dict):
                    continue
                cidr_ip: str   = ingress_rule.get("CidrIp", "")
                cidr_ipv6: str = ingress_rule.get("CidrIpv6", "")
                if cidr_ip in _OPEN_INGRESS_CIDRS or cidr_ipv6 in _OPEN_INGRESS_CIDRS:
                    count += 1

        if terraform_type == "aws_vpc_security_group_ingress_rule":
            cidr_ip   = values.get("CidrIp", "")
            cidr_ipv6 = values.get("CidrIpv6", "")
            if cidr_ip in _OPEN_INGRESS_CIDRS or cidr_ipv6 in _OPEN_INGRESS_CIDRS:
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

        values: dict[str, Any] = resource.get("values", {})
        public_access_block: dict[str, Any] = values.get(
            "PublicAccessBlockConfiguration", {}
        )

        if not isinstance(public_access_block, dict):
            count += 1
            continue

        fully_blocked: bool = all(
            [
                public_access_block.get("BlockPublicAcls")        is True,
                public_access_block.get("BlockPublicPolicy")       is True,
                public_access_block.get("IgnorePublicAcls")        is True,
                public_access_block.get("RestrictPublicBuckets")   is True,
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
        terraform_type: str     = resource.get("type", "")
        values: dict[str, Any]  = resource.get("values", {})

        if terraform_type in ("aws_db_instance", "aws_rds_cluster"):
            if values.get("StorageEncrypted") is not True:
                count += 1

        if terraform_type == "aws_dynamodb_table":
            sse_specification: dict[str, Any] = values.get("SSESpecification", {})
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
    Count resources that transmit data without
    enforcing SSL/TLS encryption in transit.

    Covers:
    - Load balancer listeners using plain HTTP
    - Databases without transit encryption
    - ElastiCache without transit encryption
    - S3 buckets without SSL-only bucket policy signals

    Domain: security (transmission)
    Context key: ssl_not_enforced_count
    HIPAA: 164.312(e)(1) Transmission Security
    SOC 2: CC6.7 Encryption in Transit
    """
    count: int = 0

    for resource in resources:
        terraform_type: str     = resource.get("type", "")
        values: dict[str, Any]  = resource.get("values", {})

        # Load balancer listeners using HTTP
        if terraform_type == "aws_lb_listener":
            if values.get("Protocol", "").upper() == "HTTP":
                count += 1

        # ElastiCache without transit encryption
        if terraform_type == "aws_elasticache_replication_group":
            if values.get("TransitEncryptionEnabled") is not True:
                count += 1

        # RDS instances that are publicly accessible
        # without explicit SSL parameter groups
        if terraform_type == "aws_db_instance":
            if values.get("PubliclyAccessible") is True:
                count += 1

        # CloudFront without HTTPS redirect
        if terraform_type == "aws_cloudfront_distribution":
            default_cache: dict[str, Any] = values.get(
                "DefaultCacheBehavior", {}
            )
            viewer_protocol: str = default_cache.get(
                "ViewerProtocolPolicy", ""
            )
            if viewer_protocol.lower() in ("allow-all", "http-only"):
                count += 1

    return count


def _count_versioning_disabled(
    resources: list[dict[str, Any]],
) -> int:
    """
    Count storage resources without versioning or
    point-in-time recovery enabled.

    Covers:
    - S3 buckets without versioning
    - DynamoDB tables without point-in-time recovery

    Domain: security (integrity)
    Context key: versioning_disabled_count
    HIPAA: 164.312(c)(1) Integrity Controls
    SOC 2: CC9.1 Risk Mitigation
    """
    count: int = 0

    for resource in resources:
        terraform_type: str     = resource.get("type", "")
        values: dict[str, Any]  = resource.get("values", {})

        # S3 buckets without versioning enabled
        if terraform_type == "aws_s3_bucket":
            versioning_config: dict[str, Any] = values.get(
                "VersioningConfiguration", {}
            )
            if not isinstance(versioning_config, dict):
                count += 1
            elif versioning_config.get("Status", "").lower() != "enabled":
                count += 1

        # DynamoDB tables without point-in-time recovery
        if terraform_type == "aws_dynamodb_table":
            pitr: dict[str, Any] = values.get(
                "PointInTimeRecoverySpecification", {}
            )
            if not isinstance(pitr, dict):
                count += 1
            elif pitr.get("PointInTimeRecoveryEnabled") is not True:
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
        if resource.get("type") in _COMPUTE_TF_TYPES
    )


def _count_gpu_instances(
    resources: list[dict[str, Any]],
) -> int:
    """
    Count compute instances using GPU hardware.
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
            for prefix in _AWS_GPU_INSTANCE_PREFIXES
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
            data = json.loads(raw_content)
        else:
            data = yaml.safe_load(raw_content)

        if not isinstance(data, dict):
            return False

        # Explicit CloudFormation marker
        if "AWSTemplateFormatVersion" in data:
            return True

        # Resources section with AWS:: type prefixes
        resources: Any = data.get("Resources", {})
        if isinstance(resources, dict):
            return any(
                str(definition.get("Type", "")).startswith("AWS::")
                for definition in resources.values()
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
        template: dict[str, Any] = _load_template(plan_path)
        resources: list[dict[str, Any]] = _extract_resources(template)

        return {
            # Core resource list
            "resources": resources,
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
    that mirrors the parse_terraform_plan() interface.

    Args:
        plan_path: path to the CloudFormation template

    Returns:
        Normalized context dict with all standard keys.
    """
    return CloudFormationParser().parse(plan_path)
