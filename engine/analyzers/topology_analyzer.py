# engine/analyzers/topology_analyzer.py
#
# Purpose:
# Analyze infrastructure topology and security posture.
#
# Responsibilities:
# - Open ingress rule detection and scoring
# - Public storage exposure detection
# - Unencrypted database detection
# - Network segmentation analysis
# - Public exposure without segmentation detection
# - Load balancer coverage analysis
# - Single-zone deployment risk
#
# Classification approach (v0.3.5):
# Resource types are classified by keyword patterns
# in the Terraform resource type name rather than
# hardcoded frozensets. This covers all current and
# future provider resource types without maintenance.
#
# Terraform resource naming convention:
#   {provider}_{service}_{subtype}
#   azurerm_public_ip           → public exposure
#   aws_internet_gateway        → public exposure
#   azurerm_network_security_group → segmentation
#   aws_security_group          → segmentation
#   aws_lb / azurerm_lb         → load balancer
#   azurerm_virtual_machine     → compute
#
# Enrichment (v0.3.5):
# Uses pre-computed security context keys from the
# Translation Layer (open_ingress_rules,
# public_storage_buckets, unencrypted_databases).
# These provide confirmed counts, not just
# resource-type presence signals.
#
# IMPORTANT:
# This analyzer NEVER performs enforcement.
# Findings are advisory only.

from __future__ import annotations

from typing import Any

from audit.audit_logger import get_logger

logger = get_logger()


# =====================================================
# RISK WEIGHTS
# =====================================================

# TODO: Replace with centralized scoring engine.

# Topology pattern weights
RISK_WEIGHT_PUBLIC_EXPOSURE = 35
RISK_WEIGHT_MISSING_LB = 20
RISK_WEIGHT_SINGLE_ZONE = 15
RISK_WEIGHT_MISSING_SEGMENTATION = 25

# Security context key weights.
# Higher than topology pattern weights because these
# are confirmed violations from the parser, not
# inferred signals from resource type presence.
RISK_WEIGHT_OPEN_INGRESS_RULE = 20  # per rule, capped at 3
RISK_WEIGHT_PUBLIC_STORAGE_BUCKET = 25  # per bucket, capped at 2
RISK_WEIGHT_UNENCRYPTED_DATABASE = 35  # per database, capped at 2


# =====================================================
# PATTERN-BASED RESOURCE CLASSIFIERS
#
# Each classifier inspects the Terraform resource type
# string using keyword matching. This approach covers
# all current and future provider resource types
# without requiring manual list maintenance.
#
# Naming convention reference:
#   AWS:    aws_{service}_{subtype}
#   Azure:  azurerm_{service}_{subtype}
#   GCP:    google_{service}_{subtype}
# =====================================================


def _is_public_exposure_resource(resource_type: str) -> bool:
    """
    Return True if the resource type indicates
    public network exposure.

    Covers:
      Public IPs and Elastic IPs
      Internet gateways and NAT gateways
      Public DNS and anycast addresses

    Pattern: keyword presence in resource type name.
    Works across AWS, Azure, GCP, and future providers
    without requiring per-provider list maintenance.
    """
    keywords = (
        "public_ip",
        "internet_gateway",
        "nat_gateway",
        "elastic_ip",
        "eip",
        "public_address",
        "global_address",
        "anycast",
    )
    return any(keyword in resource_type for keyword in keywords)


def _is_segmentation_resource(resource_type: str) -> bool:
    """
    Return True if the resource type provides
    network segmentation or firewall controls.

    Covers:
      Security groups and network ACLs
      Network security groups
      Firewall rules and policies
      WAF and network policies

    Pattern: keyword presence in resource type name.
    """
    keywords = (
        "security_group",
        "network_security_group",
        "network_acl",
        "firewall",
        "network_policy",
        "waf",
        "access_control",
    )
    return any(keyword in resource_type for keyword in keywords)


def _is_load_balancer_resource(resource_type: str) -> bool:
    """
    Return True if the resource type is a load
    balancer or traffic distribution service.

    Covers:
      Application, network, and classic load balancers
      Application gateways and front doors
      Traffic managers and forwarding rules
      Backend services and target pools

    Pattern: keyword presence in resource type name.
    """
    keywords = (
        "_lb",
        "_alb",
        "_elb",
        "_nlb",
        "load_balancer",
        "application_gateway",
        "front_door",
        "traffic_manager",
        "forwarding_rule",
        "backend_service",
        "target_pool",
        "load_balancing",
    )
    return any(keyword in resource_type for keyword in keywords)


def _is_compute_resource(resource_type: str) -> bool:
    """
    Return True if the resource type is a compute
    instance that would benefit from load balancer
    coverage in production environments.

    Covers:
      Virtual machines and instances
      Container services and tasks
      Serverless functions

    Pattern: keyword presence in resource type name.
    Excludes managed services and databases which
    have their own availability mechanisms.
    """
    keywords = (
        "virtual_machine",
        "linux_virtual_machine",
        "windows_virtual_machine",
        "aws_instance",
        "compute_instance",
        "ecs_service",
        "ecs_task",
        "container_instance",
    )
    return any(keyword in resource_type for keyword in keywords)


# =====================================================
# TOPOLOGY ANALYZER
# =====================================================


def analyze_topology(runtime_context: dict[str, Any]) -> dict[str, Any]:
    """
    Analyze infrastructure topology and security posture.

    Uses pre-computed security context keys from the
    Translation Layer for confirmed violation counts,
    and pattern-based keyword matching for topology
    classification. Pattern matching covers all current
    and future provider resource types without requiring
    manual list maintenance.

    Detects:
    - Open ingress rules (confirmed count from parser)
    - Public storage buckets (confirmed count from parser)
    - Unencrypted databases (confirmed count from parser)
    - Public resource exposure without segmentation
    - Compute resources missing load balancer coverage
    - Missing network segmentation controls
    - Single-zone deployment risk
    """

    resources: list[dict[str, Any]] = runtime_context.get("resources", [])
    environment: str = runtime_context.get("environment", "unknown")

    findings: list[dict[str, Any]] = []
    optimization_candidates: list[dict[str, Any]] = []
    risk_score: int = 0

    resource_types: list[str] = [r.get("type", "") for r in resources]

    # =================================================
    # SECURITY CONTEXT KEYS
    # Pre-computed by the Translation Layer.
    # More precise than resource type scanning —
    # these are confirmed counts, not inferred signals.
    # =================================================

    open_ingress_rules: int = int(runtime_context.get("open_ingress_rules", 0))
    public_storage_buckets: int = int(runtime_context.get("public_storage_buckets", 0))
    unencrypted_databases: int = int(runtime_context.get("unencrypted_databases", 0))

    # -------------------------------------------------
    # OPEN INGRESS RULES
    # Each open rule adds risk, capped at 3 to prevent
    # unbounded score inflation.
    # -------------------------------------------------

    if open_ingress_rules > 0:
        capped_rules: int = min(open_ingress_rules, 3)
        risk_score += RISK_WEIGHT_OPEN_INGRESS_RULE * capped_rules

        findings.append(
            {
                "type": "open_ingress_rules_detected",
                "severity": "high",
                "message": (
                    f"{open_ingress_rules} open inbound rule(s) detected "
                    f"allowing unrestricted access. "
                    f"Restrict ingress to known CIDR ranges or "
                    f"security groups."
                ),
            }
        )

        optimization_candidates.append(
            {
                "type": "restrict_ingress_rules",
                "message": (
                    f"Replace {open_ingress_rules} open ingress rule(s) "
                    f"with specific CIDR ranges or security group "
                    f"references."
                ),
                "estimated_savings_percent": 0,
            }
        )

    # -------------------------------------------------
    # PUBLIC STORAGE BUCKETS
    # Each public bucket adds risk, capped at 2.
    # -------------------------------------------------

    if public_storage_buckets > 0:
        capped_buckets: int = min(public_storage_buckets, 2)
        risk_score += RISK_WEIGHT_PUBLIC_STORAGE_BUCKET * capped_buckets

        findings.append(
            {
                "type": "public_storage_detected",
                "severity": "high",
                "message": (
                    f"{public_storage_buckets} publicly accessible "
                    f"storage resource(s) detected. "
                    f"Ensure public access is intentional and "
                    f"data is non-sensitive."
                ),
            }
        )

        optimization_candidates.append(
            {
                "type": "restrict_storage_access",
                "message": (
                    f"Review {public_storage_buckets} public storage "
                    f"resource(s) and apply access controls if "
                    f"public access is not required."
                ),
                "estimated_savings_percent": 0,
            }
        )

    # -------------------------------------------------
    # UNENCRYPTED DATABASES
    # Critical severity. Each database adds risk,
    # capped at 2.
    # -------------------------------------------------

    if unencrypted_databases > 0:
        capped_dbs: int = min(unencrypted_databases, 2)
        risk_score += RISK_WEIGHT_UNENCRYPTED_DATABASE * capped_dbs

        findings.append(
            {
                "type": "unencrypted_databases_detected",
                "severity": "critical",
                "message": (
                    f"{unencrypted_databases} unencrypted database(s) "
                    f"detected. Encryption at rest is required for "
                    f"compliance and data protection."
                ),
            }
        )

        optimization_candidates.append(
            {
                "type": "enable_database_encryption",
                "message": (
                    f"Enable encryption at rest on "
                    f"{unencrypted_databases} database(s). "
                    f"Required for HIPAA, PCI-DSS, and most "
                    f"compliance frameworks."
                ),
                "estimated_savings_percent": 0,
            }
        )

    # =================================================
    # PATTERN-BASED TOPOLOGY CLASSIFICATION
    # Classify resource types using keyword matching.
    # Covers all current and future provider types.
    # =================================================

    has_public_exposure: bool = any(
        _is_public_exposure_resource(rt) for rt in resource_types
    )
    has_segmentation: bool = any(_is_segmentation_resource(rt) for rt in resource_types)
    has_load_balancer: bool = any(
        _is_load_balancer_resource(rt) for rt in resource_types
    )
    has_compute: bool = any(_is_compute_resource(rt) for rt in resource_types)

    public_resource_names: list[str] = [
        rt for rt in resource_types if _is_public_exposure_resource(rt)
    ]

    # =================================================
    # PUBLIC EXPOSURE WITHOUT SEGMENTATION
    # =================================================

    if has_public_exposure and not has_segmentation:
        risk_score += RISK_WEIGHT_PUBLIC_EXPOSURE

        findings.append(
            {
                "type": "public_exposure_without_segmentation",
                "severity": "high",
                "message": (
                    f"Public-facing resources detected "
                    f"({', '.join(sorted(set(public_resource_names)))}) "
                    f"without network segmentation controls."
                ),
            }
        )

        optimization_candidates.append(
            {
                "type": "network_segmentation",
                "message": (
                    "Add network security groups or firewall rules "
                    "to segment public-facing resources."
                ),
                "estimated_savings_percent": 0,
            }
        )

    elif has_public_exposure and has_segmentation:
        findings.append(
            {
                "type": "public_exposure_detected",
                "severity": "low",
                "message": (
                    f"Public-facing resources detected "
                    f"({', '.join(sorted(set(public_resource_names)))}). "
                    f"Network segmentation controls are present."
                ),
            }
        )

    # =================================================
    # LOAD BALANCER COVERAGE
    # Only flag in production — single instance
    # compute in dev and test is acceptable.
    # =================================================

    if has_compute and not has_load_balancer:
        if environment in ("production", "prod", "staging"):
            risk_score += RISK_WEIGHT_MISSING_LB

            findings.append(
                {
                    "type": "missing_load_balancer",
                    "severity": "medium",
                    "message": (
                        f"Compute resources detected in {environment} "
                        f"without load balancer coverage. "
                        f"Single point of failure risk."
                    ),
                }
            )

            optimization_candidates.append(
                {
                    "type": "load_balancer_coverage",
                    "message": (
                        f"Add a load balancer in front of compute "
                        f"resources for {environment} resilience."
                    ),
                    "estimated_savings_percent": 0,
                }
            )

    # =================================================
    # NETWORK SEGMENTATION ANALYSIS
    # =================================================

    if resources and not has_segmentation:
        risk_score += RISK_WEIGHT_MISSING_SEGMENTATION

        findings.append(
            {
                "type": "missing_network_segmentation",
                "severity": "medium",
                "message": (
                    "No network segmentation controls detected. "
                    "Consider adding security groups or firewall rules."
                ),
            }
        )

        optimization_candidates.append(
            {
                "type": "security_posture",
                "message": (
                    "Implement network security groups or firewall "
                    "rules to enforce network segmentation."
                ),
                "estimated_savings_percent": 0,
            }
        )

    # =================================================
    # SINGLE-ZONE DETECTION
    # =================================================

    # NOTE:
    # Full AZ detection requires zone metadata from
    # the plan. Currently inferred from compute
    # resource count and environment.
    # Future: parse availability_zone fields directly.

    compute_resources: list[dict[str, Any]] = [
        r for r in resources if _is_compute_resource(r.get("type", ""))
    ]

    if len(compute_resources) == 1 and environment in ("production", "prod"):
        risk_score += RISK_WEIGHT_SINGLE_ZONE

        findings.append(
            {
                "type": "single_zone_compute",
                "severity": "medium",
                "message": (
                    "Single compute resource detected in production. "
                    "Multi-zone deployment recommended for resilience."
                ),
            }
        )

    logger.info(
        "topology_analysis_complete",
        extra={
            "extra": {
                "resource_count": len(resources),
                "risk_score": risk_score,
                "finding_count": len(findings),
                "open_ingress_rules": open_ingress_rules,
                "public_storage": public_storage_buckets,
                "unencrypted_databases": unencrypted_databases,
            }
        },
    )

    return {
        "analyzer": "topology_analyzer",
        "risk_score": risk_score,
        "findings": findings,
        "optimization_candidates": optimization_candidates,
        "metadata": {
            "environment": environment,
            "resource_count": len(resources),
            "has_load_balancer": has_load_balancer,
            "has_segmentation": has_segmentation,
            "open_ingress_rules": open_ingress_rules,
            "public_storage_buckets": public_storage_buckets,
            "unencrypted_databases": unencrypted_databases,
        },
    }
