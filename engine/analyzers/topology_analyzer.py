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
# Enrichment (v0.3.5):
# - Now uses pre-computed security context keys from
#   the Translation Layer (open_ingress_rules,
#   public_storage_buckets, unencrypted_databases).
#   These provide confirmed counts, not just
#   resource-type presence signals.
#
# IMPORTANT:
# This analyzer NEVER performs enforcement.
# Findings are advisory only.

from __future__ import annotations

from typing import Any

from audit.audit_logger import get_logger

logger = get_logger()


# =====================================================
# TOPOLOGY CONSTANTS
# =====================================================

# TODO: Replace with centralized scoring engine.

# Base risk weights for topology findings
RISK_WEIGHT_PUBLIC_EXPOSURE          = 35
RISK_WEIGHT_MISSING_LB               = 20
RISK_WEIGHT_SINGLE_ZONE              = 15
RISK_WEIGHT_MISSING_SEGMENTATION     = 25

# Risk weights for security context key findings.
# These are intentionally higher than topology pattern
# weights because they represent confirmed violations,
# not inferred signals from resource type presence.
RISK_WEIGHT_OPEN_INGRESS_RULE        = 20  # per rule, capped at 3
RISK_WEIGHT_PUBLIC_STORAGE_BUCKET    = 25  # per bucket, capped at 2
RISK_WEIGHT_UNENCRYPTED_DATABASE     = 35  # per database, capped at 2

# Resource types that indicate public exposure
PUBLIC_RESOURCE_INDICATORS: frozenset[str] = frozenset({
    "aws_internet_gateway",
    "aws_eip",
    "azurerm_public_ip",
    "google_compute_address",
})

# Resource types that are load balancers
LOAD_BALANCER_TYPES: frozenset[str] = frozenset({
    "aws_lb",
    "aws_alb",
    "aws_elb",
    "azurerm_lb",
    "azurerm_application_gateway",
    "google_compute_forwarding_rule",
    "google_compute_backend_service",
})

# Resource types that are compute and should
# ideally sit behind a load balancer
COMPUTE_TYPES: frozenset[str] = frozenset({
    "aws_instance",
    "aws_ecs_service",
    "azurerm_virtual_machine",
    "azurerm_linux_virtual_machine",
    "azurerm_windows_virtual_machine",
    "google_compute_instance",
})

# Resource types that indicate network segmentation
SEGMENTATION_INDICATORS: frozenset[str] = frozenset({
    "aws_security_group",
    "aws_network_acl",
    "azurerm_network_security_group",
    "google_compute_firewall",
})


# =====================================================
# TOPOLOGY ANALYZER
# =====================================================


def analyze_topology(runtime_context: dict[str, Any]) -> dict[str, Any]:
    """
    Analyze infrastructure topology and security posture.

    Uses pre-computed security context keys from the
    Translation Layer for confirmed violation counts,
    and resource type scanning for topology patterns.

    Detects:
    - Open ingress rules (confirmed count from parser)
    - Public storage buckets (confirmed count from parser)
    - Unencrypted databases (confirmed count from parser)
    - Public resource exposure without segmentation
    - Compute resources missing load balancer coverage
    - Missing network segmentation controls
    - Single-zone deployment risk
    """

    resources:   list[dict[str, Any]] = runtime_context.get("resources", [])
    environment: str                   = runtime_context.get("environment", "unknown")

    findings:               list[dict[str, Any]] = []
    optimization_candidates: list[dict[str, Any]] = []
    risk_score: int = 0

    resource_types: set[str] = {r.get("type", "") for r in resources}

    # =================================================
    # SECURITY CONTEXT KEYS
    # Pre-computed by the Translation Layer.
    # More precise than resource type scanning —
    # these are confirmed counts, not inferred signals.
    # =================================================

    open_ingress_rules:     int = int(runtime_context.get("open_ingress_rules", 0))
    public_storage_buckets: int = int(runtime_context.get("public_storage_buckets", 0))
    unencrypted_databases:  int = int(runtime_context.get("unencrypted_databases", 0))

    # -------------------------------------------------
    # OPEN INGRESS RULES
    # Each open rule adds risk, capped at 3 rules
    # to prevent unbounded score inflation.
    # -------------------------------------------------

    if open_ingress_rules > 0:
        capped_rules: int = min(open_ingress_rules, 3)
        risk_score += RISK_WEIGHT_OPEN_INGRESS_RULE * capped_rules

        findings.append({
            "type":     "open_ingress_rules_detected",
            "severity": "high",
            "message": (
                f"{open_ingress_rules} open inbound rule(s) detected "
                f"allowing unrestricted access. "
                f"Restrict ingress to known CIDR ranges or security groups."
            ),
        })

        optimization_candidates.append({
            "type":    "restrict_ingress_rules",
            "message": (
                f"Replace {open_ingress_rules} open ingress rule(s) "
                f"with specific CIDR ranges or security group references."
            ),
            "estimated_savings_percent": 0,
        })

    # -------------------------------------------------
    # PUBLIC STORAGE BUCKETS
    # Each public bucket adds risk, capped at 2.
    # -------------------------------------------------

    if public_storage_buckets > 0:
        capped_buckets: int = min(public_storage_buckets, 2)
        risk_score += RISK_WEIGHT_PUBLIC_STORAGE_BUCKET * capped_buckets

        findings.append({
            "type":     "public_storage_detected",
            "severity": "high",
            "message": (
                f"{public_storage_buckets} publicly accessible "
                f"storage resource(s) detected. "
                f"Ensure public access is intentional and data "
                f"is non-sensitive."
            ),
        })

        optimization_candidates.append({
            "type":    "restrict_storage_access",
            "message": (
                f"Review {public_storage_buckets} public storage "
                f"resource(s) and apply access controls if "
                f"public access is not required."
            ),
            "estimated_savings_percent": 0,
        })

    # -------------------------------------------------
    # UNENCRYPTED DATABASES
    # Critical severity — each adds high risk, capped
    # at 2 to prevent score inflation.
    # -------------------------------------------------

    if unencrypted_databases > 0:
        capped_dbs: int = min(unencrypted_databases, 2)
        risk_score += RISK_WEIGHT_UNENCRYPTED_DATABASE * capped_dbs

        findings.append({
            "type":     "unencrypted_databases_detected",
            "severity": "critical",
            "message": (
                f"{unencrypted_databases} unencrypted database(s) "
                f"detected. Encryption at rest is required for "
                f"compliance and data protection."
            ),
        })

        optimization_candidates.append({
            "type":    "enable_database_encryption",
            "message": (
                f"Enable encryption at rest on "
                f"{unencrypted_databases} database(s). "
                f"Required for HIPAA, PCI-DSS, and most "
                f"compliance frameworks."
            ),
            "estimated_savings_percent": 0,
        })

    # =================================================
    # PUBLIC EXPOSURE WITHOUT SEGMENTATION
    # Resource type pattern detection.
    # Complements the context key checks above.
    # =================================================

    public_resources: set[str] = resource_types & PUBLIC_RESOURCE_INDICATORS

    if public_resources:
        has_segmentation: bool = bool(resource_types & SEGMENTATION_INDICATORS)

        if not has_segmentation:
            risk_score += RISK_WEIGHT_PUBLIC_EXPOSURE

            findings.append({
                "type":     "public_exposure_without_segmentation",
                "severity": "high",
                "message": (
                    f"Public-facing resources detected "
                    f"({', '.join(sorted(public_resources))}) "
                    f"without network segmentation controls."
                ),
            })

            optimization_candidates.append({
                "type":    "network_segmentation",
                "message": (
                    "Add network security groups or firewall rules "
                    "to segment public-facing resources."
                ),
                "estimated_savings_percent": 0,
            })

        else:
            # Public exposure with segmentation — lower severity
            findings.append({
                "type":     "public_exposure_detected",
                "severity": "low",
                "message": (
                    f"Public-facing resources detected "
                    f"({', '.join(sorted(public_resources))}). "
                    f"Network segmentation controls present."
                ),
            })

    # =================================================
    # LOAD BALANCER COVERAGE
    # =================================================

    has_compute:       bool = bool(resource_types & COMPUTE_TYPES)
    has_load_balancer: bool = bool(resource_types & LOAD_BALANCER_TYPES)

    if has_compute and not has_load_balancer:
        # Only flag in production — single instance in dev is acceptable
        if environment in ("production", "prod", "staging"):
            risk_score += RISK_WEIGHT_MISSING_LB

            findings.append({
                "type":     "missing_load_balancer",
                "severity": "medium",
                "message": (
                    f"Compute resources detected in {environment} "
                    f"without load balancer coverage. "
                    f"Single point of failure risk."
                ),
            })

            optimization_candidates.append({
                "type":    "load_balancer_coverage",
                "message": (
                    f"Add a load balancer in front of compute "
                    f"resources for {environment} resilience."
                ),
                "estimated_savings_percent": 0,
            })

    # =================================================
    # NETWORK SEGMENTATION ANALYSIS
    # =================================================

    if resources and not (resource_types & SEGMENTATION_INDICATORS):
        risk_score += RISK_WEIGHT_MISSING_SEGMENTATION

        findings.append({
            "type":     "missing_network_segmentation",
            "severity": "medium",
            "message": (
                "No network segmentation controls detected. "
                "Consider adding security groups or firewall rules."
            ),
        })

        optimization_candidates.append({
            "type":    "security_posture",
            "message": (
                "Implement network security groups or firewall "
                "rules to enforce network segmentation."
            ),
            "estimated_savings_percent": 0,
        })

    # =================================================
    # SINGLE-ZONE DETECTION
    # =================================================

    # NOTE:
    # Full AZ detection requires zone metadata from the plan.
    # Currently inferred from resource count and type patterns.
    # Future: parse availability_zone fields from resource values.

    compute_resources: list[dict[str, Any]] = [
        r for r in resources
        if r.get("type", "") in COMPUTE_TYPES
    ]

    if len(compute_resources) == 1 and environment in ("production", "prod"):
        risk_score += RISK_WEIGHT_SINGLE_ZONE

        findings.append({
            "type":     "single_zone_compute",
            "severity": "medium",
            "message": (
                "Single compute resource detected in production. "
                "Multi-zone deployment recommended for resilience."
            ),
        })

    logger.info(
        "topology_analysis_complete",
        extra={
            "extra": {
                "resource_count":        len(resources),
                "risk_score":            risk_score,
                "finding_count":         len(findings),
                "open_ingress_rules":    open_ingress_rules,
                "public_storage":        public_storage_buckets,
                "unencrypted_databases": unencrypted_databases,
            }
        },
    )

    return {
        "analyzer":               "topology_analyzer",
        "risk_score":             risk_score,
        "findings":               findings,
        "optimization_candidates": optimization_candidates,
        "metadata": {
            "environment":           environment,
            "resource_count":        len(resources),
            "has_load_balancer":     has_load_balancer,
            "has_segmentation":      bool(resource_types & SEGMENTATION_INDICATORS),
            "open_ingress_rules":    open_ingress_rules,
            "public_storage_buckets": public_storage_buckets,
            "unencrypted_databases": unencrypted_databases,
        },
    }
