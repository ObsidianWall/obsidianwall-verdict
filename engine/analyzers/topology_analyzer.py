# engine/analyzers/topology_analyzer.py

# Purpose:
# Analyze infrastructure topology patterns.
#
# Responsibilities:
# - Network exposure detection
# - Load balancer coverage analysis
# - Multi-zone/region deployment assessment
# - Resource connectivity risk detection
# - Network segmentation analysis
#
# IMPORTANT:
# This analyzer NEVER performs enforcement.
# Findings are advisory only.


from audit.audit_logger import get_logger

logger = get_logger()


# =====================================================
# TOPOLOGY CONSTANTS
# =====================================================

# TODO: Replace with centralized scoring engine.
RISK_WEIGHT_PUBLIC_EXPOSURE = 35
RISK_WEIGHT_MISSING_LB = 20
RISK_WEIGHT_SINGLE_ZONE = 15
RISK_WEIGHT_MISSING_SEGMENTATION = 25

# Resource types that indicate public exposure
PUBLIC_RESOURCE_INDICATORS = {
    "aws_internet_gateway",
    "aws_eip",
    "azurerm_public_ip",
    "google_compute_address",
}

# Resource types that are load balancers
LOAD_BALANCER_TYPES = {
    "aws_lb",
    "aws_alb",
    "aws_elb",
    "azurerm_lb",
    "azurerm_application_gateway",
    "google_compute_forwarding_rule",
    "google_compute_backend_service",
}

# Resource types that are compute and should
# ideally sit behind a load balancer
COMPUTE_TYPES = {
    "aws_instance",
    "aws_ecs_service",
    "azurerm_virtual_machine",
    "azurerm_linux_virtual_machine",
    "azurerm_windows_virtual_machine",
    "google_compute_instance",
}

# Resource types that indicate network segmentation
SEGMENTATION_INDICATORS = {
    "aws_security_group",
    "aws_network_acl",
    "azurerm_network_security_group",
    "google_compute_firewall",
}


# =====================================================
# TOPOLOGY ANALYZER
# =====================================================


def analyze_topology(runtime_context: dict) -> dict:
    """
    Analyze infrastructure topology posture.

    Detects:
    - Public resource exposure without segmentation
    - Compute resources missing load balancer coverage
    - Missing network segmentation controls
    - Single-zone deployment risk
    """

    resources = runtime_context.get("resources", [])
    environment = runtime_context.get("environment", "unknown")

    findings = []
    optimization_candidates = []
    risk_score = 0

    resource_types = {r.get("type", "") for r in resources}

    # =================================================
    # PUBLIC EXPOSURE DETECTION
    # =================================================

    public_resources = resource_types & PUBLIC_RESOURCE_INDICATORS

    if public_resources:
        has_segmentation = bool(resource_types & SEGMENTATION_INDICATORS)

        if not has_segmentation:
            risk_score += RISK_WEIGHT_PUBLIC_EXPOSURE

            findings.append(
                {
                    "type": "public_exposure_without_segmentation",
                    "severity": "high",
                    "message": (
                        f"Public-facing resources detected "
                        f"({', '.join(public_resources)}) "
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

        else:
            # Public exposure with segmentation — lower severity
            findings.append(
                {
                    "type": "public_exposure_detected",
                    "severity": "low",
                    "message": (
                        f"Public-facing resources detected "
                        f"({', '.join(public_resources)}). "
                        f"Network segmentation controls present."
                    ),
                }
            )

    # =================================================
    # LOAD BALANCER COVERAGE
    # =================================================

    has_compute = bool(resource_types & COMPUTE_TYPES)
    has_load_balancer = bool(resource_types & LOAD_BALANCER_TYPES)

    if has_compute and not has_load_balancer:
        # Only flag in production — dev single-instance is acceptable
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

    if resources and not (resource_types & SEGMENTATION_INDICATORS):
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
    # Full AZ detection requires zone metadata from the plan.
    # Currently inferred from resource count and type patterns.
    # Future: parse availability_zone fields from resource values.

    compute_resources = [r for r in resources if r.get("type", "") in COMPUTE_TYPES]

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
            "has_segmentation": bool(resource_types & SEGMENTATION_INDICATORS),
        },
    }
