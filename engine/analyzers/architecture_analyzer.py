# engine/analyzers/architecture_analyzer.py

# Purpose:
# Analyze infrastructure architecture patterns.
#
# Responsibilities:
# - Architecture anti-pattern detection
# - Resilience assessment by resource class
# - Single point of failure identification
# - Deployment structure analysis
# - Environment-appropriate architecture checks
# - Architecture risk scoring
#
# IMPORTANT:
# This analyzer NEVER performs enforcement.
# Findings are advisory only.


from audit.audit_logger import get_logger


logger = get_logger()


# =====================================================
# ARCHITECTURE CONSTANTS
# =====================================================

# TODO: Replace with centralized scoring engine.
RISK_WEIGHT_SINGLE_DB           = 40
RISK_WEIGHT_SINGLE_COMPUTE      = 20
RISK_WEIGHT_SINGLE_STORAGE      = 10
RISK_WEIGHT_NO_MONITORING       = 15
RISK_WEIGHT_MIXED_CLOUD         = 10

# Resource class mappings
# NOTE: Subset — full mapping lives in optimization_catalog.
DATABASE_TYPES = {
    "aws_db_instance",
    "aws_rds_cluster",
    "azurerm_mssql_server",
    "azurerm_sql_database",
    "azurerm_postgresql_server",
    "google_sql_database_instance",
    "google_spanner_instance",
}

COMPUTE_TYPES = {
    "aws_instance",
    "aws_ecs_service",
    "aws_lambda_function",
    "azurerm_virtual_machine",
    "azurerm_linux_virtual_machine",
    "google_compute_instance",
}

STORAGE_TYPES = {
    "aws_s3_bucket",
    "azurerm_storage_account",
    "google_storage_bucket",
}

MONITORING_TYPES = {
    "aws_cloudwatch_metric_alarm",
    "azurerm_monitor_diagnostic_setting",
    "azurerm_log_analytics_workspace",
    "azurerm_sentinel_log_analytics_workspace",
    "google_monitoring_alert_policy",
    "google_logging_sink",
}

# Cloud provider prefixes for cross-cloud detection
CLOUD_PREFIXES = {
    "aws":          "aws",
    "azurerm":      "azure",
    "google":       "gcp",
}


def _detect_cloud_provider(resource_type: str) -> str:
    """Infer cloud provider from resource type prefix."""
    for prefix, provider in CLOUD_PREFIXES.items():
        if resource_type.startswith(prefix):
            return provider
    return "unknown"


# =====================================================
# ARCHITECTURE ANALYZER
# =====================================================

def analyze_architecture(
    runtime_context: dict
) -> dict:
    """
    Analyze infrastructure architecture posture.

    Detects:
    - Single-resource deployments weighted by resource class
    - Missing redundancy for production databases
    - Missing monitoring/observability resources
    - Multi-cloud complexity risk
    - Environment-inappropriate architecture patterns
    """

    resources   = runtime_context.get("resources", [])
    environment = runtime_context.get("environment", "unknown")

    findings                = []
    optimization_candidates = []
    risk_score              = 0

    resource_types = [r.get("type", "") for r in resources]
    resource_type_set = set(resource_types)

    # =================================================
    # DATABASE REDUNDANCY DETECTION
    # =================================================

    db_resources = [
        t for t in resource_types
        if t in DATABASE_TYPES
    ]

    if len(db_resources) == 1 and environment in (
        "production", "prod", "staging"
    ):

        risk_score += RISK_WEIGHT_SINGLE_DB

        findings.append({
            "type":     "single_database_no_replica",
            "severity": "high",
            "message": (
                f"Single database resource detected in {environment}. "
                f"No replica or failover configuration detected. "
                f"Data availability risk."
            )
        })

        optimization_candidates.append({
            "type": "database_redundancy",
            "message": (
                "Configure database read replicas or "
                "multi-AZ failover for production resilience."
            ),
            "estimated_savings_percent": 0
        })

    # =================================================
    # COMPUTE REDUNDANCY DETECTION
    # =================================================

    compute_resources = [
        t for t in resource_types
        if t in COMPUTE_TYPES
    ]

    if len(compute_resources) == 1 and environment in (
        "production", "prod"
    ):

        risk_score += RISK_WEIGHT_SINGLE_COMPUTE

        findings.append({
            "type":     "single_compute_resource",
            "severity": "medium",
            "message": (
                f"Single compute resource detected in {environment}. "
                f"No horizontal redundancy detected."
            )
        })

        optimization_candidates.append({
            "type": "compute_redundancy",
            "message": (
                "Consider auto-scaling groups or multiple "
                "compute instances for production resilience."
            ),
            "estimated_savings_percent": 0
        })

    # =================================================
    # SINGLE RESOURCE DEPLOYMENT (ANY CLASS)
    # =================================================

    # NOTE:
    # Weighted by resource class above.
    # This catches single-resource deployments not
    # covered by specific class checks above.

    if len(resources) == 1:

        resource_type = resource_types[0] if resource_types else ""

        # Storage-only single resource is lower risk
        if resource_type in STORAGE_TYPES:
            risk_score += RISK_WEIGHT_SINGLE_STORAGE
            severity = "low"
        else:
            severity = "medium"

        findings.append({
            "type":     "single_resource_architecture",
            "severity": severity,
            "message": (
                "Single-resource deployment detected. "
                "Review architecture for resilience requirements."
            )
        })

    # =================================================
    # MONITORING AND OBSERVABILITY
    # =================================================

    has_monitoring = bool(
        resource_type_set & MONITORING_TYPES
    )

    if not has_monitoring and environment in (
        "production", "prod", "staging"
    ):

        risk_score += RISK_WEIGHT_NO_MONITORING

        findings.append({
            "type":     "missing_observability",
            "severity": "medium",
            "message": (
                f"No monitoring or observability resources detected "
                f"in {environment} deployment."
            )
        })

        optimization_candidates.append({
            "type": "observability",
            "message": (
                "Add monitoring, alerting, and logging resources "
                "to support operational visibility."
            ),
            "estimated_savings_percent": 0
        })

    # =================================================
    # MULTI-CLOUD COMPLEXITY DETECTION
    # =================================================

    cloud_providers = {
        _detect_cloud_provider(t)
        for t in resource_type_set
        if _detect_cloud_provider(t) != "unknown"
    }

    if len(cloud_providers) > 1:

        risk_score += RISK_WEIGHT_MIXED_CLOUD

        findings.append({
            "type":     "multi_cloud_complexity",
            "severity": "low",
            "message": (
                f"Resources span multiple cloud providers "
                f"({', '.join(sorted(cloud_providers))}). "
                f"Operational complexity risk."
            )
        })

    logger.info(
        "architecture_analysis_complete",
        extra={
            "extra": {
                "resource_count":   len(resources),
                "risk_score":       risk_score,
                "finding_count":    len(findings),
                "environment":      environment,
            }
        }
    )

    return {
        "analyzer":                 "architecture_analyzer",
        "risk_score":               risk_score,
        "findings":                 findings,
        "optimization_candidates":  optimization_candidates,
        "metadata": {
            "environment":          environment,
            "resource_count":       len(resources),
            "cloud_providers":      list(cloud_providers),
            "has_monitoring":       has_monitoring,
        }
    }
