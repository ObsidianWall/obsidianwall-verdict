# engine/optimization_catalog.py

# Responsibilities: proprietary heuristics

#purpose: Containing:
            # known resource patterns
            # pricing heuristics
            # optimization mappings
            # architecture alternatives



# Purpose:
# Semantic infrastructure optimization intelligence.
#
# Responsibilities:
# - Resource classification
# - Workload optimization heuristics
# - Cross-cloud recommendation mappings
# - Deterministic optimization intelligence
#
# IMPORTANT:
# This module NEVER makes enforcement decisions.
# Recommendations are advisory only.


# =====================================================
# RESOURCE CLASSIFICATION
# =====================================================

RESOURCE_CLASSES = {

    # -------------------------------------------------
    # COMPUTE
    # -------------------------------------------------

    "aws_instance": "compute",
    "azurerm_virtual_machine": "compute",
    "google_compute_instance": "compute",

    # -------------------------------------------------
    # STORAGE
    # -------------------------------------------------

    "aws_s3_bucket": "storage",
    "azurerm_storage_account": "storage",
    "google_storage_bucket": "storage",

    # -------------------------------------------------
    # DATABASE
    # -------------------------------------------------

    "aws_db_instance": "database",
    "azurerm_mssql_server": "database",
    "google_sql_database_instance": "database",

    # -------------------------------------------------
    # CONTAINER
    # -------------------------------------------------

    "aws_ecs_cluster": "container",
    "azurerm_kubernetes_cluster": "container",
    "google_container_cluster": "container",


    # -------------------------------------------------
    # MONITORING
    # -------------------------------------------------

    "azurerm_sentinel_log_analytics_workspace": "monitoring",
    "azurerm_log_analytics_workspace":          "monitoring",
    "aws_cloudwatch_log_group":                 "monitoring",
    "google_logging_sink":                      "monitoring",
}


# =====================================================
# SEMANTIC OPTIMIZATION RULES
# =====================================================

OPTIMIZATION_RULES = [

    # =================================================
    # COMPUTE OPTIMIZATION
    # =================================================

    {
        "resource_class": "compute",

        "conditions": {
            "environment": "development",
            "workload_profile": "burstable"
        },

        "recommendations": [
            {
                "type": "rightsizing",
                "message": (
                    "Development burst workloads detected. "
                    "Consider smaller burstable compute instances."
                ),
                "estimated_savings_percent": 30,

                 "priority_score": 82,

                "confidence": 0.91,

                "severity": "medium"
            },

            {
                "type": "serverless_candidate",
                "message": (
                    "Workload may be a candidate for serverless migration."
                ),
                "estimated_savings_percent": 45,

                 "priority_score": 90,

                "confidence": 0.87,

                "severity": "high"
            }
        ]
    },

    # =================================================
    # STORAGE OPTIMIZATION
    # =================================================

    {
        "resource_class": "storage",

        "conditions": {
            "environment": "production"
        },

        "recommendations": [
            {
                "type": "lifecycle_policy",
                "message": (
                    "Review storage lifecycle policies "
                    "for cold/archive optimization."
                ),
                "estimated_savings_percent": 20,

                "priority_score": 70,

                "confidence": 0.93,

                "severity": "medium"
            }
        ]
    },

    # =================================================
    # DATABASE OPTIMIZATION
    # =================================================

    {
        "resource_class": "database",

        "conditions": {
            "environment": "production"
        },

        "recommendations": [
            {
                "type": "reserved_capacity",
                "message": (
                    "Production database workloads detected. "
                    "Evaluate reserved capacity pricing models."
                ),
                "estimated_savings_percent": 35,

                "priority_score": 88,

                "confidence": 0.95,

                "severity": "high"
            }
        ]
    },

    # =================================================
    # CONTAINER OPTIMIZATION
    # =================================================

    {
        "resource_class": "container",

        "conditions": {
            "environment": "development"
        },

        "recommendations": [
            {
                "type": "autoscaling",
                "message": (
                    "Container workloads detected. "
                    "Review autoscaling thresholds."
                ),
                "estimated_savings_percent": 15,

                 "priority_score": 60,

                "confidence": 0.84,

                "severity": "low"
            }
        ]
    }
]
