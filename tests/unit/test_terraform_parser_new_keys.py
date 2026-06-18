
# tests/unit/test_terraform_parser_new_keys.py
#
# Test suite for the two new context keys added to
# context/translators/terraform_parser.py in v0.5.0:
#
#   ssl_not_enforced_count    → HIPAA 164.312(e)(1)
#   versioning_disabled_count → HIPAA 164.312(c)(1)
#
# Tests cover both Azure and AWS resource types.

import pytest

from context.translators.terraform_parser import (
    _count_ssl_not_enforced,
    _count_versioning_disabled,
)


# =====================================================
# SSL NOT ENFORCED — AZURE
# =====================================================


class TestSslNotEnforcedAzure:

    def test_counts_mysql_server_without_ssl(self):
        resources = [
            {
                "type": "azurerm_mysql_server",
                "name": "db",
                "values": {"ssl_enforcement_enabled": False},
            }
        ]
        assert _count_ssl_not_enforced(resources) == 1

    def test_does_not_count_mysql_server_with_ssl(self):
        resources = [
            {
                "type": "azurerm_mysql_server",
                "name": "db",
                "values": {"ssl_enforcement_enabled": True},
            }
        ]
        assert _count_ssl_not_enforced(resources) == 0

    def test_counts_postgresql_server_without_ssl(self):
        resources = [
            {
                "type": "azurerm_postgresql_server",
                "name": "db",
                "values": {"ssl_enforcement_enabled": False},
            }
        ]
        assert _count_ssl_not_enforced(resources) == 1

    def test_counts_app_service_without_https_only(self):
        resources = [
            {
                "type": "azurerm_app_service",
                "name": "app",
                "values": {"https_only": False},
            }
        ]
        assert _count_ssl_not_enforced(resources) == 1

    def test_does_not_count_app_service_with_https_only(self):
        resources = [
            {
                "type": "azurerm_app_service",
                "name": "app",
                "values": {"https_only": True},
            }
        ]
        assert _count_ssl_not_enforced(resources) == 0

    def test_counts_linux_web_app_without_https_only(self):
        resources = [
            {
                "type": "azurerm_linux_web_app",
                "name": "app",
                "values": {"https_only": False},
            }
        ]
        assert _count_ssl_not_enforced(resources) == 1

    def test_counts_storage_account_with_tls10(self):
        resources = [
            {
                "type": "azurerm_storage_account",
                "name": "storage",
                "values": {"min_tls_version": "TLS1_0"},
            }
        ]
        assert _count_ssl_not_enforced(resources) == 1

    def test_counts_storage_account_with_tls11(self):
        resources = [
            {
                "type": "azurerm_storage_account",
                "name": "storage",
                "values": {"min_tls_version": "TLS1_1"},
            }
        ]
        assert _count_ssl_not_enforced(resources) == 1

    def test_does_not_count_storage_account_with_tls12(self):
        resources = [
            {
                "type": "azurerm_storage_account",
                "name": "storage",
                "values": {"min_tls_version": "TLS1_2"},
            }
        ]
        assert _count_ssl_not_enforced(resources) == 0


# =====================================================
# SSL NOT ENFORCED — AWS
# =====================================================


class TestSslNotEnforcedAws:

    def test_counts_http_lb_listener(self):
        resources = [
            {
                "type": "aws_lb_listener",
                "name": "listener",
                "values": {"protocol": "HTTP"},
            }
        ]
        assert _count_ssl_not_enforced(resources) == 1

    def test_does_not_count_https_lb_listener(self):
        resources = [
            {
                "type": "aws_lb_listener",
                "name": "listener",
                "values": {"protocol": "HTTPS"},
            }
        ]
        assert _count_ssl_not_enforced(resources) == 0

    def test_counts_elasticache_without_transit_encryption(self):
        resources = [
            {
                "type": "aws_elasticache_replication_group",
                "name": "cache",
                "values": {"transit_encryption_enabled": False},
            }
        ]
        assert _count_ssl_not_enforced(resources) == 1

    def test_does_not_count_elasticache_with_transit_encryption(self):
        resources = [
            {
                "type": "aws_elasticache_replication_group",
                "name": "cache",
                "values": {"transit_encryption_enabled": True},
            }
        ]
        assert _count_ssl_not_enforced(resources) == 0

    def test_counts_publicly_accessible_rds(self):
        resources = [
            {
                "type": "aws_db_instance",
                "name": "db",
                "values": {"publicly_accessible": True},
            }
        ]
        assert _count_ssl_not_enforced(resources) == 1

    def test_does_not_count_private_rds(self):
        resources = [
            {
                "type": "aws_db_instance",
                "name": "db",
                "values": {"publicly_accessible": False},
            }
        ]
        assert _count_ssl_not_enforced(resources) == 0

    def test_returns_zero_for_empty_resources(self):
        assert _count_ssl_not_enforced([]) == 0

    def test_counts_multiple_violations(self):
        resources = [
            {
                "type": "aws_lb_listener",
                "name": "listener",
                "values": {"protocol": "HTTP"},
            },
            {
                "type": "aws_elasticache_replication_group",
                "name": "cache",
                "values": {"transit_encryption_enabled": False},
            },
        ]
        assert _count_ssl_not_enforced(resources) == 2


# =====================================================
# VERSIONING DISABLED — AZURE
# =====================================================


class TestVersioningDisabledAzure:

    def test_counts_storage_account_without_versioning(self):
        resources = [
            {
                "type": "azurerm_storage_account",
                "name": "storage",
                "values": {
                    "blob_properties": {"versioning_enabled": False}
                },
            }
        ]
        assert _count_versioning_disabled(resources) == 1

    def test_does_not_count_storage_account_with_versioning(self):
        resources = [
            {
                "type": "azurerm_storage_account",
                "name": "storage",
                "values": {
                    "blob_properties": {"versioning_enabled": True}
                },
            }
        ]
        assert _count_versioning_disabled(resources) == 0

    def test_counts_storage_account_without_blob_properties(self):
        resources = [
            {
                "type": "azurerm_storage_account",
                "name": "storage",
                "values": {},
            }
        ]
        assert _count_versioning_disabled(resources) == 1

    def test_counts_key_vault_without_soft_delete(self):
        resources = [
            {
                "type": "azurerm_key_vault",
                "name": "kv",
                "values": {"soft_delete_enabled": False},
            }
        ]
        assert _count_versioning_disabled(resources) == 1

    def test_does_not_count_key_vault_with_soft_delete(self):
        resources = [
            {
                "type": "azurerm_key_vault",
                "name": "kv",
                "values": {"soft_delete_enabled": True},
            }
        ]
        assert _count_versioning_disabled(resources) == 0


# =====================================================
# VERSIONING DISABLED — AWS
# =====================================================


class TestVersioningDisabledAws:

    def test_counts_s3_versioning_suspended(self):
        resources = [
            {
                "type": "aws_s3_bucket_versioning",
                "name": "versioning",
                "values": {
                    "versioning_configuration": {"status": "Suspended"}
                },
            }
        ]
        assert _count_versioning_disabled(resources) == 1

    def test_does_not_count_s3_versioning_enabled(self):
        resources = [
            {
                "type": "aws_s3_bucket_versioning",
                "name": "versioning",
                "values": {
                    "versioning_configuration": {"status": "Enabled"}
                },
            }
        ]
        assert _count_versioning_disabled(resources) == 0

    def test_counts_s3_versioning_without_config(self):
        resources = [
            {
                "type": "aws_s3_bucket_versioning",
                "name": "versioning",
                "values": {},
            }
        ]
        assert _count_versioning_disabled(resources) == 1

    def test_counts_dynamodb_without_pitr(self):
        resources = [
            {
                "type": "aws_dynamodb_table",
                "name": "table",
                "values": {
                    "point_in_time_recovery": [{"enabled": False}]
                },
            }
        ]
        assert _count_versioning_disabled(resources) == 1

    def test_does_not_count_dynamodb_with_pitr(self):
        resources = [
            {
                "type": "aws_dynamodb_table",
                "name": "table",
                "values": {
                    "point_in_time_recovery": [{"enabled": True}]
                },
            }
        ]
        assert _count_versioning_disabled(resources) == 0

    def test_counts_dynamodb_without_pitr_block(self):
        resources = [
            {
                "type": "aws_dynamodb_table",
                "name": "table",
                "values": {},
            }
        ]
        assert _count_versioning_disabled(resources) == 1

    def test_returns_zero_for_empty_resources(self):
        assert _count_versioning_disabled([]) == 0

    def test_counts_multiple_violations(self):
        resources = [
            {
                "type": "aws_s3_bucket_versioning",
                "name": "v1",
                "values": {
                    "versioning_configuration": {"status": "Suspended"}
                },
            },
            {
                "type": "aws_dynamodb_table",
                "name": "table",
                "values": {},
            },
        ]
        assert _count_versioning_disabled(resources) == 2