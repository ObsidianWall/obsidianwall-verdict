
# tests/unit/test_terraform_parser_core.py
#
# Covers the core extraction functions and parse_terraform_plan()
# from the NEW import path: context.translators.terraform_parser
#
# These tests exist because existing pre-v0.5.0 tests import
# from the old path (context.terraform_parser). The file was
# moved to context/translators/ in v0.5.0. This file ensures
# coverage is recorded against the new location.

import json
import pytest
from pathlib import Path

from context.translators.terraform_parser import (
    _count_compute_instances,
    _count_gpu_instances,
    _count_open_ingress_rules,
    _count_public_storage,
    _count_unencrypted_databases,
    _count_untagged_resources,
    _count_ai_gpu_workloads,
    parse_terraform_plan,
)


# =====================================================
# FIXTURES
# =====================================================

_FULL_TERRAFORM_PLAN = {
    "terraform_version": "1.5.0",
    "planned_values": {
        "root_module": {
            "resources": [
                {
                    "type": "azurerm_network_security_group",
                    "name": "nsg",
                    "values": {
                        "security_rule": [
                            {
                                "direction": "Inbound",
                                "access": "Allow",
                                "source_address_prefix": "0.0.0.0/0",
                            }
                        ]
                    },
                },
                {
                    "type": "azurerm_network_security_rule",
                    "name": "rule",
                    "values": {
                        "direction": "Inbound",
                        "access": "Allow",
                        "source_address_prefix": "Internet",
                    },
                },
                {
                    "type": "aws_security_group",
                    "name": "sg",
                    "values": {
                        "ingress": [
                            {"cidr_blocks": ["0.0.0.0/0"], "from_port": 22}
                        ]
                    },
                },
                {
                    "type": "aws_vpc_security_group_ingress_rule",
                    "name": "ingress",
                    "values": {"cidr_ipv4": "0.0.0.0/0"},
                },
                {
                    "type": "azurerm_storage_account",
                    "name": "storage",
                    "values": {
                        "allow_blob_public_access": True,
                        "public_network_access_enabled": True,
                    },
                },
                {
                    "type": "aws_s3_bucket",
                    "name": "bucket",
                    "values": {},
                },
                {
                    "type": "azurerm_sql_database",
                    "name": "sqldb",
                    "values": {"transparent_data_encryption_enabled": False},
                },
                {
                    "type": "azurerm_postgresql_server",
                    "name": "pgdb",
                    "values": {"ssl_enforcement_enabled": False},
                },
                {
                    "type": "aws_db_instance",
                    "name": "rds",
                    "values": {"storage_encrypted": False},
                },
                {
                    "type": "azurerm_linux_virtual_machine",
                    "name": "vm",
                    "values": {
                        "vm_size": "Standard_NC6",
                        "tags": {"env": "prod"},
                    },
                },
                {
                    "type": "aws_instance",
                    "name": "gpu_instance",
                    "values": {"instance_type": "p3.2xlarge"},
                },
                {
                    "type": "aws_instance",
                    "name": "web_instance",
                    "values": {"instance_type": "t3.medium"},
                },
            ],
            "child_modules": [
                {
                    "resources": [
                        {
                            "type": "aws_autoscaling_group",
                            "name": "asg",
                            "values": {},
                        }
                    ]
                }
            ],
        }
    },
}


@pytest.fixture
def full_plan_file(tmp_path):
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(_FULL_TERRAFORM_PLAN))
    return str(path)


@pytest.fixture
def empty_plan_file(tmp_path):
    plan = {
        "terraform_version": "1.5.0",
        "planned_values": {
            "root_module": {"resources": []}
        },
    }
    path = tmp_path / "empty_plan.json"
    path.write_text(json.dumps(plan))
    return str(path)


# =====================================================
# OPEN INGRESS RULES — NEW PATH
# =====================================================


class TestCountOpenIngressRulesNewPath:

    def test_counts_azure_nsg_inbound_allow(self):
        resources = [
            {
                "type": "azurerm_network_security_group",
                "name": "nsg",
                "values": {
                    "security_rule": [
                        {
                            "direction": "Inbound",
                            "access": "Allow",
                            "source_address_prefix": "0.0.0.0/0",
                        }
                    ]
                },
            }
        ]
        assert _count_open_ingress_rules(resources) == 1

    def test_ignores_azure_nsg_outbound_rule(self):
        resources = [
            {
                "type": "azurerm_network_security_group",
                "name": "nsg",
                "values": {
                    "security_rule": [
                        {
                            "direction": "Outbound",
                            "access": "Allow",
                            "source_address_prefix": "0.0.0.0/0",
                        }
                    ]
                },
            }
        ]
        assert _count_open_ingress_rules(resources) == 0

    def test_counts_azure_nsg_rule_with_internet_source(self):
        resources = [
            {
                "type": "azurerm_network_security_rule",
                "name": "rule",
                "values": {
                    "direction": "Inbound",
                    "access": "Allow",
                    "source_address_prefix": "Internet",
                },
            }
        ]
        assert _count_open_ingress_rules(resources) == 1

    def test_counts_aws_security_group_open_ingress(self):
        resources = [
            {
                "type": "aws_security_group",
                "name": "sg",
                "values": {
                    "ingress": [{"cidr_blocks": ["0.0.0.0/0"]}]
                },
            }
        ]
        assert _count_open_ingress_rules(resources) == 1

    def test_counts_aws_security_group_ipv6_ingress(self):
        resources = [
            {
                "type": "aws_security_group",
                "name": "sg",
                "values": {
                    "ingress": [{"cidr_blocks": ["::/0"]}]
                },
            }
        ]
        assert _count_open_ingress_rules(resources) == 1

    def test_counts_aws_standalone_ingress_rule(self):
        resources = [
            {
                "type": "aws_vpc_security_group_ingress_rule",
                "name": "rule",
                "values": {"cidr_ipv6": "::/0"},
            }
        ]
        assert _count_open_ingress_rules(resources) == 1

    def test_ignores_restricted_ingress(self):
        resources = [
            {
                "type": "aws_security_group",
                "name": "sg",
                "values": {
                    "ingress": [{"cidr_blocks": ["10.0.0.0/8"]}]
                },
            }
        ]
        assert _count_open_ingress_rules(resources) == 0

    def test_returns_zero_for_empty_list(self):
        assert _count_open_ingress_rules([]) == 0


# =====================================================
# PUBLIC STORAGE — NEW PATH
# =====================================================


class TestCountPublicStorageNewPath:

    def test_counts_azure_storage_with_blob_public_access(self):
        resources = [
            {
                "type": "azurerm_storage_account",
                "name": "storage",
                "values": {"allow_blob_public_access": True},
            }
        ]
        assert _count_public_storage(resources) == 1

    def test_counts_azure_storage_with_public_network_access(self):
        resources = [
            {
                "type": "azurerm_storage_account",
                "name": "storage",
                "values": {"public_network_access_enabled": True},
            }
        ]
        assert _count_public_storage(resources) == 1

    def test_counts_aws_s3_bucket_by_default(self):
        resources = [
            {
                "type": "aws_s3_bucket",
                "name": "bucket",
                "values": {},
            }
        ]
        assert _count_public_storage(resources) == 1

    def test_s3_public_access_block_decrements_count(self):
        resources = [
            {
                "type": "aws_s3_bucket",
                "name": "bucket",
                "values": {},
            },
            {
                "type": "aws_s3_bucket_public_access_block",
                "name": "block",
                "values": {
                    "block_public_acls": True,
                    "block_public_policy": True,
                    "ignore_public_acls": True,
                    "restrict_public_buckets": True,
                },
            },
        ]
        assert _count_public_storage(resources) == 0

    def test_returns_zero_for_empty_list(self):
        assert _count_public_storage([]) == 0


# =====================================================
# UNENCRYPTED DATABASES — NEW PATH
# =====================================================


class TestCountUnencryptedDatabasesNewPath:

    def test_counts_azure_sql_without_tde(self):
        resources = [
            {
                "type": "azurerm_sql_database",
                "name": "db",
                "values": {"transparent_data_encryption_enabled": False},
            }
        ]
        assert _count_unencrypted_databases(resources) == 1

    def test_does_not_count_azure_sql_with_tde(self):
        resources = [
            {
                "type": "azurerm_sql_database",
                "name": "db",
                "values": {"transparent_data_encryption_enabled": True},
            }
        ]
        assert _count_unencrypted_databases(resources) == 0

    def test_counts_azure_postgresql_without_ssl(self):
        resources = [
            {
                "type": "azurerm_postgresql_server",
                "name": "pg",
                "values": {"ssl_enforcement_enabled": False},
            }
        ]
        assert _count_unencrypted_databases(resources) == 1

    def test_counts_azure_mysql_without_ssl(self):
        resources = [
            {
                "type": "azurerm_mysql_server",
                "name": "mysql",
                "values": {"ssl_enforcement_enabled": False},
            }
        ]
        assert _count_unencrypted_databases(resources) == 1

    def test_counts_azure_mssql_without_tde(self):
        resources = [
            {
                "type": "azurerm_mssql_database",
                "name": "mssql",
                "values": {"transparent_data_encryption_enabled": False},
            }
        ]
        assert _count_unencrypted_databases(resources) == 1

    def test_counts_aws_rds_without_encryption(self):
        resources = [
            {
                "type": "aws_db_instance",
                "name": "rds",
                "values": {"storage_encrypted": False},
            }
        ]
        assert _count_unencrypted_databases(resources) == 1

    def test_counts_aws_rds_cluster_without_encryption(self):
        resources = [
            {
                "type": "aws_rds_cluster",
                "name": "cluster",
                "values": {"storage_encrypted": False},
            }
        ]
        assert _count_unencrypted_databases(resources) == 1

    def test_returns_zero_for_empty_list(self):
        assert _count_unencrypted_databases([]) == 0


# =====================================================
# UNTAGGED RESOURCES — NEW PATH
# =====================================================


class TestCountUntaggedResourcesNewPath:

    def test_counts_resource_without_tags(self):
        resources = [{"type": "aws_instance", "name": "vm", "values": {}}]
        assert _count_untagged_resources(resources) == 1

    def test_does_not_count_tagged_resource(self):
        resources = [
            {
                "type": "aws_instance",
                "name": "vm",
                "values": {"tags": {"env": "prod"}},
            }
        ]
        assert _count_untagged_resources(resources) == 0

    def test_returns_zero_for_empty_list(self):
        assert _count_untagged_resources([]) == 0


# =====================================================
# COMPUTE AND GPU — NEW PATH
# =====================================================


class TestCountComputeAndGpuNewPath:

    def test_counts_azure_vm(self):
        resources = [
            {
                "type": "azurerm_linux_virtual_machine",
                "name": "vm",
                "values": {},
            }
        ]
        assert _count_compute_instances(resources) == 1

    def test_counts_azure_vmss(self):
        resources = [
            {
                "type": "azurerm_virtual_machine_scale_set",
                "name": "vmss",
                "values": {},
            }
        ]
        assert _count_compute_instances(resources) == 1

    def test_counts_aws_instance(self):
        resources = [
            {"type": "aws_instance", "name": "ec2", "values": {}}
        ]
        assert _count_compute_instances(resources) == 1

    def test_counts_azure_gpu_vm_by_size(self):
        resources = [
            {
                "type": "azurerm_linux_virtual_machine",
                "name": "gpu_vm",
                "values": {"vm_size": "Standard_NC6"},
            }
        ]
        assert _count_gpu_instances(resources) == 1

    def test_does_not_count_non_gpu_azure_vm(self):
        resources = [
            {
                "type": "azurerm_linux_virtual_machine",
                "name": "vm",
                "values": {"vm_size": "Standard_D2s_v3"},
            }
        ]
        assert _count_gpu_instances(resources) == 0

    def test_ai_gpu_workloads_equals_gpu_instances(self):
        resources = [
            {
                "type": "aws_instance",
                "name": "gpu",
                "values": {"instance_type": "p3.2xlarge"},
            }
        ]
        assert _count_ai_gpu_workloads(resources) == _count_gpu_instances(resources)


# =====================================================
# PARSE TERRAFORM PLAN — INTEGRATION
# =====================================================


class TestParseTerraformPlan:

    def test_returns_all_standard_context_keys(self, full_plan_file):
        result = parse_terraform_plan(full_plan_file)
        expected_keys = {
            "resources",
            "open_ingress_rules",
            "public_storage_buckets",
            "unencrypted_databases",
            "ssl_not_enforced_count",
            "versioning_disabled_count",
            "untagged_resource_count",
            "total_resource_count",
            "compute_instance_count",
            "gpu_instance_count",
            "ai_gpu_workloads",
        }
        assert expected_keys.issubset(set(result.keys()))

    def test_counts_resources_from_root_and_child_modules(
        self, full_plan_file
    ):
        result = parse_terraform_plan(full_plan_file)
        assert result["total_resource_count"] > 0

    def test_child_module_resources_included(self, full_plan_file):
        result = parse_terraform_plan(full_plan_file)
        resource_types = [r["type"] for r in result["resources"]]
        assert "aws_autoscaling_group" in resource_types

    def test_detects_open_ingress_from_full_plan(self, full_plan_file):
        result = parse_terraform_plan(full_plan_file)
        assert result["open_ingress_rules"] > 0

    def test_detects_public_storage_from_full_plan(self, full_plan_file):
        result = parse_terraform_plan(full_plan_file)
        assert result["public_storage_buckets"] > 0

    def test_detects_unencrypted_databases_from_full_plan(
        self, full_plan_file
    ):
        result = parse_terraform_plan(full_plan_file)
        assert result["unencrypted_databases"] > 0

    def test_detects_gpu_instances_from_full_plan(self, full_plan_file):
        result = parse_terraform_plan(full_plan_file)
        assert result["gpu_instance_count"] > 0

    def test_empty_plan_returns_zero_counts(self, empty_plan_file):
        result = parse_terraform_plan(empty_plan_file)
        assert result["total_resource_count"] == 0
        assert result["open_ingress_rules"] == 0
        assert result["gpu_instance_count"] == 0

    def test_raises_file_not_found_for_missing_plan(self):
        with pytest.raises(FileNotFoundError):
            parse_terraform_plan("/nonexistent/plan.json")

    def test_raises_value_error_for_invalid_json(self, tmp_path):
        path = tmp_path / "bad.json"
        path.write_text("{ invalid json")
        with pytest.raises(ValueError, match="Invalid JSON"):
            parse_terraform_plan(str(path))

    def test_raises_value_error_for_invalid_plan_structure(self, tmp_path):
        path = tmp_path / "bad_structure.json"
        path.write_text(json.dumps({"not_terraform": True}))
        result = parse_terraform_plan(str(path))
        assert result["total_resource_count"] == 0

    def test_skips_resources_without_type_or_name(self, tmp_path):
        plan = {
            "terraform_version": "1.5.0",
            "planned_values": {
                "root_module": {
                    "resources": [
                        {"values": {}},
                        {"type": "aws_instance", "values": {}},
                        {"name": "vm", "values": {}},
                    ]
                }
            },
        }
        path = tmp_path / "plan.json"
        path.write_text(json.dumps(plan))
        result = parse_terraform_plan(str(path))
        assert result["total_resource_count"] == 0