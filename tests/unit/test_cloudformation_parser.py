# tests/unit/test_cloudformation_parser.py
#
# Test suite for context/translators/cloudformation_parser.py
#
# Covers:
# - Auto-detection (is_cloudformation_template)
# - Resource extraction (_extract_resources)
# - All security context extraction functions
# - Compliance and resource limit extraction
# - CloudFormationParser.parse() integration
# - parse_cloudformation_template() convenience function
# - Error handling (file not found, invalid JSON, invalid YAML)

import json

import pytest
import yaml

from context.translators.cloudformation_parser import (
    CloudFormationParser,
    _count_ai_gpu_workloads,
    _count_compute_instances,
    _count_gpu_instances,
    _count_open_ingress_rules,
    _count_public_storage,
    _count_ssl_not_enforced,
    _count_unencrypted_databases,
    _count_untagged_resources,
    _count_versioning_disabled,
    _extract_resources,
    is_cloudformation_template,
    parse_cloudformation_template,
)


# =====================================================
# FIXTURES
# =====================================================


@pytest.fixture
def cloudformation_json_template(tmp_path):
    """Write a minimal CloudFormation JSON template to disk."""
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "MyBucket": {
                "Type": "AWS::S3::Bucket",
                "Properties": {
                    "BucketName": "test-bucket",
                },
            }
        },
    }
    path = tmp_path / "template.json"
    path.write_text(json.dumps(template))
    return str(path)


@pytest.fixture
def cloudformation_yaml_template(tmp_path):
    """Write a minimal CloudFormation YAML template to disk."""
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "MyBucket": {
                "Type": "AWS::S3::Bucket",
                "Properties": {
                    "BucketName": "test-bucket",
                },
            }
        },
    }
    path = tmp_path / "template.yaml"
    path.write_text(yaml.dump(template))
    return str(path)


@pytest.fixture
def terraform_plan_file(tmp_path):
    """Write a minimal Terraform plan JSON to disk."""
    plan = {
        "terraform_version": "1.5.0",
        "planned_values": {
            "root_module": {
                "resources": []
            }
        },
    }
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(plan))
    return str(path)


# =====================================================
# AUTO-DETECTION
# =====================================================


class TestIsCloudFormationTemplate:

    def test_detects_json_template_by_version_key(self, cloudformation_json_template):
        assert is_cloudformation_template(cloudformation_json_template) is True

    def test_detects_yaml_template_by_version_key(self, cloudformation_yaml_template):
        assert is_cloudformation_template(cloudformation_yaml_template) is True

    def test_rejects_terraform_plan(self, terraform_plan_file):
        assert is_cloudformation_template(terraform_plan_file) is False

    def test_returns_false_for_nonexistent_file(self):
        assert is_cloudformation_template("/nonexistent/path.yaml") is False

    def test_detects_template_by_aws_resource_types(self, tmp_path):
        template = {
            "Resources": {
                "MyInstance": {
                    "Type": "AWS::EC2::Instance",
                    "Properties": {"InstanceType": "t3.micro"},
                }
            }
        }
        path = tmp_path / "template.yaml"
        path.write_text(yaml.dump(template))
        assert is_cloudformation_template(str(path)) is True

    def test_returns_false_for_invalid_yaml(self, tmp_path):
        path = tmp_path / "broken.yaml"
        path.write_text("{ invalid yaml: [[[")
        assert is_cloudformation_template(str(path)) is False

    def test_returns_false_for_empty_file(self, tmp_path):
        path = tmp_path / "empty.yaml"
        path.write_text("")
        assert is_cloudformation_template(str(path)) is False


# =====================================================
# RESOURCE EXTRACTION
# =====================================================


class TestExtractResources:

    def test_extracts_known_resource_type(self):
        template = {
            "Resources": {
                "MyInstance": {
                    "Type": "AWS::EC2::Instance",
                    "Properties": {"InstanceType": "t3.micro"},
                }
            }
        }
        resources = _extract_resources(template)
        assert len(resources) == 1
        assert resources[0]["type"] == "aws_instance"
        assert resources[0]["name"] == "MyInstance"

    def test_normalizes_unknown_type_to_cf_type(self):
        template = {
            "Resources": {
                "MyCustom": {
                    "Type": "AWS::Custom::Resource",
                    "Properties": {},
                }
            }
        }
        resources = _extract_resources(template)
        assert resources[0]["type"] == "AWS::Custom::Resource"

    def test_normalizes_tags_list_to_dict(self):
        template = {
            "Resources": {
                "MyBucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {
                        "Tags": [
                            {"Key": "env", "Value": "prod"},
                            {"Key": "team", "Value": "platform"},
                        ]
                    },
                }
            }
        }
        resources = _extract_resources(template)
        assert resources[0]["values"]["tags"] == {
            "env": "prod",
            "team": "platform",
        }

    def test_returns_empty_list_for_missing_resources(self):
        assert _extract_resources({}) == []

    def test_returns_empty_list_for_non_dict_resources(self):
        assert _extract_resources({"Resources": []}) == []

    def test_skips_resource_without_type(self):
        template = {
            "Resources": {
                "BadResource": {
                    "Properties": {},
                }
            }
        }
        assert _extract_resources(template) == []

    def test_preserves_original_cf_type(self):
        template = {
            "Resources": {
                "MyInstance": {
                    "Type": "AWS::EC2::Instance",
                    "Properties": {},
                }
            }
        }
        resources = _extract_resources(template)
        assert resources[0]["_cf_type"] == "AWS::EC2::Instance"


# =====================================================
# OPEN INGRESS RULES
# =====================================================


class TestCountOpenIngressRules:

    def test_counts_open_security_group_ingress(self):
        resources = [
            {
                "type": "aws_security_group",
                "name": "sg",
                "values": {
                    "SecurityGroupIngress": [
                        {"CidrIp": "0.0.0.0/0", "IpProtocol": "tcp"}
                    ]
                },
            }
        ]
        assert _count_open_ingress_rules(resources) == 1

    def test_counts_open_ipv6_ingress(self):
        resources = [
            {
                "type": "aws_security_group",
                "name": "sg",
                "values": {
                    "SecurityGroupIngress": [
                        {"CidrIpv6": "::/0", "IpProtocol": "tcp"}
                    ]
                },
            }
        ]
        assert _count_open_ingress_rules(resources) == 1

    def test_ignores_restricted_ingress(self):
        resources = [
            {
                "type": "aws_security_group",
                "name": "sg",
                "values": {
                    "SecurityGroupIngress": [
                        {"CidrIp": "10.0.0.0/8", "IpProtocol": "tcp"}
                    ]
                },
            }
        ]
        assert _count_open_ingress_rules(resources) == 0

    def test_counts_open_standalone_ingress_rule(self):
        resources = [
            {
                "type": "aws_vpc_security_group_ingress_rule",
                "name": "rule",
                "values": {"CidrIp": "0.0.0.0/0"},
            }
        ]
        assert _count_open_ingress_rules(resources) == 1

    def test_returns_zero_with_no_security_resources(self):
        assert _count_open_ingress_rules([]) == 0


# =====================================================
# PUBLIC STORAGE
# =====================================================


class TestCountPublicStorage:

    def test_counts_bucket_without_public_access_block(self):
        resources = [
            {
                "type": "aws_s3_bucket",
                "name": "bucket",
                "values": {},
            }
        ]
        assert _count_public_storage(resources) == 1

    def test_counts_bucket_with_partial_block(self):
        resources = [
            {
                "type": "aws_s3_bucket",
                "name": "bucket",
                "values": {
                    "PublicAccessBlockConfiguration": {
                        "BlockPublicAcls": True,
                        "BlockPublicPolicy": False,
                        "IgnorePublicAcls": True,
                        "RestrictPublicBuckets": True,
                    }
                },
            }
        ]
        assert _count_public_storage(resources) == 1

    def test_does_not_count_fully_blocked_bucket(self):
        resources = [
            {
                "type": "aws_s3_bucket",
                "name": "bucket",
                "values": {
                    "PublicAccessBlockConfiguration": {
                        "BlockPublicAcls": True,
                        "BlockPublicPolicy": True,
                        "IgnorePublicAcls": True,
                        "RestrictPublicBuckets": True,
                    }
                },
            }
        ]
        assert _count_public_storage(resources) == 0

    def test_returns_zero_with_no_storage(self):
        assert _count_public_storage([]) == 0


# =====================================================
# UNENCRYPTED DATABASES
# =====================================================


class TestCountUnencryptedDatabases:

    def test_counts_unencrypted_rds_instance(self):
        resources = [
            {
                "type": "aws_db_instance",
                "name": "db",
                "values": {"StorageEncrypted": False},
            }
        ]
        assert _count_unencrypted_databases(resources) == 1

    def test_does_not_count_encrypted_rds(self):
        resources = [
            {
                "type": "aws_db_instance",
                "name": "db",
                "values": {"StorageEncrypted": True},
            }
        ]
        assert _count_unencrypted_databases(resources) == 0

    def test_counts_dynamodb_without_sse(self):
        resources = [
            {
                "type": "aws_dynamodb_table",
                "name": "table",
                "values": {"SSESpecification": {"SSEEnabled": False}},
            }
        ]
        assert _count_unencrypted_databases(resources) == 1

    def test_does_not_count_dynamodb_with_sse(self):
        resources = [
            {
                "type": "aws_dynamodb_table",
                "name": "table",
                "values": {"SSESpecification": {"SSEEnabled": True}},
            }
        ]
        assert _count_unencrypted_databases(resources) == 0

    def test_counts_elasticache_without_encryption(self):
        resources = [
            {
                "type": "aws_elasticache_replication_group",
                "name": "cache",
                "values": {"AtRestEncryptionEnabled": False},
            }
        ]
        assert _count_unencrypted_databases(resources) == 1

    def test_counts_redshift_without_encryption(self):
        resources = [
            {
                "type": "aws_redshift_cluster",
                "name": "cluster",
                "values": {"Encrypted": False},
            }
        ]
        assert _count_unencrypted_databases(resources) == 1


# =====================================================
# SSL NOT ENFORCED
# =====================================================


class TestCountSslNotEnforced:

    def test_counts_http_load_balancer_listener(self):
        resources = [
            {
                "type": "aws_lb_listener",
                "name": "listener",
                "values": {"Protocol": "HTTP"},
            }
        ]
        assert _count_ssl_not_enforced(resources) == 1

    def test_does_not_count_https_listener(self):
        resources = [
            {
                "type": "aws_lb_listener",
                "name": "listener",
                "values": {"Protocol": "HTTPS"},
            }
        ]
        assert _count_ssl_not_enforced(resources) == 0

    def test_counts_elasticache_without_transit_encryption(self):
        resources = [
            {
                "type": "aws_elasticache_replication_group",
                "name": "cache",
                "values": {"TransitEncryptionEnabled": False},
            }
        ]
        assert _count_ssl_not_enforced(resources) == 1

    def test_does_not_count_elasticache_with_transit_encryption(self):
        resources = [
            {
                "type": "aws_elasticache_replication_group",
                "name": "cache",
                "values": {"TransitEncryptionEnabled": True},
            }
        ]
        assert _count_ssl_not_enforced(resources) == 0

    def test_counts_publicly_accessible_rds(self):
        resources = [
            {
                "type": "aws_db_instance",
                "name": "db",
                "values": {"PubliclyAccessible": True},
            }
        ]
        assert _count_ssl_not_enforced(resources) == 1

    def test_counts_cloudfront_allowing_http(self):
        resources = [
            {
                "type": "aws_cloudfront_distribution",
                "name": "cdn",
                "values": {
                    "DefaultCacheBehavior": {
                        "ViewerProtocolPolicy": "allow-all"
                    }
                },
            }
        ]
        assert _count_ssl_not_enforced(resources) == 1

    def test_does_not_count_cloudfront_https_only(self):
        resources = [
            {
                "type": "aws_cloudfront_distribution",
                "name": "cdn",
                "values": {
                    "DefaultCacheBehavior": {
                        "ViewerProtocolPolicy": "https-only"
                    }
                },
            }
        ]
        assert _count_ssl_not_enforced(resources) == 0

    def test_returns_zero_with_no_resources(self):
        assert _count_ssl_not_enforced([]) == 0


# =====================================================
# VERSIONING DISABLED
# =====================================================


class TestCountVersioningDisabled:

    def test_counts_s3_without_versioning(self):
        resources = [
            {
                "type": "aws_s3_bucket",
                "name": "bucket",
                "values": {
                    "VersioningConfiguration": {"Status": "Suspended"}
                },
            }
        ]
        assert _count_versioning_disabled(resources) == 1

    def test_does_not_count_s3_with_versioning_enabled(self):
        resources = [
            {
                "type": "aws_s3_bucket",
                "name": "bucket",
                "values": {
                    "VersioningConfiguration": {"Status": "Enabled"}
                },
            }
        ]
        assert _count_versioning_disabled(resources) == 0

    def test_counts_dynamodb_without_pitr(self):
        resources = [
            {
                "type": "aws_dynamodb_table",
                "name": "table",
                "values": {
                    "PointInTimeRecoverySpecification": {
                        "PointInTimeRecoveryEnabled": False
                    }
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
                    "PointInTimeRecoverySpecification": {
                        "PointInTimeRecoveryEnabled": True
                    }
                },
            }
        ]
        assert _count_versioning_disabled(resources) == 0

    def test_returns_zero_with_no_storage(self):
        assert _count_versioning_disabled([]) == 0


# =====================================================
# UNTAGGED RESOURCES
# =====================================================


class TestCountUntaggedResources:

    def test_counts_resource_without_tags(self):
        resources = [
            {"type": "aws_instance", "name": "vm", "values": {}}
        ]
        assert _count_untagged_resources(resources) == 1

    def test_does_not_count_resource_with_tags(self):
        resources = [
            {
                "type": "aws_instance",
                "name": "vm",
                "values": {"tags": {"env": "prod"}},
            }
        ]
        assert _count_untagged_resources(resources) == 0

    def test_counts_mixed_tagged_and_untagged(self):
        resources = [
            {"type": "aws_instance", "name": "vm1", "values": {}},
            {
                "type": "aws_instance",
                "name": "vm2",
                "values": {"tags": {"env": "prod"}},
            },
        ]
        assert _count_untagged_resources(resources) == 1


# =====================================================
# COMPUTE INSTANCES
# =====================================================


class TestCountComputeInstances:

    def test_counts_ec2_instance(self):
        resources = [
            {"type": "aws_instance", "name": "vm", "values": {}}
        ]
        assert _count_compute_instances(resources) == 1

    def test_counts_autoscaling_group(self):
        resources = [
            {"type": "aws_autoscaling_group", "name": "asg", "values": {}}
        ]
        assert _count_compute_instances(resources) == 1

    def test_does_not_count_non_compute_resources(self):
        resources = [
            {"type": "aws_s3_bucket", "name": "bucket", "values": {}}
        ]
        assert _count_compute_instances(resources) == 0

    def test_returns_zero_for_empty_list(self):
        assert _count_compute_instances([]) == 0


# =====================================================
# GPU INSTANCES
# =====================================================


class TestCountGpuInstances:

    def test_counts_p3_gpu_instance(self):
        resources = [
            {
                "type": "aws_instance",
                "name": "gpu",
                "values": {"InstanceType": "p3.2xlarge"},
            }
        ]
        assert _count_gpu_instances(resources) == 1

    def test_counts_g4dn_gpu_instance(self):
        resources = [
            {
                "type": "aws_instance",
                "name": "gpu",
                "values": {"InstanceType": "g4dn.xlarge"},
            }
        ]
        assert _count_gpu_instances(resources) == 1

    def test_does_not_count_non_gpu_instance(self):
        resources = [
            {
                "type": "aws_instance",
                "name": "web",
                "values": {"InstanceType": "t3.medium"},
            }
        ]
        assert _count_gpu_instances(resources) == 0

    def test_ai_gpu_workloads_matches_gpu_instances(self):
        resources = [
            {
                "type": "aws_instance",
                "name": "gpu",
                "values": {"InstanceType": "p3.2xlarge"},
            }
        ]
        assert _count_ai_gpu_workloads(resources) == _count_gpu_instances(resources)


# =====================================================
# PARSER INTEGRATION
# =====================================================


class TestCloudFormationParserIntegration:

    def test_parse_returns_all_standard_context_keys(self, tmp_path):
        template = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "MyBucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {},
                }
            },
        }
        path = tmp_path / "template.json"
        path.write_text(json.dumps(template))

        result = CloudFormationParser().parse(str(path))

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

    def test_parse_counts_resources_correctly(self, tmp_path):
        template = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Bucket1": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {},
                },
                "Bucket2": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {},
                },
            },
        }
        path = tmp_path / "template.json"
        path.write_text(json.dumps(template))

        result = CloudFormationParser().parse(str(path))
        assert result["total_resource_count"] == 2

    def test_parse_raises_for_missing_file(self):
        with pytest.raises(FileNotFoundError):
            CloudFormationParser().parse("/nonexistent/template.json")

    def test_parse_raises_for_invalid_json(self, tmp_path):
        path = tmp_path / "bad.json"
        path.write_text("{ invalid json [[[")
        with pytest.raises(ValueError, match="Invalid JSON"):
            CloudFormationParser().parse(str(path))

    def test_parse_raises_for_invalid_yaml(self, tmp_path):
        path = tmp_path / "bad.yaml"
        path.write_text("{ invalid yaml: [[[")
        with pytest.raises(ValueError):
            CloudFormationParser().parse(str(path))

    def test_convenience_function_matches_parser(self, tmp_path):
        template = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "MyBucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {},
                }
            },
        }
        path = tmp_path / "template.json"
        path.write_text(json.dumps(template))

        parser_result = CloudFormationParser().parse(str(path))
        convenience_result = parse_cloudformation_template(str(path))
        assert parser_result == convenience_result

    def test_plan_format_property(self):
        assert CloudFormationParser().plan_format == "cloudformation"

    def test_supported_extensions_property(self):
        extensions = CloudFormationParser().supported_extensions
        assert ".json" in extensions
        assert ".yaml" in extensions
        assert ".yml" in extensions