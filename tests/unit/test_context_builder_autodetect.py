# tests/unit/test_context_builder_autodetect.py
#
# Test suite for the auto-detection logic in
# context/context_builder.py
#
# Covers:
# - _parse_plan() dispatches to CloudFormationParser
#   when given a CloudFormation template
# - _parse_plan() dispatches to parse_terraform_plan
#   when given a Terraform plan
# - build_context() returns all expected context keys

import json
from unittest.mock import MagicMock, patch

import pytest
import yaml

from context.context_builder import _parse_plan, build_context


# =====================================================
# FIXTURES
# =====================================================


@pytest.fixture
def cloudformation_template_file(tmp_path):
    """Write a minimal CloudFormation template to disk."""
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "MyBucket": {
                "Type": "AWS::S3::Bucket",
                "Properties": {},
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
# AUTO-DETECTION DISPATCH
# =====================================================


class TestParsePlanAutoDetect:

    def test_dispatches_to_cloudformation_for_cf_template(
        self, cloudformation_template_file
    ):
        with patch(
            "context.context_builder.CloudFormationParser"
        ) as mock_cf_parser_class:
            mock_parser = MagicMock()
            mock_parser.parse.return_value = {
                "resources": [],
                "open_ingress_rules": 0,
                "public_storage_buckets": 1,
                "unencrypted_databases": 0,
                "ssl_not_enforced_count": 0,
                "versioning_disabled_count": 0,
                "untagged_resource_count": 0,
                "total_resource_count": 1,
                "compute_instance_count": 0,
                "gpu_instance_count": 0,
                "ai_gpu_workloads": 0,
            }
            mock_cf_parser_class.return_value = mock_parser

            with patch(
                "context.context_builder.is_cloudformation_template",
                return_value=True,
            ):
                result = _parse_plan(cloudformation_template_file)

            mock_parser.parse.assert_called_once_with(
                cloudformation_template_file
            )
            assert result["public_storage_buckets"] == 1

    def test_dispatches_to_terraform_for_terraform_plan(
        self, terraform_plan_file
    ):
        with patch(
            "context.context_builder.is_cloudformation_template",
            return_value=False,
        ):
            with patch(
                "context.context_builder.parse_terraform_plan"
            ) as mock_tf_parser:
                mock_tf_parser.return_value = {
                    "resources": [],
                    "open_ingress_rules": 0,
                    "public_storage_buckets": 0,
                    "unencrypted_databases": 0,
                    "ssl_not_enforced_count": 0,
                    "versioning_disabled_count": 0,
                    "untagged_resource_count": 0,
                    "total_resource_count": 0,
                    "compute_instance_count": 0,
                    "gpu_instance_count": 0,
                    "ai_gpu_workloads": 0,
                }
                result = _parse_plan(terraform_plan_file)

            mock_tf_parser.assert_called_once_with(terraform_plan_file)
            assert result["total_resource_count"] == 0


# =====================================================
# BUILD CONTEXT
# =====================================================


class TestBuildContext:

    def test_build_context_returns_all_expected_keys(
        self, terraform_plan_file
    ):
        with patch(
            "context.context_builder.is_cloudformation_template",
            return_value=False,
        ):
            with patch(
                "context.context_builder.parse_terraform_plan"
            ) as mock_tf_parser:
                with patch(
                    "context.context_builder.estimate_cost"
                ) as mock_cost:
                    mock_tf_parser.return_value = {
                        "resources": [],
                        "open_ingress_rules": 0,
                        "public_storage_buckets": 0,
                        "unencrypted_databases": 0,
                        "ssl_not_enforced_count": 0,
                        "versioning_disabled_count": 0,
                        "untagged_resource_count": 0,
                        "total_resource_count": 0,
                        "compute_instance_count": 0,
                        "gpu_instance_count": 0,
                        "ai_gpu_workloads": 0,
                    }
                    mock_cost.return_value = {
                        "estimated_cost": 50.0,
                        "cost_breakdown": {},
                    }

                    result = build_context(
                        plan_path=terraform_plan_file,
                        current_spend=10.0,
                        pricing_mode="table",
                        region="eastus",
                    )

        assert result["estimated_cost"] == 50.0
        assert result["current_spend"] == 10.0
        assert result["pricing_mode"] == "table"
        assert "open_ingress_rules" in result
        assert "ssl_not_enforced_count" in result
        assert "versioning_disabled_count" in result

    def test_build_context_passes_current_spend_through(
        self, terraform_plan_file
    ):
        with patch(
            "context.context_builder.is_cloudformation_template",
            return_value=False,
        ):
            with patch(
                "context.context_builder.parse_terraform_plan"
            ) as mock_tf_parser:
                with patch(
                    "context.context_builder.estimate_cost"
                ) as mock_cost:
                    mock_tf_parser.return_value = {
                        "resources": [],
                        "open_ingress_rules": 0,
                        "public_storage_buckets": 0,
                        "unencrypted_databases": 0,
                        "ssl_not_enforced_count": 0,
                        "versioning_disabled_count": 0,
                        "untagged_resource_count": 0,
                        "total_resource_count": 0,
                        "compute_instance_count": 0,
                        "gpu_instance_count": 0,
                        "ai_gpu_workloads": 0,
                    }
                    mock_cost.return_value = {
                        "estimated_cost": 0.0,
                        "cost_breakdown": {},
                    }

                    result = build_context(
                        plan_path=terraform_plan_file,
                        current_spend=75.0,
                    )

        assert result["current_spend"] == 75.0