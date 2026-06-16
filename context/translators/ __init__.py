
# context/translators/__init__.py
#
# Translation Layer package.
#
# Translators convert infrastructure plan formats into
# the normalized runtime context dict that the governance
# evaluation engine and policy conditions expect.
#
# Available translators:
#   TerraformParser          → Terraform JSON plan
#   CloudFormationParser     → AWS CloudFormation (JSON/YAML)
#
# Planned translators:
#   BicepParser              → Azure Bicep
#   PulumiParser             → Pulumi state
#   CdktfParser              → CDK for Terraform
#
# Auto-detection:
#   is_cloudformation_template() detects CloudFormation
#   templates by file content. context_builder.py uses
#   this to dispatch to the correct parser automatically.

from context.translators.base_translator import BaseTranslator
from context.translators.cloudformation_parser import (
    CloudFormationParser,
    is_cloudformation_template,
    parse_cloudformation_template,
)
from context.translators.terraform_parser import parse_terraform_plan

__all__ = [
    "BaseTranslator",
    "CloudFormationParser",
    "is_cloudformation_template",
    "parse_cloudformation_template",
    "parse_terraform_plan",
]
