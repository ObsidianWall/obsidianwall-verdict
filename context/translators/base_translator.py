# context/translators/base_translator.py
#
# Purpose:
# Abstract base interface for the Translation Layer.
#
# The Translation Layer converts infrastructure plan
# formats into a normalized runtime context for
# policy evaluation.
#
# This interface documents that terraform_parser.py
# is one implementation of a Translation Layer, not
# a Terraform-specific monolith.
#
# Current implementations:
#   terraform_parser.py       → Terraform JSON plan
#   cloudformation_parser.py  → AWS CloudFormation
#
# Planned implementations:
#   bicep_parser.py           → Azure Bicep
#   pulumi_parser.py          → Pulumi state
#   cdktf_parser.py           → CDK for Terraform
#
# Contract:
#   Every translator must accept a plan file path
#   and return a normalized context dict containing
#   the standard keys that the evaluation engine
#   and policy conditions expect.
#
# Standard context keys (all translators must produce):
#   resources                 list[dict]  — parsed resources
#   open_ingress_rules        int         — security domain
#   public_storage_buckets    int         — security domain
#   unencrypted_databases     int         — security domain
#   ssl_not_enforced_count    int         — security domain (transmission)
#   versioning_disabled_count int         — security domain (integrity)
#   untagged_resource_count   int         — compliance domain
#   total_resource_count      int         — compliance domain
#   compute_instance_count    int         — resource_limits domain
#   gpu_instance_count        int         — resource_limits domain
#   ai_gpu_workloads          int         — ai_governance domain

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class BaseTranslator(ABC):
    """
    Abstract base class for Translation Layer implementations.

    Subclass this to add support for a new infrastructure
    plan format. Implement parse() to return a normalized
    context dict.

    All context dicts must contain the standard keys
    listed in this module's header comment.
    """

    @abstractmethod
    def parse(self, plan_path: str) -> dict[str, Any]:
        """
        Parse an infrastructure plan file and return
        a normalized runtime context dict.

        Args:
            plan_path: absolute or relative path to
                       the plan file

        Returns:
            normalized context dict containing all
            standard context keys

        Raises:
            FileNotFoundError: if plan_path does not exist
            ValueError:        if plan format is invalid
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} must implement parse()"
        )

    @property
    @abstractmethod
    def plan_format(self) -> str:
        """
        Human-readable name of the plan format
        this translator handles.

        Examples: "terraform_json", "cloudformation",
                  "bicep", "pulumi"
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} must implement plan_format"
        )

    @property
    @abstractmethod
    def supported_extensions(self) -> tuple[str, ...]:
        """
        File extensions this translator can handle.

        Examples: (".json",), (".yaml", ".yml")
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} must implement supported_extensions"
        )

    def _empty_context(self) -> dict[str, Any]:
        """
        Return an empty normalized context with all
        standard keys set to safe defaults.

        Subclasses may use this as a starting point
        and override only the keys they detect.
        """
        return {
            "resources":                 [],
            "open_ingress_rules":        0,
            "public_storage_buckets":    0,
            "unencrypted_databases":     0,
            "ssl_not_enforced_count":    0,
            "versioning_disabled_count": 0,
            "untagged_resource_count":   0,
            "total_resource_count":      0,
            "compute_instance_count":    0,
            "gpu_instance_count":        0,
            "ai_gpu_workloads":          0,
        }
