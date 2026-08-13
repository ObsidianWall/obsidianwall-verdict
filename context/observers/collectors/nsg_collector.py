# context/observers/collectors/nsg_collector.py
#
# Purpose:
# Collects Azure Network Security Groups and normalizes them
# into the {type, name, values} shape Terraform's
# azurerm_network_security_group resource produces, feeding
# context.translators.terraform_parser.count_open_ingress_rules()
# unchanged.
#
# Property verification (Microsoft's official documentation,
# corrected after an initial misreading — see note below):
#   - Listing: NetworkManagementClient.network_security_groups
#     .list(resource_group_name) — confirmed via Microsoft
#     Learn's official Python code sample and the
#     NetworkSecurityGroupsOperations class reference.
#   - SecurityRule's own fields (direction, access,
#     source_address_prefix) are CONFIRMED FLAT direct
#     attributes — verified directly against the current
#     (Dec 2025) official Microsoft Learn model documentation
#     for azure.mgmt.network.models.SecurityRule, which lists
#     them plainly in both the constructor and the class's
#     Variables table, no .properties nesting involved.
#     An earlier version of this file cited a PyPI changelog
#     entry as confirming these fields moved under a nested
#     .properties object — that was a real mistake, conflating
#     the ARM REST API's wire-format JSON nesting (which IS
#     real — every ARM resource wraps its fields under a
#     "properties" key in raw JSON) with the Python SDK's
#     object model, which flattens that nesting for direct
#     attribute access. Corrected after being caught in review.
#   - What remains genuinely UNCONFIRMED: whether
#     NetworkSecurityGroup.security_rules (the LIST itself,
#     as opposed to fields on each individual rule) sits flat
#     on the NSG object or under nsg.properties.security_rules.
#     This is a separate question from the one above — a
#     container's own nesting is independent of whether items
#     inside it are nested. Rather than guess, every field
#     read here goes through get_sdk_property(), which checks
#     .properties first and falls back to the flat attribute —
#     correct regardless of which shape turns out to be true,
#     without needing to resolve the uncertainty first.
#
# Terraform key naming note:
# terraform_parser.py's count_open_ingress_rules() reads
# values.get("security_rule", []) — SINGULAR "security_rule",
# matching Terraform's azurerm_network_security_group resource
# schema (a repeated inline block named "security_rule"). This
# is DIFFERENT from the Azure SDK's own plural attribute name
# ("security_rules") — the normalized output below deliberately
# uses the singular Terraform-convention key so the existing
# counting function works unchanged.

from __future__ import annotations

from typing import Any

from context.observers.base_observer import CloudObserverError
from context.observers.collectors.base_collector import (
    ResourceCollector,
    get_sdk_property,
)


class NSGCollector(ResourceCollector):
    """
    Collects Azure Network Security Groups. See module
    docstring for verification detail on each observed
    property, including the version-dependent .properties
    nesting this collector handles defensively.
    """

    @property
    def resource_type_name(self) -> str:
        return "network_security_groups"

    @property
    def context_keys_produced(self) -> frozenset[str]:
        return frozenset({"open_ingress_rules"})

    def collect(
        self, credential: Any, subscription_id: str, scope: str
    ) -> list[dict[str, Any]]:
        try:
            from azure.mgmt.network import NetworkManagementClient
        except ImportError as exc:
            raise CloudObserverError(
                "Azure SDK not installed. Install with:\n"
                "  pip install obsidianwall-verdict[azure]"
            ) from exc

        try:
            network_client = NetworkManagementClient(credential, subscription_id)
        except Exception as exc:
            raise CloudObserverError(
                f"Failed to create Azure Network client: {exc}"
            ) from exc

        try:
            nsgs = list(network_client.network_security_groups.list(scope))
        except Exception as exc:
            raise CloudObserverError(
                f"Failed to list network security groups in resource "
                f"group '{scope}': {exc}"
            ) from exc

        return [self._normalize(nsg) for nsg in nsgs]

    @staticmethod
    def _normalize(nsg: Any) -> dict[str, Any]:
        nsg_name = getattr(nsg, "name", "")

        raw_rules = get_sdk_property(nsg, "security_rules", default=[])
        if raw_rules is None:
            raw_rules = []

        normalized_rules: list[dict[str, Any]] = []
        for rule in raw_rules:
            normalized_rules.append(
                {
                    "direction": get_sdk_property(rule, "direction", default=""),
                    "access": get_sdk_property(rule, "access", default=""),
                    "source_address_prefix": get_sdk_property(
                        rule, "source_address_prefix", default=""
                    ),
                }
            )

        return {
            "type": "azurerm_network_security_group",
            "name": nsg_name,
            "values": {
                # Deliberately SINGULAR "security_rule" to match
                # Terraform's schema — see module docstring.
                "security_rule": normalized_rules,
            },
        }
