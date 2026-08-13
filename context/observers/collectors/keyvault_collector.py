# context/observers/collectors/keyvault_collector.py
#
# Purpose:
# Collects Azure Key Vaults and normalizes them into the
# {type, name, values} shape Terraform's azurerm_key_vault
# resource produces, feeding
# context.translators.terraform_parser.count_versioning_disabled()
# unchanged (soft delete is checked as part of that function's
# integrity-domain logic, alongside storage versioning).
#
# Property verification (Microsoft's official documentation,
# not guessed):
#   - Listing: KeyVaultManagementClient.vaults
#     .list_by_resource_group(resource_group_name=...) —
#     confirmed via Microsoft Learn's official Python code
#     sample and REST API reference.
#   - enable_soft_delete: confirmed attribute name and type
#     (bool, defaults to True) on the VaultProperties model,
#     via Microsoft Learn's official
#     azure.mgmt.keyvault.v2019_09_01.models.VaultProperties
#     documentation.
#   - Nesting: the underlying REST API and CLI query paths
#     (e.g. `az keyvault show --query "properties.enableSoftDelete"`)
#     confirm this lives under a nested properties object, not
#     flat on the top-level Vault resource — consistent with
#     the same ARM convention confirmed for NetworkSecurityGroup.
#     Read via get_sdk_property() for the same defensive
#     handling as NSGCollector, in case of SDK version
#     differences.
#
# NOTE — real behavioral caveat, not a bug in this collector:
# Azure Key Vault soft delete is effectively irreversible in
# practice once enabled (multiple documented cases of Azure
# rejecting attempts to disable it). This collector only READS
# the current state — it has no bearing on whether a given
# vault's soft-delete setting can be changed, only on whether
# it is currently enabled.

from __future__ import annotations

from typing import Any

from context.observers.base_observer import CloudObserverError
from context.observers.collectors.base_collector import (
    ResourceCollector,
    get_sdk_property,
)


class KeyVaultCollector(ResourceCollector):
    """
    Collects Azure Key Vaults. See module docstring for
    verification detail on the observed property.
    """

    @property
    def resource_type_name(self) -> str:
        return "key_vaults"

    @property
    def context_keys_produced(self) -> frozenset[str]:
        return frozenset({"versioning_disabled_count"})

    def collect(
        self, credential: Any, subscription_id: str, scope: str
    ) -> list[dict[str, Any]]:
        try:
            from azure.mgmt.keyvault import KeyVaultManagementClient
        except ImportError as exc:
            raise CloudObserverError(
                "Azure SDK not installed. Install with:\n"
                "  pip install obsidianwall-verdict[azure]"
            ) from exc

        try:
            keyvault_client = KeyVaultManagementClient(credential, subscription_id)
        except Exception as exc:
            raise CloudObserverError(
                f"Failed to create Azure Key Vault client: {exc}"
            ) from exc

        try:
            vaults = list(
                keyvault_client.vaults.list_by_resource_group(resource_group_name=scope)
            )
        except Exception as exc:
            raise CloudObserverError(
                f"Failed to list key vaults in resource group '{scope}': {exc}"
            ) from exc

        return [self._normalize(vault) for vault in vaults]

    @staticmethod
    def _normalize(vault: Any) -> dict[str, Any]:
        vault_name = getattr(vault, "name", "")

        # Defaults to True per Microsoft's documented default —
        # a vault where this genuinely can't be read defaults to
        # the SAFE assumption (soft delete enabled), consistent
        # with this collector's conservative-fail-safe pattern:
        # default toward "compliant" only when that IS the SDK's
        # own documented default, never as a guess.
        soft_delete_enabled = get_sdk_property(
            vault, "enable_soft_delete", default=True
        )

        return {
            "type": "azurerm_key_vault",
            "name": vault_name,
            "values": {
                "soft_delete_enabled": bool(soft_delete_enabled),
            },
        }
