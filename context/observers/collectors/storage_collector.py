# context/observers/collectors/storage_collector.py
#
# Purpose:
# Collects Azure Storage Account resources and normalizes
# them into the {type, name, values} shape Terraform's
# azurerm_storage_account resource produces.
#
# Property names VERIFIED against Microsoft's official
# Python SDK documentation (azure-mgmt-storage) — see the
# detailed verification notes on each field below. This is
# the same logic that lived directly in AzureObserver before
# the collector refactor; extracted here unchanged so a
# second resource type (NSGs, Key Vault) can be added without
# growing AzureObserver itself.

from __future__ import annotations

from typing import Any

from context.observers.base_observer import CloudObserverError
from context.observers.collectors.base_collector import ResourceCollector


class StorageCollector(ResourceCollector):
    """
    Collects Azure Storage Accounts. See module docstring for
    verification detail on each observed property.
    """

    @property
    def resource_type_name(self) -> str:
        return "storage_accounts"

    @property
    def context_keys_produced(self) -> frozenset[str]:
        return frozenset({"public_storage_buckets", "versioning_disabled_count"})

    def collect(
        self, credential: Any, subscription_id: str, scope: str
    ) -> list[dict[str, Any]]:
        try:
            from azure.mgmt.storage import StorageManagementClient
        except ImportError as exc:
            raise CloudObserverError(
                "Azure SDK not installed. Install with:\n"
                "  pip install obsidianwall-verdict[azure]"
            ) from exc

        try:
            storage_client = StorageManagementClient(credential, subscription_id)
        except Exception as exc:
            raise CloudObserverError(
                f"Failed to create Azure Storage client: {exc}"
            ) from exc

        try:
            accounts = list(
                storage_client.storage_accounts.list_by_resource_group(scope)
            )
        except Exception as exc:
            raise CloudObserverError(
                f"Failed to list storage accounts in resource group "
                f"'{scope}': {exc}"
            ) from exc

        return [
            self._normalize(storage_client, account, scope) for account in accounts
        ]

    @staticmethod
    def _normalize(
        storage_client: Any, account: Any, resource_group: str
    ) -> dict[str, Any]:
        """
        Property verification (Microsoft SDK documentation,
        confirmed):
          - allow_blob_public_access: direct bool attribute
          - public_network_access: direct attribute, string
            enum with exactly two values: 'Enabled' / 'Disabled'
          - minimum_tls_version: direct attribute, string:
            'TLS1_0' / 'TLS1_1' / 'TLS1_2'
          - Blob versioning is NOT a property on the
            StorageAccount object — requires a SEPARATE call
            to blob_services.get_service_properties(), returning
            is_versioning_enabled on the resulting
            BlobServiceProperties object.
        """
        account_name = getattr(account, "name", "")

        allow_public_access = getattr(account, "allow_blob_public_access", None)
        public_network_access = getattr(account, "public_network_access", None)
        min_tls_version = getattr(account, "minimum_tls_version", "TLS1_0")

        # Conservative fail-safe: if the separate blob service
        # properties call fails for any reason, default to
        # "versioning disabled" — never silently treat an
        # unknown state as compliant for a security check.
        versioning_enabled = False
        try:
            blob_service_properties = storage_client.blob_services.get_service_properties(
                resource_group, account_name
            )
            versioning_enabled = bool(
                getattr(blob_service_properties, "is_versioning_enabled", False)
            )
        except Exception:
            pass

        return {
            "type": "azurerm_storage_account",
            "name": account_name,
            "values": {
                "allow_blob_public_access": allow_public_access is True,
                "public_network_access_enabled": (
                    public_network_access == "Enabled"
                ),
                "min_tls_version": str(min_tls_version),
                "blob_properties": {
                    "versioning_enabled": versioning_enabled,
                },
            },
        }