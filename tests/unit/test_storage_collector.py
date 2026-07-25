# tests/unit/test_storage_collector.py
#
# Tests for context/observers/collectors/storage_collector.py.
# All Azure SDK calls are mocked — never touches a real
# subscription. Mock shapes match the VERIFIED property names
# confirmed against Microsoft's official Python SDK
# documentation (see storage_collector.py's module docstring).

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from context.observers.base_observer import CloudObserverError
from context.observers.collectors.storage_collector import StorageCollector


def _make_mock_account(
    name: str = "teststorageaccount",
    allow_blob_public_access: bool | None = False,
    public_network_access: str | None = "Disabled",
    minimum_tls_version: str = "TLS1_2",
) -> MagicMock:
    account = MagicMock()
    account.name = name
    account.allow_blob_public_access = allow_blob_public_access
    account.public_network_access = public_network_access
    account.minimum_tls_version = minimum_tls_version
    return account


def _make_mock_blob_service_properties(is_versioning_enabled: bool = True) -> MagicMock:
    props = MagicMock()
    props.is_versioning_enabled = is_versioning_enabled
    return props


class TestStorageCollectorIdentity:
    def test_resource_type_name(self):
        collector = StorageCollector()
        assert collector.resource_type_name == "storage_accounts"

    def test_context_keys_produced(self):
        collector = StorageCollector()
        keys = collector.context_keys_produced
        assert "public_storage_buckets" in keys
        assert "versioning_disabled_count" in keys


class TestStorageCollectorCollection:
    def test_collect_raises_clear_error_without_azure_sdk(self):
        collector = StorageCollector()
        with patch.dict("sys.modules", {"azure.mgmt.storage": None}):
            with pytest.raises(CloudObserverError) as exc_info:
                collector.collect(MagicMock(), "sub-123", "test-rg")
        assert "pip install obsidianwall-verdict[azure]" in str(exc_info.value)

    @patch("azure.mgmt.storage.StorageManagementClient")
    def test_collect_returns_normalized_resources(self, mock_client_class):
        mock_client = MagicMock()
        mock_client.storage_accounts.list_by_resource_group.return_value = [
            _make_mock_account()
        ]
        mock_client.blob_services.get_service_properties.return_value = (
            _make_mock_blob_service_properties()
        )
        mock_client_class.return_value = mock_client

        collector = StorageCollector()
        resources = collector.collect(MagicMock(), "sub-123", "test-rg")

        assert len(resources) == 1
        assert resources[0]["type"] == "azurerm_storage_account"

    @patch("azure.mgmt.storage.StorageManagementClient")
    def test_collect_normalizes_public_access_correctly(self, mock_client_class):
        mock_client = MagicMock()
        mock_client.storage_accounts.list_by_resource_group.return_value = [
            _make_mock_account(allow_blob_public_access=True)
        ]
        mock_client.blob_services.get_service_properties.return_value = (
            _make_mock_blob_service_properties()
        )
        mock_client_class.return_value = mock_client

        collector = StorageCollector()
        resources = collector.collect(MagicMock(), "sub-123", "test-rg")

        assert resources[0]["values"]["allow_blob_public_access"] is True

    @patch("azure.mgmt.storage.StorageManagementClient")
    def test_blob_service_failure_defaults_to_versioning_disabled(
        self, mock_client_class
    ):
        """
        Conservative fail-safe: if the separate blob service
        properties call fails, default to "versioning disabled"
        — never silently treat an unknown state as compliant.
        """
        mock_client = MagicMock()
        mock_client.storage_accounts.list_by_resource_group.return_value = [
            _make_mock_account()
        ]
        mock_client.blob_services.get_service_properties.side_effect = Exception(
            "insufficient permission"
        )
        mock_client_class.return_value = mock_client

        collector = StorageCollector()
        resources = collector.collect(MagicMock(), "sub-123", "test-rg")

        assert resources[0]["values"]["blob_properties"]["versioning_enabled"] is False

    @patch("azure.mgmt.storage.StorageManagementClient")
    def test_listing_failure_raises_clear_error(self, mock_client_class):
        mock_client = MagicMock()
        mock_client.storage_accounts.list_by_resource_group.side_effect = Exception(
            "resource group not found"
        )
        mock_client_class.return_value = mock_client

        collector = StorageCollector()
        with pytest.raises(CloudObserverError) as exc_info:
            collector.collect(MagicMock(), "sub-123", "nonexistent-rg")
        assert "nonexistent-rg" in str(exc_info.value)

    @patch("azure.mgmt.storage.StorageManagementClient")
    def test_empty_resource_group_returns_empty_list(self, mock_client_class):
        mock_client = MagicMock()
        mock_client.storage_accounts.list_by_resource_group.return_value = []
        mock_client_class.return_value = mock_client

        collector = StorageCollector()
        resources = collector.collect(MagicMock(), "sub-123", "empty-rg")

        assert resources == []