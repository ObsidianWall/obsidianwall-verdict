# tests/unit/test_keyvault_collector.py
#
# Tests for context/observers/collectors/keyvault_collector.py.
# All Azure SDK calls are mocked.

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from context.observers.base_observer import CloudObserverError
from context.observers.collectors.keyvault_collector import KeyVaultCollector


def _make_mock_vault(
    name: str = "test-vault", enable_soft_delete: bool | None = True
) -> MagicMock:
    vault = MagicMock()
    vault.name = name
    vault.enable_soft_delete = enable_soft_delete
    vault.properties = None
    return vault


def _make_mock_vault_nested(
    name: str = "test-vault", enable_soft_delete: bool = True
) -> MagicMock:
    """Nested .properties shape, matching the confirmed ARM
    REST API convention (properties.enableSoftDelete)."""
    vault = MagicMock()
    vault.name = name
    vault.properties.enable_soft_delete = enable_soft_delete
    return vault


class TestKeyVaultCollectorIdentity:
    def test_resource_type_name(self):
        collector = KeyVaultCollector()
        assert collector.resource_type_name == "key_vaults"

    def test_context_keys_produced(self):
        collector = KeyVaultCollector()
        assert "versioning_disabled_count" in collector.context_keys_produced


class TestKeyVaultCollectorCollection:
    def test_collect_raises_clear_error_without_azure_sdk(self):
        collector = KeyVaultCollector()
        with patch.dict("sys.modules", {"azure.mgmt.keyvault": None}):
            with pytest.raises(CloudObserverError) as exc_info:
                collector.collect(MagicMock(), "sub-123", "test-rg")
        assert "pip install obsidianwall-verdict[azure]" in str(exc_info.value)

    @patch("azure.mgmt.keyvault.KeyVaultManagementClient")
    def test_collect_returns_normalized_resources(self, mock_client_class):
        mock_client = MagicMock()
        mock_client.vaults.list_by_resource_group.return_value = [
            _make_mock_vault()
        ]
        mock_client_class.return_value = mock_client

        collector = KeyVaultCollector()
        resources = collector.collect(MagicMock(), "sub-123", "test-rg")

        assert len(resources) == 1
        assert resources[0]["type"] == "azurerm_key_vault"

    @patch("azure.mgmt.keyvault.KeyVaultManagementClient")
    def test_calls_list_by_resource_group_with_correct_kwarg(
        self, mock_client_class
    ):
        """
        Verified via Microsoft's official REST API documentation:
        vaults.list_by_resource_group(resource_group_name=...) —
        keyword argument, not positional, confirmed via the
        real Python code sample.
        """
        mock_client = MagicMock()
        mock_client.vaults.list_by_resource_group.return_value = []
        mock_client_class.return_value = mock_client

        collector = KeyVaultCollector()
        collector.collect(MagicMock(), "sub-123", "test-rg")

        mock_client.vaults.list_by_resource_group.assert_called_once_with(
            resource_group_name="test-rg"
        )

    @patch("azure.mgmt.keyvault.KeyVaultManagementClient")
    def test_soft_delete_enabled_true_normalizes_correctly(self, mock_client_class):
        mock_client = MagicMock()
        mock_client.vaults.list_by_resource_group.return_value = [
            _make_mock_vault(enable_soft_delete=True)
        ]
        mock_client_class.return_value = mock_client

        collector = KeyVaultCollector()
        resources = collector.collect(MagicMock(), "sub-123", "test-rg")

        assert resources[0]["values"]["soft_delete_enabled"] is True

    @patch("azure.mgmt.keyvault.KeyVaultManagementClient")
    def test_soft_delete_disabled_normalizes_correctly(self, mock_client_class):
        mock_client = MagicMock()
        mock_client.vaults.list_by_resource_group.return_value = [
            _make_mock_vault(enable_soft_delete=False)
        ]
        mock_client_class.return_value = mock_client

        collector = KeyVaultCollector()
        resources = collector.collect(MagicMock(), "sub-123", "test-rg")

        assert resources[0]["values"]["soft_delete_enabled"] is False

    @patch("azure.mgmt.keyvault.KeyVaultManagementClient")
    def test_nested_properties_shape_normalizes_correctly(self, mock_client_class):
        """
        The nested .properties.enable_soft_delete shape,
        matching the confirmed ARM REST API convention.
        """
        mock_client = MagicMock()
        mock_client.vaults.list_by_resource_group.return_value = [
            _make_mock_vault_nested(enable_soft_delete=False)
        ]
        mock_client_class.return_value = mock_client

        collector = KeyVaultCollector()
        resources = collector.collect(MagicMock(), "sub-123", "test-rg")

        assert resources[0]["values"]["soft_delete_enabled"] is False

    @patch("azure.mgmt.keyvault.KeyVaultManagementClient")
    def test_missing_property_defaults_to_true(self, mock_client_class):
        """
        Microsoft's documentation confirms enable_soft_delete
        defaults to True. If the value genuinely can't be read,
        default to the SDK's own documented default — not an
        arbitrary guess.
        """
        vault = MagicMock()
        vault.name = "test-vault"
        vault.properties = None
        del vault.enable_soft_delete  # simulate genuinely absent

        mock_client = MagicMock()
        mock_client.vaults.list_by_resource_group.return_value = [vault]
        mock_client_class.return_value = mock_client

        collector = KeyVaultCollector()
        resources = collector.collect(MagicMock(), "sub-123", "test-rg")

        assert resources[0]["values"]["soft_delete_enabled"] is True

    @patch("azure.mgmt.keyvault.KeyVaultManagementClient")
    def test_listing_failure_raises_clear_error(self, mock_client_class):
        mock_client = MagicMock()
        mock_client.vaults.list_by_resource_group.side_effect = Exception(
            "resource group not found"
        )
        mock_client_class.return_value = mock_client

        collector = KeyVaultCollector()
        with pytest.raises(CloudObserverError) as exc_info:
            collector.collect(MagicMock(), "sub-123", "nonexistent-rg")
        assert "nonexistent-rg" in str(exc_info.value)

    @patch("azure.mgmt.keyvault.KeyVaultManagementClient")
    def test_empty_resource_group_returns_empty_list(self, mock_client_class):
        mock_client = MagicMock()
        mock_client.vaults.list_by_resource_group.return_value = []
        mock_client_class.return_value = mock_client

        collector = KeyVaultCollector()
        resources = collector.collect(MagicMock(), "sub-123", "empty-rg")

        assert resources == []

    @patch("azure.mgmt.keyvault.KeyVaultManagementClient")
    def test_end_to_end_matches_count_versioning_disabled(self, mock_client_class):
        """
        Integration check: normalized output must be countable
        by the REAL, unmodified count_versioning_disabled()
        function.
        """
        from context.translators.terraform_parser import count_versioning_disabled

        mock_client = MagicMock()
        mock_client.vaults.list_by_resource_group.return_value = [
            _make_mock_vault(enable_soft_delete=False)
        ]
        mock_client_class.return_value = mock_client

        collector = KeyVaultCollector()
        resources = collector.collect(MagicMock(), "sub-123", "test-rg")

        count = count_versioning_disabled(resources)
        assert count == 1  # soft delete disabled → counted