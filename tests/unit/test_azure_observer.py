# tests/unit/test_azure_observer.py
#
# Tests for context/observers/azure_observer.py — orchestration
# only. StorageCollector's own collection/normalization logic
# is tested separately in test_storage_collector.py. These
# tests mock at the collector level, not the Azure SDK level,
# since AzureObserver's job is delegation, not collection.

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from context.observers.azure_observer import AzureObserver
from context.observers.base_observer import CloudObserverError


def _make_mock_collector(
    resource_type_name: str = "storage_accounts",
    context_keys: frozenset[str] = frozenset(
        {"public_storage_buckets", "versioning_disabled_count"}
    ),
    collect_return: list[dict] | None = None,
) -> MagicMock:
    collector = MagicMock()
    collector.resource_type_name = resource_type_name
    collector.context_keys_produced = context_keys
    collector.collect.return_value = collect_return or []
    return collector


class TestAzureObserverIdentity:
    def test_provider_name_is_azure(self):
        observer = AzureObserver(subscription_id="sub-123")
        assert observer.provider_name == "azure"

    def test_has_three_collectors_by_default(self):
        observer = AzureObserver(subscription_id="sub-123")
        registered_types = {c.resource_type_name for c in observer.collectors}
        assert registered_types == {
            "storage_accounts",
            "network_security_groups",
            "key_vaults",
        }


class TestAzureObserverCapabilities:
    def test_capabilities_reflect_all_registered_collectors(self):
        observer = AzureObserver(subscription_id="sub-123")
        caps = observer.capabilities
        assert caps["storage_security"] is True
        assert caps["network_security"] is True
        assert caps["secrets_management"] is True
        assert caps["database_security"] is False  # no SQL collector yet
        assert caps["compute_sizing"] is False       # no compute collector yet

    def test_capabilities_checked_by_collector_registration_not_shared_keys(self):
        """
        versioning_disabled_count is produced by BOTH
        StorageCollector and KeyVaultCollector — capabilities
        must be determined by which COLLECTOR is registered,
        not by inferring from that shared key's mere presence,
        which would be ambiguous about which domain it reflects.
        """
        observer = AzureObserver(subscription_id="sub-123")
        # Remove KeyVaultCollector, keep Storage (still produces
        # versioning_disabled_count on its own)
        observer.collectors = [
            c for c in observer.collectors
            if c.resource_type_name != "key_vaults"
        ]

        caps = observer.capabilities

        assert caps["secrets_management"] is False
        assert caps["storage_security"] is True  # unaffected

    def test_capabilities_expand_when_collector_added(self):
        """
        Proves the orchestration design actually works: adding
        a collector automatically expands capabilities, with
        NO changes needed to AzureObserver itself.
        """
        observer = AzureObserver(subscription_id="sub-123")
        observer.collectors = []  # start empty
        fake_nsg_collector = _make_mock_collector(
            resource_type_name="network_security_groups",
            context_keys=frozenset({"open_ingress_rules"}),
        )
        observer.collectors.append(fake_nsg_collector)

        caps = observer.capabilities
        assert caps["network_security"] is True
        assert caps["storage_security"] is False  # not registered in this test


class TestAzureObserverAuthentication:
    def test_authenticate_raises_clear_error_without_azure_sdk(self):
        observer = AzureObserver(subscription_id="sub-123")
        with patch.dict("sys.modules", {"azure.identity": None}):
            with pytest.raises(CloudObserverError) as exc_info:
                observer.authenticate()
        assert "pip install obsidianwall-verdict[azure]" in str(exc_info.value)

    def test_observe_raises_if_not_authenticated(self):
        observer = AzureObserver(subscription_id="sub-123")
        with pytest.raises(CloudObserverError) as exc_info:
            observer.observe("test-rg")
        assert "authenticate()" in str(exc_info.value)


class TestAzureObserverOrchestration:
    def test_observe_delegates_to_all_registered_collectors(self):
        observer = AzureObserver(subscription_id="sub-123")
        observer._credential = MagicMock()  # bypass real authenticate()

        mock_collector = _make_mock_collector(
            collect_return=[
                {
                    "type": "azurerm_storage_account",
                    "name": "acct1",
                    "values": {
                        "allow_blob_public_access": True,
                        "public_network_access_enabled": False,
                        "min_tls_version": "TLS1_2",
                        "blob_properties": {"versioning_enabled": False},
                    },
                }
            ]
        )
        observer.collectors = [mock_collector]

        context = observer.observe("test-rg")

        mock_collector.collect.assert_called_once_with(
            observer._credential, "sub-123", "test-rg"
        )
        assert len(context["resources"]) == 1

    def test_observe_only_includes_keys_from_registered_collectors(self):
        """
        The core sufficiency-check guarantee: a context key
        must be ABSENT, never fabricated as zero, if no
        registered collector actually produces it.
        """
        observer = AzureObserver(subscription_id="sub-123")
        observer._credential = MagicMock()

        # A collector that only produces public_storage_buckets,
        # NOT versioning_disabled_count
        mock_collector = _make_mock_collector(
            context_keys=frozenset({"public_storage_buckets"}),
            collect_return=[],
        )
        observer.collectors = [mock_collector]

        context = observer.observe("test-rg")

        assert "public_storage_buckets" in context
        assert "versioning_disabled_count" not in context
        assert "open_ingress_rules" not in context

    def test_observe_merges_resources_from_multiple_collectors(self):
        observer = AzureObserver(subscription_id="sub-123")
        observer._credential = MagicMock()

        storage_collector = _make_mock_collector(
            resource_type_name="storage_accounts",
            collect_return=[{"type": "azurerm_storage_account", "name": "a", "values": {}}],
        )
        nsg_collector = _make_mock_collector(
            resource_type_name="network_security_groups",
            context_keys=frozenset({"open_ingress_rules"}),
            collect_return=[{"type": "azurerm_network_security_group", "name": "b", "values": {}}],
        )
        observer.collectors = [storage_collector, nsg_collector]

        context = observer.observe("test-rg")

        assert len(context["resources"]) == 2

    def test_observe_propagates_collector_failure(self):
        observer = AzureObserver(subscription_id="sub-123")
        observer._credential = MagicMock()

        mock_collector = _make_mock_collector()
        mock_collector.collect.side_effect = CloudObserverError(
            "insufficient permission on storage accounts"
        )
        observer.collectors = [mock_collector]

        with pytest.raises(CloudObserverError) as exc_info:
            observer.observe("test-rg")
        assert "insufficient permission" in str(exc_info.value)