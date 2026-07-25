# context/observers/azure_observer.py
#
# Purpose:
# Sentinel's first cloud observer. Orchestrates a list of
# ResourceCollectors — each owns exactly one Azure resource
# type's collection and normalization. AzureObserver itself
# stays small regardless of how many resource types it
# supports:
#
#   AzureObserver
#   ├── StorageCollector        (data governance)
#   ├── NSGCollector             (network governance)
#   └── KeyVaultCollector        (secrets governance)
#
# Scope (v1): Storage Accounts, Network Security Groups, and
# Key Vault. Deliberately chosen to prove the observation
# architecture generalizes across genuinely different
# normalization shapes — scalar properties (Storage), nested
# rule collections (NSG), and a mixed object model (Key Vault)
# — rather than adding resource count for its own sake.
#
# Still deferred, real follow-up work: SQL/PostgreSQL/MySQL,
# App Services, and Compute/GPU VMs — each needs its own
# property verification pass before being added, same
# discipline used for all three collectors here.
#
# Auth model:
# Read-only only. Uses DefaultAzureCredential (managed
# identity, Azure CLI login, or environment variables) against
# the "Reader" role. This observer never requests, and must
# never be granted, write or deploy permission.
#
# Optional dependency:
# Requires the "azure" extra — pip install obsidianwall-verdict[azure].
# Import is deferred into authenticate() and each collector's
# collect() call, so importing this module never fails for
# users who haven't installed the extra.

from __future__ import annotations

from typing import Any

from context.observers.base_observer import CloudObserver, CloudObserverError
from context.observers.collectors.keyvault_collector import KeyVaultCollector
from context.observers.collectors.nsg_collector import NSGCollector
from context.observers.collectors.storage_collector import StorageCollector


class AzureObserver(CloudObserver):
    """
    Observes Azure resource state by orchestrating a list of
    ResourceCollectors. See module docstring for current scope.
    """

    def __init__(self, subscription_id: str) -> None:
        """
        Args:
            subscription_id: the Azure subscription to observe.
                Required at construction time — this observer
                is scoped to one subscription per instance.
        """
        self.subscription_id = subscription_id
        self._credential = None
        self.collectors: list[Any] = [
            StorageCollector(),
            NSGCollector(),
            KeyVaultCollector(),
        ]

    @property
    def provider_name(self) -> str:
        return "azure"

    @property
    def capabilities(self) -> dict[str, bool]:
        """
        Checked against which COLLECTORS are registered
        (via resource_type_name), not which context keys they
        produce — some context keys (e.g. versioning_disabled_count)
        are legitimately produced by more than one collector
        (StorageCollector AND KeyVaultCollector both feed it,
        since count_versioning_disabled() checks both storage
        blob versioning and Key Vault soft delete). Checking
        key presence alone would make it impossible to tell
        which specific domain a shared key's coverage actually
        reflects — checking collector registration directly
        avoids that ambiguity entirely.
        """
        registered_types = {c.resource_type_name for c in self.collectors}

        return {
            "resource_inventory": True,
            "network_security": "network_security_groups" in registered_types,
            "storage_security": "storage_accounts" in registered_types,
            "database_security": False,  # no SQL/Postgres/MySQL collector yet
            "compute_sizing": False,      # no compute/GPU collector yet
            "secrets_management": "key_vaults" in registered_types,
        }

    def authenticate(self) -> None:
        """
        Authenticate using DefaultAzureCredential — supports
        managed identity, Azure CLI login, or environment
        variables. Requires only "Reader" role on the target
        subscription. The resulting credential is shared by
        every collector — each creates its own typed SDK
        client from it, since different resource types need
        different client classes.
        """
        try:
            from azure.identity import DefaultAzureCredential
        except ImportError as exc:
            raise CloudObserverError(
                "Azure SDK not installed. Install with:\n"
                "  pip install obsidianwall-verdict[azure]"
            ) from exc

        try:
            self._credential = DefaultAzureCredential()
        except Exception as exc:
            raise CloudObserverError(
                f"Azure authentication failed: {exc}\n"
                f"Confirm you have 'Reader' role on subscription "
                f"{self.subscription_id}, and that a supported "
                f"credential (managed identity, Azure CLI login, "
                f"or environment variables) is available."
            ) from exc

    def observe(self, scope: str) -> dict[str, Any]:
        """
        Args:
            scope: an Azure resource group name.

        Returns:
            A context dict matching parse_terraform_plan()'s
            shape — resources list plus whichever domain keys
            the currently-registered collectors actually
            produced. Keys for uncovered resource types are
            simply ABSENT, never fabricated as zero — this is
            what makes context.observers.sufficiency's
            presence-based check reliable.

        Raises:
            CloudObserverError: if authenticate() was not
                called first, or if any collector's collection
                fails.
        """
        if self._credential is None:
            raise CloudObserverError(
                "authenticate() must be called before observe()."
            )

        from context.translators.terraform_parser import (
            count_open_ingress_rules,
            count_public_storage,
            count_versioning_disabled,
        )

        all_resources: list[dict[str, Any]] = []
        for collector in self.collectors:
            resources = collector.collect(
                self._credential, self.subscription_id, scope
            )
            all_resources.extend(resources)

        context: dict[str, Any] = {"resources": all_resources}

        produced_keys: set[str] = set()
        for collector in self.collectors:
            produced_keys |= collector.context_keys_produced

        # Only include a context key if a collector that
        # produces it is actually registered — never compute
        # and include a key derived from resource types no
        # collector examined.
        if "public_storage_buckets" in produced_keys:
            context["public_storage_buckets"] = count_public_storage(all_resources)
        if "versioning_disabled_count" in produced_keys:
            context["versioning_disabled_count"] = count_versioning_disabled(
                all_resources
            )
        if "open_ingress_rules" in produced_keys:
            context["open_ingress_rules"] = count_open_ingress_rules(all_resources)

        return context