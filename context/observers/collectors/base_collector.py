# context/observers/collectors/base_collector.py
#
# Purpose:
# Abstract interface for a single-resource-type collector
# within a provider observer. A CloudObserver (e.g.
# AzureObserver) orchestrates a list of these — each
# collector owns exactly one resource type's SDK client
# creation, collection, and normalization into the shared
# {type, name, values} resource shape.
#
# Why this split exists:
# AzureObserver started as one class doing storage-account
# collection directly. The moment a second resource type
# (NSGs, Key Vault) needs support, that class would grow
# unboundedly — different SDK clients, different collection
# calls, different normalization logic, all tangled together.
# Splitting collection into one class per resource type keeps
# AzureObserver itself small regardless of how many resource
# types it eventually supports:
#
#   AzureObserver
#   ├── StorageCollector
#   ├── NSGCollector       
#   ├── KeyVaultCollector  
#   └── ...
#
# Each collector creates its OWN typed SDK client (e.g.
# StorageManagementClient, NetworkManagementClient) from the
# shared credential — different Azure resource types need
# different client classes, so this can't be centralized
# further without losing type safety.

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


def get_sdk_property(obj: Any, name: str, default: Any = None) -> Any:
    """
    Read a property from an Azure SDK model object, checking
    obj.properties.<name> first, falling back to obj.<name>
    directly, then the given default.

    Why this exists: Microsoft's own azure-mgmt-network
    changelog confirms that SecurityRule's fields (direction,
    access, source_address_prefix, etc.) moved from being flat
    attributes to living under a nested .properties sub-object
    in SDK version 28.0.0+ — the same "flatten vs. nest under
    properties" pattern the underlying ARM REST API has always
    used. Rather than pin one exact SDK version and risk
    breaking on the next one, every collector reads through
    this helper so both shapes work correctly regardless of
    which SDK version is actually installed.
    """
    properties = getattr(obj, "properties", None)
    if properties is not None:
        value = getattr(properties, name, None)
        if value is not None:
            return value
    return getattr(obj, name, default)


class ResourceCollector(ABC):
    """
    Collects and normalizes ONE resource type for a cloud
    observer. Never evaluates policy, never writes anywhere —
    same read-only, narrow-responsibility boundary as
    CloudObserver itself.
    """

    @property
    @abstractmethod
    def resource_type_name(self) -> str:
        """
        Short identifier for logging and error messages —
        e.g. "storage_accounts", "network_security_groups".
        """

    @property
    @abstractmethod
    def context_keys_produced(self) -> frozenset[str]:
        """
        Which context keys this collector's output feeds into,
        once passed through the shared terraform_parser
        counting functions. Used for documentation and for
        assembling the observer's overall capabilities
        descriptor — NOT used as the sufficiency gate itself,
        which checks the actually-returned context directly
        (see context.observers.sufficiency).
        """

    @abstractmethod
    def collect(
        self, credential: Any, subscription_id: str, scope: str
    ) -> list[dict[str, Any]]:
        """
        Query this resource type within the given scope and
        return normalized resources in the shared
        {type, name, values} shape.

        Args:
            credential: an authenticated Azure credential
                object (or equivalent for other providers),
                already obtained by the orchestrating observer.
            subscription_id: the subscription to query.
            scope: provider-specific scope, e.g. a resource
                group name.

        Returns:
            A list of normalized resource dicts. Empty list
            if the resource type has no instances in scope —
            NOT an error.

        Raises:
            context.observers.base_observer.CloudObserverError
            on any collection failure. Never returns a partial
            or best-guess result silently.
        """