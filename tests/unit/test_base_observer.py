# tests/unit/test_base_observer.py
#
# Corrected against the real context/observers/base_observer.py —
# the class is CloudObserver, not BaseObserver (an earlier,
# unconfirmed guess), and it has THREE abstract methods
# (provider_name, authenticate, observe), not one.

from typing import Any

from context.observers.base_observer import CloudObserver


class _MinimalObserver(CloudObserver):
    """
    Implements every abstract method with a trivial stub,
    deliberately leaving `capabilities` at its default so the
    default implementation itself gets exercised.
    """

    @property
    def provider_name(self) -> str:
        return "test_provider"

    def authenticate(self) -> None:
        pass

    def observe(self, scope: str) -> dict[str, Any]:
        return {}


class TestCloudObserverDefaultCapabilities:
    def test_default_capabilities_are_all_false(self):
        """
        Covers the default capabilities property body — every
        real observer (azure_observer.py, etc.) overrides this,
        so the base default was never exercised directly.
        """
        observer = _MinimalObserver()
        capabilities = observer.capabilities

        assert capabilities == {
            "resource_inventory": False,
            "network_security": False,
            "storage_security": False,
            "database_security": False,
            "compute_sizing": False,
            "secrets_management": False,
        }