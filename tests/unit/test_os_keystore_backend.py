# tests/unit/test_os_keystore_backend.py
#
# Two-tier test strategy, matching this backend's own
# verified-vs-unverified split:
#
#   1. Crypto logic tests — mock ONLY keyring's storage calls
#      (an in-memory dict standing in for the OS keystore),
#      using the REAL cryptography library for everything
#      else. These run everywhere, no real OS service needed.
#
#   2. Real integration test — actually exercises a genuine OS
#      keystore. Skips cleanly on any machine without a
#      functional backend (confirmed: WSL has none; Windows
#      Credential Manager and macOS Keychain do).

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from telemetry.signing.os_keystore_backend import OSKeystoreSigningBackend


def _keyring_installed() -> bool:
    try:
        import keyring  # noqa: F401

        return True
    except ImportError:
        return False


# =====================================================
# CRYPTO LOGIC — mocked storage, real cryptography library
# =====================================================


@pytest.fixture
def fake_os_keystore(monkeypatch):
    """
    An in-memory dict standing in for keyring's actual OS
    storage — the REAL cryptography library still does all
    the actual key generation, signing, and verification work.
    """
    storage: dict[tuple[str, str], str] = {}

    fake_keyring = MagicMock()
    fake_keyring.get_keyring.return_value = "fake-backend"
    fake_keyring.get_password.side_effect = (
        lambda service, identity: storage.get((service, identity))
    )
    fake_keyring.set_password.side_effect = (
        lambda service, identity, value: storage.__setitem__(
            (service, identity), value
        )
    )

    import sys

    monkeypatch.setitem(sys.modules, "keyring", fake_keyring)
    return storage


class TestOSKeystoreCryptoLogic:
    def test_sign_generates_and_stores_new_key_on_first_use(self, fake_os_keystore):
        backend = OSKeystoreSigningBackend(identity="test@example.com")
        result = backend.sign("a3f5c9e1b2d4f6a8")

        assert backend.last_operation_created_new_key is True
        assert result.signing_method == "os-keystore-ed25519"

    def test_sign_reuses_existing_key_on_second_call(self, fake_os_keystore):
        backend = OSKeystoreSigningBackend(identity="test@example.com")
        result1 = backend.sign("data one")
        result2 = backend.sign("data two")

        assert backend.last_operation_created_new_key is False
        assert result1.key_fingerprint == result2.key_fingerprint

    def test_different_identities_get_different_keys(self, fake_os_keystore):
        backend1 = OSKeystoreSigningBackend(identity="alice@example.com")
        backend2 = OSKeystoreSigningBackend(identity="bob@example.com")

        result1 = backend1.sign("test data")
        result2 = backend2.sign("test data")

        assert result1.key_fingerprint != result2.key_fingerprint

    def test_verify_accepts_valid_signature(self, fake_os_keystore):
        backend = OSKeystoreSigningBackend(identity="test@example.com")
        data = "test data"
        result = backend.sign(data)

        assert backend.verify(data, result) is True

    def test_verify_rejects_tampered_data(self, fake_os_keystore):
        backend = OSKeystoreSigningBackend(identity="test@example.com")
        result = backend.sign("original data")

        assert backend.verify("tampered data", result) is False

    def test_verify_does_not_touch_keystore(self, fake_os_keystore):
        """
        Self-contained verification — verify() must work using
        ONLY the embedded public key, never calling back into
        keyring at all.
        """
        backend = OSKeystoreSigningBackend(identity="test@example.com")
        data = "test data"
        result = backend.sign(data)

        import sys

        fake_keyring_module = sys.modules["keyring"]
        fake_keyring_module.reset_mock()

        backend.verify(data, result)

        fake_keyring_module.get_password.assert_not_called()
        fake_keyring_module.set_password.assert_not_called()

    # The two is_available() tests below require the REAL
    # keyring package to be installed — is_available() does a
    # SUBMODULE import (from keyring.backends.fail import
    # Keyring), which cannot be correctly faked via a full
    # sys.modules["keyring"] MagicMock replacement the way
    # get_password/set_password can. Confirmed directly: a
    # full-mock attempt at these two tests produced a
    # TypeError on the isinstance() check, silently caught by
    # is_available()'s own exception handling, giving a false
    # result — not a bug in the production code (proven
    # correct on two real machines: True on Windows,
    # False on WSL), but a genuine limit of fully mocking this
    # SPECIFIC import pattern. These require the real package.

    @pytest.mark.skipif(
        not _keyring_installed(), reason="Requires the real keyring package"
    )
    def test_is_available_true_with_functional_backend(self, fake_os_keystore):
        backend = OSKeystoreSigningBackend(identity="test@example.com")
        assert backend.is_available() is True

    @pytest.mark.skipif(
        not _keyring_installed(), reason="Requires the real keyring package"
    )
    def test_is_available_false_with_fail_backend(self, monkeypatch):
        """
        Regression test for the real bug found and fixed
        earlier: is_available() must correctly detect
        keyring.backends.fail.Keyring specifically, not just
        check whether asking for a backend raised an exception
        (it doesn't — the fail backend only raises once you
        actually try to use it).
        """
        import sys

        from keyring.backends.fail import Keyring as FailKeyring

        fake_keyring = MagicMock()
        fake_keyring.get_keyring.return_value = FailKeyring()
        monkeypatch.setitem(sys.modules, "keyring", fake_keyring)

        backend = OSKeystoreSigningBackend(identity="test@example.com")
        assert backend.is_available() is False


# =====================================================
# REAL INTEGRATION — genuine OS keystore, skips if unavailable
# =====================================================


def _real_keystore_available() -> bool:
    try:
        import keyring
        from keyring.backends.fail import Keyring as FailKeyring

        return not isinstance(keyring.get_keyring(), FailKeyring)
    except Exception:
        return False


@pytest.mark.skipif(
    not _real_keystore_available(),
    reason="No functional OS keystore backend on this machine",
)
class TestOSKeystoreRealIntegration:
    def test_real_sign_and_verify_round_trip(self):
        """
        Uses an identity unlikely to collide with anything real,
        and does not clean up the stored key afterward — matches
        how this backend is actually meant to be used (a
        persistent, one-time-generated key), not a throwaway.
        """
        backend = OSKeystoreSigningBackend(
            identity="pytest-integration-test@obsidianwall.internal"
        )
        data = "real keystore integration test"

        result = backend.sign(data)
        assert backend.verify(data, result) is True