# tests/unit/test_gpg_backend.py
#
# Real end-to-end tests against an isolated, throwaway GPG
# key — never the developer's real keyring. Skips cleanly
# (not fails) on any machine without a real gpg binary, so
# CI stays honest about what it actually covers.

from __future__ import annotations

import os
import shutil
import subprocess

import pytest

from telemetry.signing.base_signing import SigningError
from telemetry.signing.gpg_backend import GPGSigningBackend

_TEST_EMAIL = "pytest-test@example.com"

pytestmark = pytest.mark.skipif(
    shutil.which("gpg") is None, reason="gpg binary not available"
)


@pytest.fixture
def isolated_gpg_key(tmp_path, monkeypatch):
    """
    Generates a real, throwaway Ed25519 GPG key in an isolated
    GNUPGHOME — never touches the real developer's keyring.
    Skips (not fails) if key generation itself doesn't work,
    since that's an environment issue, not a code issue.
    """
    gnupg_home = tmp_path / "gnupg_home"
    gnupg_home.mkdir()
    gnupg_home.chmod(0o700)

    key_config = (
        "%no-protection\n"
        "Key-Type: EDDSA\n"
        "Key-Curve: Ed25519\n"
        "Name-Real: Pytest Test Key\n"
        f"Name-Email: {_TEST_EMAIL}\n"
        "Expire-Date: 0\n"
        "%commit\n"
    )
    config_path = gnupg_home / "key_config"
    config_path.write_text(key_config)

    monkeypatch.setenv("GNUPGHOME", str(gnupg_home))

    result = subprocess.run(
        ["gpg", "--batch", "--gen-key", str(config_path)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        pytest.skip(f"Could not generate test GPG key: {result.stderr}")

    yield


class TestGPGSigningBackend:
    def test_is_available_with_real_key(self, isolated_gpg_key):
        backend = GPGSigningBackend(key_id=_TEST_EMAIL)
        assert backend.is_available() is True

    def test_is_available_false_without_matching_key(self, isolated_gpg_key):
        backend = GPGSigningBackend(key_id="nonexistent@example.com")
        assert backend.is_available() is False

    def test_sign_and_verify_round_trip(self, isolated_gpg_key):
        backend = GPGSigningBackend(key_id=_TEST_EMAIL)
        data = "a3f5c9e1b2d4f6a8c0e2b4d6f8a0c2e4b6d8f0a2c4e6b8d0f2a4c6e8b0d2f4a6"

        result = backend.sign(data)

        assert result.signing_method == "gpg"
        assert result.signature.startswith("-----BEGIN PGP SIGNATURE-----")
        assert backend.verify(data, result) is True

    def test_verify_rejects_tampered_data(self, isolated_gpg_key):
        backend = GPGSigningBackend(key_id=_TEST_EMAIL)
        result = backend.sign("original data")

        assert backend.verify("tampered data", result) is False

    def test_verify_is_self_contained(self, isolated_gpg_key, tmp_path, monkeypatch):
        """
        The core ADR-0002 guarantee: verification must work
        using ONLY the embedded public key, with zero
        dependency on the signer's original keyring — proven
        here by verifying from a COMPLETELY FRESH, empty
        GNUPGHOME.
        """
        backend = GPGSigningBackend(key_id=_TEST_EMAIL)
        data = "self-contained verification test"
        result = backend.sign(data)

        fresh_home = tmp_path / "fresh_gnupg_home"
        fresh_home.mkdir()
        fresh_home.chmod(0o700)
        monkeypatch.setenv("GNUPGHOME", str(fresh_home))

        # New backend instance in the fresh, empty environment —
        # verify() must still succeed using only result.public_key.
        fresh_backend = GPGSigningBackend()
        assert fresh_backend.verify(data, result) is True

    def test_sign_raises_without_available_key(self, isolated_gpg_key):
        backend = GPGSigningBackend(key_id="nonexistent@example.com")
        with pytest.raises(SigningError):
            backend.sign("some data")