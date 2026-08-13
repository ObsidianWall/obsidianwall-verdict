# tests/unit/test_ssh_backend.py
#
# Real end-to-end tests against an isolated, throwaway SSH
# key — never the developer's real ~/.ssh key. Skips cleanly
# (not fails) on any machine without a real ssh-keygen binary.
#
# Confirmed live on both WSL and native Windows: file-based
# signing (writes <file>.sig), the allowed_signers line
# format, and that -Y verify's success message appears on
# stdout (unlike GPG's, which uses stderr).

from __future__ import annotations

import shutil
import subprocess

import pytest

from telemetry.signing.base_signing import SigningError
from telemetry.signing.ssh_backend import SSHSigningBackend

pytestmark = pytest.mark.skipif(
    shutil.which("ssh-keygen") is None, reason="ssh-keygen binary not available"
)

_TEST_IDENTITY = "pytest-test-identity"


@pytest.fixture
def isolated_ssh_key(tmp_path):
    """
    Generates a real, throwaway Ed25519 SSH key — never the
    developer's real key. Skips (not fails) if key generation
    itself doesn't work, since that's an environment issue,
    not a code issue.
    """
    key_path = tmp_path / "test_ssh_key"

    result = subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-f", str(key_path), "-N", ""],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        pytest.skip(f"Could not generate test SSH key: {result.stderr}")

    return str(key_path)


class TestSSHSigningBackend:
    def test_is_available_with_real_key(self, isolated_ssh_key):
        backend = SSHSigningBackend(
            private_key_path=isolated_ssh_key, identity=_TEST_IDENTITY
        )
        assert backend.is_available() is True

    def test_is_available_false_for_nonexistent_key(self, tmp_path):
        backend = SSHSigningBackend(
            private_key_path=str(tmp_path / "does_not_exist"),
            identity=_TEST_IDENTITY,
        )
        assert backend.is_available() is False

    def test_sign_and_verify_round_trip(self, isolated_ssh_key):
        backend = SSHSigningBackend(
            private_key_path=isolated_ssh_key, identity=_TEST_IDENTITY
        )
        data = "a3f5c9e1b2d4f6a8c0e2b4d6f8a0c2e4b6d8f0a2c4e6b8d0f2a4c6e8b0d2f4a6"

        result = backend.sign(data)

        assert result.signing_method == "ssh"
        assert backend.verify(data, result) is True

    def test_verify_rejects_tampered_data(self, isolated_ssh_key):
        backend = SSHSigningBackend(
            private_key_path=isolated_ssh_key, identity=_TEST_IDENTITY
        )
        result = backend.sign("original data")

        assert backend.verify("tampered data", result) is False

    def test_sign_raises_without_available_key(self, tmp_path):
        backend = SSHSigningBackend(
            private_key_path=str(tmp_path / "does_not_exist"),
            identity=_TEST_IDENTITY,
        )
        with pytest.raises(SigningError):
            backend.sign("some data")

    def test_different_identity_still_verifies_same_signature(self, isolated_ssh_key):
        """
        The identity string is used to build the allowed_signers
        file at verification time — this confirms verify() uses
        the SAME identity consistently between signing and
        verifying, since SignatureResult doesn't independently
        store it (only the backend instance does).
        """
        signer = SSHSigningBackend(
            private_key_path=isolated_ssh_key, identity=_TEST_IDENTITY
        )
        data = "identity consistency test"
        result = signer.sign(data)

        # A SEPARATE backend instance, same identity, same key —
        # simulates verification happening in a different process.
        verifier = SSHSigningBackend(
            private_key_path=isolated_ssh_key, identity=_TEST_IDENTITY
        )
        assert verifier.verify(data, result) is True