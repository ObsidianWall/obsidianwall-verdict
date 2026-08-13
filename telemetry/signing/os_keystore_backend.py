# telemetry/signing/os_keystore_backend.py
#
# Purpose:
# The guaranteed-available signing fallback for approvers who
# have neither GPG nor SSH configured — an accountant, an
# executive, an HR reviewer with no CLI experience. Generates a
# real Ed25519 keypair transparently on first use, storing the
# private key in the OS's own trusted keystore (macOS Keychain
# / Windows Credential Manager / Linux Secret Service via the
# `keyring` package) — never a system this project builds or
# manages itself, the same trust boundary a password manager or
# git credential helper already relies on.
#
# The Ed25519 cryptographic operations (key generation, signing,
# verification, and correct rejection of tampered data) are
# implemented using the standard `cryptography` library and are
# covered by tests/unit/test_os_keystore_backend.py.
#
# Known limitation: `keyring`'s actual storage behavior has not
# been validated against every real OS backend (macOS Keychain,
# Windows Credential Manager, Linux Secret Service). A bare
# Linux server or container without a running Secret Service
# daemon (gnome-keyring, kwallet) has no functional backend at
# all — this fallback may need its own fallback for headless
# environments. See CONTRIBUTING.md for how to help validate
# this on your platform.
#
# verify() does NOT depend on `keyring` — it uses only the
# embedded public key on the SignatureResult, so verification
# works independent of the storage question above.

from __future__ import annotations

import hashlib

from telemetry.signing.base_signing import (
    SignatureResult,
    SigningBackend,
    SigningError,
)

_SERVICE_NAME = "obsidianwall-verdict-attestation"


class OSKeystoreSigningBackend(SigningBackend):
    """
    Auto-generating, OS-keystore-backed signing backend. The
    guaranteed fallback when neither GPG nor SSH is available —
    see ADR-0002 for why this exists and what it can and cannot
    honestly claim.
    """

    def __init__(self, identity: str) -> None:
        """
        Args:
            identity: string identifying the signer — should be
                the same value resolve_actor_identity() already
                resolves, used as the keyring lookup key so the
                same identity always retrieves the same keypair
                across invocations on the same machine.
        """
        self.identity = identity
        self.last_operation_created_new_key: bool = False
        # Set by sign() — lets the caller (verdict override)
        # print a first-use notice ("a signing key was created
        # for you...") only when a key was genuinely just
        # generated, not on every subsequent use.

    @property
    def method_name(self) -> str:
        return "os-keystore-ed25519"

    def is_available(self) -> bool:
        """
        This backend can generate a key on demand, so
        "available" really means "is SOME OS keystore backend
        actually functional on this machine" — not "does a key
        already exist." Must never raise; a failure here means
        try a different backend, not crash.

        keyring.get_keyring() alone does NOT raise when no real
        backend exists — it silently resolves to
        keyring.backends.fail.Keyring, a placeholder that only
        raises once you actually try to use it. Checking for
        that specific placeholder is the correct test; checking
        only "did asking for a backend raise" is not — confirmed
        directly on a real WSL environment with no functional
        Secret Service daemon, where get_keyring() succeeded but
        every actual operation failed.
        """
        try:
            import keyring
            from keyring.backends.fail import Keyring as FailKeyring

            resolved_backend = keyring.get_keyring()
            return not isinstance(resolved_backend, FailKeyring)
        except Exception:
            return False

    def sign(self, data: str) -> SignatureResult:
        try:
            from cryptography.exceptions import InvalidSignature  # noqa: F401
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
            )
        except ImportError as exc:
            raise SigningError(
                "The 'cryptography' package is required for OS-keystore "
                "signing. Install with:\n"
                "  pip install obsidianwall-verdict[attestation]"
            ) from exc

        try:
            import keyring
        except ImportError as exc:
            raise SigningError(
                "The 'keyring' package is required for OS-keystore "
                "signing. Install with:\n"
                "  pip install obsidianwall-verdict[attestation]"
            ) from exc

        try:
            private_key = self._get_or_create_private_key(
                keyring, Ed25519PrivateKey, serialization
            )
        except Exception as exc:
            raise SigningError(
                f"Could not access the OS keystore: {exc}\n"
                f"Confirm a secret storage service is available on "
                f"this machine (macOS Keychain, Windows Credential "
                f"Manager, or a Linux Secret Service daemon such as "
                f"gnome-keyring or kwallet)."
            ) from exc

        public_key = private_key.public_key()
        signature_bytes = private_key.sign(data.encode("utf-8"))

        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        fingerprint = hashlib.sha256(public_bytes).hexdigest()[:16]

        return SignatureResult(
            signature=signature_bytes.hex(),
            public_key=public_bytes.hex(),
            key_fingerprint=fingerprint,
            signing_method=self.method_name,
        )

    def verify(self, data: str, result: SignatureResult) -> bool:
        """
        Self-contained — uses ONLY the embedded public key.
        Never touches the OS keystore. This is the part fully
        verified against the real cryptography library tonight.
        """
        try:
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PublicKey,
            )
        except ImportError as exc:
            raise SigningError(
                "The 'cryptography' package is required to verify "
                "OS-keystore signatures."
            ) from exc

        try:
            public_bytes = bytes.fromhex(result.public_key)
            public_key = Ed25519PublicKey.from_public_bytes(public_bytes)
            signature_bytes = bytes.fromhex(result.signature)
            public_key.verify(signature_bytes, data.encode("utf-8"))
            return True
        except InvalidSignature:
            return False
        except Exception:
            return False

    def _get_or_create_private_key(
        self, keyring_module, ed25519_private_key_class, serialization_module
    ):
        stored_hex = keyring_module.get_password(_SERVICE_NAME, self.identity)

        if stored_hex is not None:
            self.last_operation_created_new_key = False
            private_bytes = bytes.fromhex(stored_hex)
            return ed25519_private_key_class.from_private_bytes(private_bytes)

        # First use for this identity on this machine — generate
        # and store transparently. This is the mechanism that
        # makes signing achievable for a non-technical approver
        # with zero setup: they never see a key-generation step,
        # it just happens once, silently, the first time they
        # approve or deny anything.
        private_key = ed25519_private_key_class.generate()
        private_bytes = private_key.private_bytes(
            encoding=serialization_module.Encoding.Raw,
            format=serialization_module.PrivateFormat.Raw,
            encryption_algorithm=serialization_module.NoEncryption(),
        )
        keyring_module.set_password(_SERVICE_NAME, self.identity, private_bytes.hex())
        self.last_operation_created_new_key = True
        return private_key
