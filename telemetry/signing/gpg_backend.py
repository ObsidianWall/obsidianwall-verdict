# telemetry/signing/gpg_backend.py
#
# Purpose:
# GPG-based attestation signing. Shells out to the user's
# real gpg binary/agent — never reimplements cryptographic
# primitives.
#
# Verification is self-contained by design: verify() uses
# ONLY the embedded public key on the SignatureResult, never
# a live keyring lookup. This means a signature remains
# verifiable even if the signer's key is later rotated out of
# their active keyring, or by an auditor with nothing but the
# stored record.
#
# Note: GPG emits "WARNING: The key's User ID is not certified
# with a trusted signature!" when verifying via a freshly-
# imported key with no established trust path. This is
# EXPECTED, not a failure — it reflects GPG's web-of-trust
# model ("do you trust this identity"), a different question
# from "did this key produce this signature" (which is what
# verify() actually checks). The warning is intentionally
# ignored; only "Good signature" + exit code 0 counts.

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

from telemetry.signing.base_signing import (
    SignatureResult,
    SigningBackend,
    SigningError,
)


class GPGSigningBackend(SigningBackend):
    """
    Signs using the user's existing GPG key via the real gpg
    binary. Never manages key material itself.
    """

    def __init__(self, key_id: str | None = None) -> None:
        """
        Args:
            key_id: GPG key identifier (email or fingerprint)
                to sign with. If None, uses gpg's own default
                signing key (--local-user omitted — gpg falls
                back to its configured default).
        """
        self.key_id = key_id

    @property
    def method_name(self) -> str:
        return "gpg"

    def is_available(self) -> bool:
        if shutil.which("gpg") is None:
            return False
        try:
            # Filters by self.key_id when one was specified —
            # matches sign()'s own key resolution
            # (_resolve_signing_fingerprint below), which DOES
            # filter by key_id. Without this filter,
            # is_available() would report True for ANY
            # nonexistent key_id as long as SOME OTHER secret
            # key happened to exist in the keyring — checking
            # "does a key exist" instead of "does THIS key
            # exist."
            list_command = ["gpg", "--list-secret-keys", "--with-colons"]
            if self.key_id:
                list_command.append(self.key_id)

            result = subprocess.run(
                list_command,
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0 and "sec" in result.stdout
        except Exception:
            return False

    def sign(self, data: str) -> SignatureResult:
        if not self.is_available():
            raise SigningError(
                "No GPG signing key available. Generate one with:\n"
                "  gpg --full-generate-key"
            )

        gpg_command = ["gpg", "--batch", "--yes"]
        if self.key_id:
            gpg_command += ["--local-user", self.key_id]
        gpg_command += ["--detach-sign", "--armor", "--output", "-"]

        try:
            result = subprocess.run(
                gpg_command,
                input=data,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except Exception as exc:
            raise SigningError(f"GPG signing failed to execute: {exc}") from exc

        if result.returncode != 0:
            raise SigningError(f"GPG signing failed: {result.stderr}")

        signature = result.stdout

        fingerprint = self._resolve_signing_fingerprint()
        public_key = self._export_public_key(fingerprint)

        return SignatureResult(
            signature=signature,
            public_key=public_key,
            key_fingerprint=fingerprint,
            signing_method="gpg",
        )

    def verify(self, data: str, result: SignatureResult) -> bool:
        # Self-contained verification: import ONLY the embedded
        # public key into an ISOLATED temporary keyring, never
        # touching or depending on the caller's own default
        # keyring. This is what makes verification reliable
        # even if the original signer's key has since been
        # rotated out of general use.
        with tempfile.TemporaryDirectory() as temp_gnupg_home:
            temp_home_path = Path(temp_gnupg_home)
            temp_home_path.chmod(0o700)

            import_result = subprocess.run(
                ["gpg", "--homedir", str(temp_home_path), "--batch", "--import"],
                input=result.public_key,
                capture_output=True,
                text=True,
                timeout=15,
            )
            if import_result.returncode != 0:
                raise SigningError(
                    f"Failed to import embedded public key for "
                    f"verification: {import_result.stderr}"
                )

            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".sig", delete=False
            ) as sig_file:
                sig_file.write(result.signature)
                sig_file_path = sig_file.name

            try:
                verify_result = subprocess.run(
                    [
                        "gpg",
                        "--homedir",
                        str(temp_home_path),
                        "--verify",
                        sig_file_path,
                        "-",
                    ],
                    input=data,
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
            finally:
                Path(sig_file_path).unlink(missing_ok=True)

            # "Good signature" appears on stderr, not stdout —
            # confirmed directly against real gpg output.
            return (
                verify_result.returncode == 0
                and "Good signature" in verify_result.stderr
            )

    def _resolve_signing_fingerprint(self) -> str:
        list_command = ["gpg", "--list-secret-keys", "--with-colons"]
        if self.key_id:
            list_command.append(self.key_id)

        result = subprocess.run(
            list_command, capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.splitlines():
            if line.startswith("fpr:"):
                return line.split(":")[9]

        raise SigningError("Could not resolve a fingerprint for the signing key.")

    def _export_public_key(self, fingerprint: str) -> str:
        result = subprocess.run(
            ["gpg", "--armor", "--export", fingerprint],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0 or not result.stdout:
            raise SigningError(
                f"Failed to export public key for {fingerprint}: {result.stderr}"
            )
        return result.stdout
