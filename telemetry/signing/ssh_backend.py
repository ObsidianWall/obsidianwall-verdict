# telemetry/signing/ssh_backend.py
#
# Purpose:
# SSH-based attestation signing, using `ssh-keygen -Y sign/
# verify` — the same mechanism git's native SSH commit-signing
# uses. Shells out to the real ssh-keygen binary — never
# reimplements cryptographic primitives.
#
# Known limitation: this implementation is built from
# documented ssh-keygen behavior and has not yet been validated
# against a live binary. Specific assumptions that need
# confirming before this is considered production-ready:
#   - Whether `ssh-keygen -Y sign` accepts data via stdin or
#     requires a real file path (this implementation uses temp
#     files to avoid depending on unconfirmed stdin support).
#   - The exact allowed_signers file line format and whether it
#     tolerates extra whitespace/comments.
#   - Whether `-Y verify`'s `-I` identity argument must exactly
#     match the identity string in the allowed_signers file.
#   - Exact placement (stdout vs. stderr) of the success message
#     this implementation checks for.
# See CONTRIBUTING.md for how to help validate this backend.

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

# Namespace string embedded in the signature, per ssh-keygen's
# own -n flag — scopes what the signature can be used to prove,
# same purpose as git's "git" namespace for commit signing.
_SIGNATURE_NAMESPACE = "obsidianwall-verdict-attestation"


class SSHSigningBackend(SigningBackend):
    """
    Signs using the user's existing SSH key via ssh-keygen -Y.

    UNVERIFIED — see module docstring. Do not enable this as a
    default backend until confirmed against a real binary.
    """

    def __init__(
        self,
        private_key_path: str | None = None,
        identity: str = "",
    ) -> None:
        """
        Args:
            private_key_path: path to the SSH private key to
                sign with. If None, defaults to ~/.ssh/id_ed25519,
                then ~/.ssh/id_rsa — UNVERIFIED default order,
                needs confirming this matches user expectation.
            identity: string identifying the signer, embedded
                in the allowed_signers file for verification.
                Should be the same identity resolve_actor_identity()
                already resolves, for consistency with the rest
                of the system.
        """
        self.private_key_path = private_key_path or self._default_key_path()
        self.identity = identity

    @property
    def method_name(self) -> str:
        return "ssh"

    def _default_key_path(self) -> str:
        home = Path.home()
        for candidate in ("id_ed25519", "id_rsa"):
            path = home / ".ssh" / candidate
            if path.exists():
                return str(path)
        return str(home / ".ssh" / "id_ed25519")  # may not exist

    def is_available(self) -> bool:
        if shutil.which("ssh-keygen") is None:
            return False
        return Path(self.private_key_path).exists()

    def sign(self, data: str) -> SignatureResult:
        if not self.is_available():
            raise SigningError(
                "No SSH signing key available. Generate one with:\n"
                "  ssh-keygen -t ed25519"
            )

        with tempfile.TemporaryDirectory() as temp_dir:
            data_path = Path(temp_dir) / "data.txt"
            data_path.write_text(data)

            try:
                result = subprocess.run(
                    [
                        "ssh-keygen",
                        "-Y",
                        "sign",
                        "-f",
                        self.private_key_path,
                        "-n",
                        _SIGNATURE_NAMESPACE,
                        str(data_path),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
            except Exception as exc:
                raise SigningError(f"SSH signing failed to execute: {exc}") from exc

            if result.returncode != 0:
                raise SigningError(f"SSH signing failed: {result.stderr}")

            # ssh-keygen -Y sign writes output to <FILE>.sig by
            # convention — UNVERIFIED that this exact naming
            # holds when a directory path is involved.
            sig_path = Path(str(data_path) + ".sig")
            if not sig_path.exists():
                raise SigningError(
                    f"Expected signature file not found at "
                    f"{sig_path} — ssh-keygen's output naming "
                    f"convention may differ from what was assumed."
                )
            signature = sig_path.read_text()

            public_key = self._read_public_key()

            return SignatureResult(
                signature=signature,
                public_key=public_key,
                key_fingerprint=self._resolve_fingerprint(),
                signing_method="ssh",
            )

    def verify(self, data: str, result: SignatureResult) -> bool:
        with tempfile.TemporaryDirectory() as temp_dir:
            data_path = Path(temp_dir) / "data.txt"
            data_path.write_text(data)

            sig_path = Path(temp_dir) / "data.txt.sig"
            sig_path.write_text(result.signature)

            # UNVERIFIED exact line format — built from
            # documented ssh-keygen allowed_signers conventions,
            # not confirmed against real output.
            allowed_signers_path = Path(temp_dir) / "allowed_signers"
            allowed_signers_path.write_text(
                f"{self.identity} {result.public_key.strip()}\n"
            )

            try:
                verify_result = subprocess.run(
                    [
                        "ssh-keygen",
                        "-Y",
                        "verify",
                        "-f",
                        str(allowed_signers_path),
                        "-I",
                        self.identity,
                        "-n",
                        _SIGNATURE_NAMESPACE,
                        "-s",
                        str(sig_path),
                    ],
                    input=data,
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
            except Exception as exc:
                raise SigningError(
                    f"SSH verification failed to execute: {exc}"
                ) from exc

            # UNVERIFIED success-string assumption — needs
            # confirming against real ssh-keygen -Y verify output.
            return verify_result.returncode == 0 and "Good" in verify_result.stdout

    def _read_public_key(self) -> str:
        pub_path = Path(self.private_key_path + ".pub")
        if not pub_path.exists():
            raise SigningError(f"Public key not found at {pub_path}")
        return pub_path.read_text()

    def _resolve_fingerprint(self) -> str:
        result = subprocess.run(
            ["ssh-keygen", "-lf", self.private_key_path],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            raise SigningError(
                f"Could not resolve SSH key fingerprint: {result.stderr}"
            )
        # Output format: "<bits> <fingerprint> <comment> (<type>)"
        # UNVERIFIED exact parsing — reasonable but unconfirmed.
        parts = result.stdout.strip().split()
        return parts[1] if len(parts) > 1 else result.stdout.strip()
