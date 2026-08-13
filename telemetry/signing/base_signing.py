# telemetry/signing/base_signing.py
#
# Purpose:
# Abstract interface for attestation/non-repudiation signing
# backends. See docs/architecture/decisions/0002-attestation-signing.md
# for the full design rationale.
#
# This is NOT tamper-protection signing — that requires an
# external trust anchor (Sentinel Cloud, HSM, cloud KMS) that
# does not exist yet. This is attestation: proving a specific
# key holder approved/denied a specific override. Layered on
# top of, not replacing, the hash-chain tamper-EVIDENCE already
# in governance_history.
#
# Design principle: NEVER reimplement cryptographic primitives.
# Every concrete backend shells out to real, independently-
# audited signing infrastructure (gpg, ssh-keygen) that already
# exists on the user's machine — same trust boundary a password
# manager or git's commit-signing already relies on.

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


class SigningError(Exception):
    """
    Raised for any signing/verification failure — no key
    available, signing binary not found, signature invalid.
    Callers (verdict override approve/deny) catch this
    specifically to produce a clear, actionable CLI error
    rather than an unhandled traceback, and to enforce the
    "no unsigned records" rule from ADR-0002 — this must
    ALWAYS block the action, never silently degrade.
    """


@dataclass
class SignatureResult:
    """
    The output of a successful signing operation. Stored
    directly on the governance_history entry — self-contained,
    so verification later never depends on a live keyring
    still having this key.
    """

    signature: str  # base64/armored signature blob
    public_key: str  # exported public key, embedded
    key_fingerprint: str  # for display + cross-entry
    # consistency checking
    signing_method: str  # "gpg" | "ssh"


class SigningBackend(ABC):
    """
    Abstract base for all attestation-signing backends.

    A concrete backend's job is narrow: detect whether a real
    signing key is available on THIS machine, sign a given
    piece of data with it, and verify a previously-produced
    signature against its embedded public key. It never
    generates or manages the underlying key material itself
    (except the OS-keystore fallback backend, which explicitly
    delegates key STORAGE to the OS's own trusted keystore,
    never inventing new key-management infrastructure).
    """

    @property
    @abstractmethod
    def method_name(self) -> str:
        """Short identifier — "gpg" or "ssh" — stored on the
        signature record so verification later knows which
        backend's verify() logic to use."""

    @abstractmethod
    def is_available(self) -> bool:
        """
        Return True if a usable signing key/binary is
        detected on this machine RIGHT NOW. Must never raise —
        used purely for detection, to decide backend priority
        order. A False here means "try the next backend,"
        not "fail the operation."
        """

    @abstractmethod
    def sign(self, data: str) -> SignatureResult:
        """
        Sign the given data (expected: a history_hash hex
        string) and return a SignatureResult.

        Raises:
            SigningError: if signing fails for any reason —
                no key, binary not found, subprocess failure.
                Never returns a partial or best-guess result.
        """

    @abstractmethod
    def verify(self, data: str, result: SignatureResult) -> bool:
        """
        Verify a previously-produced signature against the
        SAME data it was originally signed over, using ONLY
        the embedded public key on the result — never a live
        keyring lookup. Must work correctly even if the
        signing key has since been rotated out of the user's
        active keyring.

        Returns:
            True if the signature is valid, False otherwise.
            Never raises for an INVALID signature — that's a
            normal, expected verification outcome, not an
            error. Raises SigningError only for genuine
            infrastructure failures (binary missing, malformed
            input).
        """
