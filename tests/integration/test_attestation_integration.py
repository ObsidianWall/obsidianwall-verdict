# tests/integration/test_attestation_integration.py
#
# Proves the FULL attestation chain works together — not any
# one component in isolation (already covered by
# test_gpg_backend.py / test_ssh_backend.py /
# test_os_keystore_backend.py), but the SEAM between them:
#
#   sign (a real SigningBackend)
#     → persist (add_history_entry, real SQLite)
#     → retrieve (get_governance_history, same real SQLite)
#     → re-verify (verify_signature, dispatching back to the
#       SAME backend type)
#
# This is exactly the class of bug unit tests structurally
# cannot catch: each piece could pass its own tests perfectly
# while the WIRING between them is still wrong (mismatched
# field names, wrong dispatch logic, a value one side produces
# that the other side doesn't correctly consume).
#
# Uses a real, throwaway GPG key — GPG is the one backend
# confirmed working in EVERY environment tested so far
# (sandbox, WSL, and implicitly Windows via Gpg4win if
# present), making it the right choice for a test that must
# run reliably in CI, not just on one developer's machine.

from __future__ import annotations

import shutil
import subprocess
import uuid

import pytest

from tests.helpers.telemetry_patching import patch_telemetry

from telemetry.governance_store import (
    hash_history_data,
    add_history_entry,
    create_governance_record,
    get_governance_history,
    verify_signature,
)
from telemetry.signing.gpg_backend import GPGSigningBackend

pytestmark = pytest.mark.skipif(
    shutil.which("gpg") is None, reason="gpg binary not available"
)

_TEST_EMAIL = "integration-test@example.com"


@pytest.fixture
def isolated_gpg_key(tmp_path, monkeypatch):
    gnupg_home = tmp_path / "gnupg_home"
    gnupg_home.mkdir()
    gnupg_home.chmod(0o700)

    key_config = (
        "%no-protection\n"
        "Key-Type: EDDSA\n"
        "Key-Curve: Ed25519\n"
        "Name-Real: Integration Test Key\n"
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


def _make_override_eligible_record(db_path) -> str:
    result = {
        "decision_id": str(uuid.uuid4()),
        "decision": "DENY_WITH_OVERRIDE",
        "policy": "integration_test_policy",
        "conditions_passed": False,
        "governance_severity": "medium",
        "override_possible": True,
        "requires_approval": False,
        "timestamp": "2026-07-31T00:00:00+00:00",
        "risk_summary": {"overall_risk_score": 75, "effective_severity": "critical"},
    }
    with pytest_mock_telemetry_enabled():
        create_governance_record(result=result, db_path=db_path)
    return result["decision_id"]


def pytest_mock_telemetry_enabled():
    return patch_telemetry(enabled=True)


class TestAttestationEndToEnd:
    def test_signed_entry_round_trips_through_real_database(
        self, isolated_gpg_key, tmp_path
    ):
        """
        The core chain: sign → persist → retrieve → re-verify,
        through a REAL SQLite database, not a mock. This is
        the FIRST test in this whole session that proves the
        seam between the signing backends and the storage
        layer, rather than either half alone.
        """
        db_path = tmp_path / "integration_test.db"
        record_id = _make_override_eligible_record(db_path)

        backend = GPGSigningBackend(key_id=_TEST_EMAIL)
        history_data = {"reason": "Integration test approval"}
        history_hash = hash_history_data(history_data)

        signature_result = backend.sign(history_hash)

        with pytest_mock_telemetry_enabled():
            success = add_history_entry(
                record_id=record_id,
                history_category="override",
                history_action="approved",
                history_data=history_data,
                actor_identity=_TEST_EMAIL,
                signature=signature_result.signature,
                signing_public_key=signature_result.public_key,
                signing_key_fingerprint=signature_result.key_fingerprint,
                signing_method=signature_result.signing_method,
                db_path=db_path,
            )
        assert success is True

        # Retrieve through the REAL storage layer — not the
        # object we just built in memory. Proves persistence
        # genuinely round-trips, not just that the in-memory
        # values were self-consistent.
        history = get_governance_history(record_id, db_path=db_path)
        approved_entry = [h for h in history if h["history_action"] == "approved"][0]

        assert approved_entry["signature"] == signature_result.signature
        assert approved_entry["signing_method"] == "gpg"

        # Re-verify using ONLY what's in the database — proves
        # verify_signature() correctly dispatches back to
        # GPGSigningBackend and that self-contained verification
        # (embedded public key, no live keyring dependency)
        # genuinely works through the real storage round-trip.
        verification = verify_signature(record_id, db_path=db_path)

        assert verification["signed"] is True
        assert verification["verified"] is True
        assert verification["signing_method"] == "gpg"

    def test_tampered_history_data_fails_verification_after_round_trip(
        self, isolated_gpg_key, tmp_path
    ):
        """
        If the history_data were somehow altered after
        signing but before storage, verification must catch
        it — proving the chain doesn't just check "is there
        a signature present" but "does it actually match
        what's stored."
        """
        db_path = tmp_path / "tamper_test.db"
        record_id = _make_override_eligible_record(db_path)

        backend = GPGSigningBackend(key_id=_TEST_EMAIL)
        original_data = {"reason": "Original reason"}
        original_hash = hash_history_data(original_data)
        signature_result = backend.sign(original_hash)

        # Store a DIFFERENT history_data than what was signed —
        # simulates a scenario where the signature and the
        # stored data have diverged.
        tampered_data = {"reason": "Tampered reason"}

        with pytest_mock_telemetry_enabled():
            add_history_entry(
                record_id=record_id,
                history_category="override",
                history_action="approved",
                history_data=tampered_data,
                actor_identity=_TEST_EMAIL,
                signature=signature_result.signature,
                signing_public_key=signature_result.public_key,
                signing_key_fingerprint=signature_result.key_fingerprint,
                signing_method=signature_result.signing_method,
                db_path=db_path,
            )

        verification = verify_signature(record_id, db_path=db_path)

        assert verification["signed"] is True
        assert verification["verified"] is False

    def test_unsigned_entry_reports_correctly(self, tmp_path):
        """
        An entry with no signature at all (e.g. pre-attestation
        historical data) must report signed=False, verified=None
        — never crash, never falsely claim verification.
        """
        db_path = tmp_path / "unsigned_test.db"
        record_id = _make_override_eligible_record(db_path)

        with pytest_mock_telemetry_enabled():
            add_history_entry(
                record_id=record_id,
                history_category="override",
                history_action="requested",
                history_data={"reason": "No signature on this one"},
                db_path=db_path,
            )

        verification = verify_signature(record_id, db_path=db_path)

        assert verification["signed"] is False
        assert verification["verified"] is None