# tests/unit/test_override_command.py
#
# Tests for cli/commands/override.py — the two-step
# request/approve/deny override workflow, including
# separation-of-duties enforcement on approve().
#
# Uses patch_telemetry() from tests/helpers/telemetry_patching.py
# instead of patching "telemetry.governance_store.
# is_telemetry_enabled"/"get_db_path" directly — since the
# module split, create_governance_record/add_history_entry/
# get_risk_acceptance_records each live in their own module
# with their own independent binding of these two names.
# Patching only governance_store's copies left override.py's
# real calls reading/writing the REAL default database instead
# of the test's isolated one, producing "No governance decision
# found" on lookups that should have succeeded.

import uuid
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from cli.commands.override import override_app
from telemetry.governance_store import (
    create_governance_record,
    get_governance_history,
    get_risk_acceptance_records,
)
from telemetry.signing.base_signing import SignatureResult, SigningError

from tests.helpers.telemetry_patching import patch_telemetry

runner = CliRunner()

_REQUESTER_IDENTITY = "requester@example.com"
_APPROVER_IDENTITY = "approver@example.com"


def _make_result(
    decision: str = "DENY_WITH_OVERRIDE",
    override_possible: bool = True,
) -> dict:
    return {
        "decision_id": str(uuid.uuid4()),
        "decision": decision,
        "policy": "budget_policy",
        "conditions_passed": False,
        "governance_severity": "medium",
        "override_possible": override_possible,
        "requires_approval": False,
        "timestamp": "2026-07-21T00:00:00+00:00",
        "risk_summary": {"overall_risk_score": 75, "effective_severity": "critical"},
    }


def _create_record(db_path, **kwargs) -> str:
    result = _make_result(**kwargs)
    with patch_telemetry(db_path=db_path, enabled=True):
        create_governance_record(result=result, db_path=db_path)
    return result["decision_id"]


def _make_fake_signing_backend() -> MagicMock:
    """
    A deterministic, always-succeeding fake signing backend —
    stands in for GPG/SSH/keystore so command-logic tests never
    depend on real cryptography being configured on whatever
    machine runs them.
    """
    fake_backend = MagicMock()
    fake_backend.method_name = "fake"
    fake_backend.sign.return_value = SignatureResult(
        signature="fake-signature",
        public_key="fake-public-key",
        key_fingerprint="fake-fingerprint-0123456789",
        signing_method="fake",
    )
    return fake_backend


def _invoke(
    app,
    args,
    db_path,
    signing_backend=None,
    actor_identity: str = _REQUESTER_IDENTITY,
):
    """
    Invoke a command with telemetry enabled and pointed at the
    test db across every module that independently needs it
    (see patch_telemetry), signing resolution mocked to a
    deterministic fake backend, AND resolve_actor_identity()
    mocked to a SPECIFIC identity for this call. Different
    calls in the same test can (and for approve-after-request
    tests, MUST) pass different actor_identity values, or the
    separation-of-duties check will correctly refuse
    self-approval.
    """
    if signing_backend is None:
        signing_backend = _make_fake_signing_backend()

    with patch_telemetry(db_path=db_path, enabled=True):
        with patch(
            "cli.commands.override._resolve_signing_backend",
            return_value=signing_backend,
        ):
            with patch(
                "cli.commands.override.resolve_actor_identity",
                return_value=actor_identity,
            ):
                return runner.invoke(app, args)


class TestOverrideRequest:
    def test_request_succeeds_on_eligible_decision(self, tmp_path):
        db = tmp_path / "test.db"
        record_id = _create_record(db)

        result = _invoke(
            override_app, ["request", record_id, "--reason", "Emergency patch"], db
        )

        assert result.exit_code == 0
        assert "Override requested" in result.output

        history = get_governance_history(record_id, db_path=db)
        override_entries = [h for h in history if h["history_category"] == "override"]
        assert len(override_entries) == 1
        assert override_entries[0]["history_action"] == "requested"

    def test_request_rejected_when_not_override_possible(self, tmp_path):
        db = tmp_path / "test.db"
        record_id = _create_record(db, override_possible=False)

        result = _invoke(
            override_app, ["request", record_id, "--reason", "test"], db
        )

        assert result.exit_code == 1
        assert "not eligible" in result.output

    def test_request_fails_without_reason(self, tmp_path):
        db = tmp_path / "test.db"
        record_id = _create_record(db)

        result = _invoke(override_app, ["request", record_id], db)

        assert result.exit_code != 0

    def test_request_fails_for_unknown_decision(self, tmp_path):
        db = tmp_path / "test.db"

        result = _invoke(
            override_app,
            ["request", "nonexistent12", "--reason", "test"],
            db,
        )

        assert result.exit_code == 1
        assert "No governance decision found" in result.output

    def test_request_fails_cleanly_when_no_signing_available(self, tmp_path):
        """
        Mandatory signing, no unsigned fallback — see ADR-0002.
        When _resolve_signing_backend() returns None (no GPG,
        no SSH, no functional OS keystore), the command must
        refuse cleanly rather than record anything unsigned.
        """
        db = tmp_path / "test.db"
        record_id = _create_record(db)

        with patch_telemetry(db_path=db, enabled=True):
            with patch(
                "cli.commands.override._resolve_signing_backend",
                return_value=None,
            ):
                with patch(
                    "cli.commands.override.resolve_actor_identity",
                    return_value=_REQUESTER_IDENTITY,
                ):
                    result = runner.invoke(
                        override_app,
                        ["request", record_id, "--reason", "test"],
                    )

        assert result.exit_code == 1
        assert "No signing method available" in result.output

        history = get_governance_history(record_id, db_path=db)
        override_entries = [h for h in history if h["history_category"] == "override"]
        assert len(override_entries) == 0

    def test_request_fails_cleanly_when_signing_raises(self, tmp_path):
        """
        A resolved backend that exists but fails to actually
        sign (e.g. a passphrase-protected key with no TTY —
        the real failure mode confirmed live tonight) must
        also refuse cleanly, not crash or record unsigned.
        """
        db = tmp_path / "test.db"
        record_id = _create_record(db)

        failing_backend = MagicMock()
        failing_backend.method_name = "gpg"
        failing_backend.sign.side_effect = SigningError("GPG signing failed: test failure")

        result = _invoke(
            override_app,
            ["request", record_id, "--reason", "test"],
            db,
            signing_backend=failing_backend,
        )

        assert result.exit_code == 1
        assert "Signing failed" in result.output


class TestOverrideApprove:
    def test_approve_fails_without_prior_request(self, tmp_path):
        db = tmp_path / "test.db"
        record_id = _create_record(db)

        result = _invoke(
            override_app,
            ["approve", record_id, "--reason", "Approved"],
            db,
            actor_identity=_APPROVER_IDENTITY,
        )

        assert result.exit_code == 1
        assert "No override request found" in result.output

    def test_approve_succeeds_after_request(self, tmp_path):
        db = tmp_path / "test.db"
        record_id = _create_record(db)

        _invoke(
            override_app, ["request", record_id, "--reason", "Emergency"], db,
            actor_identity=_REQUESTER_IDENTITY,
        )
        result = _invoke(
            override_app, ["approve", record_id, "--reason", "Confirmed with finance"], db,
            actor_identity=_APPROVER_IDENTITY,
        )

        assert result.exit_code == 0
        assert "Override approved" in result.output

    def test_approve_creates_confirmed_risk_acceptance(self, tmp_path):
        db = tmp_path / "test.db"
        record_id = _create_record(db)

        _invoke(
            override_app, ["request", record_id, "--reason", "Emergency"], db,
            actor_identity=_REQUESTER_IDENTITY,
        )
        _invoke(
            override_app, ["approve", record_id, "--reason", "Confirmed"], db,
            actor_identity=_APPROVER_IDENTITY,
        )

        records = get_risk_acceptance_records(db_path=db)
        assert len(records) == 1
        assert records[0]["record_id"] == record_id

    def test_approved_entry_is_signed(self, tmp_path):
        """
        Confirms the signature fields actually made it into
        the persisted history entry, not just that the
        command reported success.
        """
        db = tmp_path / "test.db"
        record_id = _create_record(db)

        _invoke(
            override_app, ["request", record_id, "--reason", "Emergency"], db,
            actor_identity=_REQUESTER_IDENTITY,
        )
        _invoke(
            override_app, ["approve", record_id, "--reason", "Confirmed"], db,
            actor_identity=_APPROVER_IDENTITY,
        )

        history = get_governance_history(record_id, db_path=db)
        approved_entry = [h for h in history if h["history_action"] == "approved"][0]

        assert approved_entry["signature"] == "fake-signature"
        assert approved_entry["signing_method"] == "fake"
        assert approved_entry["signing_key_fingerprint"] == "fake-fingerprint-0123456789"

    def test_cannot_approve_twice(self, tmp_path):
        """Once approved, a second approve without a new
        request must fail — enforces that the override is
        governed, not a repeatable rubber stamp. The second
        attempt uses a DIFFERENT identity again, so this test
        exercises the "already approved" check specifically,
        not the separation-of-duties check."""
        db = tmp_path / "test.db"
        record_id = _create_record(db)

        _invoke(
            override_app, ["request", record_id, "--reason", "Emergency"], db,
            actor_identity=_REQUESTER_IDENTITY,
        )
        _invoke(
            override_app, ["approve", record_id, "--reason", "Confirmed"], db,
            actor_identity=_APPROVER_IDENTITY,
        )
        second_approve = _invoke(
            override_app, ["approve", record_id, "--reason", "Again?"], db,
            actor_identity="a-third-person@example.com",
        )

        assert second_approve.exit_code == 1
        assert "already" in second_approve.output

    def test_new_request_allows_reapproval(self, tmp_path):
        """A denied request followed by a NEW request should
        be approvable — the history is append-only, so
        re-requesting after denial is a legitimate path."""
        db = tmp_path / "test.db"
        record_id = _create_record(db)

        _invoke(
            override_app, ["request", record_id, "--reason", "First try"], db,
            actor_identity=_REQUESTER_IDENTITY,
        )
        _invoke(
            override_app, ["deny", record_id, "--reason", "Not enough detail"], db,
            actor_identity=_APPROVER_IDENTITY,
        )
        _invoke(
            override_app, ["request", record_id, "--reason", "Second try, detailed"], db,
            actor_identity=_REQUESTER_IDENTITY,
        )
        result = _invoke(
            override_app, ["approve", record_id, "--reason", "Now confirmed"], db,
            actor_identity=_APPROVER_IDENTITY,
        )

        assert result.exit_code == 0

    def test_cannot_approve_own_request(self, tmp_path):
        """
        Dedicated coverage for the separation-of-duties check
        itself.
        """
        db = tmp_path / "test.db"
        record_id = _create_record(db)

        _invoke(
            override_app, ["request", record_id, "--reason", "Emergency"], db,
            actor_identity=_REQUESTER_IDENTITY,
        )
        result = _invoke(
            override_app, ["approve", record_id, "--reason", "Self-approved"], db,
            actor_identity=_REQUESTER_IDENTITY,
        )

        assert result.exit_code == 1
        assert "Separation of duties violation" in result.output

        history = get_governance_history(record_id, db_path=db)
        approved_entries = [h for h in history if h["history_action"] == "approved"]
        assert len(approved_entries) == 0

        records = get_risk_acceptance_records(db_path=db)
        assert records == []


class TestOverrideDeny:
    def test_deny_fails_without_prior_request(self, tmp_path):
        db = tmp_path / "test.db"
        record_id = _create_record(db)

        result = _invoke(
            override_app, ["deny", record_id, "--reason", "No"], db,
            actor_identity=_APPROVER_IDENTITY,
        )

        assert result.exit_code == 1

    def test_deny_succeeds_after_request(self, tmp_path):
        db = tmp_path / "test.db"
        record_id = _create_record(db)

        _invoke(
            override_app, ["request", record_id, "--reason", "Emergency"], db,
            actor_identity=_REQUESTER_IDENTITY,
        )
        result = _invoke(
            override_app, ["deny", record_id, "--reason", "Insufficient justification"], db,
            actor_identity=_APPROVER_IDENTITY,
        )

        assert result.exit_code == 0
        assert "Override denied" in result.output

    def test_denied_override_not_in_ledger(self, tmp_path):
        db = tmp_path / "test.db"
        record_id = _create_record(db)

        _invoke(
            override_app, ["request", record_id, "--reason", "Emergency"], db,
            actor_identity=_REQUESTER_IDENTITY,
        )
        _invoke(
            override_app, ["deny", record_id, "--reason", "No"], db,
            actor_identity=_APPROVER_IDENTITY,
        )

        records = get_risk_acceptance_records(db_path=db)
        assert records == []