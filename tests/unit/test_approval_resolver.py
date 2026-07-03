# tests/unit/test_approval_resolver.py
#
# Purpose:
# Unit tests for engine/workflows/approval_resolver.py.
# Covers: build_approval_request(), _build_approval_context(),
#         _build_approver_chain(), _compute_expiry()

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pytest

from engine.workflows.approval_resolver import (
    ApprovalStatus,
    DEFAULT_APPROVAL_WINDOW_HOURS,
    SEVERITY_APPROVAL_WINDOWS,
    _build_approval_context,
    _build_approver_chain,
    _compute_expiry,
    build_approval_request,
)


# =====================================================
# FIXTURES
# =====================================================


def _make_evaluation_result(
    decision:          str  = "DENY_PENDING_APPROVAL",
    conditions_passed: bool = False,
    requires_approval: bool = True,
    governance_severity: str = "medium",
    trace: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a minimal evaluation result dict for testing."""
    return {
        "decision":             decision,
        "conditions_passed":    conditions_passed,
        "requires_approval":    requires_approval,
        "governance_severity":  governance_severity,
        "trace":                trace or [],
    }


def _make_risk_summary(
    overall_risk_score: int  = 75,
    effective_severity: str  = "high",
    total_findings:     int  = 2,
    highest_risk_analyzer: str | None = "cost_analysis",
) -> dict[str, Any]:
    """Build a minimal risk summary dict for testing."""
    return {
        "overall_risk_score":     overall_risk_score,
        "effective_severity":     effective_severity,
        "total_findings":         total_findings,
        "highest_risk_analyzer":  highest_risk_analyzer,
    }


def _make_policy_governance(
    required_approvers: list[str] | None = None,
) -> dict[str, Any]:
    """Build a minimal policy governance config dict for testing."""
    return {
        "approvals": {
            "required": required_approvers or ["security_lead"],
        }
    }


# =====================================================
# _build_approval_context
# =====================================================


class TestBuildApprovalContext:

    def test_includes_policy_name(self) -> None:
        context = _build_approval_context(
            policy_name="test_policy",
            decision="DENY_PENDING_APPROVAL",
            evaluation_result=_make_evaluation_result(),
            risk_summary=_make_risk_summary(),
        )
        assert context["policy_name"] == "test_policy"

    def test_includes_decision(self) -> None:
        context = _build_approval_context(
            policy_name="test_policy",
            decision="DENY_PENDING_APPROVAL",
            evaluation_result=_make_evaluation_result(),
            risk_summary=_make_risk_summary(),
        )
        assert context["decision"] == "DENY_PENDING_APPROVAL"

    def test_includes_risk_score(self) -> None:
        context = _build_approval_context(
            policy_name="test_policy",
            decision="DENY_PENDING_APPROVAL",
            evaluation_result=_make_evaluation_result(),
            risk_summary=_make_risk_summary(overall_risk_score=80),
        )
        assert context["overall_risk_score"] == 80

    def test_extracts_failed_conditions_from_trace(self) -> None:
        trace = [
            {"condition_id": "budget_check",  "result": False,
             "expression": "estimated_cost <= 100", "description": "Budget check"},
            {"condition_id": "tagging_check", "result": True,
             "expression": "untagged == 0",        "description": "Tagging"},
        ]
        context = _build_approval_context(
            policy_name="test_policy",
            decision="DENY_PENDING_APPROVAL",
            evaluation_result=_make_evaluation_result(trace=trace),
            risk_summary=_make_risk_summary(),
        )
        failed = context["failed_conditions"]
        assert len(failed) == 1
        assert failed[0]["condition_id"] == "budget_check"

    def test_empty_failed_conditions_for_passing_trace(self) -> None:
        trace = [
            {"condition_id": "budget_check", "result": True,
             "expression": "estimated_cost <= 100", "description": ""},
        ]
        context = _build_approval_context(
            policy_name="test_policy",
            decision="ALLOW",
            evaluation_result=_make_evaluation_result(trace=trace),
            risk_summary=_make_risk_summary(),
        )
        assert context["failed_conditions"] == []

    def test_includes_highest_risk_analyzer(self) -> None:
        context = _build_approval_context(
            policy_name="test_policy",
            decision="DENY_PENDING_APPROVAL",
            evaluation_result=_make_evaluation_result(),
            risk_summary=_make_risk_summary(highest_risk_analyzer="topology_analysis"),
        )
        assert context["highest_risk_analyzer"] == "topology_analysis"


# =====================================================
# _build_approver_chain
# =====================================================


class TestBuildApproverChain:

    def test_builds_chain_for_single_approver(self) -> None:
        chain = _build_approver_chain(["security_lead"])
        assert len(chain) == 1
        assert chain[0]["approver_role"] == "security_lead"

    def test_builds_chain_for_multiple_approvers(self) -> None:
        chain = _build_approver_chain(["security_lead", "budget_owner", "ciso"])
        assert len(chain) == 3
        roles = [entry["approver_role"] for entry in chain]
        assert "security_lead" in roles
        assert "budget_owner"  in roles
        assert "ciso"          in roles

    def test_all_entries_start_as_pending(self) -> None:
        chain = _build_approver_chain(["security_lead", "budget_owner"])
        for entry in chain:
            assert entry["status"] == ApprovalStatus.PENDING

    def test_approved_at_is_none_initially(self) -> None:
        chain = _build_approver_chain(["security_lead"])
        assert chain[0]["approved_at"] is None

    def test_rejected_at_is_none_initially(self) -> None:
        chain = _build_approver_chain(["security_lead"])
        assert chain[0]["rejected_at"] is None

    def test_approver_id_is_none_initially(self) -> None:
        """approver_id is None until auth integration in Phase 5+."""
        chain = _build_approver_chain(["security_lead"])
        assert chain[0]["approver_id"] is None

    def test_empty_approver_list_returns_empty_chain(self) -> None:
        chain = _build_approver_chain([])
        assert chain == []


# =====================================================
# _compute_expiry
# =====================================================


class TestComputeExpiry:

    def test_returns_iso_format_string(self) -> None:
        expiry = _compute_expiry("medium")
        # Should parse without error
        datetime.fromisoformat(expiry)

    def test_critical_expiry_is_shortest(self) -> None:
        critical_hours = SEVERITY_APPROVAL_WINDOWS["critical"]
        medium_hours   = SEVERITY_APPROVAL_WINDOWS["medium"]
        assert critical_hours < medium_hours

    def test_expiry_is_in_the_future(self) -> None:
        expiry = _compute_expiry("medium")
        expiry_dt = datetime.fromisoformat(expiry)
        assert expiry_dt > datetime.now(timezone.utc)

    def test_unknown_severity_uses_default_window(self) -> None:
        expiry = _compute_expiry("unknown_severity")
        expiry_dt = datetime.fromisoformat(expiry)
        assert expiry_dt > datetime.now(timezone.utc)

    def test_each_severity_has_distinct_window(self) -> None:
        """Each severity produces a different expiry window."""
        windows = list(SEVERITY_APPROVAL_WINDOWS.values())
        assert len(windows) == len(set(windows))


# =====================================================
# build_approval_request — validation
# =====================================================


class TestBuildApprovalRequestValidation:

    def test_raises_type_error_for_non_dict_evaluation_result(self) -> None:
        with pytest.raises(TypeError, match="evaluation_result must be a dict"):
            build_approval_request(
                decision_id="test-id",
                policy_name="test_policy",
                evaluation_result="not a dict",  # type: ignore
                risk_summary=_make_risk_summary(),
            )

    def test_raises_type_error_for_non_dict_risk_summary(self) -> None:
        with pytest.raises(TypeError, match="risk_summary must be a dict"):
            build_approval_request(
                decision_id="test-id",
                policy_name="test_policy",
                evaluation_result=_make_evaluation_result(),
                risk_summary="not a dict",  # type: ignore
            )

    def test_raises_value_error_for_empty_decision_id(self) -> None:
        with pytest.raises(ValueError, match="decision_id must be a non-empty string"):
            build_approval_request(
                decision_id="",
                policy_name="test_policy",
                evaluation_result=_make_evaluation_result(),
                risk_summary=_make_risk_summary(),
            )


# =====================================================
# build_approval_request — not required
# =====================================================


class TestBuildApprovalRequestNotRequired:

    def test_returns_not_required_artifact(self) -> None:
        result = build_approval_request(
            decision_id="test-id",
            policy_name="test_policy",
            evaluation_result=_make_evaluation_result(requires_approval=False),
            risk_summary=_make_risk_summary(),
        )
        assert result["approval_required"] is False
        assert result["approval_status"]   == ApprovalStatus.NOT_REQUIRED

    def test_not_required_includes_reason(self) -> None:
        result = build_approval_request(
            decision_id="test-id",
            policy_name="test_policy",
            evaluation_result=_make_evaluation_result(requires_approval=False),
            risk_summary=_make_risk_summary(),
        )
        assert "reason" in result


# =====================================================
# build_approval_request — required, no approvers
# =====================================================


class TestBuildApprovalRequestRequiredNoApprovers:

    def test_returns_pending_with_warning(self) -> None:
        """Approval required but no approvers → PENDING with warning."""
        result = build_approval_request(
            decision_id="test-id",
            policy_name="test_policy",
            evaluation_result=_make_evaluation_result(requires_approval=True),
            risk_summary=_make_risk_summary(),
            policy_governance={"approvals": {"required": []}},
        )
        assert result["approval_required"] is True
        assert result["approval_status"]   == ApprovalStatus.PENDING
        assert "warning" in result

    def test_returns_pending_when_no_governance_config(self) -> None:
        """No governance config at all → PENDING with warning."""
        result = build_approval_request(
            decision_id="test-id",
            policy_name="test_policy",
            evaluation_result=_make_evaluation_result(requires_approval=True),
            risk_summary=_make_risk_summary(),
            policy_governance=None,
        )
        assert result["approval_required"] is True
        assert "warning" in result

    def test_context_included_in_warning_response(self) -> None:
        result = build_approval_request(
            decision_id="test-id",
            policy_name="test_policy",
            evaluation_result=_make_evaluation_result(requires_approval=True),
            risk_summary=_make_risk_summary(),
            policy_governance=None,
        )
        assert "context" in result


# =====================================================
# build_approval_request — required with approvers
# =====================================================


class TestBuildApprovalRequestWithApprovers:

    def test_returns_approval_request_artifact(self) -> None:
        result = build_approval_request(
            decision_id="test-id",
            policy_name="test_policy",
            evaluation_result=_make_evaluation_result(requires_approval=True),
            risk_summary=_make_risk_summary(),
            policy_governance=_make_policy_governance(["security_lead"]),
        )
        assert result["approval_required"] is True
        assert result["approval_status"]   == ApprovalStatus.PENDING

    def test_contains_unique_approval_request_id(self) -> None:
        result_a = build_approval_request(
            decision_id="test-id",
            policy_name="test_policy",
            evaluation_result=_make_evaluation_result(requires_approval=True),
            risk_summary=_make_risk_summary(),
            policy_governance=_make_policy_governance(["security_lead"]),
        )
        result_b = build_approval_request(
            decision_id="test-id",
            policy_name="test_policy",
            evaluation_result=_make_evaluation_result(requires_approval=True),
            risk_summary=_make_risk_summary(),
            policy_governance=_make_policy_governance(["security_lead"]),
        )
        assert result_a["approval_request_id"] != result_b["approval_request_id"]

    def test_approver_chain_has_correct_length(self) -> None:
        result = build_approval_request(
            decision_id="test-id",
            policy_name="test_policy",
            evaluation_result=_make_evaluation_result(requires_approval=True),
            risk_summary=_make_risk_summary(),
            policy_governance=_make_policy_governance(
                ["security_lead", "budget_owner"]
            ),
        )
        assert len(result["approver_chain"])    == 2
        assert len(result["required_approvers"]) == 2

    def test_approver_count_matches_chain_length(self) -> None:
        result = build_approval_request(
            decision_id="test-id",
            policy_name="test_policy",
            evaluation_result=_make_evaluation_result(requires_approval=True),
            risk_summary=_make_risk_summary(),
            policy_governance=_make_policy_governance(["security_lead"]),
        )
        assert result["approver_count"] == len(result["approver_chain"])

    def test_expiry_is_set(self) -> None:
        result = build_approval_request(
            decision_id="test-id",
            policy_name="test_policy",
            evaluation_result=_make_evaluation_result(requires_approval=True),
            risk_summary=_make_risk_summary(),
            policy_governance=_make_policy_governance(["security_lead"]),
        )
        assert "expires_at" in result
        datetime.fromisoformat(result["expires_at"])

    def test_severity_affects_window(self) -> None:
        """Critical decisions have shorter approval window."""
        critical_result = build_approval_request(
            decision_id="test-id",
            policy_name="test_policy",
            evaluation_result=_make_evaluation_result(requires_approval=True),
            risk_summary=_make_risk_summary(effective_severity="critical"),
            policy_governance=_make_policy_governance(["security_lead"]),
        )
        medium_result = build_approval_request(
            decision_id="test-id",
            policy_name="test_policy",
            evaluation_result=_make_evaluation_result(requires_approval=True),
            risk_summary=_make_risk_summary(effective_severity="medium"),
            policy_governance=_make_policy_governance(["security_lead"]),
        )
        assert critical_result["approval_window_hours"] < medium_result["approval_window_hours"]

    def test_guidance_mentions_approver_roles(self) -> None:
        result = build_approval_request(
            decision_id="test-id",
            policy_name="test_policy",
            evaluation_result=_make_evaluation_result(requires_approval=True),
            risk_summary=_make_risk_summary(),
            policy_governance=_make_policy_governance(["security_lead"]),
        )
        assert "security_lead" in result["guidance"]

    def test_context_block_is_included(self) -> None:
        result = build_approval_request(
            decision_id="test-id",
            policy_name="test_policy",
            evaluation_result=_make_evaluation_result(requires_approval=True),
            risk_summary=_make_risk_summary(),
            policy_governance=_make_policy_governance(["security_lead"]),
        )
        assert "context" in result
        assert result["context"]["policy_name"] == "test_policy"

    def test_resolved_at_is_none_initially(self) -> None:
        result = build_approval_request(
            decision_id="test-id",
            policy_name="test_policy",
            evaluation_result=_make_evaluation_result(requires_approval=True),
            risk_summary=_make_risk_summary(),
            policy_governance=_make_policy_governance(["security_lead"]),
        )
        assert result["resolved_at"] is None
        assert result["resolution"]  is None