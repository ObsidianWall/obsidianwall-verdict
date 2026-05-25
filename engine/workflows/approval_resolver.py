# engine/workflows/approval_resolver.py

# Purpose:
# Build structured governance approval requests.
#
# Responsibilities:
# - Determine approval requirement
# - Build approval chain per required approver role
# - Assign initial PENDING status per approver
# - Compute approval request expiry
# - Produce approval request artifact
# - Log approval workflow initiation
#
# IMPORTANT:
# This module NEVER approves or rejects deployments.
# It produces an approval request structure only.
# Actual approval state management requires persistence
# and is a later-phase integration concern.
#
# APPROVAL STATE LIFECYCLE:
# PENDING   → awaiting approver action
# APPROVED  → all required approvers approved
# REJECTED  → one or more approvers rejected
# EXPIRED   → approval window elapsed without resolution
#
# PERSISTENCE NOTE:
# The approval request produced here should be stored
# in a persistent approval tracking system.
# That integration is Phase 5+ work.


import uuid

from datetime import datetime, timezone, timedelta
from audit.audit_logger import get_logger


logger = get_logger()


# =====================================================
# APPROVAL STATUS
# =====================================================

class ApprovalStatus:
    PENDING     = "PENDING"
    APPROVED    = "APPROVED"
    REJECTED    = "REJECTED"
    EXPIRED     = "EXPIRED"
    NOT_REQUIRED = "NOT_REQUIRED"


# =====================================================
# APPROVAL EXPIRY
# =====================================================

# Default approval window in hours.
# TODO: Make configurable via policy governance config.
DEFAULT_APPROVAL_WINDOW_HOURS = 24

SEVERITY_APPROVAL_WINDOWS = {
    "critical":     4,      # 4 hours — urgent
    "high":         12,     # 12 hours
    "medium":       24,     # 24 hours — default
    "low":          48,     # 48 hours
    "informational": 72,    # 72 hours
}


# =====================================================
# APPROVAL CONTEXT BUILDER
# =====================================================

def _build_approval_context(
    policy_name: str,
    decision: str,
    evaluation_result: dict,
    risk_summary: dict,
) -> dict:
    """
    Build the context block carried by the approval request.
    Provides approvers with everything they need to make
    an informed decision.
    """

    trace           = evaluation_result.get("trace", [])
    conditions_passed = evaluation_result.get(
        "conditions_passed", False
    )
    overall_risk    = risk_summary.get(
        "overall_risk_score", 0
    )
    effective_severity = risk_summary.get(
        "effective_severity", "medium"
    )
    total_findings  = risk_summary.get("total_findings", 0)
    highest_analyzer = risk_summary.get(
        "highest_risk_analyzer"
    )

    # Build failed condition summary for approvers
    failed_conditions = [
        {
            "condition_id": t.get("condition_id"),
            "expression":   t.get("expression"),
            "description":  t.get("description"),
        }
        for t in trace
        if not t.get("result")
    ]

    return {
        "policy_name":          policy_name,
        "decision":             decision,
        "conditions_passed":    conditions_passed,
        "failed_conditions":    failed_conditions,
        "overall_risk_score":   overall_risk,
        "effective_severity":   effective_severity,
        "total_findings":       total_findings,
        "highest_risk_analyzer": highest_analyzer,
        "governance_severity":  evaluation_result.get(
            "governance_severity", "medium"
        ),
    }


# =====================================================
# APPROVER CHAIN BUILDER
# =====================================================

def _build_approver_chain(
    required_approvers: list[str],
) -> list[dict]:
    """
    Build the approval chain with one entry per
    required approver role. All start as PENDING.
    """

    chain = []

    for approver_role in required_approvers:

        chain.append({
            "approver_role":    approver_role,
            "status":           ApprovalStatus.PENDING,

            # These fields are populated when
            # the approver takes action.
            "approved_at":      None,
            "rejected_at":      None,
            "approver_comment": None,

            # NOTE:
            # approver_id is populated when the approval
            # request is claimed by a specific user.
            # Requires auth integration — Phase 5+.
            "approver_id":      None,
        })

    return chain


# =====================================================
# EXPIRY CALCULATOR
# =====================================================

def _compute_expiry(
    effective_severity: str,
) -> str:
    """
    Compute approval request expiry timestamp.
    Severity-aware — critical decisions expire faster.
    """

    window_hours = SEVERITY_APPROVAL_WINDOWS.get(
        effective_severity,
        DEFAULT_APPROVAL_WINDOW_HOURS,
    )

    expiry = datetime.now(timezone.utc) + timedelta(
        hours=window_hours
    )

    return expiry.isoformat()


# =====================================================
# APPROVAL RESOLVER
# =====================================================

def build_approval_request(
    decision_id: str,
    policy_name: str,
    evaluation_result: dict,
    risk_summary: dict,
    policy_governance: dict | None = None,
) -> dict:
    """
    Build a structured governance approval request.

    Produces an approval request artifact containing:
    - Unique approval request ID
    - Approval chain (one entry per required approver)
    - Approval context (everything approvers need)
    - Expiry timestamp (severity-aware)
    - Initial PENDING status

    Args:
        decision_id:        ID from the parent evaluation
        policy_name:        Name of the evaluated policy
        evaluation_result:  Full evaluation result dict
        risk_summary:       Consolidated risk summary
        policy_governance:  Serialized governance config

    Returns:
        Approval request dict if approval is required.
        NOT_REQUIRED artifact if no approval needed.

    Raises:
        TypeError:  if required inputs are not correct types.
        ValueError: if decision_id is empty.
    """

    # =================================================
    # BOUNDARY VALIDATION
    # =================================================

    if not isinstance(evaluation_result, dict):
        raise TypeError("evaluation_result must be a dict")

    if not isinstance(risk_summary, dict):
        raise TypeError("risk_summary must be a dict")

    if not isinstance(decision_id, str) or not decision_id:
        raise ValueError(
            "decision_id must be a non-empty string"
        )

    # =================================================
    # CHECK APPROVAL REQUIREMENT
    # =================================================

    requires_approval = evaluation_result.get(
        "requires_approval", False
    )

    if not requires_approval:

        artifact = {
            "approval_required":    False,
            "approval_status":      ApprovalStatus.NOT_REQUIRED,
            "reason": (
                "Governance decision does not require "
                "formal approval."
            ),
        }

        logger.info(
            "approval_not_required",
            extra={
                "extra": {
                    "decision_id":  decision_id,
                    "policy_name":  policy_name,
                }
            }
        )

        return artifact

    # =================================================
    # EXTRACT REQUIRED APPROVERS
    # =================================================

    required_approvers = []

    if policy_governance:

        approvals = policy_governance.get("approvals")

        if approvals:
            required_approvers = approvals.get(
                "required", []
            )

    if not required_approvers:

        # Approval required but no approvers configured —
        # flag as a governance configuration error.

        logger.warning(
            "approval_required_no_approvers_configured",
            extra={
                "extra": {
                    "decision_id":  decision_id,
                    "policy_name":  policy_name,
                }
            }
        )

        return {
            "approval_required":    True,
            "approval_status":      ApprovalStatus.PENDING,
            "approval_request_id":  str(uuid.uuid4()),
            "required_approvers":   [],
            "approver_chain":       [],
            "warning": (
                "Approval is required but no approver roles "
                "are configured in the governance policy. "
                "Contact your governance administrator."
            ),
            "context": _build_approval_context(
                policy_name=policy_name,
                decision=evaluation_result.get(
                    "decision", "UNKNOWN"
                ),
                evaluation_result=evaluation_result,
                risk_summary=risk_summary,
            ),
        }

    # =================================================
    # BUILD APPROVAL REQUEST
    # =================================================

    approval_request_id = str(uuid.uuid4())

    effective_severity = risk_summary.get(
        "effective_severity", "medium"
    )

    expiry = _compute_expiry(effective_severity)

    approver_chain = _build_approver_chain(
        required_approvers
    )

    approval_context = _build_approval_context(
        policy_name=policy_name,
        decision=evaluation_result.get(
            "decision", "UNKNOWN"
        ),
        evaluation_result=evaluation_result,
        risk_summary=risk_summary,
    )

    # =================================================
    # APPROVAL GUIDANCE
    # =================================================

    window_hours = SEVERITY_APPROVAL_WINDOWS.get(
        effective_severity,
        DEFAULT_APPROVAL_WINDOW_HOURS,
    )

    guidance = (
        f"This deployment requires approval from "
        f"{len(required_approvers)} role(s): "
        f"{', '.join(required_approvers)}. "
        f"All required approvers must approve before "
        f"deployment can proceed. "
        f"This request expires in {window_hours} hours."
    )

    artifact = {

        "approval_required":        True,

        "approval_status":          ApprovalStatus.PENDING,

        "approval_request_id":      approval_request_id,

        # Parent evaluation this approval belongs to.
        "decision_id":              decision_id,

        "policy_name":              policy_name,

        "required_approvers":       required_approvers,

        "approver_count":           len(required_approvers),

        # One entry per required approver.
        # All start PENDING.
        "approver_chain":           approver_chain,

        # Approval window is severity-aware.
        "expires_at":               expiry,

        "approval_window_hours":    window_hours,

        "guidance":                 guidance,

        # Full context for approvers to make
        # an informed decision.
        "context":                  approval_context,

        # NOTE:
        # These fields are populated by the approval
        # tracking system when the request resolves.
        # Persistence integration is Phase 5+.
        "resolved_at":              None,
        "resolution":               None,

    }

    logger.info(
        "approval_request_built",
        extra={
            "extra": {
                "approval_request_id":  approval_request_id,
                "decision_id":          decision_id,
                "policy_name":          policy_name,
                "required_approvers":   required_approvers,
                "approver_count":       len(required_approvers),
                "effective_severity":   effective_severity,
                "expires_at":           expiry,
                "window_hours":         window_hours,
            }
        }
    )

    return artifact
