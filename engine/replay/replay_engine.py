# engine/replay/replay_engine.py

# Purpose:
# Re-execute stored governance evaluations for
# audit verification and regression testing.
#
# Responsibilities:
# - Accept stored audit artifacts as replay input
# - Re-execute evaluation with stored context
# - Compare replayed decision to original decision
# - Produce structured replay outcome artifact
# - Surface decision drift if policy has changed
#
# IMPORTANT:
# Replay results are analytical artifacts ONLY.
# They NEVER produce enforcement decisions
# that affect live infrastructure.
#
# PERSISTENCE NOTE:
# The replay engine currently accepts the stored
# input_context directly. Full persistence integration
# (loading from audit store by decision_id) is Phase 5+.
#
# USE CASES:
# - Audit decision reproducibility
# - Regression testing against stored baselines
# - Verify policy changes don't alter past decisions
# - Compliance audit trail reconstruction


import uuid
from datetime import datetime, timezone

from audit.audit_logger import get_logger
from engine.orchestrator import PolicyOrchestrator
from engine.replay.replay_schema import (
    ReplayOutcome,
    ReplayRequest,
)

logger = get_logger()


def execute_replay(
    request: ReplayRequest,
) -> ReplayOutcome:
    """
    Execute a governance replay against a stored
    audit artifact.

    Re-runs the evaluation using the stored input_context
    and the policy at policy_path. Compares the replayed
    decision to the original decision.

    Args:
        request: ReplayRequest containing original
                 decision context and policy path.

    Returns:
        ReplayOutcome with comparison results and
        full replayed evaluation artifact.
    """

    replay_id = str(uuid.uuid4())
    replay_timestamp = datetime.now(timezone.utc).isoformat()

    logger.info(
        "replay_started",
        extra={
            "extra": {
                "replay_id": replay_id,
                "original_decision_id": request.original_decision_id,
                "policy_path": request.policy_path,
                "replay_role": request.replay_role,
                "replay_label": request.replay_label,
            }
        },
    )

    try:
        # =============================================
        # RECONSTRUCT ORCHESTRATOR
        # Load policy from path and re-execute
        # with the stored input context.
        # =============================================

        orchestrator = PolicyOrchestrator.from_policy_path(request.policy_path)

        replayed_result = orchestrator.evaluate(
            context=request.stored_input_context,
            user_role=request.replay_role,
        )

        # =============================================
        # COMPARE RESULTS
        # =============================================

        original_decision = _extract_original_decision(request)

        replayed_decision = replayed_result.get("decision", "UNKNOWN")

        decision_matches = original_decision == replayed_decision

        original_conditions = _extract_original_conditions(request)

        replayed_conditions = replayed_result.get("conditions_passed", False)

        conditions_match = original_conditions == replayed_conditions

        original_risk = _extract_original_risk_score(request)

        replayed_risk = replayed_result.get("risk_summary", {}).get(
            "overall_risk_score", 0
        )

        risk_delta = replayed_risk - (original_risk or 0)

        # =============================================
        # BUILD OUTCOME
        # =============================================

        if not decision_matches:
            logger.warning(
                "replay_decision_drift_detected",
                extra={
                    "extra": {
                        "replay_id": replay_id,
                        "original_decision_id": request.original_decision_id,
                        "original_decision": original_decision,
                        "replayed_decision": replayed_decision,
                    }
                },
            )

        outcome = ReplayOutcome(
            replay_id=replay_id,
            original_decision_id=request.original_decision_id,
            replay_label=request.replay_label,
            original_decision=original_decision,
            replayed_decision=replayed_decision,
            decision_matches=decision_matches,
            original_conditions_passed=original_conditions,
            replayed_conditions_passed=replayed_conditions,
            conditions_match=conditions_match,
            original_risk_score=original_risk,
            replayed_risk_score=replayed_risk,
            risk_delta=risk_delta,
            replayed_result=replayed_result,
            replay_status="SUCCESS",
            replay_timestamp=replay_timestamp,
        )

        logger.info(
            "replay_completed",
            extra={
                "extra": {
                    "replay_id": replay_id,
                    "original_decision_id": request.original_decision_id,
                    "original_decision": original_decision,
                    "replayed_decision": replayed_decision,
                    "decision_matches": decision_matches,
                    "conditions_match": conditions_match,
                    "risk_delta": risk_delta,
                }
            },
        )

        return outcome

    except Exception as error:
        logger.error(
            "replay_failed",
            extra={
                "extra": {
                    "replay_id": replay_id,
                    "original_decision_id": request.original_decision_id,
                    "error": str(error),
                }
            },
        )

        return ReplayOutcome(
            replay_id=replay_id,
            original_decision_id=request.original_decision_id,
            replay_label=request.replay_label,
            original_decision="UNKNOWN",
            replayed_decision="UNKNOWN",
            decision_matches=False,
            original_conditions_passed=False,
            replayed_conditions_passed=False,
            conditions_match=False,
            original_risk_score=None,
            replayed_risk_score=0,
            risk_delta=0,
            replayed_result={},
            replay_status="FAILED",
            replay_timestamp=replay_timestamp,
            error=str(error),
        )


# =====================================================
# HELPERS — EXTRACT FROM STORED CONTEXT
# =====================================================


def _extract_original_decision(
    request: ReplayRequest,
) -> str:
    """
    NOTE:
    The replay request carries stored_input_context
    but not the original audit artifact directly.
    In full persistence integration, the replay engine
    fetches the original artifact by decision_id
    from the audit store.

    For now: the caller is expected to pass the original
    decision via the request label or the orchestrator
    re-evaluation is the source of truth.

    TODO: Phase 5+ — fetch from audit store by decision_id.
    """
    return "UNKNOWN_ORIGINAL"


def _extract_original_conditions(
    request: ReplayRequest,
) -> bool:
    """
    TODO: Phase 5+ — fetch from audit store by decision_id.
    """
    return False


def _extract_original_risk_score(
    request: ReplayRequest,
) -> float | None:
    """
    TODO: Phase 5+ — fetch from audit store by decision_id.
    """
    return None
