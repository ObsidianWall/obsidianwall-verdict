
# engine/replay/simulation_engine.py

# Purpose:
# Execute what-if governance simulations with
# parameter overrides against stored evaluations.
#
# Responsibilities:
# - Accept stored audit context + parameter overrides
# - Apply overrides to evaluation context
# - Re-execute governance evaluation
# - Compare simulated decision to original
# - Produce structured simulation narrative
# - Surface decision sensitivity to parameter changes
#
# IMPORTANT:
# Simulation results are analytical artifacts ONLY.
# They NEVER produce enforcement decisions
# that affect live infrastructure.
#
# USE CASES:
# - "What if budget.amount was $200 instead of $50?"
# - "What if this ran in a production environment?"
# - "What if the engineer had budget_owner role?"
# - Policy threshold calibration
# - Governance impact analysis before policy changes


import uuid

from datetime import datetime, timezone

from engine.orchestrator import PolicyOrchestrator

from engine.replay.replay_schema import (
    SimulationRequest,
    SimulationOutcome,
)

from audit.audit_logger import get_logger


logger = get_logger()


# =====================================================
# SIMULATION NARRATIVE BUILDER
# =====================================================

def _build_simulation_narrative(
    parameter_overrides: dict,
    original_decision: str,
    simulated_decision: str,
    decision_changed: bool,
    risk_delta: float,
    simulated_conditions_passed: bool,
) -> str:
    """
    Build a plain-English narrative describing what
    the simulation changed and what the outcome was.
    """

    override_summary = ", ".join(
        f"{k}={v}"
        for k, v in parameter_overrides.items()
    )

    if not decision_changed:

        narrative = (
            f"Simulation applied parameter overrides "
            f"({override_summary}). "
            f"The governance decision remained unchanged: "
            f"{simulated_decision}. "
            f"The policy is not sensitive to these "
            f"parameter changes under current conditions."
        )

    else:

        direction = (
            "improved" if simulated_conditions_passed
            else "worsened"
        )

        narrative = (
            f"Simulation applied parameter overrides "
            f"({override_summary}). "
            f"The governance decision changed from "
            f"'{original_decision}' to '{simulated_decision}'. "
            f"Governance posture {direction} under "
            f"simulated conditions. "
        )

        if risk_delta > 0:
            narrative += (
                f"Risk score increased by {risk_delta:.1f} points."
            )
        elif risk_delta < 0:
            narrative += (
                f"Risk score decreased by {abs(risk_delta):.1f} points."
            )

    return narrative


# =====================================================
# PARAMETER OVERRIDE APPLICATION
# =====================================================

def _apply_overrides(
    base_context: dict,
    parameter_overrides: dict,
) -> dict:
    """
    Apply simulation parameter overrides to the
    base input context.

    Overrides are applied as top-level context keys.
    Dot-notation keys (e.g. "budget.amount") override
    flattened parameters directly.

    The base context is never mutated —
    a copy is always produced.
    """

    simulated_context = dict(base_context)

    for key, value in parameter_overrides.items():
        simulated_context[key] = value

    return simulated_context


# =====================================================
# SIMULATION ENGINE
# =====================================================

def execute_simulation(
    request: SimulationRequest,
) -> SimulationOutcome:
    """
    Execute a what-if governance simulation.

    Applies parameter overrides to the stored evaluation
    context and re-executes the governance pipeline.
    Compares simulated outcome to the original decision.

    Args:
        request: SimulationRequest containing original
                 context, policy path, and overrides.

    Returns:
        SimulationOutcome with comparison, narrative,
        and full simulated evaluation artifact.
    """

    simulation_id       = str(uuid.uuid4())
    simulation_timestamp = datetime.now(timezone.utc).isoformat()

    logger.info(
        "simulation_started",
        extra={
            "extra": {
                "simulation_id":            simulation_id,
                "original_decision_id":     request.original_decision_id,
                "policy_path":              request.policy_path,
                "parameter_overrides":      request.parameter_overrides,
                "simulation_role":          request.simulation_role,
                "simulation_label":         request.simulation_label,
            }
        }
    )

    try:

        # =============================================
        # APPLY PARAMETER OVERRIDES
        # =============================================

        simulated_context = _apply_overrides(
            base_context=request.stored_input_context,
            parameter_overrides=request.parameter_overrides,
        )

        # =============================================
        # EXECUTE SIMULATION
        # =============================================

        orchestrator = PolicyOrchestrator.from_policy_path(
            request.policy_path
        )

        simulated_result = orchestrator.evaluate(
            context=simulated_context,
            user_role=request.simulation_role,
        )

        # =============================================
        # COMPARE TO ORIGINAL
        # TODO: Phase 5+ — fetch original from audit store
        # For now, original values are passed through
        # request or inferred from re-evaluation without
        # overrides.
        # =============================================

        # Run baseline (no overrides) for comparison
        baseline_result = orchestrator.evaluate(
            context=request.stored_input_context,
            user_role=request.simulation_role,
        )

        original_decision = baseline_result.get(
            "decision", "UNKNOWN"
        )

        simulated_decision = simulated_result.get(
            "decision", "UNKNOWN"
        )

        decision_changed = (
            original_decision != simulated_decision
        )

        original_conditions = baseline_result.get(
            "conditions_passed", False
        )

        simulated_conditions = simulated_result.get(
            "conditions_passed", False
        )

        conditions_changed = (
            original_conditions != simulated_conditions
        )

        original_risk = (
            baseline_result.get("risk_summary", {})
            .get("overall_risk_score", 0)
        )

        simulated_risk = (
            simulated_result.get("risk_summary", {})
            .get("overall_risk_score", 0)
        )

        risk_delta = simulated_risk - original_risk

        # =============================================
        # BUILD NARRATIVE
        # =============================================

        narrative = _build_simulation_narrative(
            parameter_overrides=request.parameter_overrides,
            original_decision=original_decision,
            simulated_decision=simulated_decision,
            decision_changed=decision_changed,
            risk_delta=risk_delta,
            simulated_conditions_passed=simulated_conditions,
        )

        # =============================================
        # BUILD OUTCOME
        # =============================================

        outcome = SimulationOutcome(
            simulation_id=simulation_id,
            original_decision_id=request.original_decision_id,
            simulation_label=request.simulation_label,
            parameter_overrides=request.parameter_overrides,
            original_decision=original_decision,
            simulated_decision=simulated_decision,
            decision_changed=decision_changed,
            original_conditions_passed=original_conditions,
            simulated_conditions_passed=simulated_conditions,
            conditions_changed=conditions_changed,
            original_risk_score=original_risk,
            simulated_risk_score=simulated_risk,
            risk_delta=risk_delta,
            simulation_narrative=narrative,
            simulated_result=simulated_result,
            simulation_status="SUCCESS",
            simulation_timestamp=simulation_timestamp,
        )

        logger.info(
            "simulation_completed",
            extra={
                "extra": {
                    "simulation_id":            simulation_id,
                    "original_decision_id":     request.original_decision_id,
                    "original_decision":        original_decision,
                    "simulated_decision":       simulated_decision,
                    "decision_changed":         decision_changed,
                    "conditions_changed":       conditions_changed,
                    "risk_delta":               risk_delta,
                    "parameter_overrides":      request.parameter_overrides,
                }
            }
        )

        return outcome

    except Exception as error:

        logger.error(
            "simulation_failed",
            extra={
                "extra": {
                    "simulation_id":            simulation_id,
                    "original_decision_id":     request.original_decision_id,
                    "error":                    str(error),
                }
            }
        )

        return SimulationOutcome(
            simulation_id=simulation_id,
            original_decision_id=request.original_decision_id,
            simulation_label=request.simulation_label,
            parameter_overrides=request.parameter_overrides,
            original_decision="UNKNOWN",
            simulated_decision="UNKNOWN",
            decision_changed=False,
            original_conditions_passed=False,
            simulated_conditions_passed=False,
            conditions_changed=False,
            original_risk_score=None,
            simulated_risk_score=0,
            risk_delta=0,
            simulation_narrative=f"Simulation failed: {error}",
            simulated_result={},
            simulation_status="FAILED",
            simulation_timestamp=simulation_timestamp,
            error=str(error),
        )
