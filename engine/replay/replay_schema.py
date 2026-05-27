# engine/replay/replay_schema.py

# Purpose:
# Define replay and simulation request/result schemas.
#
# Responsibilities:
# - Replay request contract
# - Simulation request contract
# - Replay result contract
# - Simulation result contract
#
# IMPORTANT:
# Replay and simulation are read-only operations.
# They NEVER produce new enforcement decisions
# that affect live infrastructure.
# Results are analytical artifacts only.


from typing import Optional

from pydantic import BaseModel

# =====================================================
# REPLAY REQUEST
# =====================================================


class ReplayRequest(BaseModel):
    """
    Request to replay a stored governance evaluation.

    The replay engine re-executes the evaluation using
    the stored runtime_context and policy, producing
    a new result that can be compared to the original.

    Use cases:
    - Verify decision reproducibility
    - Audit that policy changes would not alter
      historical decisions
    - Regression testing against stored baselines
    """

    # The original audit artifact to replay
    original_decision_id: str

    # Path to the policy file used in original evaluation.
    # NOTE: Policy storage integration replaces this
    # with policy_id lookup in Phase 5+.
    policy_path: str

    # The stored input context from the original audit.
    # Sourced from audit_artifact["input_context"].
    stored_input_context: dict

    # Role of the user in the replay context.
    # May differ from original to test role-based outcomes.
    replay_role: Optional[str] = "engineer"

    # Optional label for this replay run.
    replay_label: Optional[str] = None


# =====================================================
# SIMULATION REQUEST
# =====================================================


class SimulationRequest(BaseModel):
    """
    Request to simulate a what-if governance evaluation.

    The simulation engine applies parameter overrides
    to a stored evaluation context and re-executes,
    showing what the decision would have been under
    different conditions.

    Use cases:
    - "What if the budget was $200 instead of $50?"
    - "What if this was a production environment?"
    - "What if the engineer had budget_owner role?"
    - Policy tuning and threshold calibration
    """

    # The original audit artifact to simulate against
    original_decision_id: str

    # Path to the policy file
    policy_path: str

    # The stored input context from original audit
    stored_input_context: dict

    # Parameter overrides applied before re-evaluation.
    # Keys are flattened dot-notation or context keys.
    # Example: {"budget.amount": 200, "environment": "dev"}
    parameter_overrides: dict

    # Role override for simulation
    simulation_role: Optional[str] = "engineer"

    # Human-readable description of this simulation
    simulation_label: Optional[str] = None


# =====================================================
# REPLAY RESULT
# =====================================================


class ReplayOutcome(BaseModel):
    """
    Result of a governance replay execution.
    """

    # Identity
    replay_id: str
    original_decision_id: str
    replay_label: Optional[str]

    # Decision comparison
    original_decision: str
    replayed_decision: str
    decision_matches: bool

    # Condition comparison
    original_conditions_passed: bool
    replayed_conditions_passed: bool
    conditions_match: bool

    # Risk comparison
    original_risk_score: Optional[float]
    replayed_risk_score: float
    risk_delta: float

    # Full replayed result
    replayed_result: dict

    # Replay metadata
    replay_status: str  # SUCCESS | FAILED
    replay_timestamp: str
    error: Optional[str] = None


# =====================================================
# SIMULATION RESULT
# =====================================================


class SimulationOutcome(BaseModel):
    """
    Result of a governance simulation execution.
    """

    # Identity
    simulation_id: str
    original_decision_id: str
    simulation_label: Optional[str]

    # Parameter overrides applied
    parameter_overrides: dict

    # Decision comparison
    original_decision: str
    simulated_decision: str
    decision_changed: bool

    # Condition comparison
    original_conditions_passed: bool
    simulated_conditions_passed: bool
    conditions_changed: bool

    # Risk comparison
    original_risk_score: Optional[float]
    simulated_risk_score: float
    risk_delta: float

    # What-if narrative
    simulation_narrative: str

    # Full simulated result
    simulated_result: dict

    # Simulation metadata
    simulation_status: str  # SUCCESS | FAILED
    simulation_timestamp: str
    error: Optional[str] = None
