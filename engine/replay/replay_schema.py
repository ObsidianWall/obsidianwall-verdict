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

from typing import Any, Optional

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

    original_decision_id:  str
    policy_path:           str
    stored_input_context:  dict[str, Any]
    replay_role:           Optional[str] = "engineer"
    replay_label:          Optional[str] = None


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

    original_decision_id:  str
    policy_path:           str
    stored_input_context:  dict[str, Any]
    parameter_overrides:   dict[str, Any]
    simulation_role:       Optional[str] = "engineer"
    simulation_label:      Optional[str] = None


# =====================================================
# REPLAY RESULT
# =====================================================


class ReplayOutcome(BaseModel):
    """Result of a governance replay execution."""

    replay_id:                   str
    original_decision_id:        str
    replay_label:                Optional[str]

    original_decision:           str
    replayed_decision:           str
    decision_matches:            bool

    original_conditions_passed:  bool
    replayed_conditions_passed:  bool
    conditions_match:            bool

    original_risk_score:         Optional[float]
    replayed_risk_score:         float
    risk_delta:                  float

    replayed_result:             dict[str, Any]

    replay_status:               str   # SUCCESS | FAILED
    replay_timestamp:            str
    error:                       Optional[str] = None


# =====================================================
# SIMULATION RESULT
# =====================================================


class SimulationOutcome(BaseModel):
    """Result of a governance simulation execution."""

    simulation_id:               str
    original_decision_id:        str
    simulation_label:            Optional[str]

    parameter_overrides:         dict[str, Any]

    original_decision:           str
    simulated_decision:          str
    decision_changed:            bool

    original_conditions_passed:  bool
    simulated_conditions_passed: bool
    conditions_changed:          bool

    original_risk_score:         Optional[float]
    simulated_risk_score:        float
    risk_delta:                  float

    simulation_narrative:        str
    simulated_result:            dict[str, Any]

    simulation_status:           str   # SUCCESS | FAILED
    simulation_timestamp:        str
    error:                       Optional[str] = None
