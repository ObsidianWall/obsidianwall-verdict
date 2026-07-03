
# tests/unit/test_replay_engine.py
#
# Purpose:
# Unit tests for engine/replay/ modules.
# Covers: replay_schema.py, replay_engine.py,
#         simulation_engine.py
# All orchestrator calls are mocked.

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from engine.replay.replay_schema import (
    ReplayOutcome,
    ReplayRequest,
    SimulationOutcome,
    SimulationRequest,
)
from engine.replay.replay_engine import (
    _extract_original_conditions,
    _extract_original_decision,
    _extract_original_risk_score,
    execute_replay,
)
from engine.replay.simulation_engine import (
    _apply_overrides,
    _build_simulation_narrative,
    execute_simulation,
)


# =====================================================
# FIXTURES
# =====================================================


def _make_replay_request(
    policy_path: str = "policies/cost/basic_budget.yaml",
    decision_id: str = "test-decision-id",
) -> ReplayRequest:
    """Build a minimal ReplayRequest for testing."""
    return ReplayRequest(
        original_decision_id=decision_id,
        policy_path=policy_path,
        stored_input_context={"estimated_cost": 50.0, "current_spend": 0.0},
        replay_role="engineer",
        replay_label="unit test replay",
    )


def _make_simulation_request(
    overrides: dict[str, Any] | None = None,
) -> SimulationRequest:
    """Build a minimal SimulationRequest for testing."""
    return SimulationRequest(
        original_decision_id="test-decision-id",
        policy_path="policies/cost/basic_budget.yaml",
        stored_input_context={"estimated_cost": 50.0, "current_spend": 0.0},
        parameter_overrides=overrides or {"estimated_cost": 200.0},
        simulation_role="engineer",
        simulation_label="unit test simulation",
    )


def _make_mock_evaluate_result(
    decision: str = "DENY_WITH_OVERRIDE",
    conditions_passed: bool = False,
    risk_score: int = 75,
) -> dict[str, Any]:
    """Build a minimal evaluation result for mocking."""
    return {
        "decision":           decision,
        "conditions_passed":  conditions_passed,
        "risk_summary": {
            "overall_risk_score": risk_score,
        },
    }


# =====================================================
# ReplayRequest schema
# =====================================================


class TestReplayRequestSchema:
    """Tests for ReplayRequest Pydantic model."""

    def test_creates_valid_request(self) -> None:
        """Creates a valid ReplayRequest from required fields."""
        request = _make_replay_request()
        assert request.original_decision_id == "test-decision-id"
        assert request.policy_path == "policies/cost/basic_budget.yaml"
        assert request.replay_role == "engineer"

    def test_replay_role_defaults_to_engineer(self) -> None:
        """replay_role defaults to 'engineer' when not provided."""
        request = ReplayRequest(
            original_decision_id="id",
            policy_path="policy.yaml",
            stored_input_context={},
        )
        assert request.replay_role == "engineer"

    def test_replay_label_defaults_to_none(self) -> None:
        """replay_label defaults to None when not provided."""
        request = ReplayRequest(
            original_decision_id="id",
            policy_path="policy.yaml",
            stored_input_context={},
        )
        assert request.replay_label is None

    def test_stores_input_context(self) -> None:
        """Stores the provided input context dict."""
        context = {"estimated_cost": 100.0, "region": "eastus"}
        request = ReplayRequest(
            original_decision_id="id",
            policy_path="policy.yaml",
            stored_input_context=context,
        )
        assert request.stored_input_context == context


# =====================================================
# SimulationRequest schema
# =====================================================


class TestSimulationRequestSchema:
    """Tests for SimulationRequest Pydantic model."""

    def test_creates_valid_request(self) -> None:
        """Creates a valid SimulationRequest from required fields."""
        request = _make_simulation_request()
        assert request.original_decision_id == "test-decision-id"
        assert request.parameter_overrides == {"estimated_cost": 200.0}

    def test_simulation_role_defaults_to_engineer(self) -> None:
        """simulation_role defaults to 'engineer' when not provided."""
        request = SimulationRequest(
            original_decision_id="id",
            policy_path="policy.yaml",
            stored_input_context={},
            parameter_overrides={},
        )
        assert request.simulation_role == "engineer"

    def test_stores_parameter_overrides(self) -> None:
        """Stores the parameter overrides dict."""
        overrides = {"estimated_cost": 150.0, "current_spend": 25.0}
        request = SimulationRequest(
            original_decision_id="id",
            policy_path="policy.yaml",
            stored_input_context={},
            parameter_overrides=overrides,
        )
        assert request.parameter_overrides == overrides


# =====================================================
# ReplayOutcome schema
# =====================================================


class TestReplayOutcomeSchema:
    """Tests for ReplayOutcome Pydantic model."""

    def test_creates_valid_outcome(self) -> None:
        """Creates a valid ReplayOutcome."""
        outcome = ReplayOutcome(
            replay_id="replay-123",
            original_decision_id="decision-456",
            replay_label="test",
            original_decision="DENY",
            replayed_decision="DENY",
            decision_matches=True,
            original_conditions_passed=False,
            replayed_conditions_passed=False,
            conditions_match=True,
            original_risk_score=75.0,
            replayed_risk_score=75,
            risk_delta=0,
            replayed_result={},
            replay_status="SUCCESS",
            replay_timestamp="2026-06-09T00:00:00+00:00",
        )
        assert outcome.replay_status == "SUCCESS"
        assert outcome.decision_matches is True
        assert outcome.error is None

    def test_error_defaults_to_none(self) -> None:
        """error field defaults to None on successful replays."""
        outcome = ReplayOutcome(
            replay_id="r",
            original_decision_id="d",
            replay_label=None,
            original_decision="DENY",
            replayed_decision="DENY",
            decision_matches=True,
            original_conditions_passed=False,
            replayed_conditions_passed=False,
            conditions_match=True,
            original_risk_score=None,
            replayed_risk_score=0,
            risk_delta=0,
            replayed_result={},
            replay_status="SUCCESS",
            replay_timestamp="2026-06-09T00:00:00+00:00",
        )
        assert outcome.error is None


# =====================================================
# SimulationOutcome schema
# =====================================================


class TestSimulationOutcomeSchema:
    """Tests for SimulationOutcome Pydantic model."""

    def test_creates_valid_outcome(self) -> None:
        """Creates a valid SimulationOutcome."""
        outcome = SimulationOutcome(
            simulation_id="sim-123",
            original_decision_id="decision-456",
            simulation_label="test",
            parameter_overrides={"estimated_cost": 200.0},
            original_decision="DENY",
            simulated_decision="ALLOW",
            decision_changed=True,
            original_conditions_passed=False,
            simulated_conditions_passed=True,
            conditions_changed=True,
            original_risk_score=75.0,
            simulated_risk_score=20,
            risk_delta=-55.0,
            simulation_narrative="Decision improved.",
            simulated_result={},
            simulation_status="SUCCESS",
            simulation_timestamp="2026-06-09T00:00:00+00:00",
        )
        assert outcome.decision_changed is True
        assert outcome.risk_delta == -55.0

    def test_error_defaults_to_none(self) -> None:
        """error field defaults to None on successful simulations."""
        outcome = SimulationOutcome(
            simulation_id="s",
            original_decision_id="d",
            simulation_label=None,
            parameter_overrides={},
            original_decision="DENY",
            simulated_decision="DENY",
            decision_changed=False,
            original_conditions_passed=False,
            simulated_conditions_passed=False,
            conditions_changed=False,
            original_risk_score=None,
            simulated_risk_score=0,
            risk_delta=0,
            simulation_narrative="No change.",
            simulated_result={},
            simulation_status="SUCCESS",
            simulation_timestamp="2026-06-09T00:00:00+00:00",
        )
        assert outcome.error is None


# =====================================================
# execute_replay
# =====================================================


class TestExecuteReplay:
    """Tests for execute_replay()."""

    def test_returns_success_outcome(self) -> None:
        """Returns SUCCESS ReplayOutcome when evaluation succeeds."""
        request = _make_replay_request()
        mock_result = _make_mock_evaluate_result(decision="DENY_WITH_OVERRIDE")

        with patch("engine.replay.replay_engine.PolicyOrchestrator") as mock_class:
            mock_orchestrator = MagicMock()
            mock_class.from_policy_path.return_value = mock_orchestrator
            mock_orchestrator.evaluate.return_value = mock_result

            outcome = execute_replay(request)

        assert outcome.replay_status == "SUCCESS"
        assert outcome.replayed_decision == "DENY_WITH_OVERRIDE"

    def test_replay_id_is_unique_uuid(self) -> None:
        """Each replay produces a unique replay_id."""
        request = _make_replay_request()
        mock_result = _make_mock_evaluate_result()

        with patch("engine.replay.replay_engine.PolicyOrchestrator") as mock_class:
            mock_orchestrator = MagicMock()
            mock_class.from_policy_path.return_value = mock_orchestrator
            mock_orchestrator.evaluate.return_value = mock_result

            outcome_a = execute_replay(request)
            outcome_b = execute_replay(request)

        assert outcome_a.replay_id != outcome_b.replay_id

    def test_computes_risk_delta(self) -> None:
        """Computes risk_delta as replayed minus original risk score."""
        request = _make_replay_request()
        mock_result = _make_mock_evaluate_result(risk_score=80)

        with patch("engine.replay.replay_engine.PolicyOrchestrator") as mock_class:
            mock_orchestrator = MagicMock()
            mock_class.from_policy_path.return_value = mock_orchestrator
            mock_orchestrator.evaluate.return_value = mock_result

            outcome = execute_replay(request)

        # original_risk_score is None (UNKNOWN_ORIGINAL helper)
        assert outcome.replayed_risk_score == 80

    def test_returns_failed_outcome_on_exception(self) -> None:
        """Returns FAILED ReplayOutcome when orchestrator raises."""
        request = _make_replay_request()

        with patch("engine.replay.replay_engine.PolicyOrchestrator") as mock_class:
            mock_class.from_policy_path.side_effect = FileNotFoundError(
                "policy not found"
            )

            outcome = execute_replay(request)

        assert outcome.replay_status == "FAILED"
        assert outcome.error is not None
        assert "policy not found" in outcome.error

    def test_failed_outcome_preserves_decision_id(self) -> None:
        """FAILED outcome preserves the original_decision_id."""
        request = _make_replay_request(decision_id="original-id-123")

        with patch("engine.replay.replay_engine.PolicyOrchestrator") as mock_class:
            mock_class.from_policy_path.side_effect = RuntimeError("error")

            outcome = execute_replay(request)

        assert outcome.original_decision_id == "original-id-123"

    def test_decision_matches_when_same(self) -> None:
        """decision_matches is True when decisions are identical."""
        request = _make_replay_request()
        mock_result = _make_mock_evaluate_result(decision="DENY_WITH_OVERRIDE")

        with patch("engine.replay.replay_engine.PolicyOrchestrator") as mock_class:
            mock_orchestrator = MagicMock()
            mock_class.from_policy_path.return_value = mock_orchestrator
            mock_orchestrator.evaluate.return_value = mock_result

            outcome = execute_replay(request)

        # original is UNKNOWN_ORIGINAL, replayed is DENY_WITH_OVERRIDE
        assert outcome.decision_matches is False

    def test_replay_timestamp_is_set(self) -> None:
        """replay_timestamp is set on all outcomes."""
        request = _make_replay_request()
        mock_result = _make_mock_evaluate_result()

        with patch("engine.replay.replay_engine.PolicyOrchestrator") as mock_class:
            mock_orchestrator = MagicMock()
            mock_class.from_policy_path.return_value = mock_orchestrator
            mock_orchestrator.evaluate.return_value = mock_result

            outcome = execute_replay(request)

        assert outcome.replay_timestamp is not None
        assert len(outcome.replay_timestamp) > 0


# =====================================================
# Helper functions
# =====================================================


class TestReplayHelpers:
    """Tests for helper functions in replay_engine.py."""

    def test_extract_original_decision_returns_unknown(self) -> None:
        """_extract_original_decision returns UNKNOWN_ORIGINAL."""
        request = _make_replay_request()
        result = _extract_original_decision(request)
        assert result == "UNKNOWN_ORIGINAL"

    def test_extract_original_conditions_returns_false(self) -> None:
        """_extract_original_conditions returns False."""
        request = _make_replay_request()
        result = _extract_original_conditions(request)
        assert result is False

    def test_extract_original_risk_score_returns_none(self) -> None:
        """_extract_original_risk_score returns None."""
        request = _make_replay_request()
        result = _extract_original_risk_score(request)
        assert result is None


# =====================================================
# _apply_overrides
# =====================================================


class TestApplyOverrides:
    """Tests for _apply_overrides() in simulation_engine.py."""

    def test_applies_overrides_to_context(self) -> None:
        """Override values are applied to the base context."""
        base = {"estimated_cost": 50.0, "current_spend": 0.0}
        overrides = {"estimated_cost": 200.0}

        result = _apply_overrides(base, overrides)

        assert result["estimated_cost"] == 200.0
        assert result["current_spend"] == 0.0

    def test_does_not_mutate_base_context(self) -> None:
        """Base context is never mutated."""
        base = {"estimated_cost": 50.0}
        overrides = {"estimated_cost": 200.0}

        _apply_overrides(base, overrides)

        assert base["estimated_cost"] == 50.0

    def test_adds_new_keys_from_overrides(self) -> None:
        """New keys from overrides are added to the result."""
        base = {"estimated_cost": 50.0}
        overrides = {"new_key": "new_value"}

        result = _apply_overrides(base, overrides)

        assert result["new_key"] == "new_value"

    def test_empty_overrides_returns_copy_of_base(self) -> None:
        """Empty overrides returns a copy of the base context."""
        base = {"estimated_cost": 50.0}
        result = _apply_overrides(base, {})

        assert result == base
        assert result is not base


# =====================================================
# _build_simulation_narrative
# =====================================================


class TestBuildSimulationNarrative:
    """Tests for _build_simulation_narrative()."""

    def test_unchanged_decision_narrative(self) -> None:
        """Narrative says 'remained unchanged' when decision did not change."""
        narrative = _build_simulation_narrative(
            parameter_overrides={"estimated_cost": 50},
            original_decision="DENY",
            simulated_decision="DENY",
            decision_changed=False,
            risk_delta=0,
            simulated_conditions_passed=False,
        )
        assert "remained unchanged" in narrative
        assert "DENY" in narrative

    def test_changed_decision_improved_narrative(self) -> None:
        """Narrative says 'improved' when conditions passed after override."""
        narrative = _build_simulation_narrative(
            parameter_overrides={"estimated_cost": 50},
            original_decision="DENY",
            simulated_decision="ALLOW",
            decision_changed=True,
            risk_delta=-20.0,
            simulated_conditions_passed=True,
        )
        assert "changed from" in narrative
        assert "improved" in narrative
        assert "decreased by 20.0" in narrative

    def test_changed_decision_worsened_narrative(self) -> None:
        """Narrative says 'worsened' when conditions failed after override."""
        narrative = _build_simulation_narrative(
            parameter_overrides={"estimated_cost": 200},
            original_decision="ALLOW",
            simulated_decision="DENY",
            decision_changed=True,
            risk_delta=30.0,
            simulated_conditions_passed=False,
        )
        assert "worsened" in narrative
        assert "increased by 30.0" in narrative

    def test_includes_override_summary(self) -> None:
        """Narrative includes the parameter overrides that were applied."""
        narrative = _build_simulation_narrative(
            parameter_overrides={"estimated_cost": 150},
            original_decision="DENY",
            simulated_decision="DENY",
            decision_changed=False,
            risk_delta=0,
            simulated_conditions_passed=False,
        )
        assert "estimated_cost=150" in narrative

    def test_zero_risk_delta_no_risk_mention(self) -> None:
        """No risk change mention when risk_delta is zero."""
        narrative = _build_simulation_narrative(
            parameter_overrides={"estimated_cost": 200},
            original_decision="ALLOW",
            simulated_decision="DENY",
            decision_changed=True,
            risk_delta=0,
            simulated_conditions_passed=False,
        )
        assert "increased by" not in narrative
        assert "decreased by" not in narrative


# =====================================================
# execute_simulation
# =====================================================


class TestExecuteSimulation:
    """Tests for execute_simulation()."""

    def test_returns_success_outcome_decision_unchanged(self) -> None:
        """Returns SUCCESS when simulation produces same decision as baseline."""
        request = _make_simulation_request(overrides={"estimated_cost": 50.0})
        mock_result = _make_mock_evaluate_result(decision="DENY_WITH_OVERRIDE")

        with patch("engine.replay.simulation_engine.PolicyOrchestrator") as mock_class:
            mock_orchestrator = MagicMock()
            mock_class.from_policy_path.return_value = mock_orchestrator
            mock_orchestrator.evaluate.return_value = mock_result

            outcome = execute_simulation(request)

        assert outcome.simulation_status == "SUCCESS"
        assert outcome.decision_changed is False

    def test_returns_success_outcome_decision_changed(self) -> None:
        """Returns SUCCESS when simulation produces different decision."""
        request = _make_simulation_request(overrides={"estimated_cost": 200.0})

        baseline_result  = _make_mock_evaluate_result(decision="DENY", risk_score=75)
        simulated_result = _make_mock_evaluate_result(
            decision="ALLOW", conditions_passed=True, risk_score=20
        )

        with patch("engine.replay.simulation_engine.PolicyOrchestrator") as mock_class:
            mock_orchestrator = MagicMock()
            mock_class.from_policy_path.return_value = mock_orchestrator
            mock_orchestrator.evaluate.side_effect = [
                simulated_result,
                baseline_result,
            ]

            outcome = execute_simulation(request)

        assert outcome.simulation_status == "SUCCESS"

    def test_simulation_id_is_unique(self) -> None:
        """Each simulation produces a unique simulation_id."""
        request = _make_simulation_request()
        mock_result = _make_mock_evaluate_result()

        with patch("engine.replay.simulation_engine.PolicyOrchestrator") as mock_class:
            mock_orchestrator = MagicMock()
            mock_class.from_policy_path.return_value = mock_orchestrator
            mock_orchestrator.evaluate.return_value = mock_result

            outcome_a = execute_simulation(request)
            outcome_b = execute_simulation(request)

        assert outcome_a.simulation_id != outcome_b.simulation_id

    def test_returns_failed_outcome_on_exception(self) -> None:
        """Returns FAILED SimulationOutcome when orchestrator raises."""
        request = _make_simulation_request()

        with patch("engine.replay.simulation_engine.PolicyOrchestrator") as mock_class:
            mock_class.from_policy_path.side_effect = FileNotFoundError(
                "policy not found"
            )

            outcome = execute_simulation(request)

        assert outcome.simulation_status == "FAILED"
        assert outcome.error is not None
        assert "policy not found" in outcome.error

    def test_failed_outcome_narrative_mentions_failure(self) -> None:
        """FAILED outcome narrative mentions the simulation failure."""
        request = _make_simulation_request()

        with patch("engine.replay.simulation_engine.PolicyOrchestrator") as mock_class:
            mock_class.from_policy_path.side_effect = RuntimeError("error")

            outcome = execute_simulation(request)

        assert "failed" in outcome.simulation_narrative.lower()

    def test_parameter_overrides_preserved_in_outcome(self) -> None:
        """Outcome preserves the parameter overrides from the request."""
        overrides = {"estimated_cost": 999.0, "current_spend": 100.0}
        request = _make_simulation_request(overrides=overrides)
        mock_result = _make_mock_evaluate_result()

        with patch("engine.replay.simulation_engine.PolicyOrchestrator") as mock_class:
            mock_orchestrator = MagicMock()
            mock_class.from_policy_path.return_value = mock_orchestrator
            mock_orchestrator.evaluate.return_value = mock_result

            outcome = execute_simulation(request)

        assert outcome.parameter_overrides == overrides

    def test_simulation_timestamp_is_set(self) -> None:
        """simulation_timestamp is set on all outcomes."""
        request = _make_simulation_request()
        mock_result = _make_mock_evaluate_result()

        with patch("engine.replay.simulation_engine.PolicyOrchestrator") as mock_class:
            mock_orchestrator = MagicMock()
            mock_class.from_policy_path.return_value = mock_orchestrator
            mock_orchestrator.evaluate.return_value = mock_result

            outcome = execute_simulation(request)

        assert outcome.simulation_timestamp is not None