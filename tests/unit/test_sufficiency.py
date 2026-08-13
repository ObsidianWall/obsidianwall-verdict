# tests/unit/test_sufficiency.py
#
# Tests for context/observers/sufficiency.py — the
# pre-evaluation missing-evidence gate.

from __future__ import annotations

from context.observers.sufficiency import (
    EvaluationOutcome,
    InsufficiencyReason,
    check_sufficiency,
    infer_required_context_keys,
)


def _make_policy(*expressions: str) -> dict:
    # Real schema (confirmed against schemas/policy_schema.py and
    # real working policy files) has NO "policy:" wrapper —
    # apiVersion/kind/metadata/spec are top-level. This fixture
    # previously used a wrapper that never existed in the real
    # schema — internally consistent with sufficiency.py's OWN
    # (also wrong, now fixed) assumption, which is exactly why
    # these tests passed while the real code path was silently
    # broken against actual policy files.
    return {
        "metadata": {"name": "test_policy"},
        "spec": {
            "conditions": [
                {"id": f"cond_{i}", "expression": expr}
                for i, expr in enumerate(expressions)
            ]
        },
    }


class TestInferRequiredContextKeys:
    def test_extracts_single_referenced_key(self):
        policy = _make_policy("open_ingress_rules <= 0")
        assert infer_required_context_keys(policy) == {"open_ingress_rules"}

    def test_extracts_multiple_keys_across_conditions(self):
        policy = _make_policy(
            "open_ingress_rules <= 0", "public_storage_buckets == 0"
        )
        assert infer_required_context_keys(policy) == {
            "open_ingress_rules",
            "public_storage_buckets",
        }

    def test_ignores_non_context_identifiers(self):
        """
        budget.amount is a POLICY parameter, not an
        observer-produced context key — must not be
        treated as something an observer needs to supply.
        """
        policy = _make_policy("(current_spend + estimated_cost) <= budget.amount")
        keys = infer_required_context_keys(policy)
        assert "budget" not in keys
        assert "amount" not in keys

    def test_empty_conditions_returns_empty_set(self):
        policy = _make_policy()
        assert infer_required_context_keys(policy) == set()

    def test_expression_with_no_known_keys_returns_empty(self):
        policy = _make_policy("some_unrelated_field == 5")
        assert infer_required_context_keys(policy) == set()


class TestCheckSufficiency:
    def test_sufficient_when_all_keys_present(self):
        policy = _make_policy("public_storage_buckets == 0")
        context = {"resources": [], "public_storage_buckets": 0}

        result = check_sufficiency(policy, context)

        assert result.sufficient is True
        assert result.outcome == EvaluationOutcome.EVALUATED

    def test_insufficient_when_key_missing(self):
        policy = _make_policy("open_ingress_rules <= 0")
        context = {"resources": [], "public_storage_buckets": 0}
        # observed context has NO open_ingress_rules key at all

        result = check_sufficiency(policy, context)

        assert result.sufficient is False
        assert result.outcome == EvaluationOutcome.POLICY_NOT_EVALUATED
        assert result.reason == InsufficiencyReason.UNSUPPORTED
        assert "open_ingress_rules" in result.missing_keys

    def test_partial_coverage_still_insufficient(self):
        """
        A policy referencing TWO keys where only ONE is
        present must still be marked insufficient — partial
        coverage is not sufficient coverage.
        """
        policy = _make_policy(
            "public_storage_buckets == 0", "open_ingress_rules <= 0"
        )
        context = {"resources": [], "public_storage_buckets": 0}

        result = check_sufficiency(policy, context)

        assert result.sufficient is False
        assert result.missing_keys == {"open_ingress_rules"}

    def test_collection_error_routes_to_collection_failed(self):
        policy = _make_policy("public_storage_buckets == 0")
        context: dict = {}

        result = check_sufficiency(
            policy, context, collection_error="insufficient Azure permission"
        )

        assert result.sufficient is False
        assert result.reason == InsufficiencyReason.COLLECTION_FAILED
        assert "insufficient Azure permission" in result.detail

    def test_no_conditions_always_sufficient(self):
        policy = _make_policy()
        context: dict = {"resources": []}

        result = check_sufficiency(policy, context)

        assert result.sufficient is True

    def test_result_to_dict_shape(self):
        policy = _make_policy("open_ingress_rules <= 0")
        context: dict = {"resources": []}

        result = check_sufficiency(policy, context)
        result_dict = result.to_dict()

        assert result_dict["outcome"] == "policy_not_evaluated"
        assert result_dict["reason"] == "unsupported"
        assert "open_ingress_rules" in result_dict["missing_keys"]

    def test_evaluated_outcome_never_used_for_missing_evidence(self):
        """
        Guards the core guarantee: EVALUATED must never be
        returned when required evidence is missing — this is
        what prevents a sixth pseudo-decision from ever being
        confused with a real governance decision.
        """
        policy = _make_policy("unencrypted_databases == 0")
        context: dict = {"resources": []}  # missing the key entirely

        result = check_sufficiency(policy, context)

        assert result.outcome != EvaluationOutcome.EVALUATED