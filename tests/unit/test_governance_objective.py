# tests/unit/test_governance_objective.py
#
# Tests for engine/governance_objective.py

from engine.governance_objective import compute_governance_objective


class TestComputeGovernanceObjective:
    def test_returns_none_when_no_objective_declared(self):
        policy = {"metadata": {"name": "test_policy"}}
        result = compute_governance_objective(policy, "ALLOW")
        assert result is None

    def test_returns_none_when_metadata_missing(self):
        policy = {}
        result = compute_governance_objective(policy, "ALLOW")
        assert result is None

    def test_returns_none_when_statement_missing(self):
        policy = {"metadata": {"governance_objective": {}}}
        result = compute_governance_objective(policy, "ALLOW")
        assert result is None

    def test_upheld_for_allow(self):
        policy = {
            "metadata": {
                "governance_objective": {
                    "statement": "Maintain cloud spend within approved budget"
                }
            }
        }
        result = compute_governance_objective(policy, "ALLOW")
        assert result == {
            "statement": "Maintain cloud spend within approved budget",
            "status": "Upheld",
        }

    def test_upheld_for_allow_with_notification(self):
        policy = {
            "metadata": {
                "governance_objective": {"statement": "Stay within budget"}
            }
        }
        result = compute_governance_objective(
            policy, "ALLOW_WITH_NOTIFICATION"
        )
        assert result["status"] == "Upheld"

    def test_violated_for_deny(self):
        policy = {
            "metadata": {
                "governance_objective": {"statement": "Stay within budget"}
            }
        }
        result = compute_governance_objective(policy, "DENY")
        assert result["status"] == "Violated"

    def test_violated_for_deny_with_override(self):
        policy = {
            "metadata": {
                "governance_objective": {"statement": "Stay within budget"}
            }
        }
        result = compute_governance_objective(
            policy, "DENY_WITH_OVERRIDE"
        )
        assert result["status"] == "Violated"

    def test_pending_for_approval_required(self):
        policy = {
            "metadata": {
                "governance_objective": {"statement": "Stay within budget"}
            }
        }
        result = compute_governance_objective(
            policy, "ALLOW_WITH_APPROVAL_REQUIRED"
        )
        assert result["status"] == "Pending Approval"

    def test_never_raises_on_malformed_policy(self):
        policy = {"metadata": None}
        try:
            result = compute_governance_objective(policy, "ALLOW")
        except Exception as exc:
            assert False, f"raised unexpectedly: {exc}"
        assert result is None

    def test_never_raises_on_malformed_objective(self):
        policy = {"metadata": {"governance_objective": "not_a_dict"}}
        try:
            result = compute_governance_objective(policy, "ALLOW")
        except Exception as exc:
            assert False, f"raised unexpectedly: {exc}"
        assert result is None

    def test_statement_preserved_exactly(self):
        statement_text = "Maintain cloud spend within approved budget"
        policy = {
            "metadata": {
                "governance_objective": {"statement": statement_text}
            }
        }
        result = compute_governance_objective(policy, "DENY")
        assert result["statement"] == statement_text


class TestComputeGovernanceObjectiveEdgeCases:
    def test_returns_none_when_objective_declared_but_statement_missing(self):
        """
        Covers line 77 — `if not statement: return None`.
        Distinct from the "no governance_objective block at
        all" case (already covered elsewhere): this is a policy
        that DOES declare governance_objective, but with no
        statement key, or an empty one — the intermediate case
        between "nothing declared" and "fully declared".
        """
        policy_dict = {
            "metadata": {
                "governance_objective": {
                    # statement deliberately absent
                }
            }
        }

        result = compute_governance_objective(
            policy_dict=policy_dict,
            decision="ALLOW",
        )

        assert result is None

    def test_returns_none_when_statement_is_empty_string(self):
        """
        Same code path (falsy check), different concrete input —
        an explicitly empty string should be treated the same
        as a missing key, not as "declared."
        """
        policy_dict = {
            "metadata": {
                "governance_objective": {
                    "statement": ""
                }
            }
        }

        result = compute_governance_objective(
            policy_dict=policy_dict,
            decision="ALLOW",
        )

        assert result is None

    def test_status_is_unknown_for_unrecognized_decision(self):
        """
        Covers line 86 — the `else: status = "Unknown"` fallback.
        Every existing test fixture's decision value maps to one
        of the three known sets (UPHELD/VIOLATED/PENDING); a
        genuinely unrecognized decision string closes this gap,
        mirroring the same fix already applied to
        telemetry/governance_objectives.py's analogous fallback.
        """
        policy_dict = {
            "metadata": {
                "governance_objective": {
                    "statement": "Some real objective statement"
                }
            }
        }

        result = compute_governance_objective(
            policy_dict=policy_dict,
            decision="SOME_UNRECOGNIZED_DECISION",
        )

        assert result is not None
        assert result["status"] == "Unknown"
        assert result["statement"] == "Some real objective statement"