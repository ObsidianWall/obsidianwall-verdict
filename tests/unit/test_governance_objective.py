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