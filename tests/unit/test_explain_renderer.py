# tests/unit/test_explain_renderer.py
#
# Tests for renderers/explain_renderer.py — the mid-tier
# detail view used by verdict explain.

from renderers.explain_renderer import (
    render_explain,
    _group_recommendations_by_category,
)


def _make_artifact(**overrides) -> dict:
    """Minimal artifact dict for testing render_explain()."""
    base = {
        "decision": "DENY_WITH_OVERRIDE",
        "policy": "test_policy",
        "decision_id": "abc12345-6789-4def-a123-456789abcdef",
        "timestamp": "2026-07-16T00:00:00+00:00",
        "governance_severity": "medium",
        "risk_summary": {
            "overall_risk_score": 75,
            "effective_severity": "critical",
            "risk_narrative": "Critical infrastructure risk detected.",
        },
        "trace": [
            {
                "condition_id": "budget_check",
                "expression": "(current_spend + estimated_cost) <= budget.amount",
                "description": "Monthly spend cap enforcement",
                "result": False,
            }
        ],
        "explanation": {
            "governance_reasoning": {
                "reasoning_chain": [
                    {
                        "sequence": 1,
                        "stage": "policy_intent",
                        "outcome": "Policy applied",
                        "reason": "Policy applied to this deployment.",
                        "severity": "medium",
                    }
                ]
            },
            "analyzer_findings": [
                {
                    "analyzer": "cost_analysis",
                    "type": "budget_exceeded",
                    "severity": "critical",
                    "message": "Projected spend exceeds budget.",
                }
            ],
            "explained_recommendations": {
                "all_recommendations": [
                    {
                        "type": "budget_exceeded",
                        "message": "Reduce projected cost.",
                        "priority_tier": "critical",
                        "priority_score": 95,
                        "recommendation_confidence": 0.95,
                        "estimated_savings_percent": 0,
                    },
                    {
                        "type": "missing_network_segmentation",
                        "message": "Add network segmentation.",
                        "priority_tier": "medium",
                        "priority_score": 70,
                        "recommendation_confidence": 0.75,
                        "estimated_savings_percent": 0,
                    },
                    {
                        "type": "enforcement",
                        "message": "Deployment blocked.",
                        "priority_tier": "high",
                        "priority_score": 95,
                        "recommendation_confidence": 1.0,
                        "estimated_savings_percent": 0,
                    },
                ]
            },
        },
        "notification_manifest": {
            "notifications": [
                {"target_role": "budget_owner", "channel": "email", "priority": "urgent"},
                {"target_role": "engineering_lead", "channel": "slack", "priority": "urgent"},
            ]
        },
        "approval_request": {"approval_status": "NOT_REQUIRED"},
        "override_possible": True,
        "governance_objective": {
            "statement": "Maintain cloud spend within approved budget",
            "status": "Violated",
        },
    }
    base.update(overrides)
    return base


# =====================================================
# render_explain — smoke tests (prints, doesn't return)
# =====================================================


class TestRenderExplain:
    def test_runs_without_raising_on_full_artifact(self, capsys):
        artifact = _make_artifact()
        try:
            render_explain(artifact)
        except Exception as exc:
            import pytest
            pytest.fail(f"render_explain raised unexpectedly: {exc}")

    def test_output_contains_decision(self, capsys):
        artifact = _make_artifact()
        render_explain(artifact)
        captured = capsys.readouterr()
        assert "DENY_WITH_OVERRIDE" in captured.out

    def test_output_contains_governance_objective(self, capsys):
        artifact = _make_artifact()
        render_explain(artifact)
        captured = capsys.readouterr()
        assert "Maintain cloud spend within approved budget" in captured.out
        assert "Violated" in captured.out

    def test_output_omits_objective_section_when_absent(self, capsys):
        artifact = _make_artifact(governance_objective=None)
        artifact.pop("governance_objective", None)
        render_explain(artifact)
        captured = capsys.readouterr()
        # Should not crash and should not show a stale objective
        assert "Maintain cloud spend" not in captured.out

    def test_output_contains_governance_routing(self, capsys):
        artifact = _make_artifact()
        render_explain(artifact)
        captured = capsys.readouterr()
        assert "budget_owner" in captured.out
        assert "engineering_lead" in captured.out

    def test_output_shows_request_exception_framing(self, capsys):
        """
        v0.6.0 fix: Override section reframed as an action
        ("Request Exception" heading) rather than a passive
        noun label, with remediation shown as a parallel
        alternative under a shared "Resolution Options"
        heading — not a mandatory follow-on step.
        """
        artifact = _make_artifact()
        render_explain(artifact)
        captured = capsys.readouterr()
        assert "Request Exception" in captured.out
        assert "request an override from:" in captured.out

    def test_resolution_options_shows_both_remediate_and_exception(self, capsys):
        """
        NEW: confirms remediation and override render as two
        parallel options under one shared "Resolution Options"
        heading, not override alone — the actual structural
        fix, not just the wording rename the previous test
        already covered. Added into the existing explanation
        dict rather than replacing it, so reasoning_chain and
        analyzer_findings (also required by other tests'
        assertions on the same fixture shape) stay intact.
        """
        artifact = _make_artifact()
        artifact["explanation"]["policy_reasoning"] = {
            "remediation_steps": ["Fix the underlying condition."]
        }
        render_explain(artifact)
        captured = capsys.readouterr()
        assert "Resolution Options" in captured.out
        assert "Remediate" in captured.out
        assert "Fix the underlying condition." in captured.out
        assert "Request Exception" in captured.out
 
    def test_output_contains_reasoning_chain(self, capsys):
        artifact = _make_artifact()
        render_explain(artifact)
        captured = capsys.readouterr()
        assert "policy_intent" in captured.out

    def test_output_contains_condition_trace(self, capsys):
        artifact = _make_artifact()
        render_explain(artifact)
        captured = capsys.readouterr()
        assert "budget_check" in captured.out

    def test_output_contains_analyzer_findings(self, capsys):
        artifact = _make_artifact()
        render_explain(artifact)
        captured = capsys.readouterr()
        assert "budget_exceeded" in captured.out

    def test_output_hides_raw_confidence_and_priority_score(self, capsys):
        """
        recommendation_confidence and priority_score are
        deliberately NOT shown in the explain text view —
        only priority_tier. Full raw values remain in
        --format json/yaml.
        """
        artifact = _make_artifact()
        render_explain(artifact)
        captured = capsys.readouterr()
        assert "0.95" not in captured.out
        assert "confidence=" not in captured.out

    def test_output_contains_evidence_section_with_hash(self, capsys):
        artifact = _make_artifact()
        render_explain(artifact, artifact_hash="9b262c1758e41e09")
        captured = capsys.readouterr()
        assert "sha256:9b262c1758e41e09" in captured.out

    def test_output_contains_evidence_recorded_timestamp(self, capsys):
        artifact = _make_artifact()
        render_explain(artifact, recorded_at="2026-07-16T09:06:52+00:00")
        captured = capsys.readouterr()
        assert "2026-07-16T09:06:52+00:00" in captured.out

    def test_output_shows_verified_integrity_status(self, capsys):
        artifact = _make_artifact()
        render_explain(artifact, chain_verified=True)
        captured = capsys.readouterr()
        assert "Verified" in captured.out
        assert "chain intact" in captured.out

    def test_output_shows_tampered_integrity_status(self, capsys):
        artifact = _make_artifact()
        render_explain(artifact, chain_verified=False)
        captured = capsys.readouterr()
        assert "TAMPERED" in captured.out

    def test_output_omits_integrity_line_when_not_provided(self, capsys):
        artifact = _make_artifact()
        render_explain(artifact, chain_verified=None)
        captured = capsys.readouterr()
        assert "Integrity" not in captured.out

    def test_handles_missing_optional_fields_gracefully(self, capsys):
        """
        A minimal artifact with only the required fields
        should not crash the renderer.
        """
        minimal = {
            "decision": "ALLOW",
            "policy": "minimal_policy",
            "decision_id": "abc123",
        }
        try:
            render_explain(minimal)
        except Exception as exc:
            import pytest
            pytest.fail(f"render_explain raised on minimal artifact: {exc}")

    def test_no_recommendations_section_when_empty(self, capsys):
        artifact = _make_artifact()
        artifact["explanation"]["explained_recommendations"]["all_recommendations"] = []
        render_explain(artifact)
        captured = capsys.readouterr()
        assert "RECOMMENDATIONS" not in captured.out.upper() or "Financial" not in captured.out


# =====================================================
# _group_recommendations_by_category
# =====================================================


class TestGroupRecommendationsByCategory:
    def test_budget_exceeded_grouped_as_financial(self):
        recs = [{"type": "budget_exceeded", "message": "x"}]
        grouped = _group_recommendations_by_category(recs)
        financial = dict(grouped)["Financial"]
        assert len(financial) == 1

    def test_network_segmentation_grouped_as_security(self):
        recs = [{"type": "missing_network_segmentation", "message": "x"}]
        grouped = _group_recommendations_by_category(recs)
        security = dict(grouped)["Security"]
        assert len(security) == 1

    def test_enforcement_grouped_as_governance(self):
        recs = [{"type": "enforcement", "message": "x"}]
        grouped = _group_recommendations_by_category(recs)
        governance = dict(grouped)["Governance"]
        assert len(governance) == 1

    def test_unrecognized_type_grouped_as_other(self):
        recs = [{"type": "totally_unknown_type", "message": "x"}]
        grouped = _group_recommendations_by_category(recs)
        other = dict(grouped)["Other"]
        assert len(other) == 1

    def test_category_order_is_stable(self):
        recs = []
        grouped = _group_recommendations_by_category(recs)
        categories = [cat for cat, _ in grouped]
        assert categories == ["Financial", "Security", "Governance", "Other"]

    def test_mixed_recommendations_grouped_correctly(self):
        recs = [
            {"type": "budget_exceeded", "message": "a"},
            {"type": "cost_optimization", "message": "b"},
            {"type": "missing_network_segmentation", "message": "c"},
            {"type": "enforcement", "message": "d"},
        ]
        grouped = dict(_group_recommendations_by_category(recs))
        assert len(grouped["Financial"]) == 2
        assert len(grouped["Security"]) == 1
        assert len(grouped["Governance"]) == 1
        assert len(grouped["Other"]) == 0