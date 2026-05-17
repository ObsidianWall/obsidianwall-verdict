
# engine/orchestrator.py

# Purpose:
# Central execution orchestration layer.
#
# Responsibilities:
# - Policy loading
# - Policy validation
# - Runtime normalization
# - Analyzer execution with isolation
# - Consolidated risk scoring
# - Deterministic evaluation
# - Recommendation generation
# - Explainability artifact construction
# - Governance reasoning chain construction
# - Audit artifact construction
#
# IMPORTANT:
# This layer coordinates execution.
# It does NOT perform enforcement logic itself.


import uuid

from datetime import datetime, timezone

from schemas.policy_schema import Policy

from engine.policy_loader import load_policy

from engine.validator import validate_policy

from engine.policy_normalizer import (
    build_policy_runtime_context
)

from engine.risk_scorer import compute_risk_summary

from engine.evaluator import evaluate_policy

from engine.recommender import generate_suggestions

from engine.analyzers import (
    analyze_cost,
    analyze_topology,
    analyze_architecture,
    analyze_utilization,
)

from engine.explainability import (
    build_explanation_artifact
)

from audit.audit_logger import get_logger


logger = get_logger()


class PolicyOrchestrator:

    def __init__(
        self,
        policy: Policy
    ) -> None:

        self.policy = policy

    # =================================================
    # CONSTRUCTION FACTORY
    # =================================================

    @classmethod
    def from_policy_path(
        cls,
        policy_path: str
    ) -> "PolicyOrchestrator":
        """
        Load, normalize, and validate a policy from
        a file path. Returns a ready orchestrator instance.
        """

        raw_policy = load_policy(policy_path)

        validated_policy = validate_policy(raw_policy)

        return cls(validated_policy)

    # =================================================
    # MAIN EXECUTION PIPELINE
    # =================================================

    def evaluate(
        self,
        context: dict,
        user_role: str = "engineer"
    ) -> dict:
        """
        Execute the full governance evaluation pipeline.

        Pipeline:
        1.  Build runtime context
        2.  Execute analyzers (isolated)
        3.  Compute consolidated risk summary
        4.  Deterministic policy evaluation
        5.  Recommendation generation
        6.  Explainability + reasoning chain construction
        7.  Audit artifact construction + logging
        """

        decision_id = str(uuid.uuid4())

        timestamp = datetime.now(
            timezone.utc
        ).isoformat()

        logger.info(
            "evaluation_started",
            extra={
                "extra": {
                    "decision_id":  decision_id,
                    "policy":       self.policy.metadata.name,
                    "user_role":    user_role,
                }
            }
        )

        # =============================================
        # RUNTIME CONTEXT
        # =============================================

        runtime_context = build_policy_runtime_context(
            self.policy,
            context
        )

        # =============================================
        # ANALYZER EXECUTION
        # Isolated — analyzer failures NEVER break
        # deterministic governance execution.
        # =============================================

        analyzer_results = {}

        analyzers = [
            ("cost_analysis",         analyze_cost),
            ("topology_analysis",     analyze_topology),
            ("architecture_analysis", analyze_architecture),
            ("utilization_analysis",  analyze_utilization),
        ]

        for analyzer_name, analyzer_fn in analyzers:

            try:

                analyzer_results[analyzer_name] = (
                    analyzer_fn(runtime_context)
                )

            except Exception as error:

                analyzer_results[analyzer_name] = {
                    "status": "failed",
                    "error":  str(error),
                }

                logger.warning(
                    "analyzer_failed",
                    extra={
                        "extra": {
                            "analyzer": analyzer_name,
                            "error":    str(error),
                        }
                    }
                )

        # =============================================
        # CONSOLIDATED RISK SCORING
        # Policy severity is the baseline —
        # analyzer risk can escalate but not reduce it.
        # =============================================

        policy_severity = (
            self.policy.spec.governance.severity.value
            if self.policy.spec.governance
            else "medium"
        )

        risk_summary = compute_risk_summary(
            analyzer_results=analyzer_results,
            policy_severity=policy_severity,
        )

        # =============================================
        # DETERMINISTIC EVALUATION
        # =============================================

        evaluation_result = evaluate_policy(
            policy=self.policy,
            runtime_context=runtime_context,
            user_role=user_role
        )

        # =============================================
        # RECOMMENDATION ENGINE
        # =============================================

        suggestions = generate_suggestions(
            context=runtime_context,
            decision=evaluation_result["decision"],
            analyzer_results=analyzer_results
        )

        # =============================================
        # GOVERNANCE CONFIG SERIALIZATION
        # Passed into explainability for reasoning chain
        # governance routing stage construction.
        # =============================================

        policy_governance = (
            self.policy.spec.governance.model_dump()
            if self.policy.spec.governance
            else None
        )

        # =============================================
        # EXPLAINABILITY ARTIFACT
        # Includes governance reasoning chain,
        # risk summary, condition reasoning,
        # analyzer findings, explained recommendations,
        # and execution trace graph.
        # =============================================

        explanation = build_explanation_artifact(
            evaluation_result=evaluation_result,
            analyzer_results=analyzer_results,
            recommendations=suggestions,
            runtime_context=runtime_context,
            risk_summary=risk_summary,
            policy_name=self.policy.metadata.name,
            user_role=user_role,
            policy_governance=policy_governance,
        )

        # =============================================
        # AUDIT ARTIFACT
        # =============================================

        result = {

            "decision_id":  decision_id,

            "timestamp":    timestamp,

            "policy":       self.policy.metadata.name,

            # -----------------------------------------
            # GOVERNANCE DECISION
            # -----------------------------------------

            "decision": evaluation_result[
                "decision"
            ],

            "override_required": evaluation_result[
                "override_required"
            ],

            "requires_approval": evaluation_result[
                "requires_approval"
            ],

            "governance_severity": evaluation_result[
                "governance_severity"
            ],

            "effective_severity": risk_summary[
                "effective_severity"
            ],

            "resolution_reason": evaluation_result[
                "resolution_reason"
            ],

            "conditions_passed": evaluation_result[
                "conditions_passed"
            ],

            "trace": evaluation_result["trace"],

            # -----------------------------------------
            # RISK SUMMARY
            # -----------------------------------------

            "risk_summary": risk_summary,

            # -----------------------------------------
            # ACTIONS
            # -----------------------------------------

            "actions": [
                action.model_dump()
                for action in self.policy.spec.actions
            ],

            # -----------------------------------------
            # INTELLIGENCE LAYERS
            # -----------------------------------------

            "analyzer_results": analyzer_results,

            "suggestions":      suggestions,

            "explanation":      explanation,

            # -----------------------------------------
            # CONTEXT TRACEABILITY
            # -----------------------------------------

            "input_context":    context,

            "runtime_context":  runtime_context,
        }

        # =============================================
        # STRUCTURED AUDIT LOGGING
        # =============================================

        logger.info(
            "decision_evaluated",
            extra={
                "extra": {
                    "decision_id":          decision_id,
                    "policy":               self.policy.metadata.name,
                    "decision":             evaluation_result["decision"],
                    "conditions_passed":    evaluation_result["conditions_passed"],
                    "governance_severity":  evaluation_result["governance_severity"],
                    "effective_severity":   risk_summary["effective_severity"],
                    "overall_risk_score":   risk_summary["overall_risk_score"],
                    "requires_approval":    evaluation_result["requires_approval"],
                    "override_required":    evaluation_result["override_required"],
                    "total_findings":       risk_summary["total_findings"],
                    "user_role":            user_role,
                }
            }
        )

        return result
