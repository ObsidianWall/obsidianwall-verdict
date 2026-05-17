
# engine/orchestrator.py

# Purpose:
# Central execution orchestration layer.
#
# Responsibilities:
# - Policy loading
# - Policy validation
# - Runtime normalization
# - Analyzer execution with isolation
# - Deterministic evaluation
# - Recommendation generation
# - Explainability artifact construction
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
        1. Build runtime context
        2. Execute analyzers (isolated — failures degrade gracefully)
        3. Deterministic policy evaluation
        4. Recommendation generation
        5. Explainability artifact construction
        6. Audit artifact construction + logging
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
                    "error":  str(error)
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
        # EXPLAINABILITY ARTIFACT
        # =============================================

        explanation = build_explanation_artifact(
            evaluation_result=evaluation_result,
            analyzer_results=analyzer_results,
            recommendations=suggestions,
            runtime_context=runtime_context,
        )

        # =============================================
        # AUDIT ARTIFACT
        # =============================================

        result = {

            "decision_id": decision_id,

            "timestamp": timestamp,

            "policy": self.policy.metadata.name,

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

            "resolution_reason": evaluation_result[
                "resolution_reason"
            ],

            "conditions_passed": evaluation_result[
                "conditions_passed"
            ],

            "trace": evaluation_result["trace"],

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

            "suggestions": suggestions,

            "explanation": explanation,

            # -----------------------------------------
            # CONTEXT TRACEABILITY
            # -----------------------------------------

            "input_context": context,

            "runtime_context": runtime_context,
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
                    "requires_approval":    evaluation_result["requires_approval"],
                    "override_required":    evaluation_result["override_required"],
                }
            }
        )

        return result
