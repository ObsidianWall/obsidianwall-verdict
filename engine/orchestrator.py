
# engine/orchestrator.py

# Responsibilities:
      # load policy,
      # normalize policy,
      # validate policy,
      # build runtime context,
      # invoke evaluator,
      # invoke analyzers,
      # invoke recommender,
      # construct audit artifact.

   # This becomes:

       # the execution coordinator.

# Purpose:
# Central execution orchestration layer.
#
# Responsibilities:
# - Policy loading
# - Policy validation
# - Runtime normalization
# - Analyzer execution
# - Deterministic evaluation
# - Recommendation generation
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

        raw_policy = load_policy(
            policy_path
        )

        validated_policy = validate_policy(
            raw_policy
        )

        return cls(validated_policy)

    # =================================================
    # MAIN EXECUTION PIPELINE
    # =================================================

    def evaluate(
        self,
        context: dict,
        user_role: str = "engineer"
    ) -> dict:

        decision_id = str(uuid.uuid4())

        timestamp = datetime.now(
            timezone.utc
        ).isoformat()

        # =============================================
        # RUNTIME CONTEXT
        # =============================================

        runtime_context = (
            build_policy_runtime_context(
                self.policy,
                context
            )
        )

        # =============================================
        # ANALYZER EXECUTION
        # =============================================

        analyzer_results = {}

        analyzers = [

            (
                "cost_analysis",
                analyze_cost
            ),

            (
                "topology_analysis",
                analyze_topology
            ),

            (
                "architecture_analysis",
                analyze_architecture
            ),

            (
                "utilization_analysis",
                analyze_utilization
            ),
        ]

        for analyzer_name, analyzer_fn in analyzers:

            try:

                analyzer_results[
                    analyzer_name
                ] = analyzer_fn(
                    runtime_context
                )

            except Exception as error:

                analyzer_results[
                    analyzer_name
                ] = {

                    "status": "failed",

                    "error": str(error)
                }

                logger.warning(
                    "analyzer_failed",
                    extra={
                        "extra": {

                            "analyzer": analyzer_name,

                            "error": str(error)
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

            decision=evaluation_result[
                "decision"
            ],

            analyzer_results=analyzer_results
        )

        # =============================================
        # AUDIT ARTIFACT
        # =============================================

        result = {

            "decision_id": decision_id,

            "timestamp": timestamp,

            "policy": self.policy.metadata.name,

            "decision": evaluation_result[
                "decision"
            ],

            "override_required": (
                evaluation_result[
                    "override_required"
                ]
            ),

            "conditions_passed": (
                evaluation_result[
                    "conditions_passed"
                ]
            ),

            "trace": evaluation_result[
                "trace"
            ],

            "actions": [

                action.model_dump()

                for action
                in self.policy.spec.actions
            ],

            "analyzer_results": (
                analyzer_results
            ),

            "suggestions": suggestions,

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

                    "decision_id": (
                        decision_id
                    ),

                    "policy": (
                        self.policy.metadata.name
                    ),

                    "decision": (
                        evaluation_result[
                            "decision"
                        ]
                    ),

                    "conditions_passed": (
                        evaluation_result[
                            "conditions_passed"
                        ]
                    ),
                }
            }
        )

        return result