# engine/orchestrator.py
#
# Purpose:
# Central execution orchestration layer.
#
# Responsibilities:
# - Policy loading and validation
# - Runtime context normalization
# - Analyzer execution with isolation
# - Consolidated risk scoring
# - Deterministic policy evaluation
# - Recommendation generation
# - Governance workflow routing
#   (notifications + approval requests)
# - Explainability artifact construction
# - Audit artifact construction
#
# IMPORTANT:
# This layer coordinates execution.
# It does NOT perform enforcement logic itself.

import uuid
from datetime import datetime, timezone
from typing import Any

from audit.audit_logger import get_logger
from engine.analyzers import (
    analyze_architecture,
    analyze_cost,
    analyze_topology,
    analyze_utilization,
)
from engine.evaluator import evaluate_policy
from engine.explainability import build_explanation_artifact
from engine.policy_loader import load_policy
from engine.policy_normalizer import build_policy_runtime_context
from engine.recommender import generate_suggestions
from engine.risk_scorer import compute_risk_summary
from engine.validator import validate_policy
from engine.workflows import build_approval_request, route_notifications
from schemas.policy_schema import Policy

logger = get_logger()


class PolicyOrchestrator:
    def __init__(
        self,
        policy: Policy,
    ) -> None:
        self.policy = policy

    # =================================================
    # CONSTRUCTION FACTORY
    # =================================================

    @classmethod
    def from_policy_path(
        cls,
        policy_path: str,
    ) -> "PolicyOrchestrator":
        """
        Load, normalize, and validate a policy from
        a file path. Returns a ready orchestrator instance.
        """

        raw_policy: dict[str, Any] = load_policy(policy_path)
        validated_policy: Policy = validate_policy(raw_policy)

        return cls(validated_policy)

    # =================================================
    # MAIN EXECUTION PIPELINE
    # =================================================

    def evaluate(
        self,
        context: dict[str, Any],
        user_role: str = "engineer",
    ) -> dict[str, Any]:
        """
        Execute the full governance evaluation pipeline.

        Pipeline:
        1.  Build runtime context
        2.  Execute analyzers (isolated)
        3.  Compute consolidated risk summary
        4.  Deterministic policy evaluation
        5.  Recommendation generation
        6.  Governance workflow routing
            6a. Notification manifest
            6b. Approval request (if required)
        7.  Explainability + reasoning chain
        8.  Audit artifact construction + logging
        """

        decision_id: str = str(uuid.uuid4())

        timestamp: str = datetime.now(timezone.utc).isoformat()

        logger.info(
            "evaluation_started",
            extra={
                "extra": {
                    "decision_id": decision_id,
                    "policy": self.policy.metadata.name,
                    "user_role": user_role,
                }
            },
        )

        # =============================================
        # STEP 1 — RUNTIME CONTEXT
        # =============================================

        runtime_context: dict[str, Any] = build_policy_runtime_context(
            self.policy,
            context,
        )

        # =============================================
        # STEP 2 — ANALYZER EXECUTION
        # Isolated — analyzer failures NEVER break
        # deterministic governance execution.
        # =============================================

        analyzer_results: dict[str, Any] = {}

        analyzers: list[tuple[str, Any]] = [
            ("cost_analysis", analyze_cost),
            ("topology_analysis", analyze_topology),
            ("architecture_analysis", analyze_architecture),
            ("utilization_analysis", analyze_utilization),
        ]

        for analyzer_name, analyzer_fn in analyzers:
            try:
                analyzer_results[analyzer_name] = analyzer_fn(runtime_context)
            except Exception as error:
                analyzer_results[analyzer_name] = {
                    "status": "failed",
                    "error": str(error),
                }
                logger.warning(
                    "analyzer_failed",
                    extra={
                        "extra": {
                            "analyzer": analyzer_name,
                            "error": str(error),
                        }
                    },
                )

        # =============================================
        # STEP 3 — CONSOLIDATED RISK SCORING
        # =============================================

        policy_severity: str = (
            self.policy.spec.governance.severity.value
            if self.policy.spec.governance
            else "medium"
        )

        risk_summary: dict[str, Any] = compute_risk_summary(
            analyzer_results=analyzer_results,
            policy_severity=policy_severity,
        )

        # =============================================
        # STEP 4 — DETERMINISTIC EVALUATION
        # =============================================

        evaluation_result: dict[str, Any] = evaluate_policy(
            policy=self.policy,
            runtime_context=runtime_context,
            user_role=user_role,
        )

        # =============================================
        # STEP 5 — RECOMMENDATION ENGINE
        # =============================================

        suggestions: list[dict[str, Any]] = generate_suggestions(
            context=runtime_context,
            decision=str(evaluation_result["decision"]),
            analyzer_results=analyzer_results,
        )

        # =============================================
        # GOVERNANCE CONFIG SERIALIZATION
        # =============================================

        policy_governance: dict[str, Any] | None = (
            self.policy.spec.governance.model_dump(mode="json")
            if self.policy.spec.governance
            else None
        )

        # =============================================
        # STEP 6 — GOVERNANCE WORKFLOW ROUTING
        # Runs AFTER deterministic enforcement.
        # Workflow routing NEVER influences enforcement.
        # =============================================

        notification_manifest: dict[str, Any] = route_notifications(
            decision=str(evaluation_result["decision"]),
            effective_severity=str(risk_summary["effective_severity"]),
            policy_name=self.policy.metadata.name,
            evaluation_result=evaluation_result,
            risk_summary=risk_summary,
            policy_governance=policy_governance,
        )

        approval_request: dict[str, Any] = build_approval_request(
            decision_id=decision_id,
            policy_name=self.policy.metadata.name,
            evaluation_result=evaluation_result,
            risk_summary=risk_summary,
            policy_governance=policy_governance,
        )

        # =============================================
        # STEP 7 — EXPLAINABILITY ARTIFACT
        # =============================================

        explanation: dict[str, Any] = build_explanation_artifact(
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
        # STEP 8 — AUDIT ARTIFACT
        # =============================================

        result: dict[str, Any] = {
            "decision_id": decision_id,
            "timestamp": timestamp,
            "policy": self.policy.metadata.name,
            # -----------------------------------------
            # GOVERNANCE DECISION
            # -----------------------------------------
            "decision": evaluation_result["decision"],
            "override_required": evaluation_result["override_required"],
            "override_possible": evaluation_result["override_possible"],
            "requires_approval": evaluation_result["requires_approval"],
            "governance_severity": evaluation_result["governance_severity"],
            "effective_severity": risk_summary["effective_severity"],
            "resolution_reason": evaluation_result["resolution_reason"],
            "conditions_passed": evaluation_result["conditions_passed"],
            "trace": evaluation_result["trace"],
            # -----------------------------------------
            # RISK SUMMARY
            # -----------------------------------------
            "risk_summary": risk_summary,
            # -----------------------------------------
            # GOVERNANCE WORKFLOW
            # -----------------------------------------
            "notification_manifest": notification_manifest,
            "approval_request": approval_request,
            # -----------------------------------------
            # ACTIONS
            # -----------------------------------------
            "actions": [action.model_dump() for action in self.policy.spec.actions],
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
            # -----------------------------------------
            # PRICING METADATA
            # Captures which pricing mode was used
            # for cost estimation auditability.
            # -----------------------------------------
            "pricing_mode": context.get("pricing_mode", "table"),
        }

        # =============================================
        # STRUCTURED AUDIT LOGGING
        # =============================================

        logger.info(
            "decision_evaluated",
            extra={
                "extra": {
                    "decision_id": decision_id,
                    "policy": self.policy.metadata.name,
                    "decision": evaluation_result["decision"],
                    "conditions_passed": evaluation_result["conditions_passed"],
                    "governance_severity": evaluation_result["governance_severity"],
                    "effective_severity": risk_summary["effective_severity"],
                    "overall_risk_score": risk_summary["overall_risk_score"],
                    "requires_approval": evaluation_result["requires_approval"],
                    "override_required": evaluation_result["override_required"],
                    "total_findings": risk_summary["total_findings"],
                    "notifications": notification_manifest.get("notification_count", 0),
                    "approval_status": approval_request.get("approval_status"),
                    "user_role": user_role,
                    "pricing_mode": context.get("pricing_mode", "table"),
                }
            },
        )

        return result
