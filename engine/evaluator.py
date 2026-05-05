# engine/evaluator.py

# purpose: Orchestrates full decision lifecycle
# Pupose: produces auditable, immutable decision record
# Purpose: Central orchestrator with full traceability + logging

# Purpose: Main entry point for policy evaluation. Orchestrates the entire process.

# Purpose: Ensure policy is valid before execution (audit + safety)


import uuid
from datetime import datetime

from engine.policy_loader import load_policy
from engine.validator import validate_policy
from engine.condition_evaluator import evaluate_conditions
from engine.decision_resolver import resolve_decision
from engine.recommender import generate_suggestions
from audit.audit_logger import get_logger

logger = get_logger()


class DecisionEngine:
    def __init__(self, policy_path: str):
        raw_policy = load_policy(policy_path)
        self.policy = validate_policy(raw_policy)

    def evaluate(self, context: dict, user_role: str = "engineer"):
        decision_id = str(uuid.uuid4())
        timestamp = datetime.utcnow().isoformat()

        # 1. Evaluate conditions
        conditions_passed, trace = evaluate_conditions(self.policy, context)

        # 2. Resolve decision
        decision, override_required = resolve_decision(
            self.policy,
            conditions_passed,
            user_role
        )

        # 3. Generate advisory suggestions (NON-authoritative)
        suggestions = generate_suggestions(context, decision)

        # 4. Build result
        result = {
            "decision_id": decision_id,
            "timestamp": timestamp,
            "policy": self.policy.policy.name,
            "decision": decision,
            "override_required": override_required,
            "conditions_passed": conditions_passed,
            "trace": trace,
            "actions": [a.dict() for a in self.policy.actions],
            "suggestions": suggestions,
            "context": context,
        }

        # 5. Audit log (structured)
        logger.info(
            "decision_evaluated",
            extra={"extra": result}
        )

        return result