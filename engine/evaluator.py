# engine/evaluator.py

# Purpose:Orchestrates entire decision lifecycle

# Purpose: Main entry point for policy evaluation. Orchestrates the entire process.

# Purpose: Ensure policy is valid before execution (audit + safety)


from engine.condition_evaluator import evaluate_conditions
from engine.decision_resolver import resolve_decision
from engine.recommender import generate_suggestions
from utils.logger import get_logger
from datetime import datetime

logger = get_logger()


class DecisionEngine:

    def __init__(self, policy, context):
        self.policy = policy
        self.context = context

    def evaluate(self):

        passed, failures = evaluate_conditions(self.policy, self.context)
        decision = resolve_decision(self.policy, passed)

        suggestions = generate_suggestions(self.context)

        result = {
            "decision": decision,
            "reasons": failures if failures else ["All conditions passed"],
            "actions": [a.message for a in self.policy.actions],
            "suggestions": suggestions,
            "metadata": self.policy.metadata.dict(),
            "override_allowed": True,
            "timestamp": datetime.utcnow().isoformat()
        }

        logger.info("Decision made", extra=result)

        return result