# engine/evaluator.py

from engine.policy_loader import load_policy
from engine.condition_evaluator import evaluate_conditions
from engine.decision_resolver import resolve_decision


class DecisionEngine:
    def __init__(self, policy_path: str):
        self.policy = load_policy(policy_path)

    def evaluate(self, context: dict):
        conditions_result = evaluate_conditions(self.policy, context)

        decision = resolve_decision(self.policy, conditions_result)

        return {
            "decision": decision,
            "conditions_passed": conditions_result
        }


