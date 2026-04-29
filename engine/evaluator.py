# engine/evaluator.py

# Purpose: Orchestrates the system


from engine.policy_loader import load_policy
from engine.condition_evaluator import evaluate_conditions
from engine.decision_resolver import resolve_decision


class DecisionEngine:
    def __init__(self, policy_path: str):
        self.policy = load_policy(policy_path)

    def evaluate(self, context: dict):
        conditions_passed = evaluate_conditions(self.policy, context)
        decision = resolve_decision(self.policy, conditions_passed)

        return {
            "decision": decision,
            "conditions_passed": conditions_passed,
            "context": context,
            "policy": self.policy["policy"]["name"]
        }