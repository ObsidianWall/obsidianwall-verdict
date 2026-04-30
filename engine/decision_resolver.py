# engine/decision_resolver.py

# Purpose: Convert condition results → decision

# Purpose: Determines the final decision based on condition evaluation results.
# In a more complex system, this could involve multiple policies, weighted decisions, or even ML models. For now, it's a simple allow/deny based on the primary policy decision.


def resolve_decision(policy, passed: bool):
    if passed:
        return policy.decision.allow
    else:
        return policy.decision.deny