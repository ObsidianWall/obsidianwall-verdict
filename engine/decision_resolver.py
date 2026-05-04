# engine/decision_resolver.py

# Purpose: Introduce governance logic (not just allow/deny)

# Purpose:Convert condition results → decision

# Purpose: Determines the final decision based on condition evaluation results.
# In a more complex system, this could involve multiple policies, weighted decisions, or even ML models. For now, it's a simple allow/deny based on the primary policy decision.



def resolve_decision(policy, conditions_passed, user_role):
    decision_block = policy["policy"]["decision"]

    if conditions_passed:
        return decision_block["allow"], False

    # If failed
    override_roles = policy["policy"].get("override", {}).get("roles", [])

    if user_role in override_roles:
        return "DENY_WITH_OVERRIDE", True

    return decision_block["deny"], False