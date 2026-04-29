# engine/decision_resolver.py

def resolve_decision(policy, conditions_passed):
    decision_block = policy["policy"]["decision"]

    if conditions_passed:
        return decision_block["allow"]
    else:
        return decision_block["deny"]