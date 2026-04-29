#

def resolve_decision(policy, conditions_passed):
    if conditions_passed:
        return policy["decision"]["allow"]
    else:
        return policy["decision"]["deny"]