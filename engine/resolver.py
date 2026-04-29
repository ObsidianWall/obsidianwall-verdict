# engine/resolver.py

def resolve_decision(results: list, decision_block: dict):
    if all(results):
        return "allow"
    return "deny"
