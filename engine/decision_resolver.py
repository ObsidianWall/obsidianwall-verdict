# engine/decision_resolver.py


# Purpose:
# Convert evaluated conditions into deterministic governance decision.
#
# IMPORTANT:
# - Suggestions NEVER influence decisions
# - Decisions must remain deterministic + auditable
# - This layer is enforcement logic only


def resolve_decision(policy, conditions_passed: bool, user_role: str):
    """
    Resolve final policy decision.

    Returns:
        tuple[str, bool]
        (decision, override_required)
    """

    decision_block = policy.spec.decision

    # ---------------------------------------------------
    # PASS
    # ---------------------------------------------------
    if conditions_passed:
        return decision_block.allow, False

    # ---------------------------------------------------
    # FAIL → check override permissions
    # ---------------------------------------------------
    override_roles = policy.spec.override.roles

    if user_role in override_roles:
        return "DENY_WITH_OVERRIDE", True

    # ---------------------------------------------------
    # FAIL → hard deny
    # ---------------------------------------------------
    return decision_block.deny, False