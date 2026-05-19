
# engine/decision_resolver.py

# Purpose:
# Convert evaluated conditions into deterministic
# governance decisions with accountability routing.
#
# Responsibilities:
# - Deterministic decision resolution
# - Governance severity classification
# - Override authority validation
# - Approval requirement detection
# - Decision audit logging
#
# IMPORTANT:
# - Suggestions NEVER influence decisions
# - Decisions must remain deterministic and auditable
# - This layer is enforcement logic only
# - Governance intelligence routes AFTER this layer


from audit.audit_logger import get_logger

from schemas.policy_schema import (
    GovernanceDecision,
    GovernanceSeverity,
    Policy,
)


logger = get_logger()


# =====================================================
# HIGH SEVERITY LEVELS
# =====================================================

# Governance severity levels that trigger notification
# even when conditions pass.
NOTIFICATION_SEVERITY_LEVELS = {
    GovernanceSeverity.HIGH,
    GovernanceSeverity.CRITICAL,
}


# =====================================================
# DECISION RESOLVER
# =====================================================

def resolve_decision(
    policy: Policy,
    conditions_passed: bool,
    user_role: str,
) -> dict:
    """
    Resolve a deterministic governance decision.

    Returns a resolution dict containing:
    - decision:             5-level GovernanceDecision outcome
    - override_required:    whether an override was applied
    - requires_approval:    whether formal approval is needed
    - governance_severity:  severity level for routing

    Breaking change note:
        Previously returned tuple[str, bool].
        Now returns dict for richer governance routing.
        Callers must unpack via resolution["decision"].
    """

    decision_block      = policy.spec.decision
    override_config     = policy.spec.override
    governance_config   = policy.spec.governance

    # Compute once before the if/else branches
    override_possible = len(override_config.roles) > 0

    # -------------------------------------------------
    # RESOLVE GOVERNANCE SEVERITY
    # -------------------------------------------------

    governance_severity = (
        governance_config.severity
        if governance_config
        else GovernanceSeverity.MEDIUM
    )

    # -------------------------------------------------
    # RESOLVE APPROVAL REQUIREMENT
    # -------------------------------------------------

    requires_approval = (
        override_config.requires_approval
        if override_config.requires_approval is not None
        else False
    )

    # =================================================
    # CONDITIONS PASSED
    # =================================================

    if conditions_passed:

        # High/critical severity policies notify
        # stakeholders even when conditions pass.
        # Budget owners must remain aware of
        # high-stakes deployments within budget.

        if governance_severity in NOTIFICATION_SEVERITY_LEVELS:

            warn_decision = (
                decision_block.warn
                or GovernanceDecision.ALLOW_WITH_NOTIFICATION
            )
             # conditions passed — high severity
            return _build_resolution(
                decision=warn_decision,
                override_required=False,
                override_possible=override_possible,
                requires_approval=False,
                governance_severity=governance_severity,
                reason="conditions_passed_high_severity_notification",
            )
        # conditions passed — normal
        return _build_resolution(
            decision=decision_block.allow,
            override_required=False,
            override_possible=override_possible,
            requires_approval=False,
            governance_severity=governance_severity,
            reason="conditions_passed",
        )

    # =================================================
    # CONDITIONS FAILED — CHECK OVERRIDE AUTHORITY
    # conditions failed — override available
    # =================================================

    override_roles  = override_config.roles
    has_override    = user_role in override_roles

    if has_override:
        return _build_resolution(
            decision=GovernanceDecision.DENY_WITH_OVERRIDE,
            override_required=True,
            override_possible=True,
            requires_approval=requires_approval,
            governance_severity=governance_severity,
            reason=(
                "conditions_failed_override_available_approval_required"
                if requires_approval
                else "conditions_failed_override_available"
            ),
        )

    # =================================================
    # CONDITIONS FAILED — HARD DENY
    # =================================================

    return _build_resolution(
        decision=decision_block.deny,
        override_required=False,
        override_possible=override_possible,
        requires_approval=False,
        governance_severity=governance_severity,
        reason="conditions_failed_hard_deny",
    )


# =====================================================
# RESOLUTION BUILDER
# =====================================================

def _build_resolution(
    decision: str,
    override_required: bool,
    override_possible: bool,
    requires_approval: bool,
    governance_severity: GovernanceSeverity,
    reason: str,
) -> dict:
    """
    Build and log a governance resolution artifact.
    """

    resolution = {
        "decision":             decision,
        "override_required":    override_required,
        "override_possible":    override_possible,
        "requires_approval":    requires_approval,
        "governance_severity":  governance_severity.value,
        "resolution_reason":    reason,
    }

    logger.info(
        "decision_resolved",
        extra={
            "extra": {
                "decision":             decision,
                "override_required":    override_required,
                "requires_approval":    requires_approval,
                "governance_severity":  governance_severity.value,
                "resolution_reason":    reason,
            }
        }
    )

    return resolution
