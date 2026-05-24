# schemas/policy_schema.py

# Purpose:
# Define the canonical enforceable policy contract.
#
# Responsibilities:
# - Policy schema validation
# - Governance severity classification
# - Stakeholder notification routing contracts
# - Approval chain contracts
# - Runtime policy object model
#
# IMPORTANT:
# This schema is the single source of truth
# for what constitutes a valid ObsidianWall policy.
# All engine modules depend on this contract.


from pydantic import BaseModel
from typing import List, Optional
from enum import Enum




# =====================================================
# GOVERNANCE SEVERITY
# =====================================================

class GovernanceSeverity(str, Enum):
    """
    Tiered governance severity classification.

    Determines decision routing, notification urgency,
    and approval requirements.
    """
    INFORMATIONAL   = "informational"
    LOW             = "low"
    MEDIUM          = "medium"
    HIGH            = "high"
    CRITICAL        = "critical"


# =====================================================
# GOVERNANCE DECISION OUTCOMES
# =====================================================

class GovernanceDecision(str, Enum):
    """
    Five-level governance decision model.

    Replaces binary allow/deny with
    accountability-aware routing decisions.
    """
    ALLOW                       = "ALLOW"
    ALLOW_WITH_NOTIFICATION     = "ALLOW_WITH_NOTIFICATION"
    ALLOW_WITH_APPROVAL_REQUIRED = "ALLOW_WITH_APPROVAL_REQUIRED"
    DENY_WITH_OVERRIDE          = "DENY_WITH_OVERRIDE"
    DENY                        = "DENY"


# =====================================================
# METADATA
# =====================================================

class Metadata(BaseModel):
    """
    Policy identity and ownership metadata.
    """
    name:           str
    version:        str             # string — preserves "0.10" correctly
    owner:          str
    description:    Optional[str] = None


# =====================================================
# CONDITIONS
# =====================================================

class Condition(BaseModel):
    """
    Deterministic policy condition.
    Evaluated by the condition evaluator engine.
    """
    id:             str
    expression:     str
    description:    str


# =====================================================
# ACTIONS
# =====================================================

class Action(BaseModel):
    """
    Post-decision action directive.
    """
    type:       str
    message:    str
    severity:   Optional[str] = "info"


# =====================================================
# DECISION
# =====================================================

class Decision(BaseModel):
    """
    Policy decision outcome mapping.
    Maps condition results to governance decision outcomes.
    """
    allow:  str
    deny:   str
    warn:   Optional[str] = None


# =====================================================
# OVERRIDE
# =====================================================

class Override(BaseModel):
    """
    Policy override configuration.
    Defines who can override a governance decision
    and whether approval is required.
    """
    roles:              List[str]
    requires_approval:  Optional[bool] = False


# =====================================================
# GOVERNANCE WORKFLOW
# =====================================================

class NotificationTarget(BaseModel):
    """
    Stakeholder notification target.
    Defines who receives governance notifications
    and through which channel.
    """
    role:       str
    channel:    Optional[str] = "email"


class ApprovalConfig(BaseModel):
    """
    Approval chain configuration.
    Defines which roles must approve before
    a governance decision is resolved.
    """
    required: List[str]


class GovernanceConfig(BaseModel):
    """
    Governance workflow configuration.

    Responsibilities:
    - Severity classification
    - Stakeholder notification routing
    - Approval chain definition
    """
    severity:       GovernanceSeverity          = GovernanceSeverity.MEDIUM
    notifications:  List[NotificationTarget]    = []
    approvals:      Optional[ApprovalConfig]    = None


# =====================================================
# PARAMETERS
# =====================================================

class Budget(BaseModel):
    """
    Budget constraint parameters.
    """
    amount:             float
    period:             str
    scope:              str
    owner:              str
    flexibility:        str
    override_allowed:   bool


class Parameters(BaseModel):
    """
    Policy runtime parameters.
    Flattened by policy_normalizer before evaluation.
    """
    budget: Budget


# =====================================================
# SPEC
# =====================================================

class Spec(BaseModel):
    """
    Policy specification — the enforceable body of the policy.
    """
    inputs:         List[str]
    parameters:     Parameters
    conditions:     List[Condition]
    decision:       Decision
    override:       Override
    governance:     Optional[GovernanceConfig]  = None
    actions:        List[Action]


# =====================================================
# POLICY — ROOT CONTRACT
# =====================================================

class Policy(BaseModel):
    """
    Canonical ObsidianWall policy contract.

    This is the trusted typed object produced by
    the validator and consumed by all engine modules.
    """
    apiVersion: str
    kind:       str
    metadata:   Metadata
    spec:       Spec
