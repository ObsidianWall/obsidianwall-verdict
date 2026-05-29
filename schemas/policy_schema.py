# schemas/policy_schema.py

# Purpose:
# Define the canonical enforceable policy contract.
#
# Responsibilities:
# - Policy schema validation
# - Policy type classification and enforcement
# - Parameter contract enforcement by policy type
# - Condition consistency validation
# - Governance severity classification
# - Stakeholder notification routing contracts
# - Approval chain contracts
# - Runtime policy object model
#
# IMPORTANT:
# This schema is the single source of truth
# for what constitutes a valid ObsidianWall policy.
# All engine modules depend on this contract.
#
# GOVERNANCE DOMAINS:
# cost            → budget spend enforcement
# security        → security posture governance
# compliance      → regulatory and tagging governance
# resource_limits → infrastructure sizing governance
# network         → topology and exposure governance
# identity        → IAM and Zero Trust governance
# data_governance → data sovereignty and privacy governance
# resilience      → availability and DR governance
# ai_governance   → AI system governance
# composite       → multi-domain governance coordination
#
# HYBRID VALIDATION MODEL:
# Layer 1 — Declaration enforcement:
#   policy_type declares what parameters are required.
#   A cost policy without a budget block is rejected.
#   A security policy without a security block is rejected.
#
# Layer 2 — Condition consistency:
#   Condition expressions are inspected against the declared type.
#   An engineer cannot declare policy_type: security
#   while writing budget conditions — mismatch is caught.
#   This prevents dishonest or accidental type declarations.
#   Skipped for composite policies which intentionally
#   mix governance domains.

from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, model_validator


# =====================================================
# GOVERNANCE SEVERITY
# =====================================================


class GovernanceSeverity(str, Enum):
    """
    Tiered governance severity classification.

    Determines decision routing, notification urgency,
    and approval requirements.
    """

    INFORMATIONAL = "informational"
    LOW           = "low"
    MEDIUM        = "medium"
    HIGH          = "high"
    CRITICAL      = "critical"


# =====================================================
# GOVERNANCE DECISION OUTCOMES
# =====================================================


class GovernanceDecision(str, Enum):
    """
    Five-level governance decision model.

    Replaces binary allow/deny with
    accountability-aware routing decisions.
    """

    ALLOW                        = "ALLOW"
    ALLOW_WITH_NOTIFICATION      = "ALLOW_WITH_NOTIFICATION"
    ALLOW_WITH_APPROVAL_REQUIRED = "ALLOW_WITH_APPROVAL_REQUIRED"
    DENY_WITH_OVERRIDE           = "DENY_WITH_OVERRIDE"
    DENY                         = "DENY"


# =====================================================
# POLICY TYPE
#
# Engineers must explicitly declare the governance
# domain their policy enforces.
#
# Used by the hybrid validator to:
# - Enforce required parameter sections (Layer 1)
# - Validate condition consistency (Layer 2)
# =====================================================


class PolicyType(str, Enum):
    """
    Governance domain classification.

    Declares the governance concern this policy enforces.
    Drives parameter enforcement and condition validation.

    composite — intentionally governs multiple domains.
                Layer 2 condition validation is relaxed.
                Represents a governance coordination contract.
    """

    COST            = "cost"
    SECURITY        = "security"
    COMPLIANCE      = "compliance"
    RESOURCE_LIMITS = "resource_limits"
    NETWORK         = "network"
    IDENTITY        = "identity"
    DATA_GOVERNANCE = "data_governance"
    RESILIENCE      = "resilience"
    AI_GOVERNANCE   = "ai_governance"
    COMPOSITE       = "composite"


# =====================================================
# NOTIFICATION CHANNEL
#
# Validated enum of supported notification channels.
# Prevents silent routing failures from typos.
# =====================================================


class NotificationChannel(str, Enum):
    """
    Supported stakeholder notification channels.

    email     → email dispatch (default)
    slack     → Slack channel or user DM
    teams     → Microsoft Teams channel
    pagerduty → PagerDuty incident routing
    webhook   → generic HTTP webhook endpoint
    """

    EMAIL     = "email"
    SLACK     = "slack"
    TEAMS     = "teams"
    PAGERDUTY = "pagerduty"
    WEBHOOK   = "webhook"


# =====================================================
# METADATA
# =====================================================


class Metadata(BaseModel):
    """
    Policy identity and ownership metadata.
    """

    name:        str
    version:     str           # string — preserves "0.10" correctly
    owner:       str
    description: Optional[str] = None


# =====================================================
# CONDITIONS
# =====================================================


class Condition(BaseModel):
    """
    Deterministic policy condition.
    Evaluated by the condition evaluator engine.
    """

    id:          str
    expression:  str
    description: str


# =====================================================
# ACTIONS
# =====================================================


class Action(BaseModel):
    """
    Post-decision action directive.
    """

    type:     str
    message:  str
    severity: Optional[str] = "info"


# =====================================================
# DECISION
# =====================================================


class Decision(BaseModel):
    """
    Policy decision outcome mapping.
    Maps condition results to governance decision outcomes.
    """

    allow: str
    deny:  str
    warn:  Optional[str] = None


# =====================================================
# OVERRIDE
# =====================================================


class Override(BaseModel):
    """
    Policy override configuration.
    Defines who can override a governance decision
    and whether approval is required.
    """

    roles:             List[str]
    requires_approval: Optional[bool] = False


# =====================================================
# GOVERNANCE WORKFLOW
# =====================================================


class NotificationTarget(BaseModel):
    """
    Stakeholder notification target.
    Defines who receives governance notifications
    and through which validated channel.
    """

    role:    str
    channel: NotificationChannel = NotificationChannel.EMAIL


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

    severity:      GovernanceSeverity       = GovernanceSeverity.MEDIUM
    notifications: List[NotificationTarget] = []
    approvals:     Optional[ApprovalConfig] = None


# =====================================================
# PARAMETER MODELS
#
# Each model corresponds to one governance domain.
# Parameters are flattened to dot-notation keys by
# policy_normalizer before evaluation.
# Only present (non-None) sections contribute keys.
# =====================================================


class Budget(BaseModel):
    """
    Budget constraint parameters.
    Required for policy_type: cost.
    """

    amount:           float
    period:           str
    scope:            str
    owner:            str
    flexibility:      str
    override_allowed: bool


class SecurityConfig(BaseModel):
    """
    Security posture parameters.
    Required for policy_type: security.
    """

    allow_open_ingress:     bool = False
    allow_public_storage:   bool = False
    allow_unencrypted_db:   bool = False
    max_open_ingress_rules: int  = 0
    max_public_buckets:     int  = 0


class ComplianceConfig(BaseModel):
    """
    Compliance and tagging parameters.
    Required for policy_type: compliance.
    """

    max_untagged_resources: int       = 0
    required_tags:          List[str] = []
    enforcement:            str       = "soft"
    scope:                  str       = "all_resources"


class ResourceLimits(BaseModel):
    """
    Resource sizing and count parameters.
    Required for policy_type: resource_limits.
    """

    max_compute_instances:      int   = 5
    max_gpu_instances:          int   = 0
    max_single_deployment_cost: float = 500.0
    environment:                str   = "development"


class NetworkConfig(BaseModel):
    """
    Network topology and exposure parameters.
    Required for policy_type: network.

    Governs: segmentation, public exposure,
    port policies, regional constraints,
    private endpoint requirements.
    """

    allow_public_ingress:    bool      = False
    allow_public_egress:     bool      = False
    required_segmentation:   bool      = True
    approved_regions:        List[str] = []
    require_private_endpoints: bool    = True
    max_exposed_ports:       int       = 0
    require_firewall:        bool      = True


class IdentityConfig(BaseModel):
    """
    IAM and Zero Trust governance parameters.
    Required for policy_type: identity.

    Governs: MFA requirements, privileged access,
    service account security, just-in-time access,
    credential lifecycle policies.
    """

    require_mfa:                  bool = True
    max_privileged_roles:         int  = 2
    allow_service_account_keys:   bool = False
    require_just_in_time_access:  bool = False
    allow_permanent_credentials:  bool = False
    max_inactive_accounts:        int  = 0
    require_role_expiry:          bool = True


class DataGovernanceConfig(BaseModel):
    """
    Data sovereignty and privacy governance parameters.
    Required for policy_type: data_governance.

    Governs: PII handling, encryption requirements,
    data residency, retention policies,
    cross-region replication, public data access.
    """

    allow_pii_storage:              bool      = False
    allow_cross_region_replication: bool      = False
    encryption_required:            bool      = True
    retention_days:                 int       = 30
    approved_data_classifications:  List[str] = []
    require_data_lineage:           bool      = True
    allow_public_data_access:       bool      = False


class ResilienceConfig(BaseModel):
    """
    Availability and disaster recovery parameters.
    Required for policy_type: resilience.

    Governs: replica counts, multi-AZ requirements,
    backup policies, DR tiers, health checks,
    auto-scaling requirements.
    """

    min_replica_count:      int   = 2
    multi_az_required:      bool  = True
    backup_required:        bool  = True
    disaster_recovery_tier: str   = "tier_1"
    max_recovery_time_hours: int  = 4
    require_health_checks:  bool  = True
    require_auto_scaling:   bool  = False


class AIGovernanceConfig(BaseModel):
    """
    AI system governance parameters.
    Required for policy_type: ai_governance.

    Governs: model provenance, prompt logging,
    training data restrictions, model risk tiers,
    autonomous deployment controls, human oversight
    requirements for high-risk AI operations.

    Doctrine: AI may advise. AI may not govern.
    This policy type enforces that boundary.
    """

    allow_external_models:              bool  = False
    require_prompt_logging:             bool  = True
    allow_sensitive_training_data:      bool  = False
    model_risk_tier:                    str   = "medium"
    require_model_versioning:           bool  = True
    require_bias_evaluation:            bool  = False
    allow_autonomous_deployment:        bool  = False
    require_human_approval_high_risk:   bool  = True


# =====================================================
# PARAMETERS — MODULAR
#
# Each section is individually optional.
# The hybrid validator in Spec enforces that the
# correct section is present for the declared type.
# model_dump(exclude_none=True) ensures only present
# sections contribute keys to the runtime context.
# =====================================================


class Parameters(BaseModel):
    """
    Modular policy runtime parameters.

    Each governance domain section is optional.
    Required sections are enforced per policy_type
    by the hybrid validator in Spec.

    Flattened by policy_normalizer before evaluation.
    None sections are excluded from flattening.
    """

    budget:     Optional[Budget]              = None
    security:   Optional[SecurityConfig]      = None
    compliance: Optional[ComplianceConfig]    = None
    limits:     Optional[ResourceLimits]      = None
    network:    Optional[NetworkConfig]       = None
    identity:   Optional[IdentityConfig]      = None
    data:       Optional[DataGovernanceConfig] = None
    resilience: Optional[ResilienceConfig]    = None
    ai:         Optional[AIGovernanceConfig]  = None


# =====================================================
# CONDITION KEYWORD MAPS
#
# Used by Layer 2 of the hybrid validator.
# Maps condition expression keywords to the
# governance domain they belong to.
#
# Keywords match actual condition expression
# patterns to avoid false positives.
# =====================================================

_COST_KEYWORDS: frozenset[str] = frozenset({
    "estimated_cost", "current_spend",
    "budget.amount", "budget.period",
})

_SECURITY_KEYWORDS: frozenset[str] = frozenset({
    "open_ingress_rules", "public_storage_buckets",
    "unencrypted_databases", "security.max_open_ingress",
    "security.max_public",
})

_COMPLIANCE_KEYWORDS: frozenset[str] = frozenset({
    "untagged_resource_count", "compliance.max_untagged",
    "naming_violations",
})

_LIMITS_KEYWORDS: frozenset[str] = frozenset({
    "compute_instance_count", "gpu_instance_count",
    "limits.max_compute", "limits.max_gpu",
})

_NETWORK_KEYWORDS: frozenset[str] = frozenset({
    "public_ingress_count", "public_egress_count",
    "exposed_ports", "network.allow_public",
    "segmentation_violations", "network.max_exposed",
})

_IDENTITY_KEYWORDS: frozenset[str] = frozenset({
    "mfa_violations", "privileged_role_count",
    "identity.max_privileged", "service_account_key_count",
    "inactive_account_count",
})

_DATA_KEYWORDS: frozenset[str] = frozenset({
    "pii_resource_count", "unencrypted_data_stores",
    "data.allow_pii", "cross_region_replication_count",
    "public_data_access_count",
})

_RESILIENCE_KEYWORDS: frozenset[str] = frozenset({
    "replica_count", "multi_az_compliant",
    "resilience.min_replica", "backup_enabled",
    "recovery_time_hours",
})

_AI_KEYWORDS: frozenset[str] = frozenset({
    "external_model_count", "unlogged_ai_endpoints",
    "ai.allow_external", "high_risk_ai_deployments",
    "autonomous_deployment_count",
})

# Maps each non-composite policy type to its condition keywords
_TYPE_CONDITION_KEYWORDS: dict[PolicyType, frozenset[str]] = {
    PolicyType.COST:            _COST_KEYWORDS,
    PolicyType.SECURITY:        _SECURITY_KEYWORDS,
    PolicyType.COMPLIANCE:      _COMPLIANCE_KEYWORDS,
    PolicyType.RESOURCE_LIMITS: _LIMITS_KEYWORDS,
    PolicyType.NETWORK:         _NETWORK_KEYWORDS,
    PolicyType.IDENTITY:        _IDENTITY_KEYWORDS,
    PolicyType.DATA_GOVERNANCE: _DATA_KEYWORDS,
    PolicyType.RESILIENCE:      _RESILIENCE_KEYWORDS,
    PolicyType.AI_GOVERNANCE:   _AI_KEYWORDS,
}

# Maps each policy type to its required parameter section name
_TYPE_REQUIRED_PARAMETER: dict[PolicyType, str] = {
    PolicyType.COST:            "budget",
    PolicyType.SECURITY:        "security",
    PolicyType.COMPLIANCE:      "compliance",
    PolicyType.RESOURCE_LIMITS: "limits",
    PolicyType.NETWORK:         "network",
    PolicyType.IDENTITY:        "identity",
    PolicyType.DATA_GOVERNANCE: "data",
    PolicyType.RESILIENCE:      "resilience",
    PolicyType.AI_GOVERNANCE:   "ai",
}


# =====================================================
# SPEC
# =====================================================


class Spec(BaseModel):
    """
    Policy specification — the enforceable body of the policy.

    policy_type is optional for backward compatibility
    with policies that predate this field.
    When present, the hybrid validator enforces:

    Layer 1: Required parameter section must exist
    Layer 2: Condition expressions must be consistent
             with the declared governance domain

    policy_type will become required in v0.3.0.
    """

    policy_type: Optional[PolicyType]       = None
    inputs:      List[str]
    parameters:  Parameters
    conditions:  List[Condition]
    decision:    Decision
    override:    Override
    governance:  Optional[GovernanceConfig] = None
    actions:     List[Action]

    @model_validator(mode="after")
    def validate_policy_type_contract(self) -> "Spec":
        """
        Hybrid validator — enforces governance domain contract.

        Only runs when policy_type is declared.
        Backward compatible: policies without policy_type pass.

        Layer 1 — Declaration enforcement:
            Checks that the required parameter section
            exists for the declared policy_type.
            Cost policy without budget → rejected.
            Security policy without security → rejected.

        Layer 2 — Condition consistency:
            Inspects condition expressions for keywords
            that signal a different governance domain
            than declared. Catches dishonest or accidental
            type declarations.
            Skipped for policy_type: composite.
        """

        if self.policy_type is None:
            # Backward compatible — no policy_type declared
            return self

        # -----------------------------------------------
        # LAYER 1 — Required parameters by type
        # -----------------------------------------------

        if self.policy_type != PolicyType.COMPOSITE:
            required_param = _TYPE_REQUIRED_PARAMETER.get(self.policy_type)

            if required_param and getattr(self.parameters, required_param) is None:
                raise ValueError(
                    f"policy_type '{self.policy_type.value}' requires "
                    f"spec.parameters.{required_param}. "
                    f"Add a {required_param} block to your policy parameters."
                )

        else:
            # Composite: at least one parameter section must exist
            all_sections = [
                self.parameters.budget,
                self.parameters.security,
                self.parameters.compliance,
                self.parameters.limits,
                self.parameters.network,
                self.parameters.identity,
                self.parameters.data,
                self.parameters.resilience,
                self.parameters.ai,
            ]
            if not any(s is not None for s in all_sections):
                raise ValueError(
                    "policy_type 'composite' requires at least one "
                    "parameter section. Add one or more governance "
                    "domain blocks to spec.parameters."
                )

        # -----------------------------------------------
        # LAYER 2 — Condition consistency
        # Skipped for composite policies which intentionally
        # combine governance domains.
        # -----------------------------------------------

        if self.policy_type == PolicyType.COMPOSITE:
            return self

        condition_text = " ".join(c.expression for c in self.conditions)

        for other_type, keywords in _TYPE_CONDITION_KEYWORDS.items():

            if other_type == self.policy_type:
                continue

            matched = [k for k in keywords if k in condition_text]

            if matched:
                raise ValueError(
                    f"Condition expressions reference "
                    f"'{matched[0]}' which belongs to "
                    f"governance domain '{other_type.value}', "
                    f"but policy_type '{self.policy_type.value}' "
                    f"was declared. "
                    f"Either change policy_type to '{other_type.value}' "
                    f"or remove the mismatched condition."
                )

        return self


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
