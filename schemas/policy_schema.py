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
# HYBRID VALIDATION MODEL — TWO LAYERS:
#
# Layer 1 — Declaration enforcement:
#   policy_type declares what parameters are required.
#   A cost policy without a budget block is rejected.
#   A security policy without a security block is rejected.
#   A composite policy without governance_domains is rejected.
#   A composite policy without parameters for each declared
#   domain is rejected.
#
# Layer 2 — Condition consistency:
#   Condition expressions are inspected against declared type.
#   An engineer cannot declare policy_type: security while
#   writing budget conditions — mismatch is caught.
#   For composite: conditions are scoped to declared domains.
#   Conditions referencing undeclared domains are rejected.
#   This prevents composite from being used as a bypass.
#
# ZERO TRUST APPROACH TO COMPOSITE:
#   composite does NOT relax validation — it redirects it.
#   Every composite policy must declare its governance_domains.
#   Validation is enforced against those declared domains.
#   A bad actor cannot use composite to bypass Layer 2 —
#   composite enforces MORE checks, not fewer.


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
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# =====================================================
# GOVERNANCE DECISION OUTCOMES
# =====================================================


class GovernanceDecision(str, Enum):
    """
    Five-level governance decision model.

    Replaces binary allow/deny with
    accountability-aware routing decisions.
    """

    ALLOW = "ALLOW"
    ALLOW_WITH_NOTIFICATION = "ALLOW_WITH_NOTIFICATION"
    ALLOW_WITH_APPROVAL_REQUIRED = "ALLOW_WITH_APPROVAL_REQUIRED"
    DENY_WITH_OVERRIDE = "DENY_WITH_OVERRIDE"
    DENY = "DENY"


# =====================================================
# POLICY TYPE
# =====================================================


class PolicyType(str, Enum):
    """
    Governance domain classification.

    Declares the governance concern this policy enforces.
    Drives parameter enforcement and condition validation.

    composite — coordinates multiple governance domains.
                Requires explicit governance_domains declaration.
                Layer 2 is scoped to declared domains only.
                Cannot be used to bypass validation.
    """

    COST = "cost"
    SECURITY = "security"
    COMPLIANCE = "compliance"
    RESOURCE_LIMITS = "resource_limits"
    NETWORK = "network"
    IDENTITY = "identity"
    DATA_GOVERNANCE = "data_governance"
    RESILIENCE = "resilience"
    AI_GOVERNANCE = "ai_governance"
    COMPOSITE = "composite"


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

    EMAIL = "email"
    SLACK = "slack"
    TEAMS = "teams"
    PAGERDUTY = "pagerduty"
    WEBHOOK = "webhook"


# =====================================================
# METADATA
# =====================================================


class Metadata(BaseModel):
    """Policy identity and ownership metadata."""

    name: str
    version: str  # string — preserves "0.10" correctly
    owner: str
    description: Optional[str] = None


# =====================================================
# CONDITIONS
# =====================================================


class Condition(BaseModel):
    """
    Deterministic policy condition.
    Evaluated by the condition evaluator engine.
    """

    id: str
    expression: str
    description: str


# =====================================================
# ACTIONS
# =====================================================


class Action(BaseModel):
    """Post-decision action directive."""

    type: str
    message: str
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
    deny: str
    warn: Optional[str] = None


# =====================================================
# OVERRIDE
# =====================================================


class Override(BaseModel):
    """
    Policy override configuration.
    Defines who can override a governance decision
    and whether approval is required.
    """

    roles: List[str]
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

    role: str
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

    severity: GovernanceSeverity = GovernanceSeverity.MEDIUM
    notifications: List[NotificationTarget] = []
    approvals: Optional[ApprovalConfig] = None


# =====================================================
# PARAMETER MODELS
#
# Each model corresponds to one governance domain.
# Parameters are flattened to dot-notation keys by
# policy_normalizer before evaluation.
# Only present (non-None) sections contribute keys.
# =====================================================


class Budget(BaseModel):
    """Budget constraint parameters. Required for policy_type: cost."""

    amount: float
    period: str
    scope: str
    owner: str
    flexibility: str
    override_allowed: bool


class SecurityConfig(BaseModel):
    """Security posture parameters. Required for policy_type: security."""

    allow_open_ingress: bool = False
    allow_public_storage: bool = False
    allow_unencrypted_db: bool = False
    max_open_ingress_rules: int = 0
    max_public_buckets: int = 0


class ComplianceConfig(BaseModel):
    """Compliance and tagging parameters. Required for policy_type: compliance."""

    max_untagged_resources: int = 0
    required_tags: List[str] = []
    enforcement: str = "soft"
    scope: str = "all_resources"


class ResourceLimits(BaseModel):
    """Resource sizing parameters. Required for policy_type: resource_limits."""

    max_compute_instances: int = 5
    max_gpu_instances: int = 0
    max_single_deployment_cost: float = 500.0
    environment: str = "development"


class NetworkConfig(BaseModel):
    """Network topology parameters. Required for policy_type: network."""

    allow_public_ingress: bool = False
    allow_public_egress: bool = False
    required_segmentation: bool = True
    approved_regions: List[str] = []
    require_private_endpoints: bool = True
    max_exposed_ports: int = 0
    require_firewall: bool = True


class IdentityConfig(BaseModel):
    """IAM and Zero Trust parameters. Required for policy_type: identity."""

    require_mfa: bool = True
    max_privileged_roles: int = 2
    allow_service_account_keys: bool = False
    require_just_in_time_access: bool = False
    allow_permanent_credentials: bool = False
    max_inactive_accounts: int = 0
    require_role_expiry: bool = True


class DataGovernanceConfig(BaseModel):
    """Data sovereignty parameters. Required for policy_type: data_governance."""

    allow_pii_storage: bool = False
    allow_cross_region_replication: bool = False
    encryption_required: bool = True
    retention_days: int = 30
    approved_data_classifications: List[str] = []
    require_data_lineage: bool = True
    allow_public_data_access: bool = False


class ResilienceConfig(BaseModel):
    """Availability and DR parameters. Required for policy_type: resilience."""

    min_replica_count: int = 2
    multi_az_required: bool = True
    backup_required: bool = True
    disaster_recovery_tier: str = "tier_1"
    max_recovery_time_hours: int = 4
    require_health_checks: bool = True
    require_auto_scaling: bool = False


class AIGovernanceConfig(BaseModel):
    """
    AI system governance parameters.
    Required for policy_type: ai_governance.

    Doctrine: AI may advise. AI may not govern.
    This policy type enforces that boundary.
    """

    allow_external_models: bool = False
    require_prompt_logging: bool = True
    allow_sensitive_training_data: bool = False
    model_risk_tier: str = "medium"
    require_model_versioning: bool = True
    require_bias_evaluation: bool = False
    allow_autonomous_deployment: bool = False
    require_human_approval_high_risk: bool = True


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

    budget: Optional[Budget] = None
    security: Optional[SecurityConfig] = None
    compliance: Optional[ComplianceConfig] = None
    limits: Optional[ResourceLimits] = None
    network: Optional[NetworkConfig] = None
    identity: Optional[IdentityConfig] = None
    data: Optional[DataGovernanceConfig] = None
    resilience: Optional[ResilienceConfig] = None
    ai: Optional[AIGovernanceConfig] = None


# =====================================================
# CONDITION KEYWORD MAPS
#
# Maps condition expression keywords to governance domains.
# Used by Layer 2 to detect domain mismatches.
#
# Keywords match actual condition expression patterns
# to avoid false positives on unrelated field names.
# Each keyword belongs to exactly one domain.
# =====================================================

_COST_KEYWORDS: frozenset[str] = frozenset(
    {
        "estimated_cost",
        "current_spend",
        "budget.amount",
        "budget.period",
    }
)

_SECURITY_KEYWORDS: frozenset[str] = frozenset(
    {
        "open_ingress_rules",
        "public_storage_buckets",
        "unencrypted_databases",
        "security.max_open_ingress",
        "security.max_public",
    }
)

_COMPLIANCE_KEYWORDS: frozenset[str] = frozenset(
    {
        "untagged_resource_count",
        "compliance.max_untagged",
        "naming_violations",
    }
)

_LIMITS_KEYWORDS: frozenset[str] = frozenset(
    {
        "compute_instance_count",
        "gpu_instance_count",
        "limits.max_compute",
        "limits.max_gpu",
    }
)

_NETWORK_KEYWORDS: frozenset[str] = frozenset(
    {
        "public_ingress_count",
        "public_egress_count",
        "exposed_ports",
        "network.allow_public",
        "segmentation_violations",
        "network.max_exposed",
    }
)

_IDENTITY_KEYWORDS: frozenset[str] = frozenset(
    {
        "mfa_violations",
        "privileged_role_count",
        "identity.max_privileged",
        "service_account_key_count",
        "inactive_account_count",
    }
)

_DATA_KEYWORDS: frozenset[str] = frozenset(
    {
        "pii_resource_count",
        "unencrypted_data_stores",
        "data.allow_pii",
        "cross_region_replication_count",
        "public_data_access_count",
    }
)

_RESILIENCE_KEYWORDS: frozenset[str] = frozenset(
    {
        "replica_count",
        "multi_az_compliant",
        "resilience.min_replica",
        "backup_enabled",
        "recovery_time_hours",
    }
)

_AI_KEYWORDS: frozenset[str] = frozenset(
    {
        "external_model_count",
        "unlogged_ai_endpoints",
        "ai.allow_external",
        "high_risk_ai_deployments",
        "autonomous_deployment_count",
        # ai_gpu_workloads: GPU instances as AI deployment signals.
        # Semantically distinct from gpu_instance_count
        # (resource_limits domain) which treats GPU as a
        # sizing concern. Same hardware, different governance intent.
        "ai_gpu_workloads",
    }
)

_TYPE_CONDITION_KEYWORDS: dict[PolicyType, frozenset[str]] = {
    PolicyType.COST: _COST_KEYWORDS,
    PolicyType.SECURITY: _SECURITY_KEYWORDS,
    PolicyType.COMPLIANCE: _COMPLIANCE_KEYWORDS,
    PolicyType.RESOURCE_LIMITS: _LIMITS_KEYWORDS,
    PolicyType.NETWORK: _NETWORK_KEYWORDS,
    PolicyType.IDENTITY: _IDENTITY_KEYWORDS,
    PolicyType.DATA_GOVERNANCE: _DATA_KEYWORDS,
    PolicyType.RESILIENCE: _RESILIENCE_KEYWORDS,
    PolicyType.AI_GOVERNANCE: _AI_KEYWORDS,
}

_TYPE_REQUIRED_PARAMETER: dict[PolicyType, str] = {
    PolicyType.COST: "budget",
    PolicyType.SECURITY: "security",
    PolicyType.COMPLIANCE: "compliance",
    PolicyType.RESOURCE_LIMITS: "limits",
    PolicyType.NETWORK: "network",
    PolicyType.IDENTITY: "identity",
    PolicyType.DATA_GOVERNANCE: "data",
    PolicyType.RESILIENCE: "resilience",
    PolicyType.AI_GOVERNANCE: "ai",
}


# =====================================================
# SPEC
# =====================================================


class Spec(BaseModel):
    """
    Policy specification — the enforceable body of the policy.

    policy_type is optional for backward compatibility.
    When present, the hybrid validator enforces both layers.

    governance_domains is ONLY valid for policy_type: composite.
    Composite policies MUST declare their governance_domains —
    validation is then enforced against those declared domains.
    This prevents composite from being used as a bypass.
    """

    policy_type: Optional[PolicyType] = None
    governance_domains: Optional[List[PolicyType]] = None
    inputs: List[str]
    parameters: Parameters
    conditions: List[Condition]
    decision: Decision
    override: Override
    governance: Optional[GovernanceConfig] = None
    actions: List[Action]

    @model_validator(mode="after")
    def validate_policy_type_contract(self) -> "Spec":
        """
        Hybrid validator — enforces governance domain contract.

        Backward compatible: policies without policy_type pass.

        SINGLE DOMAIN:
        Layer 1 — required parameter section must exist
        Layer 2 — conditions must match declared domain

        COMPOSITE (Zero Trust approach):
        Layer 1a — governance_domains must be declared
        Layer 1b — no nesting (composite not in domains)
        Layer 1c — parameters must exist for each declared domain
        Layer 2  — conditions scoped to declared domains only
                   conditions from undeclared domains rejected
        """

        if self.policy_type is None:
            return self

        # ── governance_domains only valid on composite ──────────
        if self.governance_domains and self.policy_type != PolicyType.COMPOSITE:
            raise ValueError(
                f"spec.governance_domains is only valid for "
                f"policy_type 'composite'. "
                f"policy_type '{self.policy_type.value}' does not "
                f"support domain declarations."
            )

        # ── LAYER 1 — single domain ─────────────────────────────
        if self.policy_type != PolicyType.COMPOSITE:
            required_param = _TYPE_REQUIRED_PARAMETER.get(self.policy_type)

            if required_param and getattr(self.parameters, required_param) is None:
                raise ValueError(
                    f"policy_type '{self.policy_type.value}' requires "
                    f"spec.parameters.{required_param}. "
                    f"Add a {required_param} block to your policy parameters."
                )

        # ── LAYER 1 — composite ─────────────────────────────────
        else:
            # 1a — governance_domains must be declared
            if not self.governance_domains:
                raise ValueError(
                    "policy_type 'composite' requires "
                    "spec.governance_domains declaring which domains "
                    "this policy coordinates.\n"
                    "Example:\n"
                    "  governance_domains:\n"
                    "    - cost\n"
                    "    - security\n"
                    "composite without declared domains is not permitted."
                )

            # 1b — no nesting composite inside composite
            if PolicyType.COMPOSITE in self.governance_domains:
                raise ValueError(
                    "spec.governance_domains cannot include 'composite'. "
                    "Composite policies coordinate specific governance "
                    "domains, not other composite policies."
                )

            # 1c — parameters must exist for each declared domain
            for domain in self.governance_domains:
                required_param = _TYPE_REQUIRED_PARAMETER.get(domain)
                if required_param and getattr(self.parameters, required_param) is None:
                    raise ValueError(
                        f"Composite policy declares domain '{domain.value}' "
                        f"but spec.parameters.{required_param} is missing. "
                        f"Add a {required_param} block or remove "
                        f"'{domain.value}' from governance_domains."
                    )

        # ── LAYER 2 — single domain ─────────────────────────────
        if self.policy_type != PolicyType.COMPOSITE:
            condition_text = " ".join(c.expression for c in self.conditions)

            for other_type, keywords in _TYPE_CONDITION_KEYWORDS.items():
                if other_type == self.policy_type:
                    continue
                matched = [k for k in keywords if k in condition_text]
                if matched:
                    raise ValueError(
                        f"Condition expressions reference '{matched[0]}' "
                        f"which belongs to governance domain "
                        f"'{other_type.value}', but policy_type "
                        f"'{self.policy_type.value}' was declared. "
                        f"Either change policy_type to '{other_type.value}' "
                        f"or remove the mismatched condition."
                    )

        # ── LAYER 2 — composite: scoped to declared domains ─────
        else:
            condition_text = " ".join(c.expression for c in self.conditions)
            declared: set[PolicyType] = set(self.governance_domains or [])

            for other_type, keywords in _TYPE_CONDITION_KEYWORDS.items():
                if other_type in declared:
                    continue  # declared domain — keywords are permitted
                matched = [k for k in keywords if k in condition_text]
                if matched:
                    raise ValueError(
                        f"Composite policy condition references "
                        f"'{matched[0]}' which belongs to governance "
                        f"domain '{other_type.value}', but that domain "
                        f"is not listed in spec.governance_domains. "
                        f"Either add '{other_type.value}' to "
                        f"governance_domains or remove the condition."
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
    kind: str
    metadata: Metadata
    spec: Spec
