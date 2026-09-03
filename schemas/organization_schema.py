# schemas/organization_schema.py
#
# Purpose:
# Define the canonical organization authority contract — the
# schema for organization.yaml, mirroring
# schemas/policy_schema.py's own pattern (Pydantic BaseModel +
# model_validator, apiVersion/kind/metadata root shape).
#
# Per ADR-004-R-04 SS6.1: this schema module, and the
# AuthorityProvider/local-provider logic that consumes it (see
# authority/), must NOT live under telemetry/. Authority
# resolution is governance/security logic; telemetry is
# downstream evidence/audit infrastructure only.
#
# Role identity model (ADR-004-R-04 SS4):
#   role_id        immutable, unique, never reused — the
#                  canonical identifier persisted into
#                  governance history and Authority Evidence
#   name           stable configuration/CLI alias — should
#                  not normally change, but is NOT the
#                  authoritative historical identifier
#   display_name   mutable presentation text — may change
#                  freely without affecting any historical
#                  record
#
# IMPORTANT — schema scope limitation, stated explicitly:
# This module can only enforce role_id UNIQUENESS WITHIN THE
# CURRENT DOCUMENT. It has no memory of prior document states
# and therefore CANNOT enforce ADR-004-R-04's true "never
# reused" invariant — that requires persisted historical state
# (has this role_id ever existed before, even if now absent
# from the file?), which is authority/local_provider.py's
# responsibility, not this schema's. The required Tranche A
# test "retired role ID reused -> reject" is satisfied there,
# not here.
#
# This module defines STRUCTURE and STATIC validity only. It
# does NOT resolve membership, notification endpoints, or
# authorization decisions, and must not grow methods like
# is_authorized()/resolve_member()/can_approve() — those
# belong in authority/. The schema remains a data contract.

from __future__ import annotations

import re
from typing import Optional

from pydantic import BaseModel, EmailStr, Field, field_validator, model_validator

from authority.models import NotificationChannel, RoleStatus

# =====================================================
# ROLE LIFECYCLE STATUS
# =====================================================


# RoleStatus now lives in authority/models.py — imported
# above — so the schema and the authority layer share ONE
# definition rather than two independently-maintained enums
# with identical semantics. This also reverses the dependency
# direction: the authority domain model no longer needs to
# import anything from this concrete YAML schema module.


# NotificationChannel now lives in authority/models.py —
# imported above — for the same reason RoleStatus was moved:
# one shared enum, not a duplicated concept between the schema
# and the provider-neutral NotificationEndpoint that already
# carries this same value.


# =====================================================
# CANONICAL SYNTAX PATTERNS
#
# Cheap to enforce now, before these identifiers enter
# immutable, hash-chained governance history. Expensive to
# retrofit afterward.
# =====================================================

_ROLE_ID_PATTERN = re.compile(r"^role_[a-z][a-z0-9_]*$")
_ROLE_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")
_SUPPORTED_API_VERSION = "obsidianwall.io/v1"


# =====================================================
# NOTIFICATION ENDPOINT CONFIGURATION
# =====================================================


class EmailEndpoint(BaseModel):
    """
    Requires the 'email-validator' package (a dependency of
    pydantic's EmailStr, not currently declared in this
    project's requirements — must be added alongside this
    file). Used here deliberately, unlike role membership
    (see Role.members below): a notification email address
    really is supposed to be an email address, whereas a role
    member's identity is not guaranteed to be one.
    """

    address: EmailStr


class SlackEndpoint(BaseModel):
    webhook_env: str = Field(
        ...,
        description=(
            "Name of the environment variable holding the Slack "
            "webhook URL — the URL itself is never stored in "
            "organization.yaml, matching the existing "
            "notifications/config.py pattern of resolving secrets "
            "from environment variables, not committed files."
        ),
    )

    @field_validator("webhook_env")
    @classmethod
    def webhook_env_must_not_be_empty(cls, v: str) -> str:
        value = v.strip()
        if not value:
            raise ValueError("webhook_env must not be empty")
        return value


class TeamsEndpoint(BaseModel):
    webhook_env: str

    @field_validator("webhook_env")
    @classmethod
    def webhook_env_must_not_be_empty(cls, v: str) -> str:
        value = v.strip()
        if not value:
            raise ValueError("webhook_env must not be empty")
        return value


class RoleNotificationConfig(BaseModel):
    """
    Per ADR-004-R-04 SS14: notification is a side effect of a
    governance decision, resolved via role_id, never a
    substitute for or component of authorization itself.
    """

    preferred: NotificationChannel
    email: Optional[EmailEndpoint] = None
    slack: Optional[SlackEndpoint] = None
    teams: Optional[TeamsEndpoint] = None

    @model_validator(mode="after")
    def preferred_channel_must_be_configured(self) -> "RoleNotificationConfig":
        configured = {
            NotificationChannel.EMAIL: self.email is not None,
            NotificationChannel.SLACK: self.slack is not None,
            NotificationChannel.TEAMS: self.teams is not None,
        }
        if not configured.get(self.preferred, False):
            raise ValueError(
                f"preferred channel '{self.preferred.value}' is declared "
                f"but has no corresponding configuration block"
            )
        return self


# =====================================================
# ROLE — CANONICAL IDENTITY MODEL
# =====================================================


class Role(BaseModel):
    """
    A single governance role. id/name/display_name are three
    deliberately distinct fields — see module docstring and
    ADR-004-R-04 SS4. Do not collapse these into one field.
    """

    id: str = Field(
        ...,
        description="Immutable, unique, never-reused canonical identifier.",
    )
    name: str = Field(
        ...,
        description="Stable configuration/CLI alias, resolved to id.",
    )
    display_name: str = Field(
        ...,
        description="Mutable presentation label. May change freely.",
    )
    status: RoleStatus = RoleStatus.ACTIVE
    members: list[str] = Field(
        default_factory=list,
        description=(
            "Opaque, non-empty identity strings — deliberately NOT "
            "typed as EmailStr. Verdict's actual identity resolver "
            "(telemetry/identity.py's resolve_actor_identity()) can "
            "return a GITHUB_ACTOR username, a GitLab login, a bare "
            "git user.name, or an OS username — none of which are "
            "guaranteed to be email addresses, and GITHUB_ACTOR "
            "specifically is checked BEFORE any email-shaped fallback "
            "in CI, which is Verdict's primary deployment context. "
            "Requiring EmailStr here would make it structurally "
            "impossible to authorize the exact identity the system "
            "resolves in its most common real usage."
        ),
    )
    notification: Optional[RoleNotificationConfig] = None

    @field_validator("id")
    @classmethod
    def id_must_be_canonical(cls, v: str) -> str:
        if not _ROLE_ID_PATTERN.fullmatch(v):
            raise ValueError(
                f"role id '{v}' must match '^role_[a-z][a-z0-9_]*$' "
                f"(example: role_security_admin). This is a permanent "
                f"historical identifier once used in a governance "
                f"decision — canonical syntax is enforced now because "
                f"it is cheap now and expensive after the fact."
            )
        return v

    @field_validator("name")
    @classmethod
    def name_must_be_canonical(cls, v: str) -> str:
        if not _ROLE_NAME_PATTERN.fullmatch(v):
            raise ValueError(
                f"role name '{v}' must match '^[a-z][a-z0-9_]*$' "
                f"(example: security_admin) so CLI --role lookup "
                f"stays deterministic. Values are rejected, never "
                f"silently normalized — identity-bearing configuration "
                f"must not be mutated behind the author's back."
            )
        return v

    @field_validator("members")
    @classmethod
    def members_must_be_non_empty_and_unique(cls, members: list[str]) -> list[str]:
        normalized: list[str] = []
        seen: set[str] = set()

        for member in members:
            value = member.strip()

            if not value:
                raise ValueError("role member identity must not be empty")

            if value in seen:
                raise ValueError(f"duplicate role member identity '{value}'")

            seen.add(value)
            normalized.append(value)

        return normalized


# =====================================================
# ORGANIZATION AUTHORITY — ROOT CONTRACT
# =====================================================


class OrganizationMetadata(BaseModel):
    organization_id: str = Field(min_length=1)
    version: str = Field(min_length=1)

    @field_validator("organization_id", "version")
    @classmethod
    def strip_and_reject_blank(cls, v: str) -> str:
        value = v.strip()
        if not value:
            raise ValueError("must not be empty or whitespace-only")
        return value


class OrganizationAuthority(BaseModel):
    """
    Canonical organization.yaml contract — the root object
    produced by validation, consumed by authority/local_provider.py.

    Mirrors schemas/policy_schema.py's Policy root contract
    shape (apiVersion/kind/metadata/...).
    """

    apiVersion: str
    kind: str
    metadata: OrganizationMetadata
    roles: list[Role]

    @field_validator("apiVersion")
    @classmethod
    def api_version_must_be_supported(cls, v: str) -> str:
        if v != _SUPPORTED_API_VERSION:
            raise ValueError(
                f"apiVersion must be '{_SUPPORTED_API_VERSION}', got '{v}'"
            )
        return v

    @field_validator("kind")
    @classmethod
    def kind_must_be_organization_authority(cls, v: str) -> str:
        if v != "OrganizationAuthority":
            raise ValueError(f"kind must be 'OrganizationAuthority', got '{v}'")
        return v

    @model_validator(mode="after")
    def role_ids_must_be_unique_within_document(self) -> "OrganizationAuthority":
        # NOTE: this proves uniqueness within THIS document only.
        # It does not and cannot prove the ADR's true never-reused
        # invariant across time — see module docstring.
        seen_ids: dict[str, int] = {}
        for i, role in enumerate(self.roles):
            if role.id in seen_ids:
                raise ValueError(
                    f"duplicate role id '{role.id}' — first seen at index "
                    f"{seen_ids[role.id]}, again at index {i}."
                )
            seen_ids[role.id] = i
        return self

    @model_validator(mode="after")
    def role_names_must_be_unique(self) -> "OrganizationAuthority":
        """
        IMPORTANT — this enforces uniqueness within the
        CURRENT document ONLY. It does NOT, by itself, prevent
        historical alias reuse: because `name` is mutable (only
        `role_id` is declared immutable per INV-02), a role
        could be renamed before retirement, causing its OLD
        alias to disappear from the document entirely and
        become silently available for a completely unrelated
        future role. True historical alias non-reuse requires a
        persisted registry of every name ever used, analogous
        to the role_id never-reuse registry — that is
        authority/local_provider.py's responsibility, not this
        schema's. This validator only proves "no collision
        exists right now," exactly as its role_id counterpart
        only proves current-document uniqueness, not permanent
        non-reuse. Do not treat this check as satisfying the
        deliberate alias-retirement policy on its own.
        """
        seen_names: dict[str, int] = {}
        for i, role in enumerate(self.roles):
            if role.name in seen_names:
                raise ValueError(
                    f"duplicate role name '{role.name}' — first seen at "
                    f"index {seen_names[role.name]}, again at index {i}."
                )
            seen_names[role.name] = i
        return self

    @model_validator(mode="after")
    def role_names_must_not_collide_with_role_ids(self) -> "OrganizationAuthority":
        """
        A role's name field is syntactically permitted to look like
        another role's id (both patterns allow strings starting with
        'role_'). Since ADR-004-R-04 SS5 lets the CLI/provider accept
        EITHER a name or a direct role_id as fallback input, an
        uncaught collision would make --role <string> genuinely
        ambiguous — resolvable as one role by name, a DIFFERENT role
        by id. Rejected here, at schema time, before any resolver
        logic is built on top of this.
        """
        role_ids = {role.id for role in self.roles}
        for i, role in enumerate(self.roles):
            if role.name in role_ids:
                raise ValueError(
                    f"role name '{role.name}' at index {i} collides "
                    f"with a canonical role id. Role names and role "
                    f"ids must occupy distinct namespaces so --role "
                    f"resolution is unambiguous."
                )
        return self

    def get_role_by_id(self, role_id: str) -> Optional[Role]:
        """Direct lookup by immutable id — the canonical path."""
        for role in self.roles:
            if role.id == role_id:
                return role
        return None

    def get_role_by_name(self, name: str) -> Optional[Role]:
        """Alias lookup, resolved to the same Role object as get_role_by_id
        would return — used for CLI --role convenience per ADR SS5."""
        for role in self.roles:
            if role.name == name:
                return role
        return None
