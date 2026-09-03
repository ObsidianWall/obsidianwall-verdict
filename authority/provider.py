# authority/provider.py
#
# Purpose:
# Define the AuthorityProvider contract — the abstract
# interface every authority source (local YAML now; Entra,
# Atlas, Okta, a hosted ObsidianWall service later) must
# satisfy, per ADR-004-R-04 SS1/D1.
#
# CRITICAL BOUNDARY (Model A, confirmed via adversarial
# review): This interface answers narrow, factual questions.
# It does NOT answer "does this role have governance
# authority" — that question has no independent meaning.
# Governance authority is ALWAYS decision-scoped, established
# by policy-declared authorized_role_ids frozen onto a
# specific governance record.
#
# SECOND CRITICAL BOUNDARY, added after review: this interface
# depends ONLY on authority/models.py's provider-neutral types
# (AuthorityRole, RoleStatus, etc.) — NEVER on
# schemas.organization_schema.Role, which is the concrete
# local-YAML artifact shape, including fields (members,
# notification config) that don't belong on a provider-
# agnostic role identity. LocalOrganizationAuthorityProvider
# maps organization_schema.Role -> AuthorityRole internally;
# a future Entra/Atlas provider maps its own backing object to
# the same shared contract. If this file ever imports from
# schemas.organization_schema again, that is this exact
# regression happening a second time.
#
# Per ADR-004-R-04 SS6.1: this module and its implementations
# must NOT live under telemetry/.

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from authority.models import (
    AuthorityProviderFailure,
    AuthorityRole,
    AuthoritySourceMetadata,
    NotificationChannel,
    NotificationEndpoint,
    RoleResolution,
)

__all__ = [
    "AuthorityProvider",
    "AuthorityProviderError",
]


class AuthorityProviderError(Exception):
    """
    Raised when the authority provider itself cannot be
    consulted at all. Carries a structured `failure` reason
    (see authority.models.AuthorityProviderFailure) so callers
    can map it precisely to ADR D9's failure codes, e.g.:

        SOURCE_NOT_FOUND      -> ORGANIZATION_CONFIG_NOT_FOUND
        SOURCE_INVALID        -> ORGANIZATION_CONFIG_INVALID
        PROVIDER_UNAVAILABLE  -> AUTHORITY_PROVIDER_UNAVAILABLE

    Per ADR INV-15: any AuthorityProviderError must always
    result in fail-closed behavior in the caller — authorization
    cannot be established — never fail-open.
    """

    def __init__(self, failure: AuthorityProviderFailure, message: str) -> None:
        # The type annotation alone is a static contract, not a
        # runtime guarantee — Python does not enforce it. Given
        # this exception drives fail-closed authorization error
        # semantics, arbitrary strings must not be able to
        # instantiate a structurally invalid provider error, the
        # same reasoning already applied to NotificationEndpoint.
        if not isinstance(failure, AuthorityProviderFailure):
            raise TypeError(
                f"failure must be an AuthorityProviderFailure member, got {failure!r}"
            )
        super().__init__(message)
        self.failure = failure


class AuthorityProvider(ABC):
    """
    Abstract authority source. The local YAML file is the
    v0.6.0 implementation of this contract, not the
    architecture itself — see LocalOrganizationAuthorityProvider
    in authority/local_provider.py.

    REQUIRED CALL ORDER for authorization flows — do not call
    is_member() as a substitute for checking whether a role
    exists at all:

        resolve_role(ref)
              |
        role exists? (RoleResolution.resolved)
              |
        role.status eligible? (not RETIRED, typically)
              |
        is_member(actor, role.id)

    Skipping directly to is_member() on an unresolved or
    nonexistent role_id collapses ACTOR_NOT_MEMBER_OF_ROLE and
    ROLE_ID_UNKNOWN into the same observed behavior (False),
    which ADR D9 requires to remain distinguishable.

    RETIRED ROLE REQUIREMENT (binding on every implementation):
    each provider implementation must preserve or reconstruct
    historical role identity sufficiently to distinguish a
    known-retired role_id from a role_id that was never known
    at all. This obligation belongs to the PROVIDER
    IMPLEMENTATION, not necessarily its upstream directory —
    an external system like Entra may permit deletion of its
    own backing group; Verdict cannot compel Microsoft to
    retain it forever. A future EntraAuthorityProvider might
    satisfy this via its own historical role registry even when
    the upstream directory object is gone. For the v0.6.0 local
    YAML provider, this means retired role entries are retained
    as tombstones in organization.yaml, never deleted — a real,
    minor file-growth cost accepted deliberately in exchange for
    preserving historical identity.

    DELIBERATE ALIAS NON-REASSIGNMENT RULE: once a name/alias
    has been associated with a given role_id, it must never be
    reassigned to a DIFFERENT role_id — even though only
    role_id is declared immutable historical identity per
    INV-02. An old governance record or ticket referencing a
    role by its human-facing alias (e.g. "approved as
    security_admin") should never become ambiguous because that
    label was later reassigned to an unrelated role.

    THIS IS A PROVIDER-LEVEL TEMPORAL INVARIANT, NOT A SCHEMA
    ONE. Retaining retired tombstones plus current-document name
    uniqueness does NOT, by itself, guarantee this: a role can
    be renamed before retirement, causing its OLD alias to
    disappear from the document entirely and become silently
    available for a different role_id. Each provider
    implementation must independently preserve sufficient
    alias-to-role_id history to prevent that reassignment. For
    the local provider, this means a persisted historical
    registry mapping every name ever seen to the role_id it was
    associated with — not merely the current file's contents,
    and not merely retired tombstones. This is a state-transition
    invariant ("is this rename/retirement valid given what
    existed before"), not a state-validity invariant ("is this
    document internally consistent right now") — the schema can
    only ever provide the latter.
    """

    @abstractmethod
    def resolve_role(self, role_ref: str) -> RoleResolution:
        """
        Resolve a role reference — a stable name (e.g.
        "security_admin") OR a direct immutable role_id (e.g.
        "role_security_admin") — to the actual role, INCLUDING
        retired roles (see class docstring).

        The strength of this method's guarantee depends on which
        form was supplied. If role_ref was an immutable role_id,
        role=None means this ID has never been validly known,
        including as a retired tombstone — a strong, permanent
        claim (see get_role()). If role_ref was a name/alias,
        role=None means it cannot PRESENTLY be resolved — only
        role_id is declared permanent per ADR INV-02, so this
        does NOT prove the alias never existed historically.
        See RoleResolution's docstring in authority/models.py
        for the full statement of this distinction.

        Either way, role=None is a normal, expected outcome
        (e.g. a typo), distinct from AuthorityProviderError,
        which means the provider itself couldn't be consulted
        at all.

        Raises:
            AuthorityProviderError: if the provider itself
                cannot be read/reached at all.
        """
        raise NotImplementedError

    @abstractmethod
    def is_member(self, actor_identity: str, role_id: str) -> bool:
        """
        Whether actor_identity currently belongs to role_id.
        See class docstring for required call order.

        Current-state check, evaluated at call time — per ADR
        D3a, membership is resolved at action time, never
        cached across separate governance actions.

        actor_identity is an opaque string — must not assume
        email-shaped identities.

        Raises:
            AuthorityProviderError: if the provider itself
                cannot be read/reached at all.
        """
        raise NotImplementedError

    @abstractmethod
    def get_role(self, role_id: str) -> Optional[AuthorityRole]:
        """
        Direct lookup by immutable role_id, INCLUDING retired
        roles (see class docstring). Returns None ONLY if this
        role_id has never been validly used at all.

        Returns the narrow, provider-agnostic AuthorityRole —
        never the concrete local-YAML Role. Implementations
        that hold richer data internally (membership lists,
        notification config) map down to this narrow contract
        here; they don't return their internal representation
        directly.

        Raises:
            AuthorityProviderError: if the provider itself
                cannot be read/reached at all.
        """
        raise NotImplementedError

    @abstractmethod
    def get_notification_endpoint(
        self, role_id: str, channel: NotificationChannel
    ) -> Optional[NotificationEndpoint]:
        """
        The configured notification descriptor for role_id on
        the given channel — NOT a resolved secret. Takes the
        shared NotificationChannel enum, not a bare string —
        the whole point of introducing that enum was to
        eliminate exactly this kind of arbitrary-string
        ambiguity at the interface boundary. For Slack/Teams, returns the
        configured secret_env variable NAME; the dispatcher
        resolves its actual value at delivery time.

        Returns None if the role exists but has no
        configuration for this channel — treated as "no
        endpoint configured," falling back to OW_NOTIFICATION_TO
        per ADR D12/D13, never as an error.

        Per ADR D13, this has zero bearing on any authorization
        decision.

        Raises:
            AuthorityProviderError: if the provider itself
                cannot be read/reached at all.
        """
        raise NotImplementedError

    @abstractmethod
    def source_metadata(self) -> AuthoritySourceMetadata:
        """
        Provider identity/version metadata for Authority
        Evidence (ADR D6's authority_provider block).

        Does NOT establish that the source is trustworthy (per
        ADR SS9/D7a — deliberately deferred to the separate
        policy/authority-integrity workstream). Records, honestly,
        which authority-state document was relied upon.
        """
        raise NotImplementedError
