# authority/models.py
#
# Purpose:
# Provider-neutral authority domain types — shared by
# AuthorityProvider (authority/provider.py) and by
# schemas/organization_schema.py, so the dependency runs in
# ONE direction only: authority domain model <- organization
# schema, never the reverse.

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class RoleStatus(str, Enum):
    """
    Role lifecycle: active -> deprecated -> retired. A retired
    role_id remains resolvable for historical evidence but is
    not eligible for new authority grants.
    """

    ACTIVE = "active"
    DEPRECATED = "deprecated"
    RETIRED = "retired"


class NotificationChannel(str, Enum):
    """
    Moved here from organization_schema.py — notification
    routing is already part of the provider-neutral contract
    (get_notification_endpoint()), so the channel vocabulary
    belongs in the same shared domain model as everything else
    it's returned alongside, not duplicated as a bare string on
    NotificationEndpoint and a typed enum in the schema
    separately (the exact drift risk that motivated moving
    RoleStatus here in the first place).
    """

    EMAIL = "email"
    SLACK = "slack"
    TEAMS = "teams"


@dataclass(frozen=True)
class AuthorityRole:
    """
    Narrow, provider-agnostic role identity — deliberately
    excludes members and notification configuration, which
    stay behind is_member() and get_notification_endpoint()
    respectively.
    """

    id: str
    name: str
    display_name: str
    status: RoleStatus


@dataclass(frozen=True)
class RoleResolution:
    """
    Result of resolving a --role claim to an AuthorityRole.

    IMPORTANT — the strength of this method's guarantee depends
    on WHICH form of role_ref was supplied:

      - If role_ref was an immutable role_id: role=None means
        this ID has never been validly known, including as a
        retired tombstone. This is a strong, permanent claim
        (see get_role()).

      - If role_ref was a name/alias: role=None means this
        alias cannot PRESENTLY be resolved. Only role_id is
        declared immutable/permanent per ADR INV-02 — an alias
        was never promised to resolve forever, so role=None
        here does NOT prove the alias never existed historically,
        only that it doesn't resolve right now.

    Does NOT establish that the acting identity is a member of
    the resolved role, that the role is authorized for a
    specific decision, or that SoD is satisfied — `role` is
    resolved, not verified, until the rest of the authorization
    chain completes.
    """

    claimed_ref: str
    role: Optional[AuthorityRole]

    @property
    def resolved(self) -> bool:
        return self.role is not None


class AuthorityProviderFailure(str, Enum):
    SOURCE_NOT_FOUND = "source_not_found"
    SOURCE_INVALID = "source_invalid"
    PROVIDER_UNAVAILABLE = "provider_unavailable"


@dataclass(frozen=True)
class NotificationEndpoint:
    """
    A configured notification descriptor — never a resolved
    secret. Validates that each channel carries exactly the
    field it needs, so an invalid combination (e.g. an email
    channel with no address, or a slack channel with an address
    instead of a secret_env) is rejected at construction time
    rather than silently accepted and failing later at dispatch.
    """

    channel: NotificationChannel
    address: Optional[str] = None
    secret_env: Optional[str] = None

    def __post_init__(self) -> None:
        # Explicit rejection of unknown/non-enum values FIRST —
        # Python type annotations are not runtime-enforced, so
        # NotificationEndpoint(channel="discord") would otherwise
        # silently skip every branch below and be accepted.
        if not isinstance(self.channel, NotificationChannel):
            raise ValueError(
                f"channel must be a NotificationChannel member, got {self.channel!r}"
            )

        # Two DIFFERENT questions, deliberately checked
        # differently — conflating them creates a real loophole:
        # a REQUIRED field must contain actual, non-blank content
        # (whitespace-only is not useful data). A FORBIDDEN field
        # must be truly absent (None) — a whitespace-only value
        # in a forbidden field is still a value the caller
        # explicitly set, and must be rejected, not silently
        # treated as equivalent to "not provided."
        def _has_content(value: Optional[str]) -> bool:
            return bool(value and value.strip())

        def _is_absent(value: Optional[str]) -> bool:
            return value is None

        if self.channel == NotificationChannel.EMAIL:
            if not _has_content(self.address):
                raise ValueError(
                    "NotificationEndpoint(channel=EMAIL) requires a non-blank address"
                )
            if not _is_absent(self.secret_env):
                raise ValueError(
                    "NotificationEndpoint(channel=EMAIL) must not carry "
                    "secret_env (must be None, not merely blank)"
                )
        elif self.channel in (NotificationChannel.SLACK, NotificationChannel.TEAMS):
            if not _has_content(self.secret_env):
                raise ValueError(
                    f"NotificationEndpoint(channel={self.channel.value}) "
                    f"requires a non-blank secret_env"
                )
            if not _is_absent(self.address):
                raise ValueError(
                    f"NotificationEndpoint(channel={self.channel.value}) "
                    f"must not carry address (must be None, not merely blank)"
                )


@dataclass(frozen=True)
class AuthoritySourceMetadata:
    """
    Typed provider/source identity for Authority Evidence (ADR
    D6's authority_provider block).
    """

    provider_type: str
    source_identifier: str
    organization_id: Optional[str] = None
    schema_version: Optional[str] = None
    document_version: Optional[str] = None
    source_hash: Optional[str] = None
