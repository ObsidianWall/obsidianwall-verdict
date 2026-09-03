# authority/local_provider.py
#
# Purpose:
# The v0.6.0 local YAML implementation of AuthorityProvider.
# Schema validation, the provider contract, and TEMPORAL
# validation converge here — the historical registry is
# treated as SECURITY STATE, not a cache.
#
# IMPORTANT DEPLOYMENT CONSTRAINT, stated honestly rather than
# implied as solved: this provider's temporal invariants
# (role_id non-reuse, alias non-reassignment, lifecycle
# monotonicity) are only enforced ACROSS INVOCATIONS when the
# registry file itself persists between them. On a durable
# workstation or server, this holds. On an ephemeral CI runner
# with a fresh checkout every job, a NEW empty registry is
# created every run — meaning this provider cannot detect that
# an alias belonged to a different role three revisions ago if
# that revision's registry no longer exists. For v0.6.0, the
# honest position is: durable-registry deployments get full
# temporal enforcement; ephemeral CI deployments get present-
# state validation only (everything schema-level), NOT
# temporal non-reuse enforcement, unless the registry path is
# explicitly backed by persistent, version-controlled, or
# otherwise durable storage. This is a real, current limitation
# — not a documentation footnote to be quietly worked around.
#
# Per ADR-004-R-04 SS6.1: must NOT live under telemetry/.

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Optional

import yaml
from filelock import FileLock
from filelock import Timeout as FileLockTimeout
from pydantic import ValidationError

from authority.models import (
    AuthorityProviderFailure,
    AuthorityRole,
    AuthoritySourceMetadata,
    NotificationChannel,
    NotificationEndpoint,
    RoleResolution,
    RoleStatus,
)
from authority.organization_loader import load_organization
from authority.provider import AuthorityProvider, AuthorityProviderError
from schemas.organization_schema import OrganizationAuthority
from schemas.organization_schema import Role as SchemaRole

_REGISTRY_SCHEMA_VERSION = 1
_LOCK_TIMEOUT_SECONDS = 10.0

_ALLOWED_STATUS_TRANSITIONS: dict[RoleStatus, set[RoleStatus]] = {
    RoleStatus.ACTIVE: {RoleStatus.ACTIVE, RoleStatus.DEPRECATED, RoleStatus.RETIRED},
    RoleStatus.DEPRECATED: {RoleStatus.DEPRECATED, RoleStatus.RETIRED},
    RoleStatus.RETIRED: {RoleStatus.RETIRED},
}
# active -> retired directly is permitted (immediate retirement
# is operationally legitimate). No transition OUT of retired is
# permitted, in either direction — retirement is permanent.
# deprecated -> active is deliberately prohibited: this is a
# governance lifecycle policy choice, not an implementation
# accident. Reversibility during "scheduled for retirement"
# would introduce more temporal states than this version
# chooses to support.


# =====================================================
# CANONICAL HASHING (unchanged — accepted as correct)
# =====================================================


def _canonicalize_organization(org: OrganizationAuthority) -> dict[str, Any]:
    dumped = org.model_dump(mode="json", exclude_none=False)
    roles_sorted = sorted(dumped["roles"], key=lambda r: r["id"])
    for role in roles_sorted:
        role["members"] = sorted(role["members"])
    dumped["roles"] = roles_sorted
    return dumped


def _compute_source_hash(org: OrganizationAuthority) -> str:
    canonical = _canonicalize_organization(org)
    serialized = json.dumps(
        canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return sha256(serialized.encode("utf-8")).hexdigest()


# =====================================================
# HISTORICAL REGISTRY — SECURITY STATE, NOT A CACHE
# =====================================================


class TemporalAuthorityViolation(Exception):
    """A genuine invalid governance-state transition — e.g. a
    disappeared role_id or reassigned alias. This is NOT a
    provider outage; it's an invalid attempted transition,
    mapped by the caller to SOURCE_INVALID."""


class _RegistryCorrupt(Exception):
    """Internal — the registry file's own structure/version is
    invalid or unsupported. Distinct from TemporalAuthorityViolation:
    this means the SECURITY STATE MECHANISM itself cannot be
    trusted, not that the current organization.yaml violated a
    real historical fact. Mapped by the caller to
    PROVIDER_UNAVAILABLE, never SOURCE_INVALID — corrupt
    historical state must never be misattributed as a problem
    with the current governance source."""


_VALID_STATUS_VALUES = {s.value for s in RoleStatus}


def _validate_registry_structure(data: Any) -> tuple[dict[str, dict], dict[str, str]]:
    """
    Deep structural validation of decoded registry JSON.
    Raises _RegistryCorrupt for ANY deviation — malformed
    historical state must fail closed as PROVIDER_UNAVAILABLE,
    never leak as a raw AttributeError/ValueError, and never be
    misattributed to the current organization.yaml as
    SOURCE_INVALID.
    """
    if not isinstance(data, dict):
        raise _RegistryCorrupt(
            f"registry root must be a JSON object, got {type(data).__name__}"
        )

    version = data.get("version")
    if version != _REGISTRY_SCHEMA_VERSION:
        raise _RegistryCorrupt(
            f"registry version {version!r} is missing or unsupported "
            f"(expected {_REGISTRY_SCHEMA_VERSION}) — no migration path "
            f"exists yet, failing closed rather than guessing at intent"
        )

    org_id = data.get("organization_id")
    if not isinstance(org_id, str) or not org_id:
        raise _RegistryCorrupt("registry organization_id must be a non-empty string")

    role_ids = data.get("role_ids")
    if not isinstance(role_ids, dict):
        raise _RegistryCorrupt("registry role_ids must be an object")

    for rid, entry in role_ids.items():
        if not isinstance(rid, str):
            raise _RegistryCorrupt(f"registry role_ids key {rid!r} must be a string")
        if not isinstance(entry, dict):
            raise _RegistryCorrupt(
                f"registry role_ids['{rid}'] must be an object, "
                f"got {type(entry).__name__}"
            )
        first_seen = entry.get("first_seen")
        if not isinstance(first_seen, str) or not first_seen:
            raise _RegistryCorrupt(
                f"registry role_ids['{rid}'].first_seen must be a non-empty string"
            )
        status = entry.get("last_known_status")
        if status not in _VALID_STATUS_VALUES:
            raise _RegistryCorrupt(
                f"registry role_ids['{rid}'].last_known_status "
                f"{status!r} is not a valid role status"
            )

    aliases = data.get("aliases")
    if not isinstance(aliases, dict):
        raise _RegistryCorrupt("registry aliases must be an object")

    for alias, target_id in aliases.items():
        if not isinstance(alias, str) or not isinstance(target_id, str):
            raise _RegistryCorrupt(
                f"registry aliases entry {alias!r} -> {target_id!r} "
                f"must both be strings"
            )
        if target_id not in role_ids:
            raise _RegistryCorrupt(
                f"registry alias '{alias}' references unknown role_id "
                f"'{target_id}' not present in role_ids"
            )

    return role_ids, aliases


class _HistoricalRegistry:
    """
    Persisted memory of every role_id and alias ever validly
    seen by this provider instance, bound to a specific
    organization_id. Enforces role_id permanence, alias
    non-reassignment, and monotonic lifecycle transitions —
    invariants no stateless schema can provide.

    REQUIRED PROPERTY: the locking implementation must release
    ownership automatically when the owning process terminates,
    for any reason including a crash — this provider must never
    depend on manual lock-file deletion for recovery. The
    current implementation satisfies this via the `filelock`
    package's OS-backed advisory locking, but the architectural
    requirement is the property itself, not this specific
    library. A `.lock` pathname persisting on disk after some
    locking schemes does not necessarily mean the lock is still
    owned — the operating system's lock state is what matters,
    not whether the file happens to exist.
    """

    def __init__(self, registry_path: Path, expected_organization_id: str):
        self._path = registry_path
        self._lock_path = registry_path.with_suffix(registry_path.suffix + ".lock")
        self._expected_org_id = expected_organization_id
        self._role_ids: dict[str, dict[str, str]] = {}
        self._aliases: dict[str, str] = {}

    def _load_unlocked(self) -> None:
        if not self._path.exists():
            return

        try:
            with self._path.open("r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as exc:
            raise _RegistryCorrupt(
                f"registry at {self._path} could not be read/parsed: {exc}"
            ) from exc

        role_ids, aliases = _validate_registry_structure(data)

        org_id = data.get("organization_id")
        if org_id != self._expected_org_id:
            raise _RegistryCorrupt(
                f"registry at {self._path} is bound to organization_id "
                f"'{org_id}', but current organization.yaml declares "
                f"'{self._expected_org_id}'. The registry is bound to "
                f"the DECLARED organization namespace, not cryptographically "
                f"verified as belonging to a specific institution — if "
                f"this organization.yaml is genuinely new, use a "
                f"different registry_path."
            )

        self._role_ids = role_ids
        self._aliases = aliases

    def _save_unlocked(self) -> None:
        """
        Atomic replace via secure temp file in the same
        directory. Registry filesystem failures (permission,
        disk, fsync, replace) are caught here and re-raised as
        AuthorityProviderError(PROVIDER_UNAVAILABLE) — a
        historical-state persistence failure means the
        provider's required security state could not be safely
        consulted, not that the current governance source is
        invalid.
        """
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise AuthorityProviderError(
                AuthorityProviderFailure.PROVIDER_UNAVAILABLE,
                f"could not create registry directory {self._path.parent}: {exc}",
            ) from exc

        payload = {
            "version": _REGISTRY_SCHEMA_VERSION,
            "organization_id": self._expected_org_id,
            "role_ids": self._role_ids,
            "aliases": self._aliases,
        }

        tmp_path: Optional[Path] = None
        try:
            tmp_fd, tmp_name = tempfile.mkstemp(
                dir=str(self._path.parent), prefix=".authority-tmp-"
            )
            tmp_path = Path(tmp_name)

            with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, sort_keys=True)
                f.flush()
                os.fsync(f.fileno())
            try:
                os.chmod(tmp_path, 0o600)  # owner read/write only, POSIX;
                # a no-op / best-effort on platforms where this doesn't
                # apply the same way (e.g. Windows) — not a claim of
                # tamper resistance, just conservative-by-default
                # creation, consistent with treating this as local
                # security state rather than incidental metadata.
            except OSError:
                pass
            os.replace(str(tmp_path), str(self._path))
        except OSError as exc:
            # mkstemp() itself is now INSIDE this scope — a temp-
            # creation failure (disk full, permission denied, fd
            # exhaustion) is a provider-availability problem exactly
            # like a write or replace failure, and must map the same
            # way rather than leaking as a raw, unmapped OSError.
            raise AuthorityProviderError(
                AuthorityProviderFailure.PROVIDER_UNAVAILABLE,
                f"could not persist historical authority registry at "
                f"{self._path}: {exc}",
            ) from exc
        finally:
            if tmp_path is not None and tmp_path.exists():
                try:
                    tmp_path.unlink()
                except OSError:
                    pass

    def check_and_record(self, org: OrganizationAuthority) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise AuthorityProviderError(
                AuthorityProviderFailure.PROVIDER_UNAVAILABLE,
                f"could not create registry directory {self._path.parent} "
                f"before lock acquisition: {exc}",
            ) from exc

        try:
            with FileLock(str(self._lock_path), timeout=_LOCK_TIMEOUT_SECONDS):
                self._check_and_record_locked(org)
        except FileLockTimeout as exc:
            raise AuthorityProviderError(
                AuthorityProviderFailure.PROVIDER_UNAVAILABLE,
                f"could not acquire authority registry lock at "
                f"{self._lock_path} within {_LOCK_TIMEOUT_SECONDS}s",
            ) from exc
        except OSError as exc:
            # Timeout is not the only environmental failure mode —
            # lock file creation/access itself can fail (e.g. the
            # directory is traversable but the lock file cannot be
            # created within it). This must map to the same
            # PROVIDER_UNAVAILABLE outcome as a timeout, not leak as
            # a raw, platform-specific filesystem exception.
            raise AuthorityProviderError(
                AuthorityProviderFailure.PROVIDER_UNAVAILABLE,
                f"authority registry lock at {self._lock_path} could "
                f"not be acquired: {exc}",
            ) from exc

    def _check_and_record_locked(self, org: OrganizationAuthority) -> None:
        """Must only be called while holding the lock. Loads
        the LATEST registry state fresh (never a stale
        in-memory copy from before lock acquisition), validates
        the complete transition, and only mutates/persists after
        every check has passed."""
        try:
            self._load_unlocked()
        except _RegistryCorrupt as exc:
            raise AuthorityProviderError(
                AuthorityProviderFailure.PROVIDER_UNAVAILABLE, str(exc)
            ) from exc

        now = datetime.now(timezone.utc).isoformat()
        current_ids = {role.id for role in org.roles}
        historical_ids = set(self._role_ids.keys())

        missing_ids = historical_ids - current_ids
        if missing_ids:
            raise TemporalAuthorityViolation(
                f"role_id(s) {sorted(missing_ids)} previously existed but "
                f"are entirely missing from the current organization.yaml. "
                f"Historically used role IDs must remain present as "
                f"retired/deprecated tombstones — they must never be "
                f"deleted."
            )

        for role in org.roles:
            existing_owner = self._aliases.get(role.name)
            if existing_owner is not None and existing_owner != role.id:
                raise TemporalAuthorityViolation(
                    f"Alias '{role.name}' was previously associated with "
                    f"role_id '{existing_owner}' and cannot be reassigned "
                    f"to '{role.id}'."
                )

        for role in org.roles:
            prior = self._role_ids.get(role.id, {}).get("last_known_status")
            if prior is not None:
                prior_status = RoleStatus(prior)
                if role.status not in _ALLOWED_STATUS_TRANSITIONS[prior_status]:
                    raise TemporalAuthorityViolation(
                        f"role_id '{role.id}' cannot transition from "
                        f"status '{prior_status.value}' to "
                        f"'{role.status.value}'. Retirement is permanent; "
                        f"deprecated -> active is not permitted."
                    )

        # All checks passed on a CANDIDATE built from freshly-loaded
        # state — only now mutate the real dictionaries and persist.
        for role in org.roles:
            if role.id not in self._role_ids:
                self._role_ids[role.id] = {"first_seen": now}
            self._role_ids[role.id]["last_known_status"] = role.status.value
            self._aliases[role.name] = role.id

        self._save_unlocked()


# =====================================================
# SCHEMA -> DOMAIN MAPPING (unchanged — accepted as correct)
# =====================================================


def _map_schema_role_to_authority_role(role: SchemaRole) -> AuthorityRole:
    return AuthorityRole(
        id=role.id,
        name=role.name,
        display_name=role.display_name,
        status=RoleStatus(role.status.value),
    )


def _map_notification_config(
    schema_role: SchemaRole, channel: NotificationChannel
) -> Optional[NotificationEndpoint]:
    if schema_role.notification is None:
        return None
    if channel == NotificationChannel.EMAIL:
        if schema_role.notification.email is None:
            return None
        return NotificationEndpoint(
            channel=NotificationChannel.EMAIL,
            address=schema_role.notification.email.address,
        )
    if channel == NotificationChannel.SLACK:
        if schema_role.notification.slack is None:
            return None
        return NotificationEndpoint(
            channel=NotificationChannel.SLACK,
            secret_env=schema_role.notification.slack.webhook_env,
        )
    if channel == NotificationChannel.TEAMS:
        if schema_role.notification.teams is None:
            return None
        return NotificationEndpoint(
            channel=NotificationChannel.TEAMS,
            secret_env=schema_role.notification.teams.webhook_env,
        )
    return None


# =====================================================
# LOCAL PROVIDER
# =====================================================


class LocalOrganizationAuthorityProvider(AuthorityProvider):
    """
    v0.6.0 local YAML AuthorityProvider implementation. See
    module docstring for the ephemeral-CI deployment constraint
    — this provider's temporal guarantees require a durable
    registry file across invocations.

    One provider instance = one consulted, hashed, temporally-
    checked snapshot. Construct a new instance per governance
    action, per ADR D3a's action-time membership requirement.
    """

    def __init__(
        self,
        organization_path: str | Path = "organization.yaml",
        registry_path: Optional[str | Path] = None,
    ) -> None:
        self._organization_path = Path(organization_path)
        self._source_hash: Optional[str] = None
        self._organization: Optional[OrganizationAuthority] = None

        self._load_and_validate()

        if registry_path is None:
            registry_path = self._organization_path.with_name(
                self._organization_path.name + ".authority-history.json"
            )

        registry = _HistoricalRegistry(
            Path(registry_path),
            expected_organization_id=self._organization.metadata.organization_id,
        )
        try:
            registry.check_and_record(self._organization)
        except TemporalAuthorityViolation as exc:
            raise AuthorityProviderError(
                AuthorityProviderFailure.SOURCE_INVALID, str(exc)
            ) from exc

    def _load_and_validate(self) -> None:
        try:
            raw = load_organization(self._organization_path)
        except FileNotFoundError as exc:
            raise AuthorityProviderError(
                AuthorityProviderFailure.SOURCE_NOT_FOUND,
                f"organization.yaml not found at {self._organization_path}",
            ) from exc
        except UnicodeDecodeError as exc:
            raise AuthorityProviderError(
                AuthorityProviderFailure.SOURCE_INVALID,
                f"organization.yaml at {self._organization_path} is not valid UTF-8",
            ) from exc
        except yaml.YAMLError as exc:
            raise AuthorityProviderError(
                AuthorityProviderFailure.SOURCE_INVALID,
                f"organization.yaml at {self._organization_path} could "
                f"not be parsed as YAML: {exc}",
            ) from exc
        except PermissionError as exc:
            raise AuthorityProviderError(
                AuthorityProviderFailure.PROVIDER_UNAVAILABLE,
                f"organization.yaml at {self._organization_path} exists "
                f"but could not be read (permission denied)",
            ) from exc
        except OSError as exc:
            raise AuthorityProviderError(
                AuthorityProviderFailure.PROVIDER_UNAVAILABLE,
                f"organization.yaml at {self._organization_path} could "
                f"not be read: {exc}",
            ) from exc

        try:
            self._organization = OrganizationAuthority.model_validate(raw)
        except ValidationError as exc:
            raise AuthorityProviderError(
                AuthorityProviderFailure.SOURCE_INVALID,
                f"organization.yaml at {self._organization_path} failed "
                f"schema validation: {exc}",
            ) from exc

        self._source_hash = _compute_source_hash(self._organization)

    # -------------------------------------------------
    # AuthorityProvider contract
    # -------------------------------------------------

    def resolve_role(self, role_ref: str) -> RoleResolution:
        role = self._organization.get_role_by_id(role_ref)
        if role is None:
            role = self._organization.get_role_by_name(role_ref)
        if role is None:
            return RoleResolution(claimed_ref=role_ref, role=None)
        return RoleResolution(
            claimed_ref=role_ref, role=_map_schema_role_to_authority_role(role)
        )

    def is_member(self, actor_identity: str, role_id: str) -> bool:
        role = self._organization.get_role_by_id(role_id)
        if role is None:
            return False
        return actor_identity in role.members

    def get_role(self, role_id: str) -> Optional[AuthorityRole]:
        role = self._organization.get_role_by_id(role_id)
        if role is None:
            return None
        return _map_schema_role_to_authority_role(role)

    def get_notification_endpoint(
        self, role_id: str, channel: NotificationChannel
    ) -> Optional[NotificationEndpoint]:
        role = self._organization.get_role_by_id(role_id)
        if role is None:
            return None
        return _map_notification_config(role, channel)

    def source_metadata(self) -> AuthoritySourceMetadata:
        return AuthoritySourceMetadata(
            provider_type="local_organization_config",
            source_identifier=str(self._organization_path),
            organization_id=self._organization.metadata.organization_id,
            schema_version=self._organization.apiVersion,
            document_version=self._organization.metadata.version,
            source_hash=self._source_hash,
        )
