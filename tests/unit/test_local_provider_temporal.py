"""
Family 1 — Temporal authority invariants.

These test properties NO stateless schema can provide: is this
transition valid given what existed before. Each test builds
its own isolated organization.yaml + registry under tmp_path,
so tests never share state or interfere with each other.
"""

import pytest
import yaml

from authority.local_provider import LocalOrganizationAuthorityProvider
from authority.provider import AuthorityProviderError, AuthorityProviderFailure


def _write_org(path, roles):
    """roles: list of dicts with at least id/name/display_name/status/members"""
    doc = {
        "apiVersion": "obsidianwall.io/v1",
        "kind": "OrganizationAuthority",
        "metadata": {"organization_id": "acme", "version": "0.1"},
        "roles": roles,
    }
    path.write_text(yaml.dump(doc), encoding="utf-8")


def _role(id, name, status="active", members=None):
    return {
        "id": id,
        "name": name,
        "display_name": name.replace("_", " ").title(),
        "status": status,
        "members": ["alice@example.com"] if members is None else members,
    }


class TestDeletionWithoutTombstone:
    def test_deletion_without_tombstone_rejected(self, tmp_path):
        org_path = tmp_path / "organization.yaml"

        _write_org(org_path, [_role("role_security_admin", "security_admin")])
        LocalOrganizationAuthorityProvider(organization_path=org_path)

        # Role entirely removed, not retired
        _write_org(org_path, [_role("role_engineering_lead", "engineering_lead")])

        with pytest.raises(AuthorityProviderError) as exc_info:
            LocalOrganizationAuthorityProvider(organization_path=org_path)
        assert exc_info.value.failure == AuthorityProviderFailure.SOURCE_INVALID


class TestLifecycleTransitions:
    def test_retired_to_active_reversal_rejected(self, tmp_path):
        org_path = tmp_path / "organization.yaml"

        _write_org(org_path, [_role("role_x", "role_x_name", status="active")])
        LocalOrganizationAuthorityProvider(organization_path=org_path)

        _write_org(org_path, [_role("role_x", "role_x_name", status="retired")])
        LocalOrganizationAuthorityProvider(organization_path=org_path)  # valid

        _write_org(org_path, [_role("role_x", "role_x_name", status="active")])
        with pytest.raises(AuthorityProviderError) as exc_info:
            LocalOrganizationAuthorityProvider(organization_path=org_path)
        assert exc_info.value.failure == AuthorityProviderFailure.SOURCE_INVALID

    def test_deprecated_to_active_rejected(self, tmp_path):
        org_path = tmp_path / "organization.yaml"

        _write_org(org_path, [_role("role_y", "role_y_name", status="active")])
        LocalOrganizationAuthorityProvider(organization_path=org_path)

        _write_org(org_path, [_role("role_y", "role_y_name", status="deprecated")])
        LocalOrganizationAuthorityProvider(organization_path=org_path)  # valid

        _write_org(org_path, [_role("role_y", "role_y_name", status="active")])
        with pytest.raises(AuthorityProviderError) as exc_info:
            LocalOrganizationAuthorityProvider(organization_path=org_path)
        assert exc_info.value.failure == AuthorityProviderFailure.SOURCE_INVALID

    def test_active_to_retired_directly_allowed(self, tmp_path):
        """Immediate retirement, skipping deprecated, is a
        deliberately permitted transition."""
        org_path = tmp_path / "organization.yaml"

        _write_org(org_path, [_role("role_z", "role_z_name", status="active")])
        LocalOrganizationAuthorityProvider(organization_path=org_path)

        _write_org(org_path, [_role("role_z", "role_z_name", status="retired")])
        # Must NOT raise
        LocalOrganizationAuthorityProvider(organization_path=org_path)

    def test_deprecated_to_retired_allowed(self, tmp_path):
        org_path = tmp_path / "organization.yaml"

        _write_org(org_path, [_role("role_w", "role_w_name", status="deprecated")])
        LocalOrganizationAuthorityProvider(organization_path=org_path)

        _write_org(org_path, [_role("role_w", "role_w_name", status="retired")])
        LocalOrganizationAuthorityProvider(organization_path=org_path)  # must not raise


class TestHistoricalIdentityPersistence:
    def test_first_seen_not_reset_across_loads(self, tmp_path):
        """A continuing role_id's historical identity (first_seen)
        must not be overwritten on subsequent loads — this is the
        concrete evidence that identity persists rather than being
        silently 're-established' each time."""
        import json

        org_path = tmp_path / "organization.yaml"
        registry_path = tmp_path / "organization.yaml.authority-history.json"

        _write_org(org_path, [_role("role_a", "role_a_name")])
        LocalOrganizationAuthorityProvider(organization_path=org_path)
        first_registry = json.loads(registry_path.read_text())
        first_seen_1 = first_registry["role_ids"]["role_a"]["first_seen"]

        # Reload — nothing changed, but this must not reset first_seen
        LocalOrganizationAuthorityProvider(organization_path=org_path)
        second_registry = json.loads(registry_path.read_text())
        first_seen_2 = second_registry["role_ids"]["role_a"]["first_seen"]

        assert first_seen_1 == first_seen_2


class TestAliasNonReassignment:
    def test_alias_cannot_migrate_to_different_role_id(self, tmp_path):
        """
        Two-step scenario, deliberately NOT co-locating both
        roles in one document (that would just hit the schema's
        own OWN-document uniqueness check, not exercise the
        REGISTRY's cross-time memory at all):

          1. role_a uses name "shared_name"
          2. role_a is renamed away to "moved_on" (still present,
             satisfying the tombstone requirement) — the registry
             now remembers "shared_name" -> role_a historically
          3. A brand new role_b tries to claim "shared_name",
             which role_a no longer uses in the CURRENT document
             (so schema-level uniqueness alone would allow it) —
             this must still be rejected, because the REGISTRY
             remembers "shared_name" belonged to role_a
        """
        org_path = tmp_path / "organization.yaml"

        _write_org(org_path, [_role("role_a", "shared_name")])
        LocalOrganizationAuthorityProvider(organization_path=org_path)

        _write_org(org_path, [_role("role_a", "moved_on")])
        LocalOrganizationAuthorityProvider(organization_path=org_path)  # valid rename

        _write_org(
            org_path,
            [
                _role("role_a", "moved_on"),       # tombstone requirement satisfied
                _role("role_b", "shared_name"),      # attempts to reclaim the OLD alias
            ],
        )
        with pytest.raises(AuthorityProviderError) as exc_info:
            LocalOrganizationAuthorityProvider(organization_path=org_path)
        assert exc_info.value.failure == AuthorityProviderFailure.SOURCE_INVALID

    def test_legitimate_alias_rename_remains_compatible(self, tmp_path):
        """Renaming role_a's alias from 'old_name' to 'new_name'
        must succeed — the role_id itself never changed."""
        org_path = tmp_path / "organization.yaml"

        _write_org(org_path, [_role("role_a", "old_name")])
        LocalOrganizationAuthorityProvider(organization_path=org_path)

        _write_org(org_path, [_role("role_a", "new_name")])
        provider = LocalOrganizationAuthorityProvider(organization_path=org_path)

        resolution = provider.resolve_role("new_name")
        assert resolution.resolved
        assert resolution.role.id == "role_a"


class TestUnknownVsHistoricallyRetired:
    def test_unknown_id_returns_none(self, tmp_path):
        org_path = tmp_path / "organization.yaml"
        _write_org(org_path, [_role("role_a", "role_a_name")])
        provider = LocalOrganizationAuthorityProvider(organization_path=org_path)

        assert provider.get_role("role_never_existed") is None

    def test_retired_tombstone_still_resolves(self, tmp_path):
        org_path = tmp_path / "organization.yaml"

        _write_org(org_path, [_role("role_a", "role_a_name", status="active")])
        LocalOrganizationAuthorityProvider(organization_path=org_path)

        _write_org(org_path, [_role("role_a", "role_a_name", status="retired")])
        provider = LocalOrganizationAuthorityProvider(organization_path=org_path)

        role = provider.get_role("role_a")
        assert role is not None
        assert role.status.value == "retired"