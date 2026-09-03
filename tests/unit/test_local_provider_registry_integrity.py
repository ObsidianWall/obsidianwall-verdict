"""
Family 2 — Registry integrity and fail-closed behavior.

Malformed historical state must fail closed as
PROVIDER_UNAVAILABLE, never leak as a raw Python exception,
and never be misattributed as a problem with the current
organization.yaml (that would be SOURCE_INVALID — a distinct,
wrong failure code for this category).
"""

import json

import pytest
import yaml

from authority.local_provider import LocalOrganizationAuthorityProvider
from authority.provider import AuthorityProviderError, AuthorityProviderFailure


def _write_org(path, roles):
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


def _registry_path_for(org_path):
    return org_path.with_name(org_path.name + ".authority-history.json")


class TestMalformedRegistry:
    def test_invalid_json_fails_closed(self, tmp_path):
        org_path = tmp_path / "organization.yaml"
        _write_org(org_path, [_role("role_a", "role_a_name")])

        registry_path = _registry_path_for(org_path)
        registry_path.write_text("{ not valid json ][", encoding="utf-8")

        with pytest.raises(AuthorityProviderError) as exc_info:
            LocalOrganizationAuthorityProvider(organization_path=org_path)
        assert exc_info.value.failure == AuthorityProviderFailure.PROVIDER_UNAVAILABLE

    def test_wrong_top_level_type_fails_closed(self, tmp_path):
        org_path = tmp_path / "organization.yaml"
        _write_org(org_path, [_role("role_a", "role_a_name")])

        registry_path = _registry_path_for(org_path)
        registry_path.write_text(json.dumps(["not", "a", "dict"]), encoding="utf-8")

        with pytest.raises(AuthorityProviderError) as exc_info:
            LocalOrganizationAuthorityProvider(organization_path=org_path)
        assert exc_info.value.failure == AuthorityProviderFailure.PROVIDER_UNAVAILABLE

    def test_deep_type_corruption_role_entry_fails_closed(self, tmp_path):
        org_path = tmp_path / "organization.yaml"
        _write_org(org_path, [_role("role_a", "role_a_name")])

        registry_path = _registry_path_for(org_path)
        registry_path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "organization_id": "acme",
                    "role_ids": {"role_a": "garbage-not-a-dict"},
                    "aliases": {},
                }
            ),
            encoding="utf-8",
        )

        with pytest.raises(AuthorityProviderError) as exc_info:
            LocalOrganizationAuthorityProvider(organization_path=org_path)
        assert exc_info.value.failure == AuthorityProviderFailure.PROVIDER_UNAVAILABLE

    def test_invalid_status_value_fails_closed(self, tmp_path):
        org_path = tmp_path / "organization.yaml"
        _write_org(org_path, [_role("role_a", "role_a_name")])

        registry_path = _registry_path_for(org_path)
        registry_path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "organization_id": "acme",
                    "role_ids": {
                        "role_a": {"first_seen": "2026-01-01", "last_known_status": "zombie"}
                    },
                    "aliases": {},
                }
            ),
            encoding="utf-8",
        )

        with pytest.raises(AuthorityProviderError) as exc_info:
            LocalOrganizationAuthorityProvider(organization_path=org_path)
        assert exc_info.value.failure == AuthorityProviderFailure.PROVIDER_UNAVAILABLE

    def test_alias_referencing_unknown_role_id_fails_closed(self, tmp_path):
        org_path = tmp_path / "organization.yaml"
        _write_org(org_path, [_role("role_a", "role_a_name")])

        registry_path = _registry_path_for(org_path)
        registry_path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "organization_id": "acme",
                    "role_ids": {
                        "role_a": {"first_seen": "2026-01-01", "last_known_status": "active"}
                    },
                    "aliases": {"role_a_name": "role_that_does_not_exist_in_role_ids"},
                }
            ),
            encoding="utf-8",
        )

        with pytest.raises(AuthorityProviderError) as exc_info:
            LocalOrganizationAuthorityProvider(organization_path=org_path)
        assert exc_info.value.failure == AuthorityProviderFailure.PROVIDER_UNAVAILABLE


class TestSchemaVersioning:
    def test_missing_version_fails_closed(self, tmp_path):
        org_path = tmp_path / "organization.yaml"
        _write_org(org_path, [_role("role_a", "role_a_name")])

        registry_path = _registry_path_for(org_path)
        registry_path.write_text(
            json.dumps({"organization_id": "acme", "role_ids": {}, "aliases": {}}),
            encoding="utf-8",
        )

        with pytest.raises(AuthorityProviderError) as exc_info:
            LocalOrganizationAuthorityProvider(organization_path=org_path)
        assert exc_info.value.failure == AuthorityProviderFailure.PROVIDER_UNAVAILABLE

    def test_unsupported_version_fails_closed(self, tmp_path):
        org_path = tmp_path / "organization.yaml"
        _write_org(org_path, [_role("role_a", "role_a_name")])

        registry_path = _registry_path_for(org_path)
        registry_path.write_text(
            json.dumps(
                {"version": 999, "organization_id": "acme", "role_ids": {}, "aliases": {}}
            ),
            encoding="utf-8",
        )

        with pytest.raises(AuthorityProviderError) as exc_info:
            LocalOrganizationAuthorityProvider(organization_path=org_path)
        assert exc_info.value.failure == AuthorityProviderFailure.PROVIDER_UNAVAILABLE


class TestOrganizationBinding:
    def test_organization_id_mismatch_fails_closed(self, tmp_path):
        org_path = tmp_path / "organization.yaml"
        _write_org(org_path, [_role("role_a", "role_a_name")])

        registry_path = _registry_path_for(org_path)
        registry_path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "organization_id": "totally_different_org",
                    "role_ids": {},
                    "aliases": {},
                }
            ),
            encoding="utf-8",
        )

        with pytest.raises(AuthorityProviderError) as exc_info:
            LocalOrganizationAuthorityProvider(organization_path=org_path)
        assert exc_info.value.failure == AuthorityProviderFailure.PROVIDER_UNAVAILABLE


class TestCustomRegistryPath:
    def test_missing_nested_registry_directory_is_created(self, tmp_path):
        """A custom registry_path pointing at a directory that
        doesn't exist yet must succeed — the directory gets
        created before lock acquisition, not fail because it's
        missing."""
        org_path = tmp_path / "organization.yaml"
        _write_org(org_path, [_role("role_a", "role_a_name")])

        nested_registry = tmp_path / "nested" / "does" / "not" / "exist" / "history.json"

        # Must NOT raise
        LocalOrganizationAuthorityProvider(
            organization_path=org_path, registry_path=nested_registry
        )
        assert nested_registry.exists()


class TestNoPartialMutationOnRejection:
    def test_registry_unchanged_after_rejected_transition(self, tmp_path):
        org_path = tmp_path / "organization.yaml"
        registry_path = _registry_path_for(org_path)

        _write_org(org_path, [_role("role_a", "role_a_name", status="retired")])
        LocalOrganizationAuthorityProvider(organization_path=org_path)
        registry_before = registry_path.read_text()

        _write_org(org_path, [_role("role_a", "role_a_name", status="active")])
        with pytest.raises(AuthorityProviderError):
            LocalOrganizationAuthorityProvider(organization_path=org_path)

        registry_after = registry_path.read_text()
        assert registry_before == registry_after


class TestFilesystemFailureMapping:
    """
    Added after review: the implementation was specifically
    changed to map tempfile/fsync/replace/lock filesystem
    failures to PROVIDER_UNAVAILABLE rather than letting raw
    OSError leak. Those specific code paths had no test coverage
    at all until now — an untested guarantee is just an
    assertion, not a proven property.
    """

    def test_mkstemp_failure_maps_to_provider_unavailable(self, tmp_path, monkeypatch):
        org_path = tmp_path / "organization.yaml"
        registry_path = _registry_path_for(org_path)
        _write_org(org_path, [_role("role_a", "role_a_name")])

        import tempfile as tempfile_module

        def _raise(*args, **kwargs):
            raise OSError("simulated mkstemp failure")

        monkeypatch.setattr(tempfile_module, "mkstemp", _raise)

        with pytest.raises(AuthorityProviderError) as exc_info:
            LocalOrganizationAuthorityProvider(organization_path=org_path)
        assert exc_info.value.failure == AuthorityProviderFailure.PROVIDER_UNAVAILABLE
        assert not registry_path.exists()  # no partial registry left behind

    def test_fsync_failure_maps_to_provider_unavailable(self, tmp_path, monkeypatch):
        org_path = tmp_path / "organization.yaml"
        registry_path = _registry_path_for(org_path)
        _write_org(org_path, [_role("role_a", "role_a_name")])

        import os as os_module

        def _raise(*args, **kwargs):
            raise OSError("simulated fsync failure")

        monkeypatch.setattr(os_module, "fsync", _raise)

        with pytest.raises(AuthorityProviderError) as exc_info:
            LocalOrganizationAuthorityProvider(organization_path=org_path)
        assert exc_info.value.failure == AuthorityProviderFailure.PROVIDER_UNAVAILABLE
        assert not registry_path.exists()

    def test_replace_failure_maps_to_provider_unavailable_and_preserves_old_registry(
        self, tmp_path, monkeypatch
    ):
        """
        Specifically confirms the OLD registry survives intact —
        this is the actual point of the atomic-replace design:
        a replace failure must not leave a half-written or
        missing registry behind."""
        org_path = tmp_path / "organization.yaml"
        registry_path = _registry_path_for(org_path)

        _write_org(org_path, [_role("role_a", "role_a_name")])
        LocalOrganizationAuthorityProvider(organization_path=org_path)
        registry_before = registry_path.read_text()

        _write_org(
            org_path,
            [_role("role_a", "role_a_name"), _role("role_b", "role_b_name")],
        )

        import os as os_module

        def _raise(*args, **kwargs):
            raise OSError("simulated os.replace failure")

        monkeypatch.setattr(os_module, "replace", _raise)

        with pytest.raises(AuthorityProviderError) as exc_info:
            LocalOrganizationAuthorityProvider(organization_path=org_path)
        assert exc_info.value.failure == AuthorityProviderFailure.PROVIDER_UNAVAILABLE

        registry_after = registry_path.read_text()
        assert registry_before == registry_after

    def test_lock_acquisition_filesystem_error_maps_to_provider_unavailable(
        self, tmp_path, monkeypatch
    ):
        """Non-timeout lock failures (e.g. the lock file cannot
        be created at all) must map the same as a timeout."""
        org_path = tmp_path / "organization.yaml"
        _write_org(org_path, [_role("role_a", "role_a_name")])

        import filelock

        class _BrokenLock:
            def __init__(self, *args, **kwargs):
                pass

            def __enter__(self):
                raise OSError("simulated lock filesystem failure")

            def __exit__(self, *exc_info):
                return False

        monkeypatch.setattr(
            "authority.local_provider.FileLock", _BrokenLock
        )

        with pytest.raises(AuthorityProviderError) as exc_info:
            LocalOrganizationAuthorityProvider(organization_path=org_path)
        assert exc_info.value.failure == AuthorityProviderFailure.PROVIDER_UNAVAILABLE