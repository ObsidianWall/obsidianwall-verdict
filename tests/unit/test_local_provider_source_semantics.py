"""
Family 4 — Authority-source semantics: resolution, membership,
notification, and canonical source_hash behavior.
"""

import pytest
import yaml

from authority.local_provider import LocalOrganizationAuthorityProvider
from authority.models import NotificationChannel, RoleStatus


def _write_org(path, roles):
    doc = {
        "apiVersion": "obsidianwall.io/v1",
        "kind": "OrganizationAuthority",
        "metadata": {"organization_id": "acme", "version": "0.1"},
        "roles": roles,
    }
    path.write_text(yaml.dump(doc), encoding="utf-8")


def _role(id, name, status="active", members=None, notification=None):
    role = {
        "id": id,
        "name": name,
        "display_name": name.replace("_", " ").title(),
        "status": status,
        "members": ["alice@example.com"] if members is None else members,
    }
    if notification:
        role["notification"] = notification
    return role


class TestResolutionAndReload:
    def test_reload_of_unchanged_source_is_consistent(self, tmp_path):
        org_path = tmp_path / "organization.yaml"
        _write_org(org_path, [_role("role_a", "role_a_name")])

        p1 = LocalOrganizationAuthorityProvider(organization_path=org_path)
        p2 = LocalOrganizationAuthorityProvider(organization_path=org_path)

        assert p1.source_metadata().source_hash == p2.source_metadata().source_hash

    def test_resolve_by_id_and_by_name_return_same_role(self, tmp_path):
        org_path = tmp_path / "organization.yaml"
        _write_org(org_path, [_role("role_a", "role_a_name")])
        provider = LocalOrganizationAuthorityProvider(organization_path=org_path)

        by_id = provider.resolve_role("role_a")
        by_name = provider.resolve_role("role_a_name")

        assert by_id.resolved and by_name.resolved
        assert by_id.role.id == by_name.role.id == "role_a"

    def test_unresolvable_reference_returns_unresolved(self, tmp_path):
        org_path = tmp_path / "organization.yaml"
        _write_org(org_path, [_role("role_a", "role_a_name")])
        provider = LocalOrganizationAuthorityProvider(organization_path=org_path)

        resolution = provider.resolve_role("totally_unknown")
        assert not resolution.resolved
        assert resolution.role is None


class TestLifecycleStatusReflection:
    @pytest.mark.parametrize("status", ["active", "deprecated", "retired"])
    def test_get_role_reflects_current_status(self, tmp_path, status):
        """
        FIXED after review: the original version reused ONE
        org_path/registry across all three loop iterations,
        replacing the entire document each time — which meant
        iteration 2 made iteration 1's role_id disappear entirely,
        correctly triggering the (unrelated) missing-tombstone
        rejection instead of testing what this test claims to
        test. Parametrized with a FRESH org_path and registry_path
        per status value fully isolates each case.
        """
        org_path = tmp_path / f"{status}.yaml"
        registry_path = tmp_path / f"{status}.history.json"

        role_id = f"role_{status}_case"
        _write_org(org_path, [_role(role_id, f"{status}_name", status=status)])
        provider = LocalOrganizationAuthorityProvider(
            organization_path=org_path, registry_path=registry_path
        )
        role = provider.get_role(role_id)
        assert role.status == RoleStatus(status)


class TestMembership:
    def test_is_member_true_for_actual_member(self, tmp_path):
        org_path = tmp_path / "organization.yaml"
        _write_org(org_path, [_role("role_a", "role_a_name", members=["alice@example.com"])])
        provider = LocalOrganizationAuthorityProvider(organization_path=org_path)

        assert provider.is_member("alice@example.com", "role_a") is True

    def test_is_member_false_for_non_member(self, tmp_path):
        org_path = tmp_path / "organization.yaml"
        _write_org(org_path, [_role("role_a", "role_a_name", members=["alice@example.com"])])
        provider = LocalOrganizationAuthorityProvider(organization_path=org_path)

        assert provider.is_member("mallory@example.com", "role_a") is False

    def test_is_member_false_for_unknown_role(self, tmp_path):
        org_path = tmp_path / "organization.yaml"
        _write_org(org_path, [_role("role_a", "role_a_name")])
        provider = LocalOrganizationAuthorityProvider(organization_path=org_path)

        assert provider.is_member("alice@example.com", "role_never_existed") is False

    def test_is_member_handles_non_email_identity(self, tmp_path):
        """Confirms the opaque-string design decision actually
        works — a GitHub-actor-shaped identity, not an email."""
        org_path = tmp_path / "organization.yaml"
        _write_org(org_path, [_role("role_a", "role_a_name", members=["github-actor-name"])])
        provider = LocalOrganizationAuthorityProvider(organization_path=org_path)

        assert provider.is_member("github-actor-name", "role_a") is True


class TestNotificationResolution:
    def test_email_endpoint_resolves(self, tmp_path):
        org_path = tmp_path / "organization.yaml"
        _write_org(
            org_path,
            [
                _role(
                    "role_a",
                    "role_a_name",
                    notification={
                        "preferred": "email",
                        "email": {"address": "team@example.com"},
                    },
                )
            ],
        )
        provider = LocalOrganizationAuthorityProvider(organization_path=org_path)

        endpoint = provider.get_notification_endpoint(
            "role_a", NotificationChannel.EMAIL
        )
        assert endpoint is not None
        assert endpoint.address == "team@example.com"
        assert endpoint.secret_env is None

    def test_slack_endpoint_resolves_to_env_name_not_secret(self, tmp_path):
        org_path = tmp_path / "organization.yaml"
        _write_org(
            org_path,
            [
                _role(
                    "role_a",
                    "role_a_name",
                    notification={
                        "preferred": "slack",
                        "slack": {"webhook_env": "OW_TEAM_SLACK_WEBHOOK"},
                    },
                )
            ],
        )
        provider = LocalOrganizationAuthorityProvider(organization_path=org_path)

        endpoint = provider.get_notification_endpoint(
            "role_a", NotificationChannel.SLACK
        )
        assert endpoint.secret_env == "OW_TEAM_SLACK_WEBHOOK"
        assert endpoint.address is None

    def test_missing_channel_returns_none_not_error(self, tmp_path):
        org_path = tmp_path / "organization.yaml"
        _write_org(
            org_path,
            [
                _role(
                    "role_a",
                    "role_a_name",
                    notification={
                        "preferred": "email",
                        "email": {"address": "team@example.com"},
                    },
                )
            ],
        )
        provider = LocalOrganizationAuthorityProvider(organization_path=org_path)

        # Role has email configured, not teams
        endpoint = provider.get_notification_endpoint(
            "role_a", NotificationChannel.TEAMS
        )
        assert endpoint is None


class TestSourceHashCanonicalization:
    def test_hash_stable_under_role_reordering(self, tmp_path):
        org_path_1 = tmp_path / "org1.yaml"
        org_path_2 = tmp_path / "org2.yaml"

        _write_org(org_path_1, [_role("role_a", "a_name"), _role("role_b", "b_name")])
        _write_org(org_path_2, [_role("role_b", "b_name"), _role("role_a", "a_name")])

        p1 = LocalOrganizationAuthorityProvider(
            organization_path=org_path_1, registry_path=tmp_path / "r1.json"
        )
        p2 = LocalOrganizationAuthorityProvider(
            organization_path=org_path_2, registry_path=tmp_path / "r2.json"
        )

        assert p1.source_metadata().source_hash == p2.source_metadata().source_hash

    def test_hash_stable_under_member_reordering(self, tmp_path):
        org_path_1 = tmp_path / "org1.yaml"
        org_path_2 = tmp_path / "org2.yaml"

        _write_org(
            org_path_1,
            [_role("role_a", "a_name", members=["alice@example.com", "bob@example.com"])],
        )
        _write_org(
            org_path_2,
            [_role("role_a", "a_name", members=["bob@example.com", "alice@example.com"])],
        )

        p1 = LocalOrganizationAuthorityProvider(
            organization_path=org_path_1, registry_path=tmp_path / "r1.json"
        )
        p2 = LocalOrganizationAuthorityProvider(
            organization_path=org_path_2, registry_path=tmp_path / "r2.json"
        )

        assert p1.source_metadata().source_hash == p2.source_metadata().source_hash

    def test_hash_stable_under_yaml_whitespace_differences(self, tmp_path):
        org_path_1 = tmp_path / "org1.yaml"
        org_path_2 = tmp_path / "org2.yaml"

        doc = {
            "apiVersion": "obsidianwall.io/v1",
            "kind": "OrganizationAuthority",
            "metadata": {"organization_id": "acme", "version": "0.1"},
            "roles": [_role("role_a", "a_name")],
        }
        org_path_1.write_text(yaml.dump(doc, default_flow_style=False), encoding="utf-8")
        org_path_2.write_text(
            "\n\n" + yaml.dump(doc, default_flow_style=True) + "\n\n# a comment\n",
            encoding="utf-8",
        )

        p1 = LocalOrganizationAuthorityProvider(
            organization_path=org_path_1, registry_path=tmp_path / "r1.json"
        )
        p2 = LocalOrganizationAuthorityProvider(
            organization_path=org_path_2, registry_path=tmp_path / "r2.json"
        )

        assert p1.source_metadata().source_hash == p2.source_metadata().source_hash

    def test_hash_changes_on_actual_semantic_change(self, tmp_path):
        org_path = tmp_path / "organization.yaml"

        _write_org(org_path, [_role("role_a", "a_name", members=["alice@example.com"])])
        p1 = LocalOrganizationAuthorityProvider(
            organization_path=org_path, registry_path=tmp_path / "r1.json"
        )
        hash_1 = p1.source_metadata().source_hash

        _write_org(
            org_path,
            [_role("role_a", "a_name", members=["alice@example.com", "bob@example.com"])],
        )
        p2 = LocalOrganizationAuthorityProvider(
            organization_path=org_path, registry_path=tmp_path / "r1.json"
        )
        hash_2 = p2.source_metadata().source_hash

        assert hash_1 != hash_2

    @pytest.mark.parametrize(
        "mutate_field",
        ["name", "display_name", "status", "notification_email", "metadata_version"],
    )
    def test_hash_changes_on_every_semantic_dimension(self, tmp_path, mutate_field):
        """
        source_hash is DELIBERATELY the hash of the COMPLETE
        validated source, not just membership/authorization-
        relevant fields (per the explicit design decision: a
        display_name or notification change should affect the
        broad source_hash even though it may not affect
        governance authority itself). This confirms each
        dimension of that contract individually, rather than
        only proving "member changes affect the hash" and
        leaving the broader claim unverified.
        """
        org_path = tmp_path / "organization.yaml"

        base_role = _role(
            "role_a",
            "a_name",
            notification={
                "preferred": "email",
                "email": {"address": "team@example.com"},
            },
        )
        _write_org(org_path, [base_role])
        p1 = LocalOrganizationAuthorityProvider(
            organization_path=org_path, registry_path=tmp_path / "r1.json"
        )
        hash_1 = p1.source_metadata().source_hash

        import copy

        mutated_role = copy.deepcopy(base_role)
        if mutate_field == "name":
            mutated_role["name"] = "renamed_a"
        elif mutate_field == "display_name":
            mutated_role["display_name"] = "A Completely Different Display Name"
        elif mutate_field == "status":
            mutated_role["status"] = "deprecated"
        elif mutate_field == "notification_email":
            mutated_role["notification"]["email"]["address"] = "different@example.com"
        elif mutate_field == "metadata_version":
            pass  # handled separately below via doc-level metadata

        if mutate_field == "metadata_version":
            doc = {
                "apiVersion": "obsidianwall.io/v1",
                "kind": "OrganizationAuthority",
                "metadata": {"organization_id": "acme", "version": "0.2"},
                "roles": [base_role],
            }
            org_path.write_text(yaml.dump(doc), encoding="utf-8")
        else:
            _write_org(org_path, [mutated_role])

        p2 = LocalOrganizationAuthorityProvider(
            organization_path=org_path, registry_path=tmp_path / "r1.json"
        )
        hash_2 = p2.source_metadata().source_hash

        assert hash_1 != hash_2, (
            f"changing '{mutate_field}' did not affect source_hash — "
            f"violates the design decision that source_hash covers the "
            f"COMPLETE validated source, not just membership/authority "
            f"fields"
        )