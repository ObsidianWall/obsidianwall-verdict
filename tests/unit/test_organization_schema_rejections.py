"""
Direct Pydantic-level validation tests for
schemas/organization_schema.py — confirms the schema rejects
invalid input, not just accepts valid input. Converted from an
earlier ad-hoc script (originally run as `python
test_rejections.py`, invisible to pytest given testpaths =
["tests"] in pyproject.toml) into a proper, discoverable test.
"""

import copy

import pytest
from pydantic import ValidationError

from schemas.organization_schema import OrganizationAuthority

_VALID_BASE = {
    "apiVersion": "obsidianwall.io/v1",
    "kind": "OrganizationAuthority",
    "metadata": {"organization_id": "test-org", "version": "0.1"},
    "roles": [
        {
            "id": "role_security_admin",
            "name": "security_admin",
            "display_name": "Security Administrator",
            "members": ["alice@example.com"],
        }
    ],
}


def _dup_role_id(d):
    d["roles"].append({**d["roles"][0], "name": "other_name"})
    return d


def _dup_role_name(d):
    d["roles"].append({**d["roles"][0], "id": "role_other"})
    return d


def _bad_api_version(d):
    d["apiVersion"] = "obsidianwall.io/v99"
    return d


def _bad_kind(d):
    d["kind"] = "SomethingElse"
    return d


def _bad_role_id_syntax(d):
    d["roles"][0]["id"] = "SecurityAdmin"
    return d


def _bad_name_syntax(d):
    d["roles"][0]["name"] = "Security Admin!"
    return d


def _namespace_collision(d):
    d["roles"].append(
        {
            "id": "role_engineering_lead",
            "name": "role_security_admin",
            "display_name": "Engineering Lead",
            "members": ["bob@example.com"],
        }
    )
    return d


def _empty_member(d):
    d["roles"][0]["members"] = ["alice@example.com", "   "]
    return d


def _dup_member(d):
    d["roles"][0]["members"] = ["alice@example.com", "alice@example.com"]
    return d


def _missing_role_id(d):
    del d["roles"][0]["id"]
    return d


def _unconfigured_preferred_channel(d):
    d["roles"][0]["notification"] = {"preferred": "slack"}
    return d


def _bad_email(d):
    d["roles"][0]["notification"] = {
        "preferred": "email",
        "email": {"address": "not-an-email"},
    }
    return d


def _empty_webhook_env(d):
    d["roles"][0]["notification"] = {
        "preferred": "slack",
        "slack": {"webhook_env": "  "},
    }
    return d


_REJECTION_CASES = [
    ("duplicate role_id", _dup_role_id),
    ("duplicate role name", _dup_role_name),
    ("unsupported apiVersion", _bad_api_version),
    ("wrong kind", _bad_kind),
    ("non-canonical role_id syntax", _bad_role_id_syntax),
    ("non-canonical name syntax", _bad_name_syntax),
    ("name collides with another role's id", _namespace_collision),
    ("empty/whitespace member identity", _empty_member),
    ("duplicate member identity", _dup_member),
    ("missing required role_id field", _missing_role_id),
    ("preferred channel declared but not configured", _unconfigured_preferred_channel),
    ("malformed email address", _bad_email),
    ("empty webhook_env", _empty_webhook_env),
]


class TestOrganizationAuthorityAcceptsValidInput:
    def test_valid_organization_authority_accepted(self):
        OrganizationAuthority.model_validate(copy.deepcopy(_VALID_BASE))  # must not raise


class TestOrganizationAuthorityRejectsInvalidInput:
    @pytest.mark.parametrize(
        "mutate_fn", [fn for _, fn in _REJECTION_CASES],
        ids=[name for name, _ in _REJECTION_CASES],
    )
    def test_schema_rejects_invalid_organization_authority(self, mutate_fn):
        data = mutate_fn(copy.deepcopy(_VALID_BASE))
        with pytest.raises(ValidationError):
            OrganizationAuthority.model_validate(data)


class TestOrganizationAuthorityAcceptsValidNotificationConfiguration:
    def test_valid_notification_configuration_accepted(self):
        """
        The rejection matrix above proves bad notification
        configuration is rejected. It does not, by itself, prove
        a properly configured notification survives schema
        validation — this closes that gap directly, rather than
        relying on an example file to incidentally exercise it.
        """
        data = copy.deepcopy(_VALID_BASE)
        data["roles"][0]["notification"] = {
            "preferred": "email",
            "email": {"address": "security@example.com"},
            "slack": {"webhook_env": "OW_SECURITY_SLACK_WEBHOOK"},
        }
        OrganizationAuthority.model_validate(data)  # must not raise