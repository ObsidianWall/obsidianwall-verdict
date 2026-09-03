"""
Validation tests for authority/models.py's NotificationEndpoint —
confirms it rejects invalid channel/field combinations, including
whitespace-only values and unknown channel types. Converted from
an earlier ad-hoc script (originally run as `python
test_notification_endpoint.py`, invisible to pytest given
testpaths = ["tests"] in pyproject.toml) into a proper,
discoverable test.
"""

import pytest

from authority.models import NotificationChannel, NotificationEndpoint

_REJECTION_CASES = [
    (
        "email with no address",
        lambda: NotificationEndpoint(channel=NotificationChannel.EMAIL),
    ),
    (
        "email with whitespace-only address",
        lambda: NotificationEndpoint(channel=NotificationChannel.EMAIL, address="   "),
    ),
    (
        "email with secret_env instead of address",
        lambda: NotificationEndpoint(
            channel=NotificationChannel.EMAIL, secret_env="OW_X"
        ),
    ),
    (
        "slack with no secret_env",
        lambda: NotificationEndpoint(channel=NotificationChannel.SLACK),
    ),
    (
        "slack with whitespace-only secret_env",
        lambda: NotificationEndpoint(
            channel=NotificationChannel.SLACK, secret_env="   "
        ),
    ),
    (
        "slack with address instead of secret_env",
        lambda: NotificationEndpoint(
            channel=NotificationChannel.SLACK, address="a@b.com"
        ),
    ),
    (
        "slack with BOTH address and secret_env",
        lambda: NotificationEndpoint(
            channel=NotificationChannel.SLACK, address="a@b.com", secret_env="OW_X"
        ),
    ),
    (
        "teams with no secret_env",
        lambda: NotificationEndpoint(channel=NotificationChannel.TEAMS),
    ),
    (
        "teams with address instead of secret_env",
        lambda: NotificationEndpoint(
            channel=NotificationChannel.TEAMS, address="a@b.com"
        ),
    ),
    (
        "teams with BOTH address and secret_env",
        lambda: NotificationEndpoint(
            channel=NotificationChannel.TEAMS, address="a@b.com", secret_env="OW_X"
        ),
    ),
    (
        "unknown/non-enum channel string",
        lambda: NotificationEndpoint(channel="discord", secret_env="OW_X"),
    ),
]


class TestNotificationEndpointAcceptsValidInput:
    def test_email_form_accepted(self):
        NotificationEndpoint(channel=NotificationChannel.EMAIL, address="a@b.com")

    def test_slack_form_accepted(self):
        NotificationEndpoint(channel=NotificationChannel.SLACK, secret_env="OW_X")

    def test_teams_form_accepted(self):
        NotificationEndpoint(channel=NotificationChannel.TEAMS, secret_env="OW_Y")


class TestNotificationEndpointRejectsInvalidInput:
    @pytest.mark.parametrize(
        "construct_fn", [fn for _, fn in _REJECTION_CASES],
        ids=[name for name, _ in _REJECTION_CASES],
    )
    def test_invalid_combination_rejected(self, construct_fn):
        with pytest.raises(ValueError):
            construct_fn()