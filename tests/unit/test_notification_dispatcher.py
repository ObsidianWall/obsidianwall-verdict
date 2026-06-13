
# tests/unit/test_notification_dispatcher.py
#
# Purpose:
# Unit tests for notifications/dispatcher.py.
# Covers: dispatch_notifications() routing logic,
#         channel skipping, failure handling,
#         dispatch summary generation.

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest

from notifications.dispatcher import (
    _STATUS_FAILED,
    _STATUS_SENT,
    _STATUS_SKIPPED,
    dispatch_notifications,
)


# =====================================================
# FIXTURES
# =====================================================


def _make_notification(
    channel: str = "slack",
    role: str = "engineering_lead",
) -> dict[str, Any]:
    """Build a minimal notification dict for testing."""
    return {
        "target_role":       role,
        "channel":           channel,
        "priority":          "high",
        "subject":           "[ObsidianWall] Test Notification",
        "body":              "Test notification body.",
        "requires_action":   False,
        "decision":          "DENY_WITH_OVERRIDE",
        "policy":            "test_policy",
        "effective_severity": "high",
        "dispatch_status":   "pending",
    }


def _make_manifest(
    notifications: list[dict[str, Any]],
    triggered: bool = True,
) -> dict[str, Any]:
    """Build a notification manifest for testing."""
    return {
        "notifications_triggered": triggered,
        "notification_count":      len(notifications),
        "notifications":           notifications,
        "dispatch_status":         "pending",
    }


# =====================================================
# No channels configured
# =====================================================


class TestDispatchNoChannelsConfigured:
    """Tests for dispatch_notifications() when no channels are set up."""

    def test_returns_manifest_unchanged_when_not_triggered(self) -> None:
        """Returns manifest unchanged when notifications_triggered is False."""
        manifest = _make_manifest(notifications=[], triggered=False)
        result = dispatch_notifications(notification_manifest=manifest)
        assert result["notifications_triggered"] is False

    def test_skips_all_when_no_channels_configured(self) -> None:
        """Marks all notifications as skipped when no channels are configured."""
        manifest = _make_manifest([
            _make_notification(channel="email"),
            _make_notification(channel="slack"),
        ])

        with patch("notifications.dispatcher.is_email_configured", return_value=False):
            with patch("notifications.dispatcher.is_slack_configured", return_value=False):
                with patch("notifications.dispatcher.is_teams_configured", return_value=False):
                    result = dispatch_notifications(notification_manifest=manifest)

        assert result["dispatch_status"] == "skipped"
        assert result["dispatch_summary"]["skipped"] == 2
        assert result["dispatch_summary"]["sent"] == 0

    def test_returns_immediately_when_empty_notifications(self) -> None:
        """Returns immediately when notifications list is empty."""
        manifest = _make_manifest(notifications=[])
        result = dispatch_notifications(notification_manifest=manifest)
        assert result == manifest


# =====================================================
# Slack channel
# =====================================================


class TestDispatchSlack:
    """Tests for Slack channel dispatch."""

    def test_sends_slack_notification_successfully(self) -> None:
        """Dispatches Slack notification and marks as sent."""
        manifest = _make_manifest([_make_notification(channel="slack")])

        with patch("notifications.dispatcher.is_email_configured", return_value=False):
            with patch("notifications.dispatcher.is_slack_configured", return_value=True):
                with patch("notifications.dispatcher.is_teams_configured", return_value=False):
                    with patch("notifications.dispatcher.get_slack_webhook_url",
                               return_value="https://hooks.slack.com/fake"):
                        with patch("notifications.dispatcher.send_slack",
                                   return_value=True):
                            result = dispatch_notifications(
                                notification_manifest=manifest,
                                decision_id="test-decision-id",
                            )

        assert result["dispatch_status"] == "sent"
        assert result["dispatch_summary"]["sent"] == 1
        assert result["notifications"][0]["dispatch_status"] == _STATUS_SENT

    def test_marks_slack_as_failed_on_error(self) -> None:
        """Marks notification as failed when Slack send returns False."""
        manifest = _make_manifest([_make_notification(channel="slack")])

        with patch("notifications.dispatcher.is_email_configured", return_value=False):
            with patch("notifications.dispatcher.is_slack_configured", return_value=True):
                with patch("notifications.dispatcher.is_teams_configured", return_value=False):
                    with patch("notifications.dispatcher.get_slack_webhook_url",
                               return_value="https://hooks.slack.com/fake"):
                        with patch("notifications.dispatcher.send_slack",
                                   return_value=False):
                            result = dispatch_notifications(
                                notification_manifest=manifest
                            )

        assert result["dispatch_summary"]["failed"] == 1
        assert result["notifications"][0]["dispatch_status"] == _STATUS_FAILED

    def test_skips_slack_when_not_configured(self) -> None:
        """Skips Slack notification when webhook URL is not set."""
        manifest = _make_manifest([_make_notification(channel="slack")])

        with patch("notifications.dispatcher.is_email_configured", return_value=False):
            with patch("notifications.dispatcher.is_slack_configured", return_value=False):
                with patch("notifications.dispatcher.is_teams_configured", return_value=False):
                    result = dispatch_notifications(notification_manifest=manifest)

        assert result["notifications"][0]["dispatch_status"] == _STATUS_SKIPPED


# =====================================================
# Email channel
# =====================================================


class TestDispatchEmail:
    """Tests for email channel dispatch."""

    def test_sends_email_notification_successfully(self) -> None:
        """Dispatches email notification and marks as sent."""
        manifest = _make_manifest([_make_notification(channel="email")])

        with patch("notifications.dispatcher.is_email_configured", return_value=True):
            with patch("notifications.dispatcher.is_slack_configured", return_value=False):
                with patch("notifications.dispatcher.is_teams_configured", return_value=False):
                    with patch("notifications.dispatcher.get_smtp_config",
                               return_value={"host": "smtp.test.com",
                                             "port": 587,
                                             "user": "user@test.com",
                                             "password": "secret",
                                             "from_address": "from@test.com",
                                             "to_address": "to@test.com"}):
                        with patch("notifications.dispatcher.send_email",
                                   return_value=True):
                            result = dispatch_notifications(
                                notification_manifest=manifest
                            )

        assert result["dispatch_summary"]["sent"] == 1
        assert result["notifications"][0]["dispatch_status"] == _STATUS_SENT

    def test_skips_email_when_not_configured(self) -> None:
        """Skips email notification when SMTP is not configured."""
        manifest = _make_manifest([_make_notification(channel="email")])

        with patch("notifications.dispatcher.is_email_configured", return_value=False):
            with patch("notifications.dispatcher.is_slack_configured", return_value=False):
                with patch("notifications.dispatcher.is_teams_configured", return_value=False):
                    result = dispatch_notifications(notification_manifest=manifest)

        assert result["notifications"][0]["dispatch_status"] == _STATUS_SKIPPED


# =====================================================
# Teams channel
# =====================================================


class TestDispatchTeams:
    """Tests for Teams channel dispatch."""

    def test_sends_teams_notification_successfully(self) -> None:
        """Dispatches Teams notification and marks as sent."""
        manifest = _make_manifest([_make_notification(channel="teams")])

        with patch("notifications.dispatcher.is_email_configured", return_value=False):
            with patch("notifications.dispatcher.is_slack_configured", return_value=False):
                with patch("notifications.dispatcher.is_teams_configured", return_value=True):
                    with patch("notifications.dispatcher.get_teams_webhook_url",
                               return_value="https://outlook.office.com/webhook/fake"):
                        with patch("notifications.dispatcher.send_teams",
                                   return_value=True):
                            result = dispatch_notifications(
                                notification_manifest=manifest
                            )

        assert result["dispatch_summary"]["sent"] == 1
        assert result["notifications"][0]["dispatch_status"] == _STATUS_SENT


# =====================================================
# Mixed channels and partial failures
# =====================================================


class TestDispatchMixed:
    """Tests for mixed channel dispatch and partial failures."""

    def test_partial_success_status(self) -> None:
        """Reports partial status when some notifications succeed and some fail."""
        manifest = _make_manifest([
            _make_notification(channel="slack", role="engineering_lead"),
            _make_notification(channel="email", role="budget_owner"),
        ])

        with patch("notifications.dispatcher.is_email_configured", return_value=True):
            with patch("notifications.dispatcher.is_slack_configured", return_value=True):
                with patch("notifications.dispatcher.is_teams_configured", return_value=False):
                    with patch("notifications.dispatcher.get_smtp_config", return_value={}):
                        with patch("notifications.dispatcher.get_slack_webhook_url",
                                   return_value="https://hooks.slack.com/fake"):
                            with patch("notifications.dispatcher.send_slack",
                                       return_value=True):
                                with patch("notifications.dispatcher.send_email",
                                           return_value=False):
                                    result = dispatch_notifications(
                                        notification_manifest=manifest
                                    )

        assert result["dispatch_status"] == "partial"
        assert result["dispatch_summary"]["sent"] == 1
        assert result["dispatch_summary"]["failed"] == 1

    def test_unknown_channel_is_skipped(self) -> None:
        """Unknown channel types are silently skipped."""
        manifest = _make_manifest([
            _make_notification(channel="telegram"),
        ])

        with patch("notifications.dispatcher.is_email_configured", return_value=True):
            with patch("notifications.dispatcher.is_slack_configured", return_value=True):
                with patch("notifications.dispatcher.is_teams_configured", return_value=True):
                    result = dispatch_notifications(notification_manifest=manifest)

        assert result["notifications"][0]["dispatch_status"] == _STATUS_SKIPPED

    def test_exception_in_channel_does_not_crash(self) -> None:
        """Exceptions in channel senders are caught and marked as failed."""
        manifest = _make_manifest([_make_notification(channel="slack")])

        with patch("notifications.dispatcher.is_email_configured", return_value=False):
            with patch("notifications.dispatcher.is_slack_configured", return_value=True):
                with patch("notifications.dispatcher.is_teams_configured", return_value=False):
                    with patch("notifications.dispatcher.get_slack_webhook_url",
                               return_value="https://hooks.slack.com/fake"):
                        with patch("notifications.dispatcher.send_slack",
                                   side_effect=RuntimeError("unexpected error")):
                            result = dispatch_notifications(
                                notification_manifest=manifest
                            )

        assert result["dispatch_summary"]["failed"] == 1
        assert result["notifications"][0]["dispatch_status"] == _STATUS_FAILED

    def test_dispatch_summary_always_present(self) -> None:
        """Returned manifest always includes dispatch_summary."""
        manifest = _make_manifest([_make_notification(channel="slack")])

        with patch("notifications.dispatcher.is_email_configured", return_value=False):
            with patch("notifications.dispatcher.is_slack_configured", return_value=False):
                with patch("notifications.dispatcher.is_teams_configured", return_value=False):
                    result = dispatch_notifications(notification_manifest=manifest)

        assert "dispatch_summary" in result
        assert "sent"    in result["dispatch_summary"]
        assert "failed"  in result["dispatch_summary"]
        assert "skipped" in result["dispatch_summary"]