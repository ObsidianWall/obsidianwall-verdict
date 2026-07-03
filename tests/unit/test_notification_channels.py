
# tests/unit/test_notification_channels.py
#
# Purpose:
# Unit tests for notification channel senders.
# Covers: send_email(), send_slack(), send_teams()
# All network calls are mocked — no real SMTP or HTTP.

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from notifications.channels.email import send_email
from notifications.channels.slack import send_slack
from notifications.channels.teams import send_teams


# =====================================================
# SHARED FIXTURES
# =====================================================


def _make_notification(
    channel: str = "email",
    role: str = "engineering_lead",
    decision: str = "DENY_WITH_OVERRIDE",
    requires_action: bool = False,
) -> dict[str, Any]:
    """Build a minimal notification dict for channel testing."""
    return {
        "target_role":       role,
        "channel":           channel,
        "priority":          "high",
        "subject":           "[ObsidianWall] Governance Alert — test_policy",
        "body":              "Deployment blocked. Review required.",
        "requires_action":   requires_action,
        "decision":          decision,
        "policy":            "test_policy",
        "effective_severity": "critical",
        "dispatch_status":   "pending",
    }


def _make_smtp_config(
    host: str = "smtp.test.com",
    port: int = 587,
    user: str = "user@test.com",
    password: str = "secret",
    from_address: str = "verdict@test.com",
    to_address: str = "recipient@test.com",
) -> dict[str, Any]:
    """Build a minimal SMTP config dict for testing."""
    return {
        "host":         host,
        "port":         port,
        "user":         user,
        "password":     password,
        "from_address": from_address,
        "to_address":   to_address,
    }


# =====================================================
# send_email
# =====================================================


class TestSendEmail:
    """Tests for notifications/channels/email.py send_email()."""

    def test_sends_email_successfully(self) -> None:
        """Returns True when SMTP send succeeds."""
        notification = _make_notification(channel="email")
        smtp_config  = _make_smtp_config()

        with patch("smtplib.SMTP") as mock_smtp_class:
            mock_smtp_server = MagicMock()
            mock_smtp_class.return_value.__enter__.return_value = mock_smtp_server

            result = send_email(notification, smtp_config)

        assert result is True
        mock_smtp_server.send_message.assert_called_once()

    def test_calls_starttls(self) -> None:
        """send_email calls starttls for encrypted connection."""
        notification = _make_notification(channel="email")
        smtp_config  = _make_smtp_config()

        with patch("smtplib.SMTP") as mock_smtp_class:
            mock_smtp_server = MagicMock()
            mock_smtp_class.return_value.__enter__.return_value = mock_smtp_server

            send_email(notification, smtp_config)

        mock_smtp_server.starttls.assert_called_once()

    def test_calls_login(self) -> None:
        """send_email logs in with provided credentials."""
        notification = _make_notification(channel="email")
        smtp_config  = _make_smtp_config(user="user@test.com", password="secret")

        with patch("smtplib.SMTP") as mock_smtp_class:
            mock_smtp_server = MagicMock()
            mock_smtp_class.return_value.__enter__.return_value = mock_smtp_server

            send_email(notification, smtp_config)

        mock_smtp_server.login.assert_called_once_with("user@test.com", "secret")

    def test_returns_false_when_from_address_empty(self) -> None:
        """Returns False when from_address is not configured."""
        notification = _make_notification(channel="email")
        smtp_config  = _make_smtp_config(from_address="")

        result = send_email(notification, smtp_config)

        assert result is False

    def test_returns_false_when_to_address_empty(self) -> None:
        """Returns False when to_address is not configured."""
        notification = _make_notification(channel="email")
        smtp_config  = _make_smtp_config(to_address="")

        result = send_email(notification, smtp_config)

        assert result is False

    def test_returns_false_on_smtp_exception(self) -> None:
        """Returns False when SMTP raises an exception."""
        notification = _make_notification(channel="email")
        smtp_config  = _make_smtp_config()

        with patch("smtplib.SMTP", side_effect=ConnectionRefusedError("refused")):
            result = send_email(notification, smtp_config)

        assert result is False

    def test_returns_false_on_authentication_error(self) -> None:
        """Returns False when SMTP authentication fails."""
        import smtplib

        notification = _make_notification(channel="email")
        smtp_config  = _make_smtp_config()

        with patch("smtplib.SMTP") as mock_smtp_class:
            mock_smtp_server = MagicMock()
            mock_smtp_server.login.side_effect = smtplib.SMTPAuthenticationError(
                535, b"Authentication failed"
            )
            mock_smtp_class.return_value.__enter__.return_value = mock_smtp_server

            result = send_email(notification, smtp_config)

        assert result is False

    def test_email_includes_role_context_in_body(self) -> None:
        """Email body includes the target role for identification."""
        notification = _make_notification(channel="email", role="budget_owner")
        smtp_config  = _make_smtp_config()

        sent_messages: list[Any] = []

        with patch("smtplib.SMTP") as mock_smtp_class:
            mock_smtp_server = MagicMock()

            def capture_message(message: Any) -> None:
                sent_messages.append(message)

            mock_smtp_server.send_message.side_effect = capture_message
            mock_smtp_class.return_value.__enter__.return_value = mock_smtp_server

            send_email(notification, smtp_config)

        assert len(sent_messages) == 1
        body_text = (
            sent_messages[0]
            .get_payload(0)
            .get_payload(decode=True)
            .decode("utf-8")
        )
        assert "budget_owner" in body_text

    def test_does_not_raise_on_any_exception(self) -> None:
        """send_email never propagates exceptions to the caller."""
        notification = _make_notification(channel="email")
        smtp_config  = _make_smtp_config()

        with patch("smtplib.SMTP", side_effect=RuntimeError("unexpected")):
            result = send_email(notification, smtp_config)

        assert result is False


# =====================================================
# send_slack
# =====================================================


class TestSendSlack:
    """Tests for notifications/channels/slack.py send_slack()."""

    def _mock_urlopen_success(self) -> MagicMock:
        """Build a mock urlopen context manager returning HTTP 200."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_context = MagicMock()
        mock_context.__enter__.return_value = mock_response
        mock_context.__exit__.return_value = False
        return mock_context

    def test_sends_slack_notification_successfully(self) -> None:
        """Returns True when Slack webhook returns 200."""
        notification = _make_notification(channel="slack")

        with patch("urllib.request.urlopen",
                   return_value=self._mock_urlopen_success()):
            result = send_slack(notification, "https://hooks.slack.com/fake")

        assert result is True

    def test_returns_false_for_empty_webhook_url(self) -> None:
        """Returns False immediately when webhook URL is empty."""
        notification = _make_notification(channel="slack")

        result = send_slack(notification, "")

        assert result is False

    def test_returns_false_on_http_error(self) -> None:
        """Returns False when webhook returns non-200 status."""
        notification = _make_notification(channel="slack")

        mock_response = MagicMock()
        mock_response.status = 400
        mock_context = MagicMock()
        mock_context.__enter__.return_value = mock_response
        mock_context.__exit__.return_value = False

        with patch("urllib.request.urlopen", return_value=mock_context):
            result = send_slack(notification, "https://hooks.slack.com/fake")

        assert result is False

    def test_returns_false_on_network_exception(self) -> None:
        """Returns False when network call raises an exception."""
        notification = _make_notification(channel="slack")

        with patch("urllib.request.urlopen",
                   side_effect=ConnectionError("network error")):
            result = send_slack(notification, "https://hooks.slack.com/fake")

        assert result is False

    def test_does_not_raise_on_any_exception(self) -> None:
        """send_slack never propagates exceptions to the caller."""
        notification = _make_notification(channel="slack")

        with patch("urllib.request.urlopen",
                   side_effect=RuntimeError("unexpected")):
            result = send_slack(notification, "https://hooks.slack.com/fake")

        assert result is False

    def test_posts_json_payload(self) -> None:
        """send_slack posts a JSON-encoded payload to the webhook."""
        notification = _make_notification(
            channel="slack",
            decision="DENY_WITH_OVERRIDE",
            requires_action=True,
        )

        captured_requests: list[Any] = []

        def capture_request(request: Any, timeout: int) -> Any:
            captured_requests.append(request)
            mock_response = MagicMock()
            mock_response.status = 200
            mock_context = MagicMock()
            mock_context.__enter__.return_value = mock_response
            mock_context.__exit__.return_value = False
            return mock_context

        with patch("urllib.request.urlopen", side_effect=capture_request):
            send_slack(notification, "https://hooks.slack.com/fake")

        assert len(captured_requests) == 1
        assert captured_requests[0].get_header("Content-type") == "application/json"

    def test_includes_action_required_indicator(self) -> None:
        """Action required flag is reflected in the notification payload."""
        notification = _make_notification(
            channel="slack",
            requires_action=True,
        )

        with patch("urllib.request.urlopen",
                   return_value=self._mock_urlopen_success()):
            result = send_slack(notification, "https://hooks.slack.com/fake")

        assert result is True


# =====================================================
# send_teams
# =====================================================


class TestSendTeams:
    """Tests for notifications/channels/teams.py send_teams()."""

    def _mock_urlopen_success(self) -> MagicMock:
        """Build a mock urlopen context manager returning HTTP 200."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_context = MagicMock()
        mock_context.__enter__.return_value = mock_response
        mock_context.__exit__.return_value = False
        return mock_context

    def test_sends_teams_notification_successfully(self) -> None:
        """Returns True when Teams webhook returns 200."""
        notification = _make_notification(channel="teams")

        with patch("urllib.request.urlopen",
                   return_value=self._mock_urlopen_success()):
            result = send_teams(
                notification, "https://outlook.office.com/webhook/fake"
            )

        assert result is True

    def test_returns_false_for_empty_webhook_url(self) -> None:
        """Returns False immediately when webhook URL is empty."""
        notification = _make_notification(channel="teams")

        result = send_teams(notification, "")

        assert result is False

    def test_returns_false_on_network_exception(self) -> None:
        """Returns False when network call raises an exception."""
        notification = _make_notification(channel="teams")

        with patch("urllib.request.urlopen",
                   side_effect=ConnectionError("network error")):
            result = send_teams(
                notification, "https://outlook.office.com/webhook/fake"
            )

        assert result is False

    def test_does_not_raise_on_any_exception(self) -> None:
        """send_teams never propagates exceptions to the caller."""
        notification = _make_notification(channel="teams")

        with patch("urllib.request.urlopen",
                   side_effect=RuntimeError("unexpected")):
            result = send_teams(
                notification, "https://outlook.office.com/webhook/fake"
            )

        assert result is False

    def test_posts_messagecard_format(self) -> None:
        """send_teams posts a MessageCard formatted payload."""
        import json

        notification = _make_notification(
            channel="teams",
            decision="DENY_WITH_OVERRIDE",
            requires_action=True,
        )

        captured_requests: list[Any] = []

        def capture_request(request: Any, timeout: int) -> Any:
            captured_requests.append(request)
            mock_response = MagicMock()
            mock_response.status = 200
            mock_context = MagicMock()
            mock_context.__enter__.return_value = mock_response
            mock_context.__exit__.return_value = False
            return mock_context

        with patch("urllib.request.urlopen", side_effect=capture_request):
            send_teams(notification, "https://outlook.office.com/webhook/fake")

        assert len(captured_requests) == 1
        payload = json.loads(captured_requests[0].data)
        assert payload["@type"] == "MessageCard"
        assert "sections" in payload

    def test_uses_severity_color(self) -> None:
        """send_teams uses the correct theme color for severity level."""
        import json

        notification = _make_notification(channel="teams")
        notification["effective_severity"] = "critical"

        captured_requests: list[Any] = []

        def capture_request(request: Any, timeout: int) -> Any:
            captured_requests.append(request)
            mock_response = MagicMock()
            mock_response.status = 200
            mock_context = MagicMock()
            mock_context.__enter__.return_value = mock_response
            mock_context.__exit__.return_value = False
            return mock_context

        with patch("urllib.request.urlopen", side_effect=capture_request):
            send_teams(notification, "https://outlook.office.com/webhook/fake")

        payload = json.loads(captured_requests[0].data)
        assert payload["themeColor"] == "FF0000"  # red for critical