# tests/unit/test_notification_config.py
#
# Purpose:
# Unit tests for notifications/config.py.
# Covers: get_smtp_config(), is_email_configured(),
#         is_slack_configured(), is_teams_configured()

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from notifications.config import (
    get_smtp_config,
    get_slack_webhook_url,
    get_teams_webhook_url,
    is_email_configured,
    is_slack_configured,
    is_teams_configured,
)


class TestGetSmtpConfig:
    """Tests for get_smtp_config()."""

    def test_returns_defaults_when_no_env_set(self) -> None:
        """Returns empty strings and default port when no env vars set."""
        env = {k: v for k, v in os.environ.items()
               if not k.startswith("OW_")}
        with patch.dict(os.environ, env, clear=True):
            config = get_smtp_config()
        assert config["host"]         == ""
        assert config["port"]         == 587
        assert config["from_address"] == ""
        assert config["to_address"]   == ""

    def test_smtp_port_uses_custom_value(self) -> None:
        """OW_SMTP_PORT overrides default port 587."""
        with patch.dict(os.environ, {"OW_SMTP_PORT": "465"}, clear=False):
            config = get_smtp_config()
        assert config["port"] == 465

    def test_smtp_host_from_env(self) -> None:
        """OW_SMTP_HOST sets the host field."""
        with patch.dict(os.environ, {"OW_SMTP_HOST": "smtp.example.com"}, clear=False):
            config = get_smtp_config()
        assert config["host"] == "smtp.example.com"

    def test_from_address_from_env(self) -> None:
        """OW_NOTIFICATION_FROM sets the from_address field."""
        with patch.dict(
            os.environ,
            {"OW_NOTIFICATION_FROM": "verdict@example.com"},
            clear=False,
        ):
            config = get_smtp_config()
        assert config["from_address"] == "verdict@example.com"

    def test_to_address_from_env(self) -> None:
        """OW_NOTIFICATION_TO sets the to_address field."""
        with patch.dict(
            os.environ,
            {"OW_NOTIFICATION_TO": "alerts@example.com"},
            clear=False,
        ):
            config = get_smtp_config()
        assert config["to_address"] == "alerts@example.com"


class TestIsEmailConfigured:
    """Tests for is_email_configured()."""

    def test_configured_when_all_fields_set(self) -> None:
        """Returns True when all required SMTP fields are set."""
        env = {
            "OW_SMTP_HOST":         "smtp.example.com",
            "OW_SMTP_USER":         "user@example.com",
            "OW_SMTP_PASS":         "secret",
            "OW_NOTIFICATION_TO":   "to@example.com",
            "OW_NOTIFICATION_FROM": "from@example.com",
        }
        with patch.dict(os.environ, env, clear=True):
            assert is_email_configured() is True

    def test_not_configured_when_from_address_missing(self) -> None:
        """Returns False when OW_NOTIFICATION_FROM is not set."""
        env = {
            "OW_SMTP_HOST":       "smtp.example.com",
            "OW_SMTP_USER":       "user@example.com",
            "OW_SMTP_PASS":       "secret",
            "OW_NOTIFICATION_TO": "to@example.com",
        }
        with patch.dict(os.environ, env, clear=True):
            assert is_email_configured() is False

    def test_not_configured_when_host_missing(self) -> None:
        """Returns False when OW_SMTP_HOST is not set."""
        env = {
            "OW_SMTP_USER":         "user@example.com",
            "OW_SMTP_PASS":         "secret",
            "OW_NOTIFICATION_TO":   "to@example.com",
            "OW_NOTIFICATION_FROM": "from@example.com",
        }
        with patch.dict(os.environ, env, clear=True):
            assert is_email_configured() is False

    def test_not_configured_when_no_env_vars(self) -> None:
        """Returns False when no environment variables are set."""
        env = {k: v for k, v in os.environ.items()
               if not k.startswith("OW_")}
        with patch.dict(os.environ, env, clear=True):
            assert is_email_configured() is False


class TestIsSlackConfigured:
    """Tests for is_slack_configured()."""

    def test_configured_when_webhook_url_set(self) -> None:
        """Returns True when OW_SLACK_WEBHOOK_URL is set."""
        with patch.dict(
            os.environ,
            {"OW_SLACK_WEBHOOK_URL": "https://hooks.slack.com/fake"},
            clear=False,
        ):
            assert is_slack_configured() is True

    def test_not_configured_when_url_empty(self) -> None:
        """Returns False when OW_SLACK_WEBHOOK_URL is not set."""
        env = {k: v for k, v in os.environ.items()
               if k != "OW_SLACK_WEBHOOK_URL"}
        with patch.dict(os.environ, env, clear=True):
            assert is_slack_configured() is False

    def test_returns_webhook_url_from_env(self) -> None:
        """get_slack_webhook_url() returns the configured URL."""
        with patch.dict(
            os.environ,
            {"OW_SLACK_WEBHOOK_URL": "https://hooks.slack.com/abc"},
            clear=False,
        ):
            assert get_slack_webhook_url() == "https://hooks.slack.com/abc"


class TestIsTeamsConfigured:
    """Tests for is_teams_configured()."""

    def test_configured_when_webhook_url_set(self) -> None:
        """Returns True when OW_TEAMS_WEBHOOK_URL is set."""
        with patch.dict(
            os.environ,
            {"OW_TEAMS_WEBHOOK_URL": "https://outlook.office.com/webhook/fake"},
            clear=False,
        ):
            assert is_teams_configured() is True

    def test_not_configured_when_url_empty(self) -> None:
        """Returns False when OW_TEAMS_WEBHOOK_URL is not set."""
        env = {k: v for k, v in os.environ.items()
               if k != "OW_TEAMS_WEBHOOK_URL"}
        with patch.dict(os.environ, env, clear=True):
            assert is_teams_configured() is False

    def test_returns_webhook_url_from_env(self) -> None:
        """get_teams_webhook_url() returns the configured URL."""
        with patch.dict(
            os.environ,
            {"OW_TEAMS_WEBHOOK_URL": "https://outlook.office.com/webhook/abc"},
            clear=False,
        ):
            assert get_teams_webhook_url() == "https://outlook.office.com/webhook/abc"