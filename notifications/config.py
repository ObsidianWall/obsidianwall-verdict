# notifications/config.py
#
# Purpose:
# Notification channel configuration from environment variables.
#
# All notification channels are opt-in.
# If no environment variables are set, dispatch silently
# no-ops — no errors, no warnings, no CLI impact.
#
# Email configuration:
#   OW_SMTP_HOST          SMTP server hostname
#   OW_SMTP_PORT          SMTP port (default: 587)
#   OW_SMTP_USER          SMTP username / login
#   OW_SMTP_PASS          SMTP password
#   OW_NOTIFICATION_FROM  Sender address (default: verdict@obsidianwall.io)
#   OW_NOTIFICATION_TO    Recipient address (all notifications)
#
# Slack configuration:
#   OW_SLACK_WEBHOOK_URL  Slack incoming webhook URL
#
# Teams configuration:
#   OW_TEAMS_WEBHOOK_URL  Microsoft Teams incoming webhook URL
#
# MVP note on email addressing:
#   The notification manifest uses role names (budget_owner,
#   engineering_lead) not email addresses. For MVP, all email
#   notifications route to OW_NOTIFICATION_TO regardless of role.
#   Role-to-email mapping is a Compass feature when a user
#   directory exists.

from __future__ import annotations

import os
from typing import Any

_SMTP_HOST_KEY = "OW_SMTP_HOST"
_SMTP_PORT_KEY = "OW_SMTP_PORT"
_SMTP_USER_KEY = "OW_SMTP_USER"
_SMTP_PASS_KEY = "OW_SMTP_PASS"
_NOTIFY_FROM_KEY = "OW_NOTIFICATION_FROM"
_NOTIFY_TO_KEY = "OW_NOTIFICATION_TO"
_SLACK_WEBHOOK_KEY = "OW_SLACK_WEBHOOK_URL"
_TEAMS_WEBHOOK_KEY = "OW_TEAMS_WEBHOOK_URL"

_DEFAULT_FROM_ADDRESS = "verdict@obsidianwall.io"
_DEFAULT_SMTP_PORT = 587


def get_smtp_config() -> dict[str, Any]:
    """
    Return SMTP configuration from environment variables.

    Returns a dict with all required fields.
    Empty strings indicate unconfigured values.
    """
    return {
        "host": os.environ.get(_SMTP_HOST_KEY, ""),
        "port": int(os.environ.get(_SMTP_PORT_KEY, str(_DEFAULT_SMTP_PORT))),
        "user": os.environ.get(_SMTP_USER_KEY, ""),
        "password": os.environ.get(_SMTP_PASS_KEY, ""),
        "from_address": os.environ.get(_NOTIFY_FROM_KEY, _DEFAULT_FROM_ADDRESS),
        "to_address": os.environ.get(_NOTIFY_TO_KEY, ""),
    }


def is_email_configured() -> bool:
    """
    Return True if all required SMTP fields are set.

    Requires: host, user, password, and to_address.
    Port and from_address have safe defaults.
    """
    cfg = get_smtp_config()
    return bool(cfg["host"] and cfg["user"] and cfg["password"] and cfg["to_address"])


def get_slack_webhook_url() -> str:
    """Return the Slack incoming webhook URL, or empty string."""
    return os.environ.get(_SLACK_WEBHOOK_KEY, "")


def is_slack_configured() -> bool:
    """Return True if the Slack webhook URL is set."""
    return bool(get_slack_webhook_url())


def get_teams_webhook_url() -> str:
    """Return the Teams incoming webhook URL, or empty string."""
    return os.environ.get(_TEAMS_WEBHOOK_KEY, "")


def is_teams_configured() -> bool:
    """Return True if the Teams webhook URL is set."""
    return bool(get_teams_webhook_url())
