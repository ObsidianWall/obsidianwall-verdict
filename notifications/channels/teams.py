# notifications/channels/teams.py
#
# Purpose:
# Microsoft Teams webhook dispatch for governance notifications.
#
# Uses Adaptive Cards format via Teams incoming webhook.
# No Teams SDK dependency — plain urllib.request only.
# Zero external dependencies beyond Python stdlib.
#
# Webhook setup:
#   Teams channel → Manage channel → Connectors
#   → Incoming Webhook → Configure → copy URL
#   Set OW_TEAMS_WEBHOOK_URL to the copied URL.
#
# IMPORTANT:
# This module NEVER raises exceptions to the caller.
# All failures are caught internally and return False.
# The dispatcher handles logging.

from __future__ import annotations

import json
import urllib.request
from typing import Any

from cli.display import decision_icon

_TIMEOUT_SECONDS: int = 5

# Severity-to-color mapping for Adaptive Card accent colors.
# Teams uses hex color strings for card theming.
_SEVERITY_COLOR: dict[str, str] = {
    "critical": "FF0000",  # red
    "high": "FF6600",  # orange
    "medium": "FFC300",  # amber
    "low": "0076D7",  # blue
    "informational": "808080",  # grey
}

# Priority-to-emoji mapping for Teams message headers.
# Five distinct icons — no two priorities share the same emoji.
_PRIORITY_EMOJI: dict[str, str] = {
    "urgent": "🚨",
    "high": "⚠️",
    "medium": "🔔",
    "low": "🔵",
    "informational": "ℹ️",
}


def send_teams(
    notification: dict[str, Any],
    webhook_url: str,
) -> bool:
    """
    Send a single governance notification to a Microsoft Teams
    incoming webhook using Adaptive Cards format.

    Args:
        notification:  single notification dict from manifest
        webhook_url:   Teams incoming webhook URL

    Returns:
        True if webhook returned HTTP 200, False otherwise.
        Never raises.
    """
    try:
        if not webhook_url:
            return False

        role: str = notification.get("target_role", "unknown")
        body: str = notification.get("body", "")
        priority: str = notification.get("priority", "medium")
        decision: str = notification.get("decision", "")
        severity: str = notification.get("effective_severity", "")
        policy: str = notification.get("policy", "")
        requires: bool = notification.get("requires_action", False)

        header_emoji: str = _PRIORITY_EMOJI.get(priority, "ℹ️")
        decision_icon_str: str = decision_icon(decision)
        accent_color: str = _SEVERITY_COLOR.get(severity.lower(), "0076D7")
        action_note: str = (
            "⚡ Action required" if requires else "Awareness notification"
        )

        # Adaptive Card payload
        # Compatible with Teams incoming webhooks.
        # Uses MessageCard format for maximum compatibility
        # across Teams versions and connector configurations.
        payload: dict[str, Any] = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": accent_color,
            "summary": f"ObsidianWall Governance Alert — {policy}",
            "sections": [
                {
                    "activityTitle": f"{header_emoji} ObsidianWall Governance Alert",
                    "activitySubtitle": action_note,
                    "facts": [
                        {
                            "name": "Policy",
                            "value": policy,
                        },
                        {
                            "name": "Decision",
                            "value": f"{decision_icon_str} {decision}",
                        },
                        {
                            "name": "Severity",
                            "value": severity.upper(),
                        },
                        {
                            "name": "Intended for",
                            "value": role,
                        },
                    ],
                    "markdown": True,
                },
                {
                    "text": body,
                },
            ],
        }

        data: bytes = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            webhook_url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        with urllib.request.urlopen(req, timeout=_TIMEOUT_SECONDS) as response:
            return response.status == 200

    except Exception:
        # Never propagate — caller handles logging
        return False
