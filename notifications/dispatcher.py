# notifications/dispatcher.py
#
# Purpose:
# Dispatch governance notifications from a manifest.
#
# Responsibilities:
# - Read the notification manifest from evaluate()
# - Route each notification to the correct channel sender
# - Update dispatch_status on each notification record
# - Return an updated manifest with dispatch summary
# - Never raise — dispatch failures must not crash the CLI
#
# Architecture boundary:
# This dispatcher is the ONLY place that calls channel senders.
# Channel senders (email.py, slack.py) never call each other.
# The orchestrator never calls channel senders directly.
#
# Sentinel integration:
# The dispatcher can also be called for outcome-based
# notifications when Sentinel detects compliance violations
# or drift. The manifest structure is the same.
#
# Channel configuration (silent no-op if unconfigured):
#   Email: OW_SMTP_HOST + OW_SMTP_USER + OW_SMTP_PASS + OW_NOTIFICATION_TO
#   Slack: OW_SLACK_WEBHOOK_URL

from __future__ import annotations

from typing import Any

from audit.audit_logger import get_logger
from notifications.channels.email import send_email
from notifications.channels.slack import send_slack
from notifications.config import (
    get_slack_webhook_url,
    get_smtp_config,
    is_email_configured,
    is_slack_configured,
)

logger = get_logger()

# Dispatch status constants
_STATUS_SENT    = "sent"
_STATUS_FAILED  = "failed"
_STATUS_SKIPPED = "skipped_not_configured"


def dispatch_notifications(
    notification_manifest: dict[str, Any],
    decision_id: str = "",
) -> dict[str, Any]:
    """
    Dispatch all pending notifications from a governance
    decision manifest.

    Routes each notification to the correct channel sender
    based on the channel field in each notification record.

    This function NEVER raises. All dispatch failures are
    caught, logged, and reflected in the returned manifest.
    Notification failures must never crash the CLI or
    influence governance decisions.

    If no channels are configured, all notifications are
    marked as skipped_not_configured and the function
    returns immediately without network calls.

    Args:
        notification_manifest:  complete notification manifest
                                from route_notifications()
        decision_id:            governance decision UUID for logging

    Returns:
        Updated manifest dict with:
        - dispatch_status updated on each notification
        - dispatch_summary with sent/failed/skipped counts
        - top-level dispatch_status summary string
    """

    # ── No notifications to dispatch ─────────────────
    if not notification_manifest.get("notifications_triggered"):
        return notification_manifest

    notifications: list[dict[str, Any]] = notification_manifest.get("notifications", [])

    if not notifications:
        return notification_manifest

    # ── Resolve channel availability once ────────────
    # Check configuration state once before the loop
    # rather than per-notification to avoid redundant
    # environment variable reads.
    email_configured: bool = is_email_configured()
    slack_configured: bool = is_slack_configured()

    # If nothing is configured, mark all as skipped and return
    if not email_configured and not slack_configured:
        skipped = [
            {**n, "dispatch_status": _STATUS_SKIPPED}
            for n in notifications
        ]
        return {
            **notification_manifest,
            "notifications":    skipped,
            "dispatch_summary": {
                "sent":    0,
                "failed":  0,
                "skipped": len(skipped),
            },
            "dispatch_status": "skipped",
        }

    smtp_config: dict[str, Any] = get_smtp_config() if email_configured else {}
    webhook_url: str            = get_slack_webhook_url() if slack_configured else ""

    sent_count:   int = 0
    failed_count: int = 0
    skip_count:   int = 0

    updated_notifications: list[dict[str, Any]] = []

    for notification in notifications:
        channel: str = notification.get("channel", "email")
        updated: dict[str, Any] = dict(notification)

        try:
            if channel == "email":
                if email_configured:
                    success: bool = send_email(notification, smtp_config)
                    updated["dispatch_status"] = (
                        _STATUS_SENT if success else _STATUS_FAILED
                    )
                    if success:
                        sent_count += 1
                        logger.info(
                            "notification_sent",
                            extra={
                                "extra": {
                                    "channel":     "email",
                                    "role":        notification.get("target_role"),
                                    "decision":    notification.get("decision"),
                                    "decision_id": decision_id,
                                }
                            },
                        )
                    else:
                        failed_count += 1
                        logger.warning(
                            "notification_failed",
                            extra={
                                "extra": {
                                    "channel":     "email",
                                    "role":        notification.get("target_role"),
                                    "decision_id": decision_id,
                                }
                            },
                        )
                else:
                    updated["dispatch_status"] = _STATUS_SKIPPED
                    skip_count += 1

            elif channel == "slack":
                if slack_configured:
                    success = send_slack(notification, webhook_url)
                    updated["dispatch_status"] = (
                        _STATUS_SENT if success else _STATUS_FAILED
                    )
                    if success:
                        sent_count += 1
                        logger.info(
                            "notification_sent",
                            extra={
                                "extra": {
                                    "channel":     "slack",
                                    "role":        notification.get("target_role"),
                                    "decision":    notification.get("decision"),
                                    "decision_id": decision_id,
                                }
                            },
                        )
                    else:
                        failed_count += 1
                        logger.warning(
                            "notification_failed",
                            extra={
                                "extra": {
                                    "channel":     "slack",
                                    "role":        notification.get("target_role"),
                                    "decision_id": decision_id,
                                }
                            },
                        )
                else:
                    updated["dispatch_status"] = _STATUS_SKIPPED
                    skip_count += 1

            else:
                # Unknown channel — skip without error
                updated["dispatch_status"] = _STATUS_SKIPPED
                skip_count += 1

        except Exception as exc:
            # Absolute safety net — dispatch must never crash CLI
            updated["dispatch_status"] = _STATUS_FAILED
            failed_count += 1
            logger.warning(
                "notification_dispatch_error",
                extra={
                    "extra": {
                        "channel":     channel,
                        "role":        notification.get("target_role"),
                        "error":       str(exc),
                        "decision_id": decision_id,
                    }
                },
            )

        updated_notifications.append(updated)

    # ── Dispatch summary ──────────────────────────────
    dispatch_summary: dict[str, int] = {
        "sent":    sent_count,
        "failed":  failed_count,
        "skipped": skip_count,
    }

    if sent_count > 0 or failed_count > 0:
        logger.info(
            "notification_dispatch_complete",
            extra={
                "extra": {
                    "sent":        sent_count,
                    "failed":      failed_count,
                    "skipped":     skip_count,
                    "decision_id": decision_id,
                }
            },
        )

    # Determine top-level dispatch status
    top_status: str
    if sent_count > 0 and failed_count == 0:
        top_status = "sent"
    elif sent_count > 0 and failed_count > 0:
        top_status = "partial"
    elif failed_count > 0:
        top_status = "failed"
    else:
        top_status = "skipped"

    return {
        **notification_manifest,
        "notifications":    updated_notifications,
        "dispatch_summary": dispatch_summary,
        "dispatch_status":  top_status,
    }
