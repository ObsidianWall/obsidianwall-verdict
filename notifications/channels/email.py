# notifications/channels/email.py
#
# Purpose:
# SMTP email dispatch for governance notifications.
#
# Responsibilities:
# - Accept a single notification dict from the manifest
# - Build a properly formatted MIME email
# - Send via configured SMTP server with STARTTLS
# - Return True on success, False on any failure
#
# IMPORTANT:
# This module NEVER raises exceptions to the caller.
# All failures are caught internally and return False.
# The dispatcher handles logging.
#
# Role addressing (MVP):
# The manifest uses role names, not email addresses.
# All email notifications are sent to OW_NOTIFICATION_TO.
# The role name appears in the subject and body so the
# recipient knows who the notification is intended for.
# Role-to-email mapping is a future Compass feature.

from __future__ import annotations

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any


def send_email(
    notification: dict[str, Any],
    smtp_config: dict[str, Any],
) -> bool:
    """
    Send a single governance notification via SMTP.

    Builds a MIME email from the notification manifest entry
    and sends via STARTTLS SMTP.

    Args:
        notification:  single notification dict from manifest
        smtp_config:   SMTP configuration from notifications.config

    Returns:
        True if email was sent successfully, False otherwise.
        Never raises.
    """
    try:
        subject: str = notification.get(
            "subject", "ObsidianWall Governance Notification"
        )
        body: str = notification.get("body", "")
        role: str = notification.get("target_role", "unknown")
        decision: str = notification.get("decision", "")
        policy: str = notification.get("policy", "")

        from_addr: str = smtp_config.get("from_address", "verdict@obsidianwall.io")
        to_addr: str = smtp_config.get("to_address", "")

        if not to_addr:
            return False

        msg = MIMEMultipart()
        msg["From"] = from_addr
        msg["To"] = to_addr
        msg["Subject"] = subject

        # Prepend role context to body.
        # MVP: one recipient address receives all role notifications.
        # The role field tells the recipient who this notification
        # is intended for organizationally.
        full_body: str = (
            f"Governance notification intended for: {role}\n"
            f"Policy: {policy}\n"
            f"Decision: {decision}\n"
            f"{'─' * 48}\n\n"
            f"{body}"
        )

        msg.attach(MIMEText(full_body, "plain"))

        host: str = smtp_config.get("host", "")
        port: int = int(smtp_config.get("port", 587))
        user: str = smtp_config.get("user", "")
        password: str = smtp_config.get("password", "")

        with smtplib.SMTP(host, port, timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(user, password)
            server.send_message(msg)

        return True

    except Exception:
        # Never propagate — caller handles logging
        return False
