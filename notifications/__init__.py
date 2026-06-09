# notifications/__init__.py
#
# Purpose:
# Notification dispatch layer for ObsidianWall Verdict.
#
# Exposes dispatch_notifications() as the single entry point.
# Channel senders (email, slack) are internal implementation
# details — callers never import them directly.

from notifications.dispatcher import dispatch_notifications

__all__ = ["dispatch_notifications"]
