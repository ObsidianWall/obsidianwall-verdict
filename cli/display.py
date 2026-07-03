# cli/display.py
#
# Purpose:
# Shared display utilities for audit and sentinel commands.
#
# Centralised here so icon mappings, severity labels, and
# risk bar rendering are consistent across all CLI output.
# Both audit and sentinel import from this module — any
# display change is made once and applies everywhere.

from __future__ import annotations

# =====================================================
# DECISION ICONS
# =====================================================

_DECISION_ICONS: dict[str, str] = {
    "ALLOW": "✅",
    "ALLOW_WITH_NOTIFICATION": "ℹ️ ",
    "DENY": "🚫",
    "DENY_WITH_OVERRIDE": "⚠️ ",
    "DENY_PENDING_APPROVAL": "⏳",
}


def decision_icon(decision: str) -> str:
    """
    Return the display icon for a governance decision.

    Falls back to ℹ️  for any unrecognised decision type
    so new decision types never produce blank or broken output.

    Args:
        decision: governance decision string

    Returns:
        single emoji string
    """
    return _DECISION_ICONS.get(decision, "ℹ️ ")
