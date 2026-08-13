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

from datetime import datetime, timezone

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


def format_display_timestamp(raw_timestamp: str) -> str:
    """Format stored UTC timestamps for CLI display.

    Governance records store ISO-8601 timestamps with optional
    fractional seconds. The audit and ledger views preserve that
    precision so evaluations happening within the same second
    still remain distinguishable — genuinely useful for spotting
    machine-generated bursts of records (e.g. a test suite
    writing to the wrong database) versus real, human-paced
    activity.

    Microseconds are ALWAYS included now, even when exactly zero
    (".000000" rather than omitting the fraction entirely) — the
    previous version's `if dt.microsecond:` made output length
    depend on the actual value, so any record landing on an exact
    whole second printed a SHORTER string than every other row,
    misaligning any fixed-width table column regardless of how
    wide that column was declared. Output is now always exactly
    30 characters ("YYYY-MM-DD HH:MM:SS.ffffff UTC"), so any
    caller using a column width of 30+ gets guaranteed-consistent
    alignment across every row, not just most of them.
    """
    if not raw_timestamp:
        return "—"

    text = str(raw_timestamp).strip()
    if not text:
        return "—"

    if text.endswith("Z"):
        text = text[:-1] + "+00:00"

    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return f"{text} UTC"

    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc)
    else:
        dt = dt.replace(tzinfo=timezone.utc)

    base = dt.strftime("%Y-%m-%d %H:%M:%S")
    base = f"{base}.{dt.microsecond:06d}"

    return f"{base} UTC"
