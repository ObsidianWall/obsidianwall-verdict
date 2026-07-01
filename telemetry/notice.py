# telemetry/notice.py
#
# Purpose:
# Show a one-time disclosure notice on first run,
# so opt-out telemetry is disclosed up front rather
# than discovered later.
#
# Behavior:
# - Shown exactly once per machine, on the first
#   invocation of any verdict command.
# - A marker file at ~/.obsidianwall/.notice_shown
#   prevents it from showing again.
# - Does not block execution — prints, then continues.
# - If OW_HISTORY_ENABLED or OW_TELEMETRY_ENABLED is
#   already set in the environment, the notice still
#   shows once, but the user's existing choice is
#   respected and not overridden.

from __future__ import annotations

from pathlib import Path

from telemetry.config import get_db_dir, is_telemetry_enabled

_NOTICE_MARKER = "notice_shown"


def _marker_path() -> Path:
    return get_db_dir() / _NOTICE_MARKER


def show_first_run_notice_if_needed() -> None:
    """
    Print the telemetry disclosure notice once per
    machine. Safe to call on every CLI invocation —
    it no-ops after the first run.
    """
    marker = _marker_path()

    if marker.exists():
        return

    status = "enabled" if is_telemetry_enabled() else "disabled"

    print(
        "\n"
        "Verdict collects anonymous local usage data by default\n"
        "(decision counts, risk scores, condition pass/fail —\n"
        "never plan contents, costs, resource names, or org info).\n"
        "\n"
        f"Status: {status}\n"
        "Stored locally at ~/.obsidianwall/decisions.db\n"
        "Nothing is transmitted off this machine in this version.\n"
        "\n"
        "Disable anytime:  export OW_HISTORY_ENABLED=false\n"
        "Learn more:        https://obsidianwall.dev/concepts/telemetry\n"
    )

    try:
        marker.touch()
    except OSError:
        # Non-fatal — if we can't write the marker,
        # the notice may show again next run. That is
        # an acceptable failure mode; it must never
        # block the CLI.
        pass
