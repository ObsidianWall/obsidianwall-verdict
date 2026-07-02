# telemetry/config.py
#
# Purpose:
# Telemetry configuration for ObsidianWall Verdict.
#
# Telemetry is ENABLED by default (opt-out model).
# Users can disable it at any time.
#
# What is collected (when enabled — the default):
#   - Evaluation counts and timestamps
#   - Policy name and policy type
#   - Decision outcomes (ALLOW/DENY/etc)
#   - Risk scores (overall and per analyzer domain)
#   - Override and approval events (role + approved/denied + notes)
#   - Condition failure and pass patterns (condition IDs only)
#   - A SHA-256 hash of the plan file path (not its contents)
#   - The policy file path, stored as-is
#
# What is NEVER collected:
#   - Plan contents or resource configurations
#   - Cost amounts or budget values
#   - Resource names or identifiers
#   - Organization or team identifiers
#   - Policy file contents
#   - IP addresses or user identifiers
#
# How to opt out:
#   export OW_HISTORY_ENABLED=false
#   (legacy alias OW_TELEMETRY_ENABLED=false also works)
#
# Storage:
#   ~/.obsidianwall/decisions.db  (SQLite, local only)
#   No remote transmission in this version.
#   This data never leaves the user's machine.
#
# IMPORTANT — keep this comment block in sync with
# is_telemetry_enabled() below and with the public
# privacy policy at obsidianwall.com/privacy.html.
# A future hosted feature (Compass) will introduce
# OPTIONAL, explicitly opt-in remote sync. That will
# be a separate consent flow — it must never be
# enabled by this opt-out default.

from __future__ import annotations

import os
from pathlib import Path

# =====================================================
# TELEMETRY CONFIGURATION
# =====================================================

_ENV_KEY = "OW_HISTORY_ENABLED"
_ENV_KEY_LEGACY = "OW_TELEMETRY_ENABLED"
_DB_DIR = Path.home() / ".obsidianwall"
_DB_PATH = _DB_DIR / "decisions.db"


def is_telemetry_enabled() -> bool:
    """
    Returns True unless the user has explicitly opted out.

    OW_HISTORY_ENABLED takes precedence when set.
    Falls back to legacy OW_TELEMETRY_ENABLED for
    backward compatibility.
    Defaults to True — this is an opt-out model.

    To opt out:
        export OW_HISTORY_ENABLED=false
    """
    if _ENV_KEY in os.environ:
        return os.environ[_ENV_KEY].lower() == "true"
    if _ENV_KEY_LEGACY in os.environ:
        return os.environ[_ENV_KEY_LEGACY].lower() == "true"
    return True


def get_db_path() -> Path:
    """
    Returns the path to the local SQLite decisions database.
    Creates the directory if it does not exist.
    """
    _DB_DIR.mkdir(parents=True, exist_ok=True)
    return _DB_PATH


def get_db_dir() -> Path:
    """Returns the ObsidianWall data directory."""
    _DB_DIR.mkdir(parents=True, exist_ok=True)
    return _DB_DIR
