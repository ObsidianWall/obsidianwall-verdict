# telemetry/config.py
#
# Purpose:
# Opt-in telemetry configuration for ObsidianWall Verdict.
#
# Telemetry is DISABLED by default.
# Users must explicitly enable it.
#
# What is collected (when enabled):
#   - Evaluation counts
#   - Policy type distribution
#   - Decision outcomes (ALLOW/DENY/etc)
#   - Risk scores (aggregated)
#   - Override and approval rates
#   - Condition failure patterns (condition IDs only)
#
# What is NEVER collected:
#   - Plan contents or resource configurations
#   - Cost amounts or budget values
#   - Resource names or identifiers
#   - Organization or team identifiers
#   - Policy file contents
#   - IP addresses or user identifiers
#
# How to enable:
#   export OW_TELEMETRY_ENABLED=true
#   or set OW_TELEMETRY_ENABLED=true in .env
#
# Storage:
#   ~/.obsidianwall/decisions.db  (SQLite, local only)
#   No remote telemetry in v0.3.0
#   Remote opt-in telemetry planned for v0.5.0

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
    Returns True unless explicitly opted out.

    Governance history is enabled by default.
    Stored only at ~/.obsidianwall/decisions.db.
    Nothing is transmitted remotely.

    To opt out:
        export OW_HISTORY_ENABLED=false

    Legacy variable also supported:
        export OW_TELEMETRY_ENABLED=false
    """
    if _ENV_KEY_LEGACY in os.environ:
        return os.environ[_ENV_KEY_LEGACY].lower() == "true"
    return os.environ.get(_ENV_KEY, "true").lower() == "true"


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
