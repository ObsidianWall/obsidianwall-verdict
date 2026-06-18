
# tests/unit/test_telemetry_config.py
#
# Purpose:
# Unit tests for telemetry/config.py.
# Covers: is_telemetry_enabled(), get_db_path()

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from telemetry.config import get_db_path, is_telemetry_enabled


class TestIsTelemetryEnabled:
    """Tests for is_telemetry_enabled()."""

    def test_enabled_by_default(self) -> None:
        """Governance history is on by default — opt-out model."""
        env = {k: v for k, v in os.environ.items()
               if k not in ("OW_HISTORY_ENABLED", "OW_TELEMETRY_ENABLED")}
        with patch.dict(os.environ, env, clear=True):
            assert is_telemetry_enabled() is True

    def test_disabled_via_history_key(self) -> None:
        """OW_HISTORY_ENABLED=false disables history."""
        with patch.dict(os.environ, {"OW_HISTORY_ENABLED": "false"}, clear=False):
            assert is_telemetry_enabled() is False

    def test_enabled_via_history_key(self) -> None:
        """OW_HISTORY_ENABLED=true explicitly enables history."""
        with patch.dict(os.environ, {"OW_HISTORY_ENABLED": "true"}, clear=False):
            assert is_telemetry_enabled() is True

    def test_disabled_via_legacy_key(self) -> None:
        """Legacy OW_TELEMETRY_ENABLED=false is respected."""
        env = {k: v for k, v in os.environ.items()
               if k not in ("OW_HISTORY_ENABLED", "OW_TELEMETRY_ENABLED")}
        env["OW_TELEMETRY_ENABLED"] = "false"
        with patch.dict(os.environ, env, clear=True):
            assert is_telemetry_enabled() is False

    def test_enabled_via_legacy_key(self) -> None:
        """Legacy OW_TELEMETRY_ENABLED=true is respected."""
        env = {k: v for k, v in os.environ.items()
               if k not in ("OW_HISTORY_ENABLED", "OW_TELEMETRY_ENABLED")}
        env["OW_TELEMETRY_ENABLED"] = "true"
        with patch.dict(os.environ, env, clear=True):
            assert is_telemetry_enabled() is True

    def test_new_key_takes_precedence_over_legacy(self) -> None:
        """OW_HISTORY_ENABLED takes precedence when both are set."""
        with patch.dict(
            os.environ,
            {
                "OW_HISTORY_ENABLED":    "true",
                "OW_TELEMETRY_ENABLED":  "false",
            },
            clear=False,
        ):
            assert is_telemetry_enabled() is True

    def test_case_insensitive_false(self) -> None:
        """FALSE and False are treated as disabled."""
        for value in ("FALSE", "False"):
            with patch.dict(os.environ, {"OW_HISTORY_ENABLED": value}, clear=False):
                assert is_telemetry_enabled() is False

    def test_case_insensitive_true(self) -> None:
        """TRUE and True are treated as enabled."""
        for value in ("TRUE", "True"):
            with patch.dict(os.environ, {"OW_HISTORY_ENABLED": value}, clear=False):
                assert is_telemetry_enabled() is True
           

class TestGetDbPath:
    """Tests for get_db_path()."""

    def test_default_path_is_in_home_directory(self) -> None:
        """Default database path lives under ~/.obsidianwall/."""
        env = {k: v for k, v in os.environ.items()
               if "OW_DB" not in k}
        with patch.dict(os.environ, env, clear=True):
            database_path = get_db_path()
            assert ".obsidianwall" in str(database_path)

    def test_returns_path_object(self) -> None:
        """get_db_path() returns a Path object."""
        database_path = get_db_path()
        assert isinstance(database_path, Path)

    def test_path_ends_with_db_file(self) -> None:
        """Database path ends with a .db file."""
        database_path = get_db_path()
        assert database_path.suffix == ".db"
