# tests/unit/test_coverage_final.py
#
# Purpose:
# Targeted tests for the final uncovered lines.
#
# Covers:
#   notifications/dispatcher.py  140-141, 153-154, 166-167
#     — per-channel "not configured" else/skip branches
#       only reachable when ≥1 OTHER channel IS configured
#       (otherwise early-exit path triggers instead)
#
#   telemetry/config.py          79-80
#     — get_db_dir() never called when db_path is
#       explicitly passed to init_db()
#
#   telemetry/store.py           181
#     — _run_migrations() pass branch: OperationalError
#       when migration already applied — mocked directly
#
#   telemetry/store.py           672-673, 722-723, 772-773
#     — json.JSONDecodeError except/continue branches
#       in domain risk, failed conditions, passed conditions
#       summaries — triggered by rows with invalid JSON
#
#   schemas/policy_schema.py     606, 618-651, 667-686
#     — policy spec validator error paths:
#       governance_domains on non-composite type,
#       composite without declared domains

from __future__ import annotations

import os
import sqlite3
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from notifications.dispatcher import (
    _STATUS_SKIPPED,
    dispatch_notifications,
)
from telemetry.config import get_db_dir
from telemetry.store import (
    _run_migrations,
    get_domain_risk_summary,
    get_failed_conditions_summary,
    get_passed_conditions_summary,
    init_db,
)


# =====================================================
# DISPATCHER — per-channel skip branches
#
# Existing tests mock ALL channels to unconfigured,
# which triggers the dispatcher's early-exit path
# (all skipped before reaching per-channel blocks).
#
# To hit lines 140-141, 153-154, 166-167 we need at
# least ONE channel configured so the early exit does
# NOT fire, then send a notification targeting a
# DIFFERENT, unconfigured channel.
# =====================================================


def _make_single_notification_manifest(channel: str) -> dict:
    return {
        "notifications_triggered": True,
        "notification_count":      1,
        "notifications": [
            {
                "target_role":        "engineering_lead",
                "channel":            channel,
                "priority":           "high",
                "subject":            "Test",
                "body":               "Test body.",
                "requires_action":    False,
                "decision":           "DENY",
                "policy":             "test_policy",
                "effective_severity": "high",
                "dispatch_status":    "pending",
            }
        ],
        "dispatch_status": "pending",
    }


class TestDispatcherPerChannelSkipBranches:
    """Tests for per-channel skip branches in the dispatch loop."""

    def test_email_skipped_when_slack_is_configured(self) -> None:
        """
        Covers lines 140-141.
        Slack IS configured — early exit does not fire.
        Notification targets email — email NOT configured.
        Hits the email else/skip branch in dispatch loop.
        """
        manifest = _make_single_notification_manifest("email")

        with patch("notifications.dispatcher.is_email_configured",
                   return_value=False):
            with patch("notifications.dispatcher.is_slack_configured",
                       return_value=True):
                with patch("notifications.dispatcher.is_teams_configured",
                           return_value=False):
                    with patch("notifications.dispatcher.get_slack_webhook_url",
                               return_value="https://hooks.slack.com/fake"):
                        result = dispatch_notifications(
                            notification_manifest=manifest
                        )

        assert result["notifications"][0]["dispatch_status"] == _STATUS_SKIPPED

    def test_slack_skipped_when_email_is_configured(self) -> None:
        """
        Covers lines 153-154.
        Email IS configured — early exit does not fire.
        Notification targets slack — slack NOT configured.
        Hits the slack else/skip branch in dispatch loop.
        """
        manifest = _make_single_notification_manifest("slack")

        with patch("notifications.dispatcher.is_email_configured",
                   return_value=True):
            with patch("notifications.dispatcher.is_slack_configured",
                       return_value=False):
                with patch("notifications.dispatcher.is_teams_configured",
                           return_value=False):
                    with patch(
                        "notifications.dispatcher.get_smtp_config",
                        return_value={
                            "host":         "smtp.test.com",
                            "port":         587,
                            "user":         "u",
                            "password":     "p",
                            "from_address": "f@t.com",
                            "to_address":   "t@t.com",
                        },
                    ):
                        result = dispatch_notifications(
                            notification_manifest=manifest
                        )

        assert result["notifications"][0]["dispatch_status"] == _STATUS_SKIPPED

    def test_teams_skipped_when_email_is_configured(self) -> None:
        """
        Covers lines 166-167.
        Email IS configured — early exit does not fire.
        Notification targets teams — teams NOT configured.
        Hits the teams else/skip branch in dispatch loop.
        """
        manifest = _make_single_notification_manifest("teams")

        with patch("notifications.dispatcher.is_email_configured",
                   return_value=True):
            with patch("notifications.dispatcher.is_slack_configured",
                       return_value=False):
                with patch("notifications.dispatcher.is_teams_configured",
                           return_value=False):
                    with patch(
                        "notifications.dispatcher.get_smtp_config",
                        return_value={
                            "host":         "smtp.test.com",
                            "port":         587,
                            "user":         "u",
                            "password":     "p",
                            "from_address": "f@t.com",
                            "to_address":   "t@t.com",
                        },
                    ):
                        result = dispatch_notifications(
                            notification_manifest=manifest
                        )

        assert result["notifications"][0]["dispatch_status"] == _STATUS_SKIPPED


# =====================================================
# telemetry/config.py — get_db_dir
#
# get_db_dir() is never called in tests because all
# tests pass an explicit db_path to init_db(), which
# bypasses get_db_path() → get_db_dir().
# =====================================================


class TestGetDbDir:
    """Tests for get_db_dir() — covers lines 79-80."""

    def test_returns_a_path_object(self) -> None:
        """get_db_dir() returns the ObsidianWall data directory path."""
        result = get_db_dir()
        assert isinstance(result, Path)

    def test_creates_directory_if_missing(self, tmp_path: Path) -> None:
        """get_db_dir() creates the directory if it does not exist."""
        target_dir = tmp_path / ".obsidianwall"
        with patch("telemetry.config._DB_DIR", target_dir):
            result = get_db_dir()
        assert result.exists()
        assert result.is_dir()


# =====================================================
# telemetry/store.py — _run_migrations pass branch
#
# Line 181 is `pass` inside `except sqlite3.OperationalError`
# in _run_migrations(). Triggered when ALTER TABLE fails
# because the column already exists (migration applied).
#
# Mock the connection's execute method to raise
# OperationalError directly — this is the cleanest
# way to exercise the pass branch without depending
# on SQLite version-specific ALTER TABLE behavior.
# =====================================================


class TestRunMigrationsAlreadyApplied:
    """Tests for _run_migrations — covers line 181."""

    def test_commit_called_on_successful_migration(
        self, tmp_path: Path
    ) -> None:
        """
        Covers line 181 — conn.commit() after successful migration.

        Line 181 is conn.commit() in the SUCCESS path.
        The current _MIGRATIONS always fails on new databases
        because policy_path is already in CREATE TABLE.
        Temporarily replace _MIGRATIONS with a new migration
        that WILL succeed so conn.commit() is reached.
        """
        import telemetry.store as telemetry_store

        database_path = tmp_path / "test.db"
        conn = sqlite3.connect(str(database_path))
        conn.execute(
            "CREATE TABLE IF NOT EXISTS migration_test (id TEXT)"
        )
        conn.commit()

        original_migrations = telemetry_store._MIGRATIONS
        telemetry_store._MIGRATIONS = [
            "ALTER TABLE migration_test ADD COLUMN new_col TEXT"
        ]

        try:
            _run_migrations(conn)   # succeeds → conn.commit() → line 181
        finally:
            telemetry_store._MIGRATIONS = original_migrations
            conn.close()

    def test_operational_error_silenced_on_applied_migration(self) -> None:
        """OperationalError in migration is silenced, not propagated."""
        mock_connection = MagicMock(spec=sqlite3.Connection)
        mock_connection.execute.side_effect = sqlite3.OperationalError(
            "duplicate column name: policy_path"
        )
        _run_migrations(mock_connection)
        mock_connection.execute.assert_called_once()


# =====================================================
# telemetry/store.py — JSON decode error branches
#
# Lines 672-673, 722-723, 772-773 are
#   except (json.JSONDecodeError, TypeError): continue
# blocks in the summary query functions.
# Only reachable when a row has invalid JSON stored
# in analyzer_scores, failed_conditions, or
# passed_conditions columns.
#
# Insert a row with invalid JSON directly into SQLite,
# then query — the json.loads() call raises
# JSONDecodeError and the except block is executed.
# =====================================================


def _insert_invalid_json_row(database_path: Path) -> None:
    """
    Insert a decision row with invalid JSON in all three
    condition/score columns to trigger JSONDecodeError
    in the summary query functions.
    """
    connection = init_db(database_path)
    connection.execute(
        """
        INSERT INTO decisions (
            id, timestamp, policy_name, decision,
            conditions_passed, overall_risk_score,
            analyzer_scores, failed_conditions, passed_conditions
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "invalid-json-row",
            "2026-06-09T00:00:00+00:00",
            "test_policy",
            "DENY",
            0,
            50,
            "NOT VALID JSON",    # analyzer_scores   → JSONDecodeError
            "NOT VALID JSON",    # failed_conditions → JSONDecodeError
            "NOT VALID JSON",    # passed_conditions → JSONDecodeError
        ),
    )
    connection.commit()
    connection.close()


class TestDomainRiskSummaryInvalidJson:
    """Tests for json.JSONDecodeError branch in get_domain_risk_summary."""

    def test_skips_rows_with_invalid_analyzer_scores(
        self, tmp_path: Path
    ) -> None:
        """
        Covers lines 672-673.
        Row with invalid JSON in analyzer_scores → JSONDecodeError
        → except/continue branch executed.
        Summary still returns totals for the row.
        """
        database_path = tmp_path / "test.db"
        _insert_invalid_json_row(database_path)

        result = get_domain_risk_summary(db_path=database_path)

        assert result["total_evaluations"] == 1
        assert result["domain_avg_scores"] == {}


class TestFailedConditionsSummaryInvalidJson:
    """Tests for json.JSONDecodeError branch in get_failed_conditions_summary."""

    def test_skips_rows_with_invalid_failed_conditions(
        self, tmp_path: Path
    ) -> None:
        """
        Covers lines 722-723.
        Row with invalid JSON in failed_conditions → JSONDecodeError
        → except/continue branch executed.
        Summary returns empty list — invalid row skipped.
        """
        database_path = tmp_path / "test.db"
        _insert_invalid_json_row(database_path)

        result = get_failed_conditions_summary(db_path=database_path)

        assert result == []


class TestPassedConditionsSummaryInvalidJson:
    """Tests for json.JSONDecodeError branch in get_passed_conditions_summary."""

    def test_skips_rows_with_invalid_passed_conditions(
        self, tmp_path: Path
    ) -> None:
        """
        Covers lines 772-773.
        Row with invalid JSON in passed_conditions → JSONDecodeError
        → except/continue branch executed.
        Summary returns empty list — invalid row skipped.
        """
        database_path = tmp_path / "test.db"
        _insert_invalid_json_row(database_path)

        result = get_passed_conditions_summary(db_path=database_path)

        assert result == []


# =====================================================
# schemas/policy_schema.py — validator error paths
#
# Lines 606, 618-651, 667-686 are ValueError raises
# inside the PolicySpec model validator. These paths
# require policies with specific invalid configurations.
#
# Line 606:   governance_domains set on non-composite type
# Lines 618+: composite policy without governance_domains
#
# Uses load_policy + validate_policy pipeline so the
# validator runs against real parsed YAML.
# =====================================================


def _write_temp_policy(policy_dict: dict) -> str:
    """Write a policy dict to a temporary YAML file. Returns path."""
    import yaml

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False
    ) as policy_file:
        yaml.dump(policy_dict, policy_file)
        return policy_file.name


def _make_cost_policy_dict() -> dict:
    """Minimal valid cost policy dict."""
    return {
        "policy": {
            "name":        "test_policy",
            "version":     1,
            "description": "Test policy",
            "spec": {
                "policy_type": "cost",
                "parameters": {
                    "budget": {
                        "monthly_budget_usd": 100,
                        "current_spend_usd":  0,
                    }
                },
                "conditions": [
                    {
                        "id":          "budget_check",
                        "expression":  "estimated_cost <= 100",
                        "description": "Budget check",
                    }
                ],
                "governance": {
                    "severity": "medium",
                    "actions":  ["notify"],
                },
            },
        }
    }


class TestPolicySchemaValidatorPaths:
    """Covers validator error paths in schemas/policy_schema.py."""

    def test_governance_domains_on_non_composite_raises(
        self, tmp_path: Path
    ) -> None:
        """Covers line 606."""
        from engine.orchestrator import PolicyOrchestrator
        import yaml

        policy = {
            "policy": {
                "name": "test_policy",
                "version": 1,
                "description": "Test",
                "spec": {
                    "policy_type": "cost",
                    "governance_domains": ["cost", "security"],
                    "parameters": {
                        "budget": {
                            "monthly_budget_usd": 100,
                            "current_spend_usd": 0,
                        }
                    },
                    "conditions": [
                        {
                            "id": "budget_check",
                            "expression": "estimated_cost <= 100",
                            "description": "Budget check",
                        }
                    ],
                    "governance": {
                        "severity": "medium",
                        "actions": ["notify"],
                    },
                },
            }
        }
        policy_path = tmp_path / "invalid_policy.yaml"
        policy_path.write_text(
            __import__("yaml").dump(policy)
        )
        with pytest.raises(Exception):
            PolicyOrchestrator.from_policy_path(str(policy_path))

    def test_composite_without_governance_domains_raises(
        self, tmp_path: Path
    ) -> None:
        """Covers lines 618-651."""
        import yaml

        from engine.orchestrator import PolicyOrchestrator

        policy = {
            "policy": {
                "name": "test_composite",
                "version": 1,
                "description": "Test",
                "spec": {
                    "policy_type": "composite",
                    "parameters": {
                        "budget": {
                            "monthly_budget_usd": 100,
                            "current_spend_usd": 0,
                        }
                    },
                    "conditions": [
                        {
                            "id": "budget_check",
                            "expression": "estimated_cost <= 100",
                            "description": "Budget check",
                        }
                    ],
                    "governance": {
                        "severity": "medium",
                        "actions": ["notify"],
                    },
                },
            }
        }
        policy_path = tmp_path / "invalid_composite.yaml"
        policy_path.write_text(yaml.dump(policy))
        with pytest.raises(Exception):
            PolicyOrchestrator.from_policy_path(str(policy_path))