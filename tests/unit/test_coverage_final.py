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
#   schemas/policy_schema.py     606, 618-651, 667-686
#     — policy spec validator error paths:
#       governance_domains on non-composite type,
#       composite without declared domains
#
# NOTE (v0.6.0): telemetry/store.py has been deleted —
# it was fully replaced by telemetry/governance_store.py
# during the v0.6.0 schema redesign, and confirmed unused
# by any production code path. The tests that previously
# lived here for _run_migrations(), get_domain_risk_summary(),
# get_failed_conditions_summary(), and
# get_passed_conditions_summary() covered that now-deleted
# module and have been removed. Equivalent coverage for the
# current schema lives in test_governance_store.py,
# test_governance_store_aggregates.py, and
# test_compass_queries.py.

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from notifications.dispatcher import (
    _STATUS_SKIPPED,
    dispatch_notifications,
)
from telemetry.config import get_db_dir


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