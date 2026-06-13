
# tests/unit/test_telemetry_targeted.py
#
# Purpose:
# Targeted tests for specific uncovered lines in
# telemetry/store.py (181, 672-673, 722-723, 772-773)
# and telemetry/config.py (79-80).

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from telemetry.store import (
    get_decision_by_id,
    get_domain_risk_summary,
    get_failed_conditions_summary,
    get_passed_conditions_summary,
    init_db,
    record_decision,
)
from telemetry.config import is_telemetry_enabled


class TestRecordDecisionEmptyIdPath:

    def test_returns_false_when_decision_id_empty(
        self, tmp_path: Path
    ) -> None:
        """Covers line 181 — empty decision_id returns False."""
        with patch("telemetry.store.is_telemetry_enabled", return_value=True):
            result = record_decision(
                result={
                    "decision_id":    "",
                    "policy":         "test_policy",
                    "decision":       "DENY",
                    "conditions_passed": False,
                    "override_required": False,
                    "override_possible": False,
                    "requires_approval": False,
                    "governance_severity": "medium",
                    "effective_severity":  "high",
                    "trace": [],
                    "risk_summary": {
                        "overall_risk_score": 0,
                        "analyzer_scores": {},
                        "total_findings": 0,
                    },
                    "pricing_mode": "table",
                },
                db_path=tmp_path / "test.db",
            )
        assert result is False


class TestGetDecisionByIdEmptyDb:

    def test_returns_none_when_db_is_empty(self, tmp_path: Path) -> None:
        """Covers lines 672-673 — no row found path."""
        database_path = tmp_path / "test.db"
        init_db(database_path)
        result = get_decision_by_id("nonexistent-id", db_path=database_path)
        assert result is None


class TestGetDomainRiskSummaryEmptyDb:

    def test_returns_empty_dict_when_db_is_empty(
        self, tmp_path: Path
    ) -> None:
        """Covers lines 722-723 — empty rows returns {}."""
        database_path = tmp_path / "test.db"
        init_db(database_path)
        result = get_domain_risk_summary(db_path=database_path)
        assert result == {}


class TestGetFailedConditionsSummaryEmptyDb:

    def test_returns_empty_list_when_db_is_empty(
        self, tmp_path: Path
    ) -> None:
        """Covers lines 772-773 — empty rows returns []."""
        database_path = tmp_path / "test.db"
        init_db(database_path)
        result = get_failed_conditions_summary(db_path=database_path)
        assert result == []


class TestGetPassedConditionsSummaryEmptyDb:

    def test_returns_empty_list_when_db_is_empty(
        self, tmp_path: Path
    ) -> None:
        """Additional empty DB path coverage."""
        database_path = tmp_path / "test.db"
        init_db(database_path)
        result = get_passed_conditions_summary(db_path=database_path)
        assert result == []


class TestIsTelemetryEnabledLineCoverage:

    def test_returns_true_when_only_legacy_key_enabled(self) -> None:
        """Covers line 79 — legacy key path with True value."""
        env = {k: v for k, v in os.environ.items()
               if k not in ("OW_HISTORY_ENABLED", "OW_TELEMETRY_ENABLED")}
        env["OW_TELEMETRY_ENABLED"] = "true"
        with patch.dict(os.environ, env, clear=True):
            assert is_telemetry_enabled() is True

    def test_returns_true_when_no_keys_set(self) -> None:
        """Covers line 80 — default True return."""
        env = {k: v for k, v in os.environ.items()
               if k not in ("OW_HISTORY_ENABLED", "OW_TELEMETRY_ENABLED")}
        with patch.dict(os.environ, env, clear=True):
            assert is_telemetry_enabled() is True