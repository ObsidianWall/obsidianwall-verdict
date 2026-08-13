# telemetry/governance_objectives.py
#
# Purpose:
# Compass foundation — folds every governance record sharing
# a governance objective into aggregate Upheld/Violated/
# Pending counts plus a basic trend, answering Compass's
# headline capability: "Objective X has been upheld 96.5% of
# the time this period, improving 2.1% versus prior period."
# Depends on governance_records.py for get_records_by_objective()
# — the one intentional cross-module dependency in this split,
# since objective-folding is fundamentally a query ON TOP OF
# records, not a peer concern to them.

from __future__ import annotations

from pathlib import Path
from typing import Any

from telemetry.governance_records import get_records_by_objective

_OBJECTIVE_UPHELD_DECISIONS = {"ALLOW", "ALLOW_WITH_NOTIFICATION"}
_OBJECTIVE_VIOLATED_DECISIONS = {"DENY", "DENY_WITH_OVERRIDE"}
_OBJECTIVE_PENDING_DECISIONS = {"ALLOW_WITH_APPROVAL_REQUIRED"}


def _classify_for_objective_summary(decision: str) -> str:
    """Classify a decision string into upheld/violated/pending/unknown."""
    if decision in _OBJECTIVE_UPHELD_DECISIONS:
        return "upheld"
    if decision in _OBJECTIVE_VIOLATED_DECISIONS:
        return "violated"
    if decision in _OBJECTIVE_PENDING_DECISIONS:
        return "pending"
    return "unknown"


def get_objective_summary(
    governance_objective_statement: str,
    db_path: Path | None = None,
) -> dict[str, Any]:
    """
    Fold every governance record sharing a governance objective
    into aggregate Upheld/Violated/Pending counts, plus a basic
    trend comparing the most recent half of records against the
    earlier half.

    This is the query behind Compass's headline capability:
    "Objective X has been upheld 96.5% of the time this period,
    improving 2.1% versus the prior period."

    Trend classification:
      "improving"          upheld_rate rose more than 5 points
      "declining"           upheld_rate fell more than 5 points
      "stable"                change within +/-5 points
      "insufficient_data"      fewer than 4 records total

    Returns an all-zero summary with trend "insufficient_data"
    if no records exist for this objective. Never raises.

    Args:
        governance_objective_statement: the exact statement
            text as declared in policy metadata
        db_path: optional path override (for testing)
    """
    records = get_records_by_objective(governance_objective_statement, db_path=db_path)

    if not records:
        return {
            "statement": governance_objective_statement,
            "total_records": 0,
            "upheld_count": 0,
            "violated_count": 0,
            "pending_count": 0,
            "upheld_rate": 0.0,
            "trend": "insufficient_data",
        }

    total = len(records)
    upheld_count = sum(
        1
        for r in records
        if _classify_for_objective_summary(r.get("decision", "")) == "upheld"
    )
    violated_count = sum(
        1
        for r in records
        if _classify_for_objective_summary(r.get("decision", "")) == "violated"
    )
    pending_count = sum(
        1
        for r in records
        if _classify_for_objective_summary(r.get("decision", "")) == "pending"
    )

    upheld_rate = round(upheld_count / total * 100, 1) if total else 0.0

    # Trend — records are newest-first (per get_records_by_objective).
    # Split into recent half vs. older half and compare upheld rates.
    trend = "insufficient_data"
    if total >= 4:
        half = total // 2
        recent = records[:half]
        older = records[half:]

        recent_upheld = sum(
            1
            for r in recent
            if _classify_for_objective_summary(r.get("decision", "")) == "upheld"
        )
        older_upheld = sum(
            1
            for r in older
            if _classify_for_objective_summary(r.get("decision", "")) == "upheld"
        )

        recent_rate = recent_upheld / len(recent) * 100 if recent else 0.0
        older_rate = older_upheld / len(older) * 100 if older else 0.0

        delta = recent_rate - older_rate
        if delta > 5.0:
            trend = "improving"
        elif delta < -5.0:
            trend = "declining"
        else:
            trend = "stable"

    return {
        "statement": governance_objective_statement,
        "total_records": total,
        "upheld_count": upheld_count,
        "violated_count": violated_count,
        "pending_count": pending_count,
        "upheld_rate": upheld_rate,
        "trend": trend,
    }
