# telemetry/governance_outcomes.py
#
# Purpose:
# Sentinel/Compass-facing outcome and drift analytics — pure
# read-only aggregation over history entries verdict sentinel
# scan has already recorded. Neither function here writes
# anything. Distinct from governance_audit.py's Verdict-facing
# analytics, even though both are "analytics over the same
# underlying tables" — outcomes.py answers "what happened after
# deployment," audit.py answers "what did the policy decide."

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from telemetry.governance_db import init_governance_db


def get_outcome_summary(
    db_path: Path | None = None,
) -> list[dict[str, Any]]:
    """
    Return outcome/drift event counts from governance_history,
    grouped by the outcome_type stored in each entry's
    history_data. Powers the "Deployment Outcomes" section
    of verdict audit.

    Outcomes are populated by Sentinel after post-deployment
    verification — this returns meaningful data only once
    verdict sentinel scan has run at least once.
    """
    conn = None
    try:
        conn = init_governance_db(db_path)
        cursor = conn.execute(
            """
            SELECT history_data FROM governance_history
            WHERE history_category IN ('outcome', 'drift')
            """
        )
        rows = [dict(row) for row in cursor.fetchall()]

        if not rows:
            return []

        outcome_counts: dict[str, int] = {}

        for row in rows:
            try:
                data = json.loads(row["history_data"])
                outcome_type = data.get("outcome_type", "unknown")
                outcome_counts[outcome_type] = outcome_counts.get(outcome_type, 0) + 1
            except (json.JSONDecodeError, TypeError, KeyError):
                continue

        return sorted(
            [{"outcome_type": k, "count": v} for k, v in outcome_counts.items()],
            key=lambda x: x["count"],  # type: ignore[return-value]
            reverse=True,
        )

    except Exception:
        return []

    finally:
        if conn is not None:
            conn.close()


# =====================================================
# COMPASS QUERY FOUNDATION
#
# Read-only correlation and folding queries that Compass
# reads directly. Neither function writes anything — they
# are pure aggregation over data Verdict and Sentinel have
# already recorded via create_governance_record() and
# add_history_entry().
# =====================================================


def get_outcome_correlation(
    db_path: Path | None = None,
) -> list[dict[str, Any]]:
    """
    Correlate governance decisions with their observed outcomes.

    Powers Compass's Governance Intelligence layer. Enables
    queries like: "92% of cost denials that were overridden
    resulted in budget_overrun" — joining each record's
    original decision against every outcome/drift event
    subsequently recorded against it by verdict sentinel scan.

    Returns rows sorted by frequency, highest first. Empty
    list if no outcome/drift history exists yet, or on error.
    Never raises.
    """
    conn = None
    try:
        conn = init_governance_db(db_path)
        cursor = conn.execute(
            """
            SELECT r.policy_name, r.decision, h.history_data
            FROM governance_records r
            JOIN governance_history h ON h.record_id = r.record_id
            WHERE h.history_category IN ('outcome', 'drift')
            """
        )
        rows = [dict(row) for row in cursor.fetchall()]

        correlation_counts: dict[tuple[str, str, str], int] = {}

        for row in rows:
            try:
                data = json.loads(row["history_data"])
                outcome_type = data.get("outcome_type", "unknown")
            except (json.JSONDecodeError, TypeError, KeyError):
                continue

            key = (row["policy_name"], row["decision"], outcome_type)
            correlation_counts[key] = correlation_counts.get(key, 0) + 1

        results = [
            {
                "policy_name": policy_name,
                "decision": decision,
                "outcome_type": outcome_type,
                "frequency": count,
            }
            for (
                policy_name,
                decision,
                outcome_type,
            ), count in correlation_counts.items()
        ]

        return sorted(
            results,
            key=lambda x: x["frequency"],  # type: ignore[return-value]
            reverse=True,
        )

    except Exception:
        return []
    finally:
        if conn is not None:
            conn.close()
