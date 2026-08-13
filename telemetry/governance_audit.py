# telemetry/governance_audit.py
#
# Purpose:
# Aggregate analytics powering verdict audit specifically —
# policy effectiveness, domain risk summaries, and condition
# failure/pass frequency. Isolated from generic record storage
# so a future audit-semantics bug (like the 500-vs-685 count
# discrepancy and the >100% override-rate inflation both fixed
# in this same pass) is immediately known to live in exactly
# this one file, not somewhere inside a 2,000-line module
# covering ten unrelated responsibilities.

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from telemetry.governance_db import init_governance_db


def get_policy_effectiveness(
    policy_name: str | None = None,
    db_path: Path | None = None,
) -> list[dict[str, Any]]:
    """
    Return per-policy effectiveness summaries: evaluation
    counts, denial counts, override-eligible counts, and
    CONFIRMED override/approval counts.

    override_count and approval_count count DISTINCT DECISIONS
    that reached an approved outcome — not every override/
    approval-related history event. A single decision's real
    request+approve cycle produces 2 history rows tagged
    'override' (one 'requested', one 'approved'); counting
    both as separate overrides let override_count exceed
    total_denied, producing an impossible ">100%" override
    rate in verdict audit.

    override_eligible_count is a further fix: hard DENY
    decisions have no override path at all, so including them
    in an override-rate denominator dilutes the metric with
    decisions that were never eligible for an exception in the
    first place. override_eligible_count scopes specifically
    to DENY_WITH_OVERRIDE, so callers can compute:

        override_rate = override_count / override_eligible_count

    which answers "when an exception was possible, how often
    was one actually granted" — bounded 0-100% by construction.

    If policy_name is provided, returns a single policy
    summary. Otherwise returns all policies sorted by
    evaluation volume.
    """
    conn = None
    try:
        conn = init_governance_db(db_path)

        # NOTE: total_denied uses COUNT(DISTINCT CASE WHEN ...
        # THEN r.record_id END), NOT SUM(CASE WHEN ... THEN 1
        # ELSE 0 END). The LEFT JOIN to governance_history
        # produces one row per (record, history entry) pair —
        # any record with more than one history entry (e.g. a
        # record that has had verdict sentinel scan run against
        # it, adding an outcome/drift entry beyond its original
        # CREATED entry) would have its decision counted once
        # PER HISTORY ROW under SUM(CASE...), not once per
        # record. This previously allowed total_denied to
        # exceed total_evaluations. COUNT(DISTINCT ... record_id)
        # dedupes correctly regardless of join multiplication,
        # the same way total_evaluations already did.
        base_query = """
            SELECT
                r.policy_name,
                COUNT(DISTINCT r.record_id) as total_evaluations,
                COUNT(DISTINCT CASE WHEN r.decision IN ('DENY', 'DENY_WITH_OVERRIDE')
                    THEN r.record_id END) as total_denied,
                COUNT(DISTINCT CASE WHEN r.decision = 'DENY_WITH_OVERRIDE'
                    THEN r.record_id END) as override_eligible_count,
                COUNT(DISTINCT CASE WHEN h.history_category = 'override'
                    AND h.history_action = 'approved'
                    THEN r.record_id END) as override_count,
                COUNT(DISTINCT CASE WHEN h.history_category = 'approval'
                    AND h.history_action = 'approved'
                    THEN r.record_id END) as approval_count,
                MAX(r.created_at) as last_evaluation
            FROM governance_records r
            LEFT JOIN governance_history h ON h.record_id = r.record_id
        """

        if policy_name:
            query = base_query + " WHERE r.policy_name = ? GROUP BY r.policy_name"
            cursor = conn.execute(query, (policy_name,))
        else:
            query = (
                base_query + " GROUP BY r.policy_name ORDER BY total_evaluations DESC"
            )
            cursor = conn.execute(query)

        rows = [dict(row) for row in cursor.fetchall()]
        return rows

    except Exception:
        return []

    finally:
        if conn is not None:
            conn.close()


def get_domain_risk_summary(
    db_path: Path | None = None,
) -> dict[str, Any]:
    """
    Return aggregated risk scores by governance domain
    (analyzer), plus true totals across ALL records.

    Powers the risk summary section of verdict audit.
    analyzer_scores is stored as JSON per record and
    unpacked here for domain-level aggregation.

    total_evaluations/total_denied/deny_rate are computed
    from the FULL table, matching the unbounded population
    used by get_failed_conditions_summary() and
    get_policy_effectiveness() — these numbers appear
    side-by-side in verdict audit's output, and previously
    diverged because two lines later silently overwrote these
    correct full-table totals with the LIMIT 500 sample's
    numbers. That made "Total evaluations" silently mean "the
    500 most recent" while every other section counted
    everything, so e.g. a single policy's eval count could
    exceed the displayed grand total. Uses COUNT(DISTINCT
    record_id) rather than COUNT(*) purely for consistency
    with get_policy_effectiveness()'s pattern — record_id is
    the primary key, so the two are always numerically
    identical here; this is a style match, not a correctness
    fix. decision IN (...) replaces an earlier LIKE '%DENY%',
    which happened to work only because both current decision
    values contain that substring — fragile against any
    future decision value that coincidentally contains it
    without meaning it.

    domain_avg_scores itself is still sampled to the 500
    most recent records — averaging over the full table on
    every invocation isn't worth the cost, and a recency-
    weighted average is arguably the more useful number for
    that section anyway. Callers rendering this should compare
    total_evaluations against 500 to disclose when
    domain_avg_scores reflects a sample rather than the full
    population — see cli/commands/audit.py's dynamic header.
    """
    conn = None
    try:
        conn = init_governance_db(db_path)

        totals_row = conn.execute(
            """
            SELECT
                COUNT(DISTINCT record_id) as total_count,
                COUNT(
                    DISTINCT CASE
                        WHEN decision IN ('DENY', 'DENY_WITH_OVERRIDE')
                        THEN record_id
                    END
                ) as deny_total
            FROM governance_records
            """
        ).fetchone()
        total_count = totals_row["total_count"]
        deny_total = totals_row["deny_total"]

        if total_count == 0:
            return {}

        cursor = conn.execute(
            """
            SELECT decision, analyzer_scores
            FROM governance_records
            ORDER BY created_at DESC
            LIMIT 500
            """
        )
        rows = [dict(row) for row in cursor.fetchall()]

        domain_scores: dict[str, list[int]] = {}
        for row in rows:
            try:
                scores: dict[str, int] = json.loads(row.get("analyzer_scores") or "{}")
                for domain, score in scores.items():
                    domain_scores.setdefault(domain, []).append(score)
            except (json.JSONDecodeError, TypeError):
                continue

        return {
            "total_evaluations": total_count,
            "total_denied": deny_total,
            "deny_rate": (
                round(deny_total / total_count * 100, 1) if total_count else 0
            ),
            "domain_avg_scores": {
                domain: round(sum(s) / len(s), 1)
                for domain, s in domain_scores.items()
                if s
            },
        }

    except Exception:
        return {}

    finally:
        if conn is not None:
            conn.close()


def get_failed_conditions_summary(
    db_path: Path | None = None,
) -> list[dict[str, Any]]:
    """
    Aggregate failed condition counts across all records.
    Powers the "Why denied?" section of verdict audit.

    Rate is scoped PER CONDITION, not across total evaluations:
        rate = (times this condition failed) /
               (times this condition was actually evaluated —
                i.e. appeared in EITHER failed_conditions OR
                passed_conditions on some record)

    This matters once multiple policies with different
    conditions exist. A condition that only exists inside one
    narrow policy would previously show an artificially low
    rate (diluted by every OTHER policy's unrelated
    evaluations in the denominator) even if it failed every
    single time it was actually checked. Scoping the
    denominator to "times this condition was applicable"
    fixes that.
    """
    conn = None
    try:
        conn = init_governance_db(db_path)
        cursor = conn.execute(
            """
            SELECT failed_conditions, passed_conditions
            FROM governance_records
            WHERE failed_conditions IS NOT NULL
               OR passed_conditions IS NOT NULL
            """
        )
        rows = [dict(row) for row in cursor.fetchall()]

        if not rows:
            return []

        failed_counts: dict[str, int] = {}
        evaluated_counts: dict[str, int] = {}

        for row in rows:
            try:
                failed: list[str] = json.loads(row.get("failed_conditions") or "[]")
            except (json.JSONDecodeError, TypeError):
                failed = []
            try:
                passed: list[str] = json.loads(row.get("passed_conditions") or "[]")
            except (json.JSONDecodeError, TypeError):
                passed = []

            for cid in failed:
                if cid:
                    failed_counts[cid] = failed_counts.get(cid, 0) + 1
                    evaluated_counts[cid] = evaluated_counts.get(cid, 0) + 1
            for cid in passed:
                if cid:
                    evaluated_counts[cid] = evaluated_counts.get(cid, 0) + 1

        return sorted(
            [
                {
                    "condition_id": cid,
                    "count": count,
                    "rate": round(count / evaluated_counts[cid] * 100, 1)
                    if evaluated_counts.get(cid)
                    else 0.0,
                }
                for cid, count in failed_counts.items()
            ],
            key=lambda x: x["count"],  # type: ignore[return-value]
            reverse=True,
        )

    except Exception:
        return []

    finally:
        if conn is not None:
            conn.close()


def get_passed_conditions_summary(
    db_path: Path | None = None,
) -> list[dict[str, Any]]:
    """
    Aggregate passed condition counts across all records.
    Powers the "Why allowed?" section of verdict audit.

    Rate is scoped PER CONDITION, not across total evaluations
    — see get_failed_conditions_summary()'s docstring for the
    full reasoning. Same fix, mirrored:
        rate = (times this condition passed) /
               (times this condition was actually evaluated)
    """
    conn = None
    try:
        conn = init_governance_db(db_path)
        cursor = conn.execute(
            """
            SELECT failed_conditions, passed_conditions
            FROM governance_records
            WHERE failed_conditions IS NOT NULL
               OR passed_conditions IS NOT NULL
            """
        )
        rows = [dict(row) for row in cursor.fetchall()]

        if not rows:
            return []

        passed_counts: dict[str, int] = {}
        evaluated_counts: dict[str, int] = {}

        for row in rows:
            try:
                failed: list[str] = json.loads(row.get("failed_conditions") or "[]")
            except (json.JSONDecodeError, TypeError):
                failed = []
            try:
                passed: list[str] = json.loads(row.get("passed_conditions") or "[]")
            except (json.JSONDecodeError, TypeError):
                passed = []

            for cid in passed:
                if cid:
                    passed_counts[cid] = passed_counts.get(cid, 0) + 1
                    evaluated_counts[cid] = evaluated_counts.get(cid, 0) + 1
            for cid in failed:
                if cid:
                    evaluated_counts[cid] = evaluated_counts.get(cid, 0) + 1

        return sorted(
            [
                {
                    "condition_id": cid,
                    "count": count,
                    "rate": round(count / evaluated_counts[cid] * 100, 1)
                    if evaluated_counts.get(cid)
                    else 0.0,
                }
                for cid, count in passed_counts.items()
            ],
            key=lambda x: x["count"],  # type: ignore[return-value]
            reverse=True,
        )

    except Exception:
        return []

    finally:
        if conn is not None:
            conn.close()
