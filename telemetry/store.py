# telemetry/store.py
#
# Purpose:
# Local SQLite decision history store.
#
# Responsibilities:
# - Initialize database schema on first use
# - Write governance decisions to local store
# - Write override and approval events
# - Query decision history for audit command
# - Query policy effectiveness metrics
#
# Privacy:
# - No plan contents stored
# - No cost amounts stored
# - No resource names stored
# - No organization identifiers stored
# - Plan is represented by SHA-256 hash only
#
# Schema:
#   decisions      → one row per evaluation
#   overrides      → one row per override event
#   approvals      → one row per approval event
#
# Location:
#   ~/.obsidianwall/decisions.db

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from telemetry.config import get_db_path, is_telemetry_enabled


# =====================================================
# SCHEMA
# =====================================================

_SCHEMA = """
-- Governance decision history.
-- One row per verdict evaluate invocation.
CREATE TABLE IF NOT EXISTS decisions (
    id                  TEXT PRIMARY KEY,
    timestamp           TEXT NOT NULL,
    policy_name         TEXT NOT NULL,
    policy_type         TEXT,
    decision            TEXT NOT NULL,
    conditions_passed   INTEGER NOT NULL DEFAULT 0,
    overall_risk_score  INTEGER NOT NULL DEFAULT 0,
    effective_severity  TEXT,
    governance_severity TEXT,
    override_required   INTEGER NOT NULL DEFAULT 0,
    override_possible   INTEGER NOT NULL DEFAULT 0,
    requires_approval   INTEGER NOT NULL DEFAULT 0,
    user_role           TEXT,
    plan_hash           TEXT,
    total_findings      INTEGER NOT NULL DEFAULT 0,
    failed_conditions   TEXT,
    passed_conditions   TEXT,
    analyzer_scores     TEXT,
    pricing_mode        TEXT,
    region              TEXT
);

-- Override events.
-- One row per override decision on a blocked deployment.
CREATE TABLE IF NOT EXISTS overrides (
    id              TEXT PRIMARY KEY,
    decision_id     TEXT NOT NULL,
    override_role   TEXT,
    timestamp       TEXT NOT NULL,
    approved        INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (decision_id) REFERENCES decisions(id)
);

-- Approval events.
-- One row per approval workflow resolution.
CREATE TABLE IF NOT EXISTS approvals (
    id              TEXT PRIMARY KEY,
    decision_id     TEXT NOT NULL,
    approver_role   TEXT,
    timestamp       TEXT NOT NULL,
    approved        INTEGER NOT NULL DEFAULT 0,
    notes           TEXT,
    FOREIGN KEY (decision_id) REFERENCES decisions(id)
);

-- Policy effectiveness summary.
-- Updated on each evaluation — running totals per policy.
CREATE TABLE IF NOT EXISTS policy_effectiveness (
    policy_name         TEXT PRIMARY KEY,
    policy_type         TEXT,
    total_evaluations   INTEGER NOT NULL DEFAULT 0,
    total_allowed       INTEGER NOT NULL DEFAULT 0,
    total_denied        INTEGER NOT NULL DEFAULT 0,
    total_overrides     INTEGER NOT NULL DEFAULT 0,
    total_approvals     INTEGER NOT NULL DEFAULT 0,
    last_evaluation     TEXT,
    last_updated        TEXT NOT NULL
);
"""


# =====================================================
# DATABASE INITIALIZATION
# =====================================================


def init_db(db_path: Path | None = None) -> sqlite3.Connection:
    """
    Initialize the SQLite database and create schema
    if it does not exist.

    Args:
        db_path: optional path override (for testing)

    Returns:
        open sqlite3.Connection
    """
    path = db_path or get_db_path()
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(_SCHEMA)
    conn.commit()
    return conn


# =====================================================
# WRITE
# =====================================================


def record_decision(
    result:    dict[str, Any],
    plan_path: str | None = None,
) -> bool:
    """
    Write a governance decision to the local store.

    Only writes if telemetry is enabled.
    Never writes plan contents — only a SHA-256
    hash of the plan path is stored.

    Args:
        result:    complete verdict evaluate result dict
        plan_path: path to the Terraform plan file

    Returns:
        True if written, False if telemetry disabled
        or write failed
    """
    if not is_telemetry_enabled():
        return False

    try:
        decision_id = result.get("decision_id", "")
        if not decision_id:
            return False

        timestamp = result.get(
            "timestamp",
            datetime.now(timezone.utc).isoformat(),
        )

        # Hash the plan path — never store plan contents
        plan_hash: str | None = None
        if plan_path:
            plan_hash = hashlib.sha256(
                plan_path.encode("utf-8")
            ).hexdigest()[:16]

        # Extract risk summary
        risk_summary: dict[str, Any] = result.get(
            "risk_summary", {}
        )

        # Extract condition traces
        trace: list[dict[str, Any]] = result.get("trace", [])
        failed  = [t["condition_id"] for t in trace if not t.get("result", True)]
        passed  = [t["condition_id"] for t in trace if t.get("result", True)]

        # Analyzer scores — store as JSON string
        analyzer_scores = json.dumps(
            risk_summary.get("analyzer_scores", {})
        )

        conn = init_db()

        conn.execute(
            """
            INSERT OR REPLACE INTO decisions (
                id, timestamp, policy_name, policy_type,
                decision, conditions_passed,
                overall_risk_score, effective_severity,
                governance_severity, override_required,
                override_possible, requires_approval,
                user_role, plan_hash, total_findings,
                failed_conditions, passed_conditions,
                analyzer_scores, pricing_mode, region
            ) VALUES (
                ?, ?, ?, ?,
                ?, ?,
                ?, ?,
                ?, ?,
                ?, ?,
                ?, ?, ?,
                ?, ?,
                ?, ?, ?
            )
            """,
            (
                decision_id,
                timestamp,
                result.get("policy", ""),
                None,                          # policy_type added in v0.3.5
                result.get("decision", ""),
                1 if result.get("conditions_passed") else 0,
                risk_summary.get("overall_risk_score", 0),
                risk_summary.get("effective_severity", ""),
                result.get("governance_severity", ""),
                1 if result.get("override_required") else 0,
                1 if result.get("override_possible") else 0,
                1 if result.get("requires_approval") else 0,
                None,                          # user_role not in result yet
                plan_hash,
                risk_summary.get("total_findings", 0),
                json.dumps(failed),
                json.dumps(passed),
                analyzer_scores,
                result.get("pricing_mode", "table"),
                None,                          # region not in result yet
            ),
        )

        _update_effectiveness(
            conn,
            policy_name=result.get("policy", ""),
            decision=result.get("decision", ""),
            timestamp=timestamp,
        )

        conn.commit()
        conn.close()
        return True

    except Exception:
        # Telemetry must never crash the CLI
        return False


def record_override(
    decision_id:   str,
    override_role: str | None,
    approved:      bool,
) -> bool:
    """
    Record an override event against a decision.

    Args:
        decision_id:   the decision being overridden
        override_role: role exercising override authority
        approved:      whether the override was approved

    Returns:
        True if written, False if telemetry disabled
    """
    if not is_telemetry_enabled():
        return False

    try:
        import uuid
        conn = init_db()

        conn.execute(
            """
            INSERT INTO overrides (
                id, decision_id, override_role,
                timestamp, approved
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()),
                decision_id,
                override_role,
                datetime.now(timezone.utc).isoformat(),
                1 if approved else 0,
            ),
        )

        conn.commit()
        conn.close()

        return True

    except Exception:
        return False


def record_approval(
    decision_id:   str,
    approver_role: str | None,
    approved:      bool,
    notes:         str | None = None,
) -> bool:
    """
    Record an approval event against a decision.

    Args:
        decision_id:   the decision requiring approval
        approver_role: role approving or rejecting
        approved:      whether approval was granted
        notes:         optional approval notes

    Returns:
        True if written, False if telemetry disabled
    """
    if not is_telemetry_enabled():
        return False

    try:
        import uuid
        conn = init_db()

        conn.execute(
            """
            INSERT INTO approvals (
                id, decision_id, approver_role,
                timestamp, approved, notes
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()),
                decision_id,
                approver_role,
                datetime.now(timezone.utc).isoformat(),
                1 if approved else 0,
                notes,
            ),
        )

        conn.commit()
        conn.close()
        return True

    except Exception:
        return False


# =====================================================
# EFFECTIVENESS TRACKING
# =====================================================


def _update_effectiveness(
    conn:        sqlite3.Connection,
    policy_name: str,
    decision:    str,
    timestamp:   str,
) -> None:
    """
    Update running totals in policy_effectiveness table.
    Called inside record_decision — same connection/transaction.
    """
    now = datetime.now(timezone.utc).isoformat()

    is_denied = decision in ("DENY", "DENY_WITH_OVERRIDE")

    conn.execute(
        """
        INSERT INTO policy_effectiveness (
            policy_name, total_evaluations,
            total_allowed, total_denied,
            last_evaluation, last_updated
        ) VALUES (?, 1, ?, ?, ?, ?)
        ON CONFLICT(policy_name) DO UPDATE SET
            total_evaluations = total_evaluations + 1,
            total_allowed     = total_allowed + excluded.total_allowed,
            total_denied      = total_denied  + excluded.total_denied,
            last_evaluation   = excluded.last_evaluation,
            last_updated      = excluded.last_updated
        """,
        (
            policy_name,
            0 if is_denied else 1,
            1 if is_denied else 0,
            timestamp,
            now,
        ),
    )


# =====================================================
# READ — for verdict audit and verdict history
# =====================================================


def get_recent_decisions(
    limit: int = 50,
    db_path: Path | None = None,
) -> list[dict[str, Any]]:
    """
    Return the most recent governance decisions.

    Args:
        limit:   maximum rows to return
        db_path: optional path override (for testing)

    Returns:
        list of decision dicts ordered by timestamp desc
    """
    try:
        conn = init_db(db_path)
        cursor = conn.execute(
            """
            SELECT * FROM decisions
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (limit,),
        )
        rows = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return rows
    except Exception:
        return []


def get_policy_effectiveness(
    policy_name: str | None = None,
    db_path: Path | None = None,
) -> list[dict[str, Any]]:
    """
    Return policy effectiveness summaries.

    Args:
        policy_name: filter to specific policy (optional)
        db_path:     optional path override (for testing)

    Returns:
        list of effectiveness dicts
    """
    try:
        conn = init_db(db_path)

        if policy_name:
            cursor = conn.execute(
                """
                SELECT
                    pe.*,
                    COUNT(o.id) as override_count,
                    COUNT(a.id) as approval_count
                FROM policy_effectiveness pe
                LEFT JOIN decisions d ON d.policy_name = pe.policy_name
                LEFT JOIN overrides o ON o.decision_id = d.id
                LEFT JOIN approvals a ON a.decision_id = d.id
                WHERE pe.policy_name = ?
                GROUP BY pe.policy_name
                """,
                (policy_name,),
            )
        else:
            cursor = conn.execute(
                """
                SELECT
                    pe.*,
                    COUNT(o.id) as override_count,
                    COUNT(a.id) as approval_count
                FROM policy_effectiveness pe
                LEFT JOIN decisions d ON d.policy_name = pe.policy_name
                LEFT JOIN overrides o ON o.decision_id = d.id
                LEFT JOIN approvals a ON a.decision_id = d.id
                GROUP BY pe.policy_name
                ORDER BY pe.total_evaluations DESC
                """
            )

        rows = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return rows
    except Exception:
        return []


def get_decision_by_id(
    decision_id: str,
    db_path: Path | None = None,
) -> dict[str, Any] | None:
    """
    Return a single decision by ID.

    Args:
        decision_id: the UUID of the decision
        db_path:     optional path override (for testing)

    Returns:
        decision dict or None if not found
    """
    try:
        conn = init_db(db_path)
        cursor = conn.execute(
            "SELECT * FROM decisions WHERE id = ?",
            (decision_id,),
        )
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None
    except Exception:
        return None


def get_domain_risk_summary(
    db_path: Path | None = None,
) -> dict[str, Any]:
    """
    Return aggregated risk scores by governance domain.
    Used by verdict audit command.

    Args:
        db_path: optional path override (for testing)

    Returns:
        dict of domain → aggregated risk data
    """
    try:
        conn = init_db(db_path)
        cursor = conn.execute(
            """
            SELECT
                policy_name,
                decision,
                overall_risk_score,
                effective_severity,
                analyzer_scores,
                conditions_passed,
                failed_conditions,
                timestamp
            FROM decisions
            ORDER BY timestamp DESC
            LIMIT 500
            """
        )
        rows = [dict(row) for row in cursor.fetchall()]
        conn.close()

        if not rows:
            return {}

        # Aggregate analyzer scores across recent decisions
        domain_scores: dict[str, list[int]] = {}
        deny_counts:   dict[str, int] = {}
        total_count = len(rows)
        deny_total  = sum(1 for r in rows if "DENY" in r["decision"])

        for row in rows:
            try:
                scores: dict[str, int] = json.loads(
                    row.get("analyzer_scores") or "{}"
                )
                for domain, score in scores.items():
                    domain_scores.setdefault(domain, []).append(score)
            except (json.JSONDecodeError, TypeError):
                continue

        summary: dict[str, Any] = {
            "total_evaluations": total_count,
            "total_denied":      deny_total,
            "deny_rate":         round(deny_total / total_count * 100, 1)
                                 if total_count else 0,
            "domain_avg_scores": {
                domain: round(sum(scores) / len(scores), 1)
                for domain, scores in domain_scores.items()
                if scores
            },
        }

        return summary

    except Exception:
        return {}
