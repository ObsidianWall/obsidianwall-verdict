# telemetry/store.py
#
# Purpose:
# Local SQLite decision history store.
#
# Responsibilities:
# - Initialize database schema on first use
# - Write governance decisions to local store
# - Write override and approval events
# - Write outcome events (populated by Sentinel v0.4.0)
# - Query decision history for audit command
# - Query policy effectiveness metrics
# - Query outcome correlation for governance intelligence
#
# Privacy:
# - No plan contents stored
# - No cost amounts stored
# - No resource names stored
# - No organization identifiers stored
# - Plan is represented by SHA-256 hash only
#
# Telemetry layers implemented here:
#   Layer 1 — Decision Telemetry      (decisions table)
#   Layer 2 — Evaluation Telemetry    (decisions table — conditions)
#   Layer 3 — Governance Workflow     (overrides + approvals tables)
#   Layer 4 — Outcome Telemetry       (outcomes table — schema defined,
#                                      populated by Sentinel v0.4.0)
#   Layer 5 — Drift Telemetry         (outcomes table, type=drift_detected)
#   Layer 6 — Effectiveness Telemetry (policy_effectiveness — derived/computed)
#
# Database evolution:
#   v0.3.0  SQLite — local only (~/.obsidianwall/decisions.db)
#   v0.4.0  Added policy_path column for Sentinel verification
#   Compass PostgreSQL (Supabase) — hosted, multi-tenant
#
# Location:
#   ~/.obsidianwall/decisions.db

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from telemetry.config import get_db_path, is_telemetry_enabled


# =====================================================
# SCHEMA
# =====================================================

_SCHEMA = """
-- Governance decision history.
-- Layers 1 + 2: Decision and Evaluation Telemetry.
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
    region              TEXT,
    policy_path         TEXT
);

-- Override events.
-- Layer 3: Governance Workflow Telemetry.
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
-- Layer 3: Governance Workflow Telemetry.
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

-- Outcome events.
-- Layer 4 + 5: Outcome and Drift Telemetry.
-- Schema defined now. Populated by Sentinel v0.4.0.
--
-- outcome_type values:
--   deployment_success    → deployment completed, no drift
--   deployment_failure    → deployment failed after authorization
--   budget_overrun        → actual cost exceeded estimate
--   security_incident     → security event after allowed deployment
--   compliance_violation  → previously passing conditions now failing
--   availability_event    → availability impact after deployment
--   drift_detected        → infrastructure drifted from declared state
--
-- Correlating decisions with outcomes enables:
--   "92% of cost denials that were overridden
--    resulted in budget_overrun within 30 days"
--
-- That is Governance Intelligence.
CREATE TABLE IF NOT EXISTS outcomes (
    id              TEXT PRIMARY KEY,
    decision_id     TEXT NOT NULL,
    outcome_type    TEXT NOT NULL,
    timestamp       TEXT NOT NULL,
    severity        TEXT,
    description     TEXT,
    metadata        TEXT,
    FOREIGN KEY (decision_id) REFERENCES decisions(id)
);

-- Policy effectiveness summary.
-- Layer 6: Effectiveness Telemetry (derived, not collected).
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
# MIGRATIONS
# =====================================================

# Each migration is a single SQL statement.
# Applied in order on every init_db() call.
# Idempotent — OperationalError means already applied.
_MIGRATIONS: list[str] = [
    # v0.4.0: Store policy path for Sentinel verification.
    # Sentinel loads the policy path from the stored decision
    # to re-evaluate the current plan without requiring the
    # user to re-specify the policy on the command line.
    "ALTER TABLE decisions ADD COLUMN policy_path TEXT",
]


def _run_migrations(conn: sqlite3.Connection) -> None:
    """
    Apply incremental schema migrations to an existing database.

    Safe to run on every init_db() call — each migration is
    guarded by a try/except on OperationalError, which fires
    when the column already exists. This makes each migration
    idempotent regardless of the database version.
    """
    for migration in _MIGRATIONS:
        try:
            conn.execute(migration)
            conn.commit()
        except sqlite3.OperationalError:
            pass  # Already applied — safe to continue


# =====================================================
# DATABASE INITIALIZATION
# =====================================================


def init_db(db_path: Path | None = None) -> sqlite3.Connection:
    """
    Initialize the SQLite database, create schema if needed,
    and apply any pending migrations.

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
    _run_migrations(conn)
    return conn


# =====================================================
# WRITE — Layer 1 + 2: Decision and Evaluation
# =====================================================


def record_decision(
    result:      dict[str, Any],
    plan_path:   str | None = None,
    policy_path: str | None = None,
) -> bool:
    """
    Write a governance decision to the local store.
    Covers telemetry layers 1 and 2.

    Only writes if governance history is enabled.
    Never writes plan contents — only a SHA-256
    hash of the plan path is stored.

    The policy_path is stored as-is and used by Sentinel
    to re-evaluate the current plan against the same policy
    without requiring the user to re-specify it.

    Args:
        result:      complete verdict evaluate result dict
        plan_path:   path to the Terraform plan file
        policy_path: path to the policy YAML file

    Returns:
        True if written, False if history disabled
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

        risk_summary: dict[str, Any] = result.get("risk_summary", {})

        # Layer 2: condition evaluation detail
        trace: list[dict[str, Any]] = result.get("trace", [])
        failed = [t["condition_id"] for t in trace if not t.get("result", True)]
        passed = [t["condition_id"] for t in trace if t.get("result", True)]

        analyzer_scores = json.dumps(risk_summary.get("analyzer_scores", {}))

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
                analyzer_scores, pricing_mode, region,
                policy_path
            ) VALUES (
                ?, ?, ?, ?,
                ?, ?,
                ?, ?,
                ?, ?,
                ?, ?,
                ?, ?, ?,
                ?, ?,
                ?, ?, ?,
                ?
            )
            """,
            (
                decision_id,
                timestamp,
                result.get("policy", ""),
                None,
                result.get("decision", ""),
                1 if result.get("conditions_passed") else 0,
                risk_summary.get("overall_risk_score", 0),
                risk_summary.get("effective_severity", ""),
                result.get("governance_severity", ""),
                1 if result.get("override_required") else 0,
                1 if result.get("override_possible") else 0,
                1 if result.get("requires_approval") else 0,
                None,
                plan_hash,
                risk_summary.get("total_findings", 0),
                json.dumps(failed),
                json.dumps(passed),
                analyzer_scores,
                result.get("pricing_mode", "table"),
                None,
                policy_path,
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
        # Governance history must never crash the CLI
        return False


# =====================================================
# WRITE — Layer 3: Governance Workflow
# =====================================================


def record_override(
    decision_id:   str,
    override_role: str | None,
    approved:      bool,
) -> bool:
    """
    Record an override event against a decision.
    Telemetry layer 3.
    """
    if not is_telemetry_enabled():
        return False

    try:
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
    Telemetry layer 3.
    """
    if not is_telemetry_enabled():
        return False

    try:
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
# WRITE — Layer 4 + 5: Outcome and Drift
# Populated by Sentinel v0.4.0.
# Schema defined here so correlation exists from day one.
# =====================================================


def record_outcome(
    decision_id:  str,
    outcome_type: str,
    severity:     str | None = None,
    description:  str | None = None,
    metadata:     dict[str, Any] | None = None,
) -> bool:
    """
    Record an outcome event against a governance decision.
    Telemetry layers 4 and 5.

    Called by Sentinel after observing reality against
    a previous governance decision.

    outcome_type values:
        deployment_success   — no drift, decision still holds
        deployment_failure   — deployment failed post-authorization
        budget_overrun       — cost exceeded estimate
        security_incident    — security event after allowed deployment
        compliance_violation — previously passing conditions now failing
        availability_event   — availability impact after deployment
        drift_detected       — infrastructure drifted from declared state

    Args:
        decision_id:  UUID of the original governance decision
        outcome_type: what actually happened
        severity:     informational | low | medium | high | critical
        description:  human-readable outcome description
        metadata:     domain-specific outcome data (JSON-serializable)

    Returns:
        True if written, False if history disabled or failed
    """
    if not is_telemetry_enabled():
        return False

    try:
        conn = init_db()
        conn.execute(
            """
            INSERT INTO outcomes (
                id, decision_id, outcome_type,
                timestamp, severity, description, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()),
                decision_id,
                outcome_type,
                datetime.now(timezone.utc).isoformat(),
                severity,
                description,
                json.dumps(metadata) if metadata else None,
            ),
        )
        conn.commit()
        conn.close()
        return True

    except Exception:
        return False


# =====================================================
# EFFECTIVENESS — Layer 6 (derived)
# =====================================================


def _update_effectiveness(
    conn:        sqlite3.Connection,
    policy_name: str,
    decision:    str,
    timestamp:   str,
) -> None:
    """
    Update running totals in policy_effectiveness.
    Called inside record_decision — same connection.
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
# READ — for verdict audit, sentinel, effectiveness
# =====================================================


def get_recent_decisions(
    limit:   int        = 50,
    db_path: Path | None = None,
) -> list[dict[str, Any]]:
    """Return most recent governance decisions."""
    try:
        conn   = init_db(db_path)
        cursor = conn.execute(
            "SELECT * FROM decisions ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        )
        rows = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return rows
    except Exception:
        return []


def get_policy_effectiveness(
    policy_name: str | None  = None,
    db_path:     Path | None = None,
) -> list[dict[str, Any]]:
    """Return policy effectiveness summaries with override counts."""
    try:
        conn = init_db(db_path)
        if policy_name:
            cursor = conn.execute(
                """
                SELECT
                    pe.*,
                    COUNT(DISTINCT o.id)  as override_count,
                    COUNT(DISTINCT a.id)  as approval_count,
                    COUNT(DISTINCT oc.id) as outcome_count
                FROM policy_effectiveness pe
                LEFT JOIN decisions d  ON d.policy_name = pe.policy_name
                LEFT JOIN overrides o  ON o.decision_id = d.id
                LEFT JOIN approvals a  ON a.decision_id = d.id
                LEFT JOIN outcomes  oc ON oc.decision_id = d.id
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
                    COUNT(DISTINCT o.id)  as override_count,
                    COUNT(DISTINCT a.id)  as approval_count,
                    COUNT(DISTINCT oc.id) as outcome_count
                FROM policy_effectiveness pe
                LEFT JOIN decisions d  ON d.policy_name = pe.policy_name
                LEFT JOIN overrides o  ON o.decision_id = d.id
                LEFT JOIN approvals a  ON a.decision_id = d.id
                LEFT JOIN outcomes  oc ON oc.decision_id = d.id
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
    db_path:     Path | None = None,
) -> dict[str, Any] | None:
    """Return a single decision by ID with outcomes."""
    try:
        conn   = init_db(db_path)
        cursor = conn.execute(
            "SELECT * FROM decisions WHERE id = ?",
            (decision_id,),
        )
        row = cursor.fetchone()
        if not row:
            conn.close()
            return None

        result = dict(row)

        outcomes_cursor = conn.execute(
            "SELECT * FROM outcomes WHERE decision_id = ? ORDER BY timestamp",
            (decision_id,),
        )
        result["outcomes"] = [dict(r) for r in outcomes_cursor.fetchall()]

        conn.close()
        return result
    except Exception:
        return None


def get_domain_risk_summary(
    db_path: Path | None = None,
) -> dict[str, Any]:
    """
    Return aggregated risk scores by governance domain.
    Used by verdict audit command.
    """
    try:
        conn   = init_db(db_path)
        cursor = conn.execute(
            """
            SELECT
                policy_name, decision, overall_risk_score,
                effective_severity, analyzer_scores,
                conditions_passed, failed_conditions, timestamp
            FROM decisions
            ORDER BY timestamp DESC
            LIMIT 500
            """
        )
        rows = [dict(row) for row in cursor.fetchall()]
        conn.close()

        if not rows:
            return {}

        domain_scores: dict[str, list[int]] = {}
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

        return {
            "total_evaluations": total_count,
            "total_denied":      deny_total,
            "deny_rate":         (
                round(deny_total / total_count * 100, 1)
                if total_count else 0
            ),
            "domain_avg_scores": {
                domain: round(sum(s) / len(s), 1)
                for domain, s in domain_scores.items()
                if s
            },
        }

    except Exception:
        return {}


def get_failed_conditions_summary(
    db_path: Path | None = None,
) -> list[dict[str, Any]]:
    """
    Aggregate failed condition counts across all decisions.
    Powers the 'Why denied?' section of verdict audit.
    """
    try:
        conn   = init_db(db_path)
        cursor = conn.execute(
            """
            SELECT failed_conditions
            FROM decisions
            WHERE failed_conditions IS NOT NULL
            """
        )
        rows = [dict(row) for row in cursor.fetchall()]
        conn.close()

        if not rows:
            return []

        condition_counts: dict[str, int] = {}
        total: int = len(rows)

        for row in rows:
            try:
                failed: list[str] = json.loads(
                    row.get("failed_conditions") or "[]"
                )
                for cid in failed:
                    condition_counts[cid] = condition_counts.get(cid, 0) + 1
            except (json.JSONDecodeError, TypeError):
                continue

        return sorted(
            [
                {
                    "condition_id": cid,
                    "count":        count,
                    "rate":         round(count / total * 100, 1),
                }
                for cid, count in condition_counts.items()
            ],
            key=lambda x: x["count"],  # type: ignore[return-value]
            reverse=True,
        )

    except Exception:
        return []


def get_passed_conditions_summary(
    db_path: Path | None = None,
) -> list[dict[str, Any]]:
    """
    Aggregate passed condition counts across all decisions.
    Powers the 'Why allowed?' section of verdict audit.
    """
    try:
        conn   = init_db(db_path)
        cursor = conn.execute(
            """
            SELECT passed_conditions
            FROM decisions
            WHERE passed_conditions IS NOT NULL
            """
        )
        rows = [dict(row) for row in cursor.fetchall()]
        conn.close()

        if not rows:
            return []

        condition_counts: dict[str, int] = {}
        total: int = len(rows)

        for row in rows:
            try:
                passed: list[str] = json.loads(
                    row.get("passed_conditions") or "[]"
                )
                for cid in passed:
                    condition_counts[cid] = condition_counts.get(cid, 0) + 1
            except (json.JSONDecodeError, TypeError):
                continue

        return sorted(
            [
                {
                    "condition_id": cid,
                    "count":        count,
                    "rate":         round(count / total * 100, 1),
                }
                for cid, count in condition_counts.items()
            ],
            key=lambda x: x["count"],  # type: ignore[return-value]
            reverse=True,
        )

    except Exception:
        return []


def get_outcome_summary(
    db_path: Path | None = None,
) -> list[dict[str, Any]]:
    """
    Return outcome type counts across all recorded outcomes.
    Powers the 'Deployment Outcomes' section of verdict audit.
    """
    try:
        conn   = init_db(db_path)
        cursor = conn.execute(
            """
            SELECT outcome_type, COUNT(*) as count
            FROM outcomes
            GROUP BY outcome_type
            ORDER BY count DESC
            """
        )
        rows = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return rows
    except Exception:
        return []


def get_outcome_correlation(
    db_path: Path | None = None,
) -> list[dict[str, Any]]:
    """
    Correlate governance decisions with outcomes.
    Powers future Governance Intelligence in Compass.
    """
    try:
        conn   = init_db(db_path)
        cursor = conn.execute(
            """
            SELECT
                d.policy_name,
                d.decision,
                oc.outcome_type,
                COUNT(*) as frequency
            FROM decisions d
            JOIN outcomes oc ON oc.decision_id = d.id
            GROUP BY d.policy_name, d.decision, oc.outcome_type
            ORDER BY frequency DESC
            """
        )
        rows = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return rows
    except Exception:
        return []
