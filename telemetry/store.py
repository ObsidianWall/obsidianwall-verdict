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
# - Write and read evidence artifacts (v0.5.2)
# - Query decision history for audit command
# - Query policy effectiveness metrics
# - Query outcome correlation for governance intelligence
#
# Privacy:
# - No plan contents stored
# - No cost amounts stored
# - No resource names stored
# - No organization identifiers stored
# - Plan is represented by SHA-256 hash of the file PATH only
# - Policy is represented by SHA-256 hash of file CONTENTS
#   (portable across machines — same policy = same hash)
# - Policy path stored as-is for Sentinel runtime use only
#   (see note in record_decision on path vs. hash separation)
#
# Telemetry layers implemented here:
#   Layer 1 — Decision Telemetry      (decisions table)
#   Layer 2 — Evaluation Telemetry    (decisions table — conditions)
#   Layer 3 — Governance Workflow     (overrides + approvals tables)
#   Layer 4 — Outcome Telemetry       (outcomes table — schema defined,
#                                      populated by Sentinel v0.4.0)
#   Layer 5 — Drift Telemetry         (outcomes table, type=drift_detected)
#   Layer 6 — Effectiveness Telemetry (policy_effectiveness — derived/computed)
#   Layer 7 — Evidence Store          (decision_artifacts — v0.5.2)
#
# Policy identity design:
#   policy_path         — runtime only (Sentinel re-evaluation)
#                         never used for cross-environment analytics
#   policy_content_hash — telemetry identity (SHA-256 of file contents)
#                         portable: same policy file on any machine = same hash
#                         enables "which policies are most common" queries
#   policy_family       — high-level governance intent classification
#                         (cost_governance, security_compliance, etc.)
#                         enables "which governance intents are most enforced"
#                         analytics without file path exposure
#
# Decision vs. Evidence design (v0.5.2):
#   The decisions table stays lean and query-optimized —
#   it holds only the operational metadata needed for fast
#   aggregate queries (risk scores, condition pass/fail,
#   policy names). Think of it as a decision ledger.
#
#   The decision_artifacts table is a separate evidence
#   store. It holds full JSON payloads — the complete
#   verdict evaluate result, and in the future other
#   evidence kinds (trace graph exports, Sentinel drift
#   snapshots, SBOMs, cost reports) — keyed by decision_id
#   and artifact_type. This separation means:
#     - Compass can query decisions cheaply without
#       loading full artifacts for aggregate analysis
#     - New evidence types can be added as new
#       artifact_type values without schema changes
#     - verdict explain retrieves full evidence without
#       depending on the original --output file still
#       existing on disk
#
# Database evolution:
#   v0.3.0  SQLite — local only (~/.obsidianwall/decisions.db)
#   v0.4.0  Added policy_path column for Sentinel verification
#   v0.5.1  Added policy_content_hash and policy_family columns
#   v0.5.2  Added decision_artifacts table (evidence store)
#   Compass PostgreSQL (Supabase) — hosted, multi-tenant (future)
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
from telemetry.policy_classifier import classify_policy_family

# =====================================================
# SCHEMA
# =====================================================

_SCHEMA = """
-- Governance decision history.
-- Layers 1 + 2: Decision and Evaluation Telemetry.
-- One row per verdict evaluate invocation.
--
-- This table is intentionally lean. Full evidentiary
-- detail (reasoning chains, trace graphs, explained
-- recommendations) lives in decision_artifacts, not here.
-- Keeping this table lean means aggregate queries across
-- thousands of decisions stay fast.
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
    policy_path         TEXT,
    policy_content_hash TEXT,
    policy_family       TEXT
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
-- Correlating decisions with outcomes enables queries like:
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

-- Evidence store.
-- Layer 7: Evidence Store (v0.5.2).
--
-- Full JSON artifacts linked to decisions, kept
-- deliberately separate from the lean decisions table.
-- One decision can accumulate multiple artifact types
-- over time without any schema change:
--   "evaluation"        the full verdict evaluate result
--   "trace_graph"        (future) standalone trace exports
--   "sentinel_snapshot"  (future) post-deployment drift evidence
--   "sbom"               (future) software bill of materials
--   "cost_report"        (future) detailed cost breakdown exports
--
-- verdict explain reads from this table by decision_id,
-- so full evidence remains available even if the original
-- --output file has been overwritten or deleted.
CREATE TABLE IF NOT EXISTS decision_artifacts (
    id              TEXT PRIMARY KEY,
    decision_id     TEXT NOT NULL,
    artifact_type   TEXT NOT NULL,
    artifact_json   TEXT NOT NULL,
    artifact_hash   TEXT,
    created_at      TEXT NOT NULL,
    FOREIGN KEY (decision_id) REFERENCES decisions(id)
);

-- Index for the common lookup pattern: fetch the most
-- recent artifact of a given type for a decision.
CREATE INDEX IF NOT EXISTS idx_decision_artifacts_decision_id
    ON decision_artifacts(decision_id);
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
    # v0.5.1: Privacy-safe policy content identity.
    # policy_content_hash — SHA-256 of policy file contents,
    # not the path. Same policy on different machines
    # produces the same hash, enabling cross-environment
    # analytics without file path exposure.
    "ALTER TABLE decisions ADD COLUMN policy_content_hash TEXT",
    # v0.5.1: High-level governance intent classification.
    # policy_family answers "what governance intent are
    # organizations enforcing?" rather than "what file
    # did they use?" — the analytically valuable question.
    # See telemetry/policy_classifier.py for family definitions.
    "ALTER TABLE decisions ADD COLUMN policy_family TEXT",
]


def _run_migrations(conn: sqlite3.Connection) -> None:
    """
    Apply incremental schema migrations to an existing database.

    Safe to run on every init_db() call — each migration is
    guarded by a try/except on OperationalError, which fires
    when the column already exists. This makes each migration
    idempotent regardless of the database version.

    Note: the decision_artifacts table (v0.5.2) is created
    via _SCHEMA (CREATE TABLE IF NOT EXISTS), not a migration,
    since it is a new table rather than a column addition to
    an existing table.
    """
    for migration in _MIGRATIONS:
        try:
            conn.execute(migration)
            conn.commit()
        except sqlite3.OperationalError:
            pass  # Column already exists — safe to continue.


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
# HELPERS — Privacy-safe policy identity
# =====================================================


def _compute_policy_content_hash(policy_path: str | None) -> str | None:
    """
    Compute a short SHA-256 hash of policy file CONTENTS.

    Design intent — content hash vs. path hash:
      Path hash:    SHA256("/home/alice/budget.yaml")
                    Changes if the file moves. Unique per machine.
                    Not useful for cross-environment analytics.

      Content hash: SHA256(file_contents)
                    Stable if the file moves. Same on every machine.
                    Enables "which policies are most deployed" queries
                    without leaking any file system information.

    Returns the first 16 hex characters (64 bits of entropy),
    sufficient to identify policy versions without storing
    the full hash in every row.

    Returns None if policy_path is None, the file is unreadable,
    or any error occurs. Never raises — telemetry must not
    crash the CLI.
    """
    if not policy_path:
        return None
    try:
        contents = Path(policy_path).read_bytes()
        return hashlib.sha256(contents).hexdigest()[:16]
    except Exception:
        return None


def _classify_policy(policy_path: str | None) -> str | None:
    """
    Classify a policy file into a high-level governance family.

    Loads the policy YAML and delegates to the policy classifier.
    Returns None if classification fails for any reason —
    missing file, parse error, or unrecognizable content all
    produce None rather than raising. Telemetry must not crash.

    See telemetry/policy_classifier.py for family definitions
    and the keyword matching logic.
    """
    if not policy_path:
        return None
    try:
        from engine.policy_loader import load_policy as _load_policy

        policy_dict = _load_policy(policy_path)
        return classify_policy_family(policy_dict)
    except Exception:
        return None


# =====================================================
# WRITE — Layer 1 + 2: Decision and Evaluation
# =====================================================


def record_decision(
    result: dict[str, Any],
    plan_path: str | None = None,
    policy_path: str | None = None,
    db_path: Path | None = None,
) -> bool:
    """
    Write a governance decision to the local store.
    Covers telemetry layers 1 and 2.

    Only writes if governance history is enabled.

    Policy identity is stored as three separate values
    with different purposes:
      policy_path         — stored as-is for Sentinel runtime
                            re-evaluation. Never used for analytics.
      policy_content_hash — SHA-256 of file contents. Portable
                            across machines. Used for analytics.
      policy_family       — high-level governance intent.
                            Used for aggregate queries.

    Plan identity is stored as a SHA-256 hash of the plan PATH
    (not its contents). This is less portable than a content hash
    but sufficient for correlating evaluations within a single
    environment, and avoids storing any infrastructure detail.

    This function writes only operational metadata to the
    lean decisions table. Full evidence (the complete result
    dict) is stored separately via record_artifact() — see
    that function for the evidence store design.

    Args:
        result:      complete verdict evaluate result dict
        plan_path:   path to the Terraform plan or CloudFormation
                     template file
        policy_path: path to the ObsidianWall policy YAML file

    Returns:
        True if written, False if history disabled or write failed.
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

        # Hash the plan PATH — never store plan contents.
        # First 16 hex chars sufficient for correlation within
        # an environment without full hash storage overhead.
        plan_hash: str | None = None
        if plan_path:
            plan_hash = hashlib.sha256(plan_path.encode("utf-8")).hexdigest()[:16]

        # Privacy-safe policy identity for telemetry.
        # policy_path is kept for Sentinel runtime use.
        # policy_content_hash and policy_family are for analytics.
        # All three can be None — telemetry must not crash CLI.
        policy_content_hash = _compute_policy_content_hash(policy_path)
        policy_family = _classify_policy(policy_path)

        risk_summary: dict[str, Any] = result.get("risk_summary", {})

        # Layer 2: Condition evaluation detail.
        # Store condition IDs only — no condition expressions
        # or evaluated values are persisted.
        trace: list[dict[str, Any]] = result.get("trace", [])
        failed = [t["condition_id"] for t in trace if not t.get("result", True)]
        passed = [t["condition_id"] for t in trace if t.get("result", True)]

        analyzer_scores = json.dumps(risk_summary.get("analyzer_scores", {}))

        conn = init_db(db_path)

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
                policy_path, policy_content_hash, policy_family
            ) VALUES (
                ?, ?, ?, ?,
                ?, ?,
                ?, ?,
                ?, ?,
                ?, ?,
                ?, ?, ?,
                ?, ?,
                ?, ?, ?,
                ?, ?, ?
            )
            """,
            (
                decision_id,
                timestamp,
                result.get("policy", ""),
                None,  # policy_type — reserved
                result.get("decision", ""),
                1 if result.get("conditions_passed") else 0,
                risk_summary.get("overall_risk_score", 0),
                risk_summary.get("effective_severity", ""),
                result.get("governance_severity", ""),
                1 if result.get("override_required") else 0,
                1 if result.get("override_possible") else 0,
                1 if result.get("requires_approval") else 0,
                None,  # user_role — reserved
                plan_hash,
                risk_summary.get("total_findings", 0),
                json.dumps(failed),
                json.dumps(passed),
                analyzer_scores,
                result.get("pricing_mode", "table"),
                None,  # region — reserved
                policy_path,
                policy_content_hash,
                policy_family,
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
        # Governance history must never crash the CLI.
        # Silently return False — the evaluation result
        # has already been printed to stdout.
        return False


# =====================================================
# WRITE — Layer 7: Evidence Store (v0.5.2)
# =====================================================


def record_artifact(
    decision_id: str,
    artifact: dict[str, Any],
    artifact_type: str = "evaluation",
    db_path: Path | None = None,
) -> bool:
    """
    Store a full evidence artifact linked to a decision.

    This is the evidence store — deliberately separate from
    the lean decisions table (see module docstring: "Decision
    vs. Evidence design"). Call this after record_decision()
    to persist the complete governance artifact for later
    retrieval by verdict explain.

    Args:
        decision_id:   UUID of the governance decision this
                       artifact provides evidence for
        artifact:      the full artifact dict to store
                       (typically the complete verdict
                       evaluate result)
        artifact_type: classifies the evidence kind.
                       Defaults to "evaluation" — the full
                       verdict evaluate result. Future values:
                       "trace_graph", "sentinel_snapshot",
                       "sbom", "cost_report".
        db_path:       optional path override (for testing)

    Returns:
        True if written, False if history disabled or write
        failed. Never raises — evidence storage must not
        crash the CLI.
    """
    if not is_telemetry_enabled():
        return False

    try:
        artifact_json = json.dumps(artifact, default=str)
        artifact_hash = hashlib.sha256(artifact_json.encode("utf-8")).hexdigest()[:16]

        conn = init_db(db_path)
        conn.execute(
            """
            INSERT INTO decision_artifacts (
                id, decision_id, artifact_type,
                artifact_json, artifact_hash, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()),
                decision_id,
                artifact_type,
                artifact_json,
                artifact_hash,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        conn.commit()
        conn.close()
        return True

    except Exception:
        return False


# =====================================================
# WRITE — Layer 3: Governance Workflow
# =====================================================


def record_override(
    decision_id: str,
    override_role: str | None,
    approved: bool,
    db_path: Path | None = None,
) -> bool:
    """
    Record an override event against a governance decision.
    Telemetry layer 3.

    Called when an authorized role overrides a DENY_WITH_OVERRIDE
    decision to allow a deployment to proceed despite a failed
    policy condition.

    Args:
        decision_id:   UUID of the original governance decision
        override_role: the role that performed the override
        approved:      True if the override was granted
    """
    if not is_telemetry_enabled():
        return False

    try:
        conn = init_db(db_path)
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
    decision_id: str,
    approver_role: str | None,
    approved: bool,
    notes: str | None = None,
    db_path: Path | None = None,
) -> bool:
    """
    Record an approval event against a governance decision.
    Telemetry layer 3.

    Called when an ALLOW_WITH_APPROVAL_REQUIRED decision
    reaches its approval resolution — either granted or denied
    by the designated approver role.

    Args:
        decision_id:    UUID of the original governance decision
        approver_role:  the role that resolved the approval
        approved:       True if the approval was granted
        notes:          optional human-readable approval notes
    """
    if not is_telemetry_enabled():
        return False

    try:
        conn = init_db(db_path)
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
# Schema defined here. Populated by Sentinel v0.4.0+.
# Defined early so the correlation schema exists from
# the first evaluation, even before Sentinel runs.
# =====================================================


def record_outcome(
    decision_id: str,
    outcome_type: str,
    severity: str | None = None,
    description: str | None = None,
    metadata: dict[str, Any] | None = None,
    db_path: Path | None = None,
) -> bool:
    """
    Record an outcome event against a governance decision.
    Telemetry layers 4 and 5.

    Called by Sentinel after observing post-deployment reality
    against the original governance decision. Correlating
    decisions with outcomes is what enables Governance
    Intelligence queries in Compass, e.g.:
      "92% of cost denials that were overridden resulted
       in budget_overrun within 30 days."

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
        outcome_type: what actually happened post-deployment
        severity:     informational | low | medium | high | critical
        description:  human-readable outcome description
        metadata:     domain-specific outcome data (JSON-serializable)
    """
    if not is_telemetry_enabled():
        return False

    try:
        conn = init_db(db_path)
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
# EFFECTIVENESS — Layer 6 (derived, not collected)
# Running totals per policy — never a separate write,
# always computed inside record_decision on the same
# connection to avoid partial writes.
# =====================================================


def _update_effectiveness(
    conn: sqlite3.Connection,
    policy_name: str,
    decision: str,
    timestamp: str,
) -> None:
    """
    Update running totals in policy_effectiveness.

    Called inside record_decision on the same open connection,
    so both the decision row and the effectiveness update
    commit atomically. If either fails, neither persists.

    Uses INSERT ... ON CONFLICT to upsert atomically —
    avoids a read-then-write race condition.
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
# READ — Layer 7: Evidence Store (v0.5.2)
#
# All three evidence-store read functions are grouped
# here together: get_artifact() for full content,
# get_artifact_metadata() for hash/timestamp only
# (powers the Evidence section of verdict explain
# without loading the full artifact), and
# list_artifact_types() to discover what evidence
# kinds exist for a decision.
# =====================================================


def get_artifact(
    decision_id: str,
    artifact_type: str = "evaluation",
    db_path: Path | None = None,
) -> dict[str, Any] | None:
    """
    Retrieve the most recent evidence artifact for a
    decision, parsed back into a dict.

    Powers verdict explain — loads the full governance
    artifact by decision_id without requiring the original
    --output file to still exist on disk.

    Args:
        decision_id:   UUID of the governance decision
        artifact_type: which evidence kind to retrieve.
                       Defaults to "evaluation".
        db_path:       optional path override (for testing)

    Returns:
        Parsed artifact dict, or None if no artifact exists
        for this decision_id and artifact_type, or if the
        stored JSON fails to parse.
    """
    try:
        conn = init_db(db_path)
        cursor = conn.execute(
            """
            SELECT artifact_json FROM decision_artifacts
            WHERE decision_id = ? AND artifact_type = ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (decision_id, artifact_type),
        )
        row = cursor.fetchone()
        conn.close()

        if not row:
            return None

        return json.loads(row["artifact_json"])

    except Exception:
        return None


def get_artifact_metadata(
    decision_id: str,
    artifact_type: str = "evaluation",
    db_path: Path | None = None,
) -> dict[str, Any] | None:
    """
    Retrieve metadata about a stored evidence artifact,
    without the full artifact content.

    Powers the Evidence section of verdict explain — shows
    the artifact hash and recorded timestamp as proof this
    is stored governance evidence, not just a policy check
    result, without exposing the full row structure or the
    complete artifact content to the CLI layer.

    Args:
        decision_id:   UUID of the governance decision
        artifact_type: which evidence kind to retrieve.
                       Defaults to "evaluation".
        db_path:       optional path override (for testing)

    Returns:
        dict with "artifact_hash" and "created_at" keys,
        or None if no artifact exists for this decision_id
        and artifact_type.
    """
    try:
        conn = init_db(db_path)
        cursor = conn.execute(
            """
            SELECT artifact_hash, created_at FROM decision_artifacts
            WHERE decision_id = ? AND artifact_type = ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (decision_id, artifact_type),
        )
        row = cursor.fetchone()
        conn.close()

        if not row:
            return None

        return {
            "artifact_hash": row["artifact_hash"],
            "created_at": row["created_at"],
        }

    except Exception:
        return None


def list_artifact_types(
    decision_id: str,
    db_path: Path | None = None,
) -> list[str]:
    """
    Return the distinct artifact types stored for a decision.

    Useful for verdict explain to report what evidence is
    available before attempting to load a specific type —
    e.g. once Sentinel writes "sentinel_snapshot" artifacts,
    this lets the CLI say "evaluation + sentinel_snapshot
    evidence available" rather than guessing.

    Returns an empty list if no artifacts exist or on error.
    """
    try:
        conn = init_db(db_path)
        cursor = conn.execute(
            """
            SELECT DISTINCT artifact_type FROM decision_artifacts
            WHERE decision_id = ?
            """,
            (decision_id,),
        )
        rows = [row["artifact_type"] for row in cursor.fetchall()]
        conn.close()
        return rows
    except Exception:
        return []


# =====================================================
# READ — for verdict audit, sentinel, effectiveness
# =====================================================


def get_recent_decisions(
    limit: int = 50,
    db_path: Path | None = None,
) -> list[dict[str, Any]]:
    """
    Return most recent governance decisions, newest first.
    Powers the decision history section of verdict audit.
    """
    try:
        conn = init_db(db_path)
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
    policy_name: str | None = None,
    db_path: Path | None = None,
) -> list[dict[str, Any]]:
    """
    Return policy effectiveness summaries with override and
    approval counts joined from the workflow tables.

    If policy_name is provided, returns a single policy summary.
    Otherwise returns all policies sorted by evaluation volume.
    """
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
    db_path: Path | None = None,
) -> dict[str, Any] | None:
    """
    Return a single governance decision by ID, including
    any outcome events recorded against it by Sentinel.

    Returns None if the decision_id does not exist or
    any read error occurs.

    Note: this returns operational metadata from the
    decisions table only. For the full evidentiary
    artifact (reasoning chains, trace graphs, explained
    recommendations), use get_artifact() instead.
    """
    try:
        conn = init_db(db_path)
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
    Return aggregated risk scores by governance domain
    across the 500 most recent decisions.

    Powers the risk summary section of verdict audit.
    Analyzer scores are stored as JSON per decision and
    unpacked here for domain-level aggregation.
    """
    try:
        conn = init_db(db_path)
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
        deny_total = sum(1 for r in rows if "DENY" in r["decision"])

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


def get_failed_conditions_summary(
    db_path: Path | None = None,
) -> list[dict[str, Any]]:
    """
    Aggregate failed condition counts across all decisions.

    Powers the "Why denied?" section of verdict audit.
    Returns conditions sorted by failure frequency, with
    a failure rate expressed as a percentage of all decisions
    that recorded any failed conditions.
    """
    try:
        conn = init_db(db_path)
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
                failed: list[str] = json.loads(row.get("failed_conditions") or "[]")
                for cid in failed:
                    condition_counts[cid] = condition_counts.get(cid, 0) + 1
            except (json.JSONDecodeError, TypeError):
                continue

        return sorted(
            [
                {
                    "condition_id": cid,
                    "count": count,
                    "rate": round(count / total * 100, 1),
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

    Powers the "Why allowed?" section of verdict audit.
    Returns conditions sorted by pass frequency, with
    a pass rate expressed as a percentage of all decisions
    that recorded any passed conditions.
    """
    try:
        conn = init_db(db_path)
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
                passed: list[str] = json.loads(row.get("passed_conditions") or "[]")
                for cid in passed:
                    condition_counts[cid] = condition_counts.get(cid, 0) + 1
            except (json.JSONDecodeError, TypeError):
                continue

        return sorted(
            [
                {
                    "condition_id": cid,
                    "count": count,
                    "rate": round(count / total * 100, 1),
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

    Powers the "Deployment Outcomes" section of verdict audit.
    Outcomes are populated by Sentinel after post-deployment
    verification — this query returns meaningful data only
    after Sentinel has been run against at least one decision.
    """
    try:
        conn = init_db(db_path)
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
    Correlate governance decisions with their observed outcomes.

    Powers future Governance Intelligence in Compass.
    Enables queries like: "Which decisions most frequently
    lead to budget_overrun?" or "What override patterns
    precede security_incident outcomes?"

    Returns rows sorted by frequency, highest first.
    Only returns data for decisions that have at least
    one outcome recorded by Sentinel.
    """
    try:
        conn = init_db(db_path)
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
