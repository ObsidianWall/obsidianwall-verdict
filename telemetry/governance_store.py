# telemetry/governance_store.py
#
# Purpose:
# Sentinel's governance record store — the organization's
# governance memory. Replaces the decisions, overrides,
# approvals, and outcomes tables from v0.5.x with a single
# object model: governance_records (the stable, queryable
# object) + governance_history (the append-only history log).
#
# See docs/architecture/sentinel-architecture-v1.md (private)
# for the full design rationale.
#
# Object model:
#   governance_records    Lean, queryable. One row per
#                         governance decision. Identity,
#                         intent, decision, routing.
#   governance_history     Append-only. Every subsequent event
#                         in a record's lifecycle — override,
#                         approval, outcome, drift, evidence —
#                         is a new history entry. Nothing is
#                         ever updated in place.
#   governance_evidence     Full JSON payload (renamed from
#                         decision_artifacts in v0.5.2).
#                         Referenced by artifact_hash on the
#                         record. Not limited to Verdict —
#                         Sentinel, Compass, and future systems
#                         can all write evidence here.
#
# History entries are typed with two dimensions rather than
# one flat string, so querying stays simple as new types are
# added over time:
#   history_category   decision | override | approval |
#                       outcome | drift | evidence
#   history_action      created | requested | approved |
#                       denied | revoked | observed |
#                       detected | resolved
#
# Governance objective identity:
# Each record stores BOTH the objective statement text (for
# humans reading a single record) and a SHA-256 hash of that
# text (for Compass to group thousands of records without
# repeatedly comparing long strings).
#
# Migration:
# v0.6.0 is a clean cutover, handled automatically by
# telemetry/migration.py on first run against an old-schema
# database. See that module for the migration logic.
#
# Tamper-evidence:
# Each history entry's hash is chained to the previous entry's
# hash for the same record (history_hash / prev_history_hash).
# This detects — not cryptographically prevents — tampering
# with local history. A record-level aggregate hash (Merkle-style
# record_root_hash) is deferred until there's a concrete need
# to verify integrity across many records at once, rather than
# building that structure ahead of any real usage to validate
# it against.

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from telemetry.config import get_db_path, is_telemetry_enabled
from telemetry.identity import resolve_actor_identity, resolve_execution_host
from telemetry.policy_classifier import classify_policy_family

# =====================================================
# SCHEMA
# =====================================================

_SCHEMA = """
-- Governance Record.
-- The stable, queryable object. One row per governance
-- decision. Lean enough for fast aggregate queries — full
-- detail lives in governance_evidence (referenced by
-- artifact_hash) and in governance_history.
CREATE TABLE IF NOT EXISTS governance_records (
    record_id                       TEXT PRIMARY KEY,

    -- Identity
    policy_name                      TEXT NOT NULL,
    policy_content_hash               TEXT,
    policy_family                       TEXT,
    artifact_hash                        TEXT,

    -- Intent — both forms stored: text for humans reading a
    -- single record, hash for Compass grouping across many
    -- records without comparing long strings repeatedly.
    governance_objective_statement        TEXT,
    governance_objective_hash               TEXT,

    -- Decision
    decision                                TEXT NOT NULL,
    conditions_passed                        INTEGER NOT NULL DEFAULT 0,
    overall_risk_score                        INTEGER NOT NULL DEFAULT 0,
    effective_severity                         TEXT,
    governance_severity                         TEXT,

    -- Routing (as of creation — history entries capture changes)
    override_possible                            INTEGER NOT NULL DEFAULT 0,
    requires_approval                             INTEGER NOT NULL DEFAULT 0,

    -- Relationships — indexed hash columns, not a graph store.
    -- Typed linked-object IDs (Engineer, Project, Incident,
    -- etc.) are deferred until those entities actually exist
    -- elsewhere in the data model.
    plan_hash                                      TEXT,
    user_role                                       TEXT,

    -- Metadata
    verdict_version                                  TEXT,
    created_at                                        TEXT NOT NULL,

    -- Aggregate analytics data — stored as JSON columns so
    -- verdict audit can compute domain risk summaries and
    -- condition failure/pass frequency without loading the
    -- full evidence artifact for every record.
    analyzer_scores                                    TEXT,
    -- JSON: {"cost_analysis": 50, "topology_analysis": 25, ...}
    failed_conditions                                    TEXT,
    -- JSON: ["budget_check", ...]
    passed_conditions                                     TEXT,
    -- JSON: ["encryption_check", ...]

    -- Risk Acceptance Ledger foundation (v0.6.0).
    -- True at creation time when the decision is
    -- DENY_WITH_OVERRIDE AND override_possible — i.e. this
    -- record COULD become a risk acceptance. Whether it
    -- ACTUALLY was accepted is confirmed later by an
    -- OVERRIDE_APPROVED entry in governance_history — see
    -- get_risk_acceptance_records(). This column only marks
    -- eligibility at creation; it is never updated afterward.
    is_risk_acceptance_candidate                         INTEGER NOT NULL DEFAULT 0,

    -- Denormalized cache of the latest history entry — the
    -- record remains first-class; this avoids a join for the
    -- common "what's the current state" read.
    current_history_number                            INTEGER NOT NULL DEFAULT 1,
    current_history_category                           TEXT NOT NULL DEFAULT 'decision',
    current_history_action                              TEXT NOT NULL DEFAULT 'created'
);

-- Governance History.
-- Append-only. Every event in a record's lifecycle — override
-- requested, outcome observed, drift detected — is a new
-- entry. Nothing is ever updated in place. Named "history"
-- rather than "revisions" because it holds more than revisions
-- of the original decision — it accumulates the record's full
-- operational history over time.
CREATE TABLE IF NOT EXISTS governance_history (
    history_id               TEXT PRIMARY KEY,
    record_id                 TEXT NOT NULL,
    history_number              INTEGER NOT NULL,

    -- Split into two dimensions so queries stay simple as
    -- new types accumulate. "Show me every override-related
    -- event" is WHERE history_category = 'override', not an
    -- ever-growing IN (...) list of flat type strings.
    history_category               TEXT NOT NULL,
    -- decision | override | approval | outcome | drift | evidence
    history_action                   TEXT NOT NULL,
    -- created | requested | approved | denied | revoked |
    -- observed | detected | resolved

    history_data                       TEXT NOT NULL,   -- JSON, type-specific
    history_hash                         TEXT NOT NULL,   -- SHA-256 of history_data
    prev_history_hash                      TEXT,            -- chains to previous
                                                             -- entry for this record

    actor_role                               TEXT,
    actor_identity                             TEXT,
    -- Best-effort actor identity for this specific history
    -- entry (e.g. who approved an override) — same resolution
    -- and same "not authentication" caveat as
    -- governance_records.executed_by.
    execution_host                               TEXT,
    -- Hostname only — same scope limit as
    -- governance_records.execution_host. An override
    -- approval can happen on a different machine than the
    -- original decision, so this is captured per-entry.
    created_at                                 TEXT NOT NULL,

    FOREIGN KEY (record_id) REFERENCES governance_records(record_id)
);

-- Governance Evidence.
-- Renamed from decision_artifacts (v0.5.2) to reflect that
-- evidence is not limited to Verdict's output — Sentinel,
-- Compass, and future systems can all write evidence here,
-- keyed by record_id and evidence_type.
CREATE TABLE IF NOT EXISTS governance_evidence (
    evidence_id       TEXT PRIMARY KEY,
    record_id           TEXT NOT NULL,
    evidence_type          TEXT NOT NULL,
    -- "evaluation"        the full verdict evaluate result
    -- "trace_graph"        (future) standalone trace exports
    -- "sentinel_snapshot"   (future) post-deployment drift evidence
    -- "sbom"                 (future) software bill of materials
    -- "cost_report"           (future) detailed cost breakdown exports
    evidence_json               TEXT NOT NULL,
    evidence_hash                 TEXT,
    created_at                      TEXT NOT NULL,
    FOREIGN KEY (record_id) REFERENCES governance_records(record_id)
);

"""


# =====================================================
# INDEXES
#
# Deliberately separate from _SCHEMA's table creation.
# CREATE TABLE IF NOT EXISTS is a no-op on a table that
# already exists — it does NOT add new columns. If an
# index here referenced a column added after the table
# was first created on a user's machine, running it in
# the same script as CREATE TABLE would fail with
# "no such column" the moment that column is missing.
# Indexes run AFTER _MIGRATIONS below, guaranteeing every
# column they reference actually exists first.
# =====================================================

_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_gov_records_policy_name
    ON governance_records(policy_name);
CREATE INDEX IF NOT EXISTS idx_gov_records_policy_content_hash
    ON governance_records(policy_content_hash);
CREATE INDEX IF NOT EXISTS idx_gov_records_objective_hash
    ON governance_records(governance_objective_hash);
CREATE INDEX IF NOT EXISTS idx_gov_records_decision
    ON governance_records(decision);
CREATE INDEX IF NOT EXISTS idx_gov_records_created_at
    ON governance_records(created_at);
CREATE INDEX IF NOT EXISTS idx_gov_records_risk_acceptance
    ON governance_records(is_risk_acceptance_candidate);

CREATE INDEX IF NOT EXISTS idx_history_record_id
    ON governance_history(record_id);
CREATE INDEX IF NOT EXISTS idx_history_category
    ON governance_history(history_category);
CREATE UNIQUE INDEX IF NOT EXISTS idx_history_record_seq
    ON governance_history(record_id, history_number);

CREATE INDEX IF NOT EXISTS idx_evidence_record_id
    ON governance_evidence(record_id);
"""


# =====================================================
# MIGRATIONS
#
# Columns added to governance_records after the table was
# first created on existing installations. CREATE TABLE
# IF NOT EXISTS never adds columns to an existing table —
# each addition needs an explicit ALTER TABLE here, applied
# idempotently (OperationalError means the column already
# exists, safe to ignore). Same proven pattern used by
# telemetry/store.py's _MIGRATIONS list.
#
# Every column below was added to _SCHEMA incrementally
# during v0.6.0 development, after some installations had
# already created the table. Listed here so any existing
# database gets brought up to the current schema on the
# next init_governance_db() call, regardless of which
# intermediate schema version it was created under.
# =====================================================

_MIGRATIONS: list[str] = [
    "ALTER TABLE governance_records ADD COLUMN governance_objective_hash TEXT",
    "ALTER TABLE governance_records ADD COLUMN analyzer_scores TEXT",
    "ALTER TABLE governance_records ADD COLUMN failed_conditions TEXT",
    "ALTER TABLE governance_records ADD COLUMN passed_conditions TEXT",
    "ALTER TABLE governance_records ADD COLUMN "
    "is_risk_acceptance_candidate INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE governance_records ADD COLUMN executed_by TEXT",
    "ALTER TABLE governance_history ADD COLUMN actor_identity TEXT",
    "ALTER TABLE governance_records ADD COLUMN execution_host TEXT",
    "ALTER TABLE governance_history ADD COLUMN execution_host TEXT",
]


def _run_migrations(conn: sqlite3.Connection) -> None:
    """
    Apply incremental schema migrations. Safe to run on
    every init_governance_db() call — each migration is
    guarded by OperationalError, which fires when the
    column already exists, making every migration
    idempotent regardless of the database's current state.
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


def init_governance_db(db_path: Path | None = None) -> sqlite3.Connection:
    """
    Initialize the governance record schema. Safe to call
    on every operation.

    Order matters:
      1. Create tables (IF NOT EXISTS — no-ops on existing
         installations, but the CREATE statement includes
         every column for BRAND NEW installations)
      2. Run migrations (ALTER TABLE — brings EXISTING
         installations up to date with any columns added
         after their table was first created)
      3. Create indexes (only after migrations guarantee
         every referenced column actually exists)
    """
    path = db_path or get_db_path()
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")

    conn.executescript(_SCHEMA)
    conn.commit()

    _run_migrations(conn)

    conn.executescript(_INDEXES)
    conn.commit()

    return conn


# =====================================================
# HASHING HELPERS
# =====================================================


def _hash_history_data(history_data: dict[str, Any]) -> str:
    """
    Compute a SHA-256 hash of history entry data for
    tamper-evidence. Sorted keys so semantically identical
    data always produces the same hash regardless of dict
    ordering.
    """
    serialized = json.dumps(history_data, sort_keys=True, default=str)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def hash_objective_statement(statement: str | None) -> str | None:
    """
    Compute a SHA-256 hash of a governance objective statement,
    for Compass to group records without repeatedly comparing
    long text. Returns None if statement is None or empty.
    """
    if not statement:
        return None
    return hashlib.sha256(statement.encode("utf-8")).hexdigest()


def _compute_policy_content_hash(policy_path: str | None) -> str | None:
    """
    Compute a short SHA-256 hash of policy file CONTENTS.
    Portable across machines — same policy file on any host
    produces the same hash. Same behavior as v0.5.x's
    telemetry/store.py implementation.

    Returns None if policy_path is None, the file is unreadable,
    or any error occurs. Never raises.
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
    Same behavior as v0.5.x's telemetry/store.py implementation.

    Returns None if classification fails for any reason.
    Never raises.
    """
    if not policy_path:
        return None
    try:
        from engine.policy_loader import load_policy as _load_policy

        policy_dict = _load_policy(policy_path)
        return classify_policy_family(policy_dict)
    except Exception:
        return None


def _get_latest_history_hash(
    conn: sqlite3.Connection,
    record_id: str,
) -> str | None:
    """Return the history_hash of the most recent entry for a
    record, or None if this will be the first entry."""
    cursor = conn.execute(
        """
        SELECT history_hash FROM governance_history
        WHERE record_id = ?
        ORDER BY history_number DESC
        LIMIT 1
        """,
        (record_id,),
    )
    row = cursor.fetchone()
    return row["history_hash"] if row else None


def _get_next_history_number(
    conn: sqlite3.Connection,
    record_id: str,
) -> int:
    """Return the next sequential history_number for a record."""
    cursor = conn.execute(
        """
        SELECT MAX(history_number) as max_num
        FROM governance_history
        WHERE record_id = ?
        """,
        (record_id,),
    )
    row = cursor.fetchone()
    max_num = row["max_num"] if row and row["max_num"] is not None else 0
    return max_num + 1


# =====================================================
# WRITE — Create a Governance Record
# =====================================================


def create_governance_record(
    result: dict[str, Any],
    plan_path: str | None = None,
    policy_path: str | None = None,
    policy_content_hash: str | None = None,
    policy_family: str | None = None,
    artifact_hash: str | None = None,
    verdict_version: str | None = None,
    db_path: Path | None = None,
) -> bool:
    """
    Create a new governance record and its first history
    entry (category="decision", action="created"). This is
    the entry point Verdict calls at the end of evaluate() —
    it replaces record_decision() + record_artifact() from
    v0.5.x with a single call.

    policy_content_hash and policy_family are auto-computed
    from policy_path if not explicitly provided — the caller
    does not need to compute them separately, matching the
    simplicity of the old record_decision() call signature.

    Returns:
        True if written, False if telemetry disabled or write
        failed. Never raises — governance recording must not
        crash the CLI.
    """
    if not is_telemetry_enabled():
        return False

    conn = None
    try:
        record_id = result.get("decision_id", "")
        if not record_id:
            return False

        timestamp = result.get(
            "timestamp",
            datetime.now(timezone.utc).isoformat(),
        )

        plan_hash: str | None = None
        if plan_path:
            plan_hash = hashlib.sha256(
                plan_path.encode("utf-8")
            ).hexdigest()[:16]

        # Auto-compute if not explicitly provided
        if policy_content_hash is None:
            policy_content_hash = _compute_policy_content_hash(policy_path)
        if policy_family is None:
            policy_family = _classify_policy(policy_path)

        risk_summary: dict[str, Any] = result.get("risk_summary", {})
        governance_objective: dict[str, Any] = result.get(
            "governance_objective", {}
        )
        objective_statement = governance_objective.get("statement")
        objective_hash = hash_objective_statement(objective_statement)

        conn = init_governance_db(db_path)

        # Extract condition trace + analyzer scores for
        # aggregate analytics (verdict audit reads these
        # directly from governance_records, avoiding a full
        # evidence artifact load per record).
        trace: list[dict[str, Any]] = result.get("trace", [])
        failed_condition_ids = [
            t.get("condition_id", "")
            for t in trace
            if not t.get("result", True)
        ]
        passed_condition_ids = [
            t.get("condition_id", "")
            for t in trace
            if t.get("result", True)
        ]
        analyzer_scores_json = json.dumps(
            risk_summary.get("analyzer_scores", {}), default=str
        )

        # Best-effort "who ran this" and "on what machine" —
        # see telemetry/identity.py. NOT authentication.
        # executed_by separate from user_role (--role), which
        # is a claimed authorization level, not an identity.
        # execution_host is hostname only — never IP/location.
        executed_by = resolve_actor_identity()
        execution_host = resolve_execution_host()

        conn.execute(
            """
            INSERT INTO governance_records (
                record_id, policy_name, policy_content_hash,
                policy_family, artifact_hash,
                governance_objective_statement,
                governance_objective_hash,
                decision, conditions_passed, overall_risk_score,
                effective_severity, governance_severity,
                override_possible, requires_approval,
                plan_hash, user_role, verdict_version,
                executed_by, execution_host,
                created_at, analyzer_scores, failed_conditions,
                passed_conditions, is_risk_acceptance_candidate,
                current_history_number,
                current_history_category, current_history_action
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1,
                'decision', 'created'
            )
            """,
            (
                record_id,
                result.get("policy", ""),
                policy_content_hash,
                policy_family,
                artifact_hash,
                objective_statement,
                objective_hash,
                result.get("decision", ""),
                1 if result.get("conditions_passed") else 0,
                risk_summary.get("overall_risk_score", 0),
                risk_summary.get("effective_severity", ""),
                result.get("governance_severity", ""),
                1 if result.get("override_possible") else 0,
                1 if result.get("requires_approval") else 0,
                plan_hash,
                None,  # user_role — reserved
                verdict_version,
                executed_by,
                execution_host,
                timestamp,
                analyzer_scores_json,
                json.dumps(failed_condition_ids, default=str),
                json.dumps(passed_condition_ids, default=str),
                1 if (
                    result.get("decision", "") == "DENY_WITH_OVERRIDE"
                    and result.get("override_possible")
                ) else 0,
            ),
        )

        history_data = {
            "decision": result.get("decision", ""),
            "policy": result.get("policy", ""),
        }
        history_hash = _hash_history_data(history_data)

        conn.execute(
            """
            INSERT INTO governance_history (
                history_id, record_id, history_number,
                history_category, history_action,
                history_data, history_hash,
                prev_history_hash, actor_role, created_at
            ) VALUES (?, ?, 1, 'decision', 'created', ?, ?, NULL, ?, ?)
            """,
            (
                str(uuid.uuid4()),
                record_id,
                json.dumps(history_data, default=str),
                history_hash,
                result.get("_actor_role"),
                timestamp,
            ),
        )

        conn.commit()
        return True

    except Exception:
        return False

    finally:
        if conn is not None:
            conn.close()


# =====================================================
# WRITE — Governance Evidence
# =====================================================


def record_governance_evidence(
    record_id: str,
    evidence: dict[str, Any],
    evidence_type: str = "evaluation",
    db_path: Path | None = None,
) -> bool:
    """
    Store a full evidence payload linked to a governance record.
    Renamed from record_artifact() (v0.5.2) — same behavior,
    writing to governance_evidence instead of decision_artifacts.

    Returns:
        True if written, False if telemetry disabled or write
        failed. Never raises.
    """
    if not is_telemetry_enabled():
        return False

    conn = None
    try:
        evidence_json = json.dumps(evidence, default=str)
        evidence_hash = hashlib.sha256(
            evidence_json.encode("utf-8")
        ).hexdigest()[:16]

        conn = init_governance_db(db_path)
        conn.execute(
            """
            INSERT INTO governance_evidence (
                evidence_id, record_id, evidence_type,
                evidence_json, evidence_hash, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()),
                record_id,
                evidence_type,
                evidence_json,
                evidence_hash,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        conn.commit()
        return True

    except Exception:
        return False

    finally:
        if conn is not None:
            conn.close()


def get_governance_evidence(
    record_id: str,
    evidence_type: str = "evaluation",
    db_path: Path | None = None,
) -> dict[str, Any] | None:
    """
    Retrieve the most recent evidence payload for a record,
    parsed back into a dict. Renamed from get_artifact() (v0.5.2).

    Returns None if no evidence exists for this record_id and
    evidence_type, or if parsing fails.
    """
    conn = None
    try:
        conn = init_governance_db(db_path)
        cursor = conn.execute(
            """
            SELECT evidence_json FROM governance_evidence
            WHERE record_id = ? AND evidence_type = ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (record_id, evidence_type),
        )
        row = cursor.fetchone()

        if not row:
            return None

        return json.loads(row["evidence_json"])

    except Exception:
        return None

    finally:
        if conn is not None:
            conn.close()


def get_governance_evidence_metadata(
    record_id: str,
    evidence_type: str = "evaluation",
    db_path: Path | None = None,
) -> dict[str, Any] | None:
    """
    Retrieve evidence metadata (hash, timestamp) without the
    full payload. Renamed from get_artifact_metadata() (v0.5.2).
    Powers the Evidence section of verdict explain.
    """
    conn = None
    try:
        conn = init_governance_db(db_path)
        cursor = conn.execute(
            """
            SELECT evidence_hash, created_at FROM governance_evidence
            WHERE record_id = ? AND evidence_type = ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (record_id, evidence_type),
        )
        row = cursor.fetchone()

        if not row:
            return None

        return {
            "evidence_hash": row["evidence_hash"],
            "created_at": row["created_at"],
        }

    except Exception:
        return None

    finally:
        if conn is not None:
            conn.close()


# =====================================================
# WRITE — Add a Governance History Entry
# =====================================================


def add_history_entry(
    record_id: str,
    history_category: str,
    history_action: str,
    history_data: dict[str, Any],
    actor_role: str | None = None,
    actor_identity: str | None = None,
    execution_host: str | None = None,
    db_path: Path | None = None,
) -> bool:
    """
    Append a new entry to a governance record's history.

    This is the single mutation mechanism for a record's
    entire lifecycle — override requests/approvals, approval
    decisions, outcome observations, drift detection, evidence
    additions, and any future event type — all use this one
    function.

    history_category + history_action are split so queries
    stay simple as new event types accumulate. "Every
    override-related event" is WHERE history_category =
    'override' — no growing IN (...) list to maintain.

    Args:
        record_id:         the governance record this entry
                           applies to
        history_category:  decision | override | approval |
                           outcome | drift | evidence
        history_action:     created | requested | approved |
                           denied | revoked | observed |
                           detected | resolved
        history_data:        type-specific JSON-serializable
                           payload
        actor_role:          claimed authorization role
                           (e.g. "budget_owner") — who or
                           what CLAIMS to have triggered this
        actor_identity:      best-effort resolved identity
                           (see telemetry/identity.py) — WHO
                           actually ran the command. Auto-
                           resolved via resolve_actor_identity()
                           if not explicitly provided. NOT
                           authentication — a signal, not a
                           security control.
        db_path:              optional path override (for testing)

    Returns:
        True if written, False if telemetry disabled, the
        parent record does not exist, or the write failed.
        Never raises.
    """
    if not is_telemetry_enabled():
        return False

    if actor_identity is None:
        actor_identity = resolve_actor_identity()
    if execution_host is None:
        execution_host = resolve_execution_host()

    conn = None
    try:
        conn = init_governance_db(db_path)

        parent = conn.execute(
            "SELECT record_id FROM governance_records WHERE record_id = ?",
            (record_id,),
        ).fetchone()
        if parent is None:
            return False

        history_number = _get_next_history_number(conn, record_id)
        prev_hash = _get_latest_history_hash(conn, record_id)
        history_hash = _hash_history_data(history_data)
        timestamp = datetime.now(timezone.utc).isoformat()

        conn.execute(
            """
            INSERT INTO governance_history (
                history_id, record_id, history_number,
                history_category, history_action,
                history_data, history_hash,
                prev_history_hash, actor_role, actor_identity,
                execution_host, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()),
                record_id,
                history_number,
                history_category,
                history_action,
                json.dumps(history_data, default=str),
                history_hash,
                prev_hash,
                actor_role,
                actor_identity,
                execution_host,
                timestamp,
            ),
        )

        conn.execute(
            """
            UPDATE governance_records
            SET current_history_number = ?,
                current_history_category = ?,
                current_history_action = ?
            WHERE record_id = ?
            """,
            (history_number, history_category, history_action, record_id),
        )

        conn.commit()
        return True

    except Exception:
        return False

    finally:
        if conn is not None:
            conn.close()


# =====================================================
# READ — Governance Record
# =====================================================


def get_governance_record(
    record_id: str,
    db_path: Path | None = None,
) -> dict[str, Any] | None:
    """
    Return a single governance record by ID. Does NOT include
    history — use get_governance_history() for that.

    Returns None if the record does not exist or on read error.
    """
    conn = None
    try:
        conn = init_governance_db(db_path)
        cursor = conn.execute(
            "SELECT * FROM governance_records WHERE record_id = ?",
            (record_id,),
        )
        row = cursor.fetchone()

        if not row:
            return None

        return dict(row)

    except Exception:
        return None

    finally:
        if conn is not None:
            conn.close()


def get_governance_history(
    record_id: str,
    history_category: str | None = None,
    db_path: Path | None = None,
) -> list[dict[str, Any]]:
    """
    Return the full history for a governance record, oldest
    first. Each entry includes its parsed history_data.

    Args:
        record_id:         the governance record
        history_category:  optional filter, e.g. "override" to
                           see only override-related events
        db_path:             optional path override (for testing)

    Returns an empty list if the record has no history or on
    read error. Never raises.
    """
    conn = None
    try:
        conn = init_governance_db(db_path)

        if history_category:
            cursor = conn.execute(
                """
                SELECT * FROM governance_history
                WHERE record_id = ? AND history_category = ?
                ORDER BY history_number ASC
                """,
                (record_id, history_category),
            )
        else:
            cursor = conn.execute(
                """
                SELECT * FROM governance_history
                WHERE record_id = ?
                ORDER BY history_number ASC
                """,
                (record_id,),
            )

        rows = [dict(row) for row in cursor.fetchall()]

        for row in rows:
            try:
                row["history_data"] = json.loads(row["history_data"])
            except (json.JSONDecodeError, TypeError):
                pass

        return rows

    except Exception:
        return []

    finally:
        if conn is not None:
            conn.close()


def verify_history_chain(
    record_id: str,
    db_path: Path | None = None,
) -> dict[str, Any]:
    """
    Verify the tamper-evidence chain for a record's history.
    Recomputes each entry's hash from its stored data and
    confirms prev_history_hash links match.

    Returns:
        dict with "verified" (bool), "history_count" (int),
        and "broken_at" (int | None — the history_number
        where verification first failed, if any).
    """
    conn = None
    try:
        conn = init_governance_db(db_path)
        cursor = conn.execute(
            """
            SELECT history_number, history_data, history_hash,
                   prev_history_hash
            FROM governance_history
            WHERE record_id = ?
            ORDER BY history_number ASC
            """,
            (record_id,),
        )
        rows = [dict(row) for row in cursor.fetchall()]

        if not rows:
            return {"verified": True, "history_count": 0, "broken_at": None}

        expected_prev_hash: str | None = None

        for row in rows:
            try:
                data = json.loads(row["history_data"])
            except (json.JSONDecodeError, TypeError):
                data = row["history_data"]

            recomputed_hash = _hash_history_data(
                data if isinstance(data, dict) else {"_raw": data}
            )

            if recomputed_hash != row["history_hash"]:
                return {
                    "verified": False,
                    "history_count": len(rows),
                    "broken_at": row["history_number"],
                }

            if row["prev_history_hash"] != expected_prev_hash:
                return {
                    "verified": False,
                    "history_count": len(rows),
                    "broken_at": row["history_number"],
                }

            expected_prev_hash = row["history_hash"]

        return {"verified": True, "history_count": len(rows), "broken_at": None}

    except Exception:
        return {"verified": False, "history_count": 0, "broken_at": None}

    finally:
        if conn is not None:
            conn.close()


# =====================================================
# READ — Aggregate / Relational Queries
# =====================================================


def get_records_by_objective(
    governance_objective_statement: str,
    db_path: Path | None = None,
) -> list[dict[str, Any]]:
    """
    Return all governance records sharing a given governance
    objective, newest first. Queries by objective_hash
    internally for consistent, efficient grouping — pass the
    human-readable statement, the hash lookup is automatic.

    This is the query that makes governance analytics possible:
    "show me every decision made in service of this objective."
    """
    conn = None
    try:
        objective_hash = hash_objective_statement(governance_objective_statement)
        if objective_hash is None:
            return []

        conn = init_governance_db(db_path)
        cursor = conn.execute(
            """
            SELECT * FROM governance_records
            WHERE governance_objective_hash = ?
            ORDER BY created_at DESC
            """,
            (objective_hash,),
        )
        rows = [dict(row) for row in cursor.fetchall()]
        return rows
    except Exception:
        return []

    finally:
        if conn is not None:
            conn.close()


def get_records_by_policy(
    policy_content_hash: str,
    db_path: Path | None = None,
) -> list[dict[str, Any]]:
    """
    Return all governance records sharing a given policy
    content hash, newest first. Portable across machines.
    """
    conn = None
    try:
        conn = init_governance_db(db_path)
        cursor = conn.execute(
            """
            SELECT * FROM governance_records
            WHERE policy_content_hash = ?
            ORDER BY created_at DESC
            """,
            (policy_content_hash,),
        )
        rows = [dict(row) for row in cursor.fetchall()]
        return rows
    except Exception:
        return []

    finally:
        if conn is not None:
            conn.close()


def resolve_record_id(
    short_or_full_id: str,
    db_path: Path | None = None,
) -> str | None:
    """
    Resolve a short decision ID prefix (e.g. the first 8
    characters, as shown in verdict evaluate's output footer)
    to a full record_id.

    If short_or_full_id is already a full UUID matching a
    stored record, returns it unchanged. Otherwise searches
    recent records for a unique prefix match.

    Shared by verdict explain, verdict override, and any
    future command needing the same short-ID lookup — kept
    here as a single public function rather than duplicated
    privately in each CLI command module.

    Returns None if no match is found, or if the prefix
    matches more than one record (ambiguous).
    """
    exact = get_governance_record(short_or_full_id, db_path=db_path)
    if exact is not None:
        return short_or_full_id

    conn = None
    try:
        conn = init_governance_db(db_path)
        cursor = conn.execute(
            "SELECT record_id FROM governance_records "
            "ORDER BY created_at DESC LIMIT 500"
        )
        recent_ids = [row["record_id"] for row in cursor.fetchall()]
    except Exception:
        return None
    finally:
        if conn is not None:
            conn.close()

    matches = [rid for rid in recent_ids if rid.startswith(short_or_full_id)]

    if len(matches) == 1:
        return matches[0]

    return None


def get_most_recent_record(
    db_path: Path | None = None,
) -> dict[str, Any] | None:
    """
    Return the single most recently created governance record.

    Powers verdict sentinel scan's default comparison target
    when no --decision-id is explicitly provided.
    """
    conn = None
    try:
        conn = init_governance_db(db_path)
        cursor = conn.execute(
            "SELECT * FROM governance_records ORDER BY created_at DESC LIMIT 1"
        )
        row = cursor.fetchone()
        return dict(row) if row else None
    except Exception:
        return None

    finally:
        if conn is not None:
            conn.close()


def get_recent_records(
    limit: int = 50,
    db_path: Path | None = None,
) -> list[dict[str, Any]]:
    """
    Return the most recent governance records, newest first.
    Powers the decision history section of verdict audit.
    """
    conn = None
    try:
        conn = init_governance_db(db_path)
        cursor = conn.execute(
            "SELECT * FROM governance_records ORDER BY created_at DESC LIMIT ?",
            (limit,),
        )
        rows = [dict(row) for row in cursor.fetchall()]
        return rows
    except Exception:
        return []

    finally:
        if conn is not None:
            conn.close()


# =====================================================
# READ — Aggregate Analytics (powers verdict audit)
# =====================================================


def get_policy_effectiveness(
    policy_name: str | None = None,
    db_path: Path | None = None,
) -> list[dict[str, Any]]:
    """
    Return per-policy effectiveness summaries: evaluation
    counts, denial counts, and override/approval counts
    (counted from governance_history, category='override'
    or 'approval').

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
                COUNT(DISTINCT CASE WHEN h.history_category = 'override'
                    THEN h.history_id END) as override_count,
                COUNT(DISTINCT CASE WHEN h.history_category = 'approval'
                    THEN h.history_id END) as approval_count,
                MAX(r.created_at) as last_evaluation
            FROM governance_records r
            LEFT JOIN governance_history h ON h.record_id = r.record_id
        """

        if policy_name:
            query = base_query + " WHERE r.policy_name = ? GROUP BY r.policy_name"
            cursor = conn.execute(query, (policy_name,))
        else:
            query = (
                base_query
                + " GROUP BY r.policy_name ORDER BY total_evaluations DESC"
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
    (analyzer) across the 500 most recent records.

    Powers the risk summary section of verdict audit.
    analyzer_scores is stored as JSON per record and
    unpacked here for domain-level aggregation.
    """
    conn = None
    try:
        conn = init_governance_db(db_path)
        cursor = conn.execute(
            """
            SELECT decision, analyzer_scores
            FROM governance_records
            ORDER BY created_at DESC
            LIMIT 500
            """
        )
        rows = [dict(row) for row in cursor.fetchall()]

        if not rows:
            return {}

        domain_scores: dict[str, list[int]] = {}
        total_count = len(rows)
        deny_total = sum(1 for r in rows if "DENY" in (r["decision"] or ""))

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
                    "rate": round(
                        count / evaluated_counts[cid] * 100, 1
                    ) if evaluated_counts.get(cid) else 0.0,
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
                    "rate": round(
                        count / evaluated_counts[cid] * 100, 1
                    ) if evaluated_counts.get(cid) else 0.0,
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


def get_risk_acceptance_records(
    db_path: Path | None = None,
) -> list[dict[str, Any]]:
    """
    Return governance records that represent CONFIRMED risk
    acceptance — a DENY_WITH_OVERRIDE decision that was
    subsequently approved via an OVERRIDE_APPROVED entry in
    governance_history.

    This is the foundation query for the Risk Acceptance
    Ledger (v0.6.0 architecture phase). A record being
    is_risk_acceptance_candidate=1 only means it COULD become
    a risk acceptance — this function confirms it actually
    was, by joining against the approval event.

    Each returned record includes an "accepted_by" field
    (the actor_role from the approving OVERRIDE_APPROVED
    entry, if resolved — NOT authentication, best-effort only),
    "accepted_by_role" (the claimed --role at approval time),
    and "accepted_at" (that entry's created_at).

    Returns newest first. Empty list on error or if no
    confirmed risk acceptances exist yet.
    """
    conn = None
    try:
        conn = init_governance_db(db_path)
        cursor = conn.execute(
            """
            SELECT
                r.*,
                h.actor_role as accepted_by_role,
                h.actor_identity as accepted_by,
                h.created_at as accepted_at
            FROM governance_records r
            JOIN governance_history h ON h.record_id = r.record_id
            WHERE r.is_risk_acceptance_candidate = 1
              AND h.history_category = 'override'
              AND h.history_action = 'approved'
            ORDER BY h.created_at DESC
            """
        )
        rows = [dict(row) for row in cursor.fetchall()]
        return rows
    except Exception:
        return []

    finally:
        if conn is not None:
            conn.close()


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
            [
                {"outcome_type": k, "count": v}
                for k, v in outcome_counts.items()
            ],
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
            for (policy_name, decision, outcome_type), count
            in correlation_counts.items()
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


# Decision classification for objective summary folding.
# Mirrors engine/governance_objective.py's mapping exactly —
# kept as a local copy here rather than imported, since
# governance_store.py must not depend on engine/ (storage
# layer stays independent of evaluation logic).
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
    records = get_records_by_objective(
        governance_objective_statement, db_path=db_path
    )

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
        1 for r in records
        if _classify_for_objective_summary(r.get("decision", "")) == "upheld"
    )
    violated_count = sum(
        1 for r in records
        if _classify_for_objective_summary(r.get("decision", "")) == "violated"
    )
    pending_count = sum(
        1 for r in records
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
            1 for r in recent
            if _classify_for_objective_summary(r.get("decision", "")) == "upheld"
        )
        older_upheld = sum(
            1 for r in older
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
