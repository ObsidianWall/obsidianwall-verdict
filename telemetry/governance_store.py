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
    created_at                                 TEXT NOT NULL,

    FOREIGN KEY (record_id) REFERENCES governance_records(record_id)
);

CREATE INDEX IF NOT EXISTS idx_history_record_id
    ON governance_history(record_id);
CREATE INDEX IF NOT EXISTS idx_history_category
    ON governance_history(history_category);
CREATE UNIQUE INDEX IF NOT EXISTS idx_history_record_seq
    ON governance_history(record_id, history_number);

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

CREATE INDEX IF NOT EXISTS idx_evidence_record_id
    ON governance_evidence(record_id);
"""


# =====================================================
# DATABASE INITIALIZATION
# =====================================================


def init_governance_db(db_path: Path | None = None) -> sqlite3.Connection:
    """
    Initialize the governance record schema. Safe to call
    on every operation — CREATE TABLE IF NOT EXISTS makes
    this idempotent.
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
            plan_hash = hashlib.sha256(plan_path.encode("utf-8")).hexdigest()[:16]

        # Auto-compute if not explicitly provided
        if policy_content_hash is None:
            policy_content_hash = _compute_policy_content_hash(policy_path)
        if policy_family is None:
            policy_family = _classify_policy(policy_path)

        risk_summary: dict[str, Any] = result.get("risk_summary", {})
        governance_objective: dict[str, Any] = result.get("governance_objective", {})
        objective_statement = governance_objective.get("statement")
        objective_hash = hash_objective_statement(objective_statement)

        conn = init_governance_db(db_path)

        # Extract condition trace + analyzer scores for
        # aggregate analytics (verdict audit reads these
        # directly from governance_records, avoiding a full
        # evidence artifact load per record).
        trace: list[dict[str, Any]] = result.get("trace", [])
        failed_condition_ids = [
            t.get("condition_id", "") for t in trace if not t.get("result", True)
        ]
        passed_condition_ids = [
            t.get("condition_id", "") for t in trace if t.get("result", True)
        ]
        analyzer_scores_json = json.dumps(
            risk_summary.get("analyzer_scores", {}), default=str
        )

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
                created_at, analyzer_scores, failed_conditions,
                passed_conditions, is_risk_acceptance_candidate,
                current_history_number,
                current_history_category, current_history_action
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1,
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
                timestamp,
                analyzer_scores_json,
                json.dumps(failed_condition_ids, default=str),
                json.dumps(passed_condition_ids, default=str),
                1
                if (
                    result.get("decision", "") == "DENY_WITH_OVERRIDE"
                    and result.get("override_possible")
                )
                else 0,
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
        evidence_hash = hashlib.sha256(evidence_json.encode("utf-8")).hexdigest()[:16]

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
        actor_role:          who or what triggered this entry
        db_path:              optional path override (for testing)

    Returns:
        True if written, False if telemetry disabled, the
        parent record does not exist, or the write failed.
        Never raises.
    """
    if not is_telemetry_enabled():
        return False

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
                prev_history_hash, actor_role, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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

        base_query = """
            SELECT
                r.policy_name,
                COUNT(DISTINCT r.record_id) as total_evaluations,
                SUM(CASE WHEN r.decision IN ('DENY', 'DENY_WITH_OVERRIDE')
                    THEN 1 ELSE 0 END) as total_denied,
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
    """
    conn = None
    try:
        conn = init_governance_db(db_path)
        cursor = conn.execute(
            """
            SELECT failed_conditions FROM governance_records
            WHERE failed_conditions IS NOT NULL
            """
        )
        rows = [dict(row) for row in cursor.fetchall()]

        if not rows:
            return []

        condition_counts: dict[str, int] = {}
        total = len(rows)

        for row in rows:
            try:
                failed: list[str] = json.loads(row.get("failed_conditions") or "[]")
                for cid in failed:
                    if cid:
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

    finally:
        if conn is not None:
            conn.close()


def get_passed_conditions_summary(
    db_path: Path | None = None,
) -> list[dict[str, Any]]:
    """
    Aggregate passed condition counts across all records.
    Powers the "Why allowed?" section of verdict audit.
    """
    conn = None
    try:
        conn = init_governance_db(db_path)
        cursor = conn.execute(
            """
            SELECT passed_conditions FROM governance_records
            WHERE passed_conditions IS NOT NULL
            """
        )
        rows = [dict(row) for row in cursor.fetchall()]

        if not rows:
            return []

        condition_counts: dict[str, int] = {}
        total = len(rows)

        for row in rows:
            try:
                passed: list[str] = json.loads(row.get("passed_conditions") or "[]")
                for cid in passed:
                    if cid:
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
    entry) and "accepted_at" (that entry's created_at).

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
                h.actor_role as accepted_by,
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
            [{"outcome_type": k, "count": v} for k, v in outcome_counts.items()],
            key=lambda x: x["count"],  # type: ignore[return-value]
            reverse=True,
        )

    except Exception:
        return []

    finally:
        if conn is not None:
            conn.close()
