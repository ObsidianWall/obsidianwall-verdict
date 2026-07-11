# telemetry/governance_store.py
#
# Purpose:
# Sentinel's governance record store — the organization's
# governance memory. Replaces the decisions, overrides,
# approvals, and outcomes tables from v0.5.x with a single
# object model: governance_records (the stable, queryable
# object) + governance_record_revisions (the append-only
# mutation log).
#
# See docs/architecture/sentinel-architecture-v1.md (private)
# for the full design rationale.
#
# Object model:
#   governance_records            Lean, queryable. One row per
#                                 governance decision. Identity,
#                                 intent, decision, routing.
#   governance_record_revisions   Append-only. Every subsequent
#                                 mutation — override, approval,
#                                 outcome, drift — is a new
#                                 revision. Nothing is ever
#                                 updated in place.
#   decision_artifacts            UNCHANGED from v0.5.2. Full
#                                 JSON payload, referenced by
#                                 artifact_hash on the record.
#
# Migration:
# v0.6.0 is a clean cutover, not a dual-write period. See
# scripts/migrate_to_governance_records.py for the one-time
# migration of any existing decisions.db data. Old tables
# (decisions, overrides, approvals, outcomes) are dropped
# after migration completes successfully.
#
# Tamper-evidence:
# Each revision's hash is chained to the previous revision's
# hash for the same record (revision_hash / prev_revision_hash).
# This detects — not cryptographically prevents — tampering
# with local history. It does not use external signing or
# notarization. See "Deferred Decisions" in the architecture
# doc for the reasoning.

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
-- Governance Record.
-- The stable, queryable object. One row per governance
-- decision. Lean enough for fast aggregate queries — full
-- detail lives in decision_artifacts (referenced by
-- artifact_hash) and in the revision history.
CREATE TABLE IF NOT EXISTS governance_records (
    record_id                       TEXT PRIMARY KEY,

    -- Identity
    policy_name                      TEXT NOT NULL,
    policy_content_hash               TEXT,
    policy_family                       TEXT,
    artifact_hash                        TEXT,

    -- Intent
    governance_objective_statement        TEXT,

    -- Decision
    decision                                TEXT NOT NULL,
    conditions_passed                        INTEGER NOT NULL DEFAULT 0,
    overall_risk_score                        INTEGER NOT NULL DEFAULT 0,
    effective_severity                         TEXT,
    governance_severity                         TEXT,

    -- Routing (as of creation — revisions capture changes)
    override_possible                            INTEGER NOT NULL DEFAULT 0,
    requires_approval                             INTEGER NOT NULL DEFAULT 0,

    -- Relationships — indexed columns, not a graph store
    plan_hash                                      TEXT,
    user_role                                       TEXT,

    -- Metadata
    verdict_version                                  TEXT,
    created_at                                        TEXT NOT NULL,

    -- Denormalized cache of latest revision — the record
    -- remains first-class; this avoids a join for the
    -- common "what's the current state" read.
    current_revision_number                            INTEGER NOT NULL DEFAULT 1,
    current_revision_type                               TEXT NOT NULL DEFAULT 'CREATED'
);

CREATE INDEX IF NOT EXISTS idx_gov_records_policy_name
    ON governance_records(policy_name);
CREATE INDEX IF NOT EXISTS idx_gov_records_policy_content_hash
    ON governance_records(policy_content_hash);
CREATE INDEX IF NOT EXISTS idx_gov_records_objective
    ON governance_records(governance_objective_statement);
CREATE INDEX IF NOT EXISTS idx_gov_records_decision
    ON governance_records(decision);
CREATE INDEX IF NOT EXISTS idx_gov_records_created_at
    ON governance_records(created_at);

-- Revision History.
-- Append-only. Every mutation to a record's state is a new
-- revision — override requested, outcome observed, drift
-- detected. Nothing is ever updated in place. Replaces the
-- separate overrides, approvals, and outcomes tables from
-- v0.5.x with one uniform mutation log.
CREATE TABLE IF NOT EXISTS governance_record_revisions (
    revision_id             TEXT PRIMARY KEY,
    record_id                 TEXT NOT NULL,
    revision_number             INTEGER NOT NULL,

    revision_type                 TEXT NOT NULL,
    -- Open-ended values — new types need no schema change:
    --   CREATED
    --   OVERRIDE_REQUESTED / OVERRIDE_APPROVED /
    --   OVERRIDE_DENIED / OVERRIDE_REVOKED
    --   APPROVAL_REQUESTED / APPROVAL_GRANTED /
    --   APPROVAL_DENIED
    --   OUTCOME_OBSERVED / DRIFT_DETECTED / DRIFT_RESOLVED
    --   EVIDENCE_ADDED / RE_EVALUATED

    revision_data                   TEXT NOT NULL,
    revision_hash                     TEXT NOT NULL,
    prev_revision_hash                  TEXT,

    actor_role                            TEXT,
    created_at                              TEXT NOT NULL,

    FOREIGN KEY (record_id) REFERENCES governance_records(record_id)
);

CREATE INDEX IF NOT EXISTS idx_revisions_record_id
    ON governance_record_revisions(record_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_revisions_record_seq
    ON governance_record_revisions(record_id, revision_number);
"""


# =====================================================
# DATABASE INITIALIZATION
# =====================================================


def init_governance_db(db_path: Path | None = None) -> sqlite3.Connection:
    """
    Initialize the governance record schema. Safe to call
    on every operation — CREATE TABLE IF NOT EXISTS makes
    this idempotent.

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
# HASHING HELPERS
# =====================================================


def _hash_revision_data(revision_data: dict[str, Any]) -> str:
    """
    Compute a SHA-256 hash of revision data for tamper-evidence.
    Uses sorted keys so semantically identical data always
    produces the same hash regardless of dict ordering.
    """
    serialized = json.dumps(revision_data, sort_keys=True, default=str)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _get_latest_revision_hash(
    conn: sqlite3.Connection,
    record_id: str,
) -> str | None:
    """
    Return the revision_hash of the most recent revision for
    a record, or None if this will be the first revision.
    """
    cursor = conn.execute(
        """
        SELECT revision_hash FROM governance_record_revisions
        WHERE record_id = ?
        ORDER BY revision_number DESC
        LIMIT 1
        """,
        (record_id,),
    )
    row = cursor.fetchone()
    return row["revision_hash"] if row else None


def _get_next_revision_number(
    conn: sqlite3.Connection,
    record_id: str,
) -> int:
    """Return the next sequential revision_number for a record."""
    cursor = conn.execute(
        """
        SELECT MAX(revision_number) as max_rev
        FROM governance_record_revisions
        WHERE record_id = ?
        """,
        (record_id,),
    )
    row = cursor.fetchone()
    max_rev = row["max_rev"] if row and row["max_rev"] is not None else 0
    return max_rev + 1


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
    Create a new governance record and its first revision
    (CREATED). This is the entry point Verdict calls at the
    end of evaluate() — it replaces record_decision() +
    record_artifact() from v0.5.x with a single call that
    writes both the record and the initial revision
    atomically.

    Args:
        result:               complete verdict evaluate result dict
        plan_path:             path to the Terraform plan or
                               CloudFormation template
        policy_path:            path to the policy YAML file
        policy_content_hash:     precomputed content hash, if
                               already available from the caller
        policy_family:            precomputed family classification
        artifact_hash:             hash of the full artifact, if
                               already computed by the evidence
                               store write
        verdict_version:            the running Verdict version string
        db_path:                     optional path override (for testing)

    Returns:
        True if written, False if telemetry disabled or write
        failed. Never raises — governance recording must not
        crash the CLI.
    """
    if not is_telemetry_enabled():
        return False

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

        risk_summary: dict[str, Any] = result.get("risk_summary", {})
        governance_objective: dict[str, Any] = result.get(
            "governance_objective", {}
        )

        conn = init_governance_db(db_path)

        conn.execute(
            """
            INSERT INTO governance_records (
                record_id, policy_name, policy_content_hash,
                policy_family, artifact_hash,
                governance_objective_statement,
                decision, conditions_passed, overall_risk_score,
                effective_severity, governance_severity,
                override_possible, requires_approval,
                plan_hash, user_role, verdict_version,
                created_at, current_revision_number,
                current_revision_type
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 'CREATED'
            )
            """,
            (
                record_id,
                result.get("policy", ""),
                policy_content_hash,
                policy_family,
                artifact_hash,
                governance_objective.get("statement"),
                result.get("decision", ""),
                1 if result.get("conditions_passed") else 0,
                risk_summary.get("overall_risk_score", 0),
                risk_summary.get("effective_severity", ""),
                result.get("governance_severity", ""),
                1 if result.get("override_possible") else 0,
                1 if result.get("requires_approval") else 0,
                plan_hash,
                None,  # user_role — reserved, matches v0.5.x pattern
                verdict_version,
                timestamp,
            ),
        )

        # First revision: CREATED
        revision_data = {
            "decision": result.get("decision", ""),
            "policy": result.get("policy", ""),
        }
        revision_hash = _hash_revision_data(revision_data)

        conn.execute(
            """
            INSERT INTO governance_record_revisions (
                revision_id, record_id, revision_number,
                revision_type, revision_data, revision_hash,
                prev_revision_hash, actor_role, created_at
            ) VALUES (?, ?, 1, 'CREATED', ?, ?, NULL, ?, ?)
            """,
            (
                str(uuid.uuid4()),
                record_id,
                json.dumps(revision_data, default=str),
                revision_hash,
                result.get("_actor_role"),
                timestamp,
            ),
        )

        conn.commit()
        conn.close()
        return True

    except Exception:
        return False


# =====================================================
# WRITE — Add a Revision
# =====================================================


def add_revision(
    record_id: str,
    revision_type: str,
    revision_data: dict[str, Any],
    actor_role: str | None = None,
    db_path: Path | None = None,
) -> bool:
    """
    Append a new revision to a governance record's history.

    This is the single mutation mechanism for a governance
    record's entire lifecycle — override requests/approvals,
    approval decisions, outcome observations, drift detection,
    evidence additions, and any future mutation type — all use
    this one function. New revision_type values require no
    schema change.

    The revision is chained to the previous revision via
    prev_revision_hash for tamper-evidence: altering any past
    revision's content breaks every hash after it.

    Also updates the denormalized current_revision_number and
    current_revision_type on the parent record, so common reads
    ("what's the latest state") don't require a join.

    Args:
        record_id:      the governance record this revision
                        applies to
        revision_type:  a value from the open-ended set
                        documented in the schema comment
                        (CREATED, OVERRIDE_REQUESTED,
                        OUTCOME_OBSERVED, DRIFT_DETECTED, etc.)
        revision_data:  type-specific JSON-serializable payload
        actor_role:     who or what triggered this revision
                        (engineer, budget_owner, sentinel-scan,
                        system)
        db_path:        optional path override (for testing)

    Returns:
        True if written, False if telemetry disabled, the
        parent record does not exist, or the write failed.
        Never raises — must not crash the caller.
    """
    if not is_telemetry_enabled():
        return False

    try:
        conn = init_governance_db(db_path)

        # Confirm parent record exists — FK constraint would
        # catch this too, but checking explicitly gives a
        # clean False return instead of relying on the
        # exception path for an expected condition.
        parent = conn.execute(
            "SELECT record_id FROM governance_records WHERE record_id = ?",
            (record_id,),
        ).fetchone()
        if parent is None:
            conn.close()
            return False

        revision_number = _get_next_revision_number(conn, record_id)
        prev_hash = _get_latest_revision_hash(conn, record_id)
        revision_hash = _hash_revision_data(revision_data)
        timestamp = datetime.now(timezone.utc).isoformat()

        conn.execute(
            """
            INSERT INTO governance_record_revisions (
                revision_id, record_id, revision_number,
                revision_type, revision_data, revision_hash,
                prev_revision_hash, actor_role, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()),
                record_id,
                revision_number,
                revision_type,
                json.dumps(revision_data, default=str),
                revision_hash,
                prev_hash,
                actor_role,
                timestamp,
            ),
        )

        # Update the denormalized "current state" cache on
        # the parent record.
        conn.execute(
            """
            UPDATE governance_records
            SET current_revision_number = ?,
                current_revision_type = ?
            WHERE record_id = ?
            """,
            (revision_number, revision_type, record_id),
        )

        conn.commit()
        conn.close()
        return True

    except Exception:
        return False


# =====================================================
# READ — Governance Record
# =====================================================


def get_governance_record(
    record_id: str,
    db_path: Path | None = None,
) -> dict[str, Any] | None:
    """
    Return a single governance record by ID.

    Does NOT include revision history — use get_revision_history()
    for that. This keeps the common "what is this record" read
    fast, matching the "lean record, heavy history on demand"
    design principle.

    Returns None if the record does not exist or on read error.
    """
    try:
        conn = init_governance_db(db_path)
        cursor = conn.execute(
            "SELECT * FROM governance_records WHERE record_id = ?",
            (record_id,),
        )
        row = cursor.fetchone()
        conn.close()

        if not row:
            return None

        return dict(row)

    except Exception:
        return None


def get_revision_history(
    record_id: str,
    db_path: Path | None = None,
) -> list[dict[str, Any]]:
    """
    Return the full revision history for a governance record,
    oldest first. Each revision includes its parsed revision_data.

    Returns an empty list if the record has no revisions or
    on read error. Never raises.
    """
    try:
        conn = init_governance_db(db_path)
        cursor = conn.execute(
            """
            SELECT * FROM governance_record_revisions
            WHERE record_id = ?
            ORDER BY revision_number ASC
            """,
            (record_id,),
        )
        rows = [dict(row) for row in cursor.fetchall()]
        conn.close()

        for row in rows:
            try:
                row["revision_data"] = json.loads(row["revision_data"])
            except (json.JSONDecodeError, TypeError):
                pass  # Leave as raw string if parse fails

        return rows

    except Exception:
        return []


def verify_revision_chain(
    record_id: str,
    db_path: Path | None = None,
) -> dict[str, Any]:
    """
    Verify the tamper-evidence chain for a record's revision
    history. Recomputes each revision's hash from its stored
    data and confirms prev_revision_hash links match.

    Returns:
        dict with:
          "verified": bool — True if the entire chain is intact
          "revision_count": int
          "broken_at_revision": int | None — the revision_number
              where verification first failed, if any
    """
    try:
        conn = init_governance_db(db_path)
        cursor = conn.execute(
            """
            SELECT revision_number, revision_data, revision_hash,
                   prev_revision_hash
            FROM governance_record_revisions
            WHERE record_id = ?
            ORDER BY revision_number ASC
            """,
            (record_id,),
        )
        rows = [dict(row) for row in cursor.fetchall()]
        conn.close()

        if not rows:
            return {
                "verified": True,
                "revision_count": 0,
                "broken_at_revision": None,
            }

        expected_prev_hash: str | None = None

        for row in rows:
            try:
                data = json.loads(row["revision_data"])
            except (json.JSONDecodeError, TypeError):
                data = row["revision_data"]

            recomputed_hash = _hash_revision_data(
                data if isinstance(data, dict) else {"_raw": data}
            )

            if recomputed_hash != row["revision_hash"]:
                return {
                    "verified": False,
                    "revision_count": len(rows),
                    "broken_at_revision": row["revision_number"],
                }

            if row["prev_revision_hash"] != expected_prev_hash:
                return {
                    "verified": False,
                    "revision_count": len(rows),
                    "broken_at_revision": row["revision_number"],
                }

            expected_prev_hash = row["revision_hash"]

        return {
            "verified": True,
            "revision_count": len(rows),
            "broken_at_revision": None,
        }

    except Exception:
        return {
            "verified": False,
            "revision_count": 0,
            "broken_at_revision": None,
        }


# =====================================================
# READ — Aggregate / Relational Queries
# =====================================================


def get_records_by_objective(
    governance_objective_statement: str,
    db_path: Path | None = None,
) -> list[dict[str, Any]]:
    """
    Return all governance records sharing a given governance
    objective statement, newest first.

    This is the query that makes governance analytics possible:
    "show me every decision made in service of this objective,"
    the foundation for Compass answering "is this objective
    succeeding?"
    """
    try:
        conn = init_governance_db(db_path)
        cursor = conn.execute(
            """
            SELECT * FROM governance_records
            WHERE governance_objective_statement = ?
            ORDER BY created_at DESC
            """,
            (governance_objective_statement,),
        )
        rows = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return rows
    except Exception:
        return []


def get_records_by_policy(
    policy_content_hash: str,
    db_path: Path | None = None,
) -> list[dict[str, Any]]:
    """
    Return all governance records sharing a given policy
    content hash, newest first. Portable across machines —
    the same policy evaluated on different hosts produces
    the same policy_content_hash.
    """
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
        conn.close()
        return rows
    except Exception:
        return []
