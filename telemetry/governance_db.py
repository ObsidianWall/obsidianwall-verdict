# telemetry/governance_db.py
#
# Purpose:
# Schema, migrations, and connection setup for the governance
# record store. Split out of governance_store.py (which grew
# past 2,000 lines covering schema through Compass analytics)
# so each responsibility has its own focused module. See
# telemetry/governance_store.py for the re-export shim that
# keeps existing imports working unchanged during the
# transition.
#
# Object model, tamper-evidence design, and migration
# strategy are documented in full in the original
# governance_store.py header — not repeated here to avoid
# two copies of the same design rationale drifting apart.

from __future__ import annotations

import sqlite3
from pathlib import Path

from telemetry.config import get_db_path

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
    # Attestation signing — see ADR-0002. Applies to override
    # request/approve/deny history entries. NULL for any entry
    # that predates this migration, or for identity-only
    # entries where signing genuinely was never applicable
    # (e.g. auto-generated 'decision created' entries from
    # verdict evaluate, which no human approves or denies).
    "ALTER TABLE governance_history ADD COLUMN signature TEXT",
    # Base64/armored signature blob. What actually gets
    # signed is history_hash — see verify_signature() below,
    # which ties the signature to the SAME digest already
    # covered by the tamper-evidence hash chain, rather than
    # a second, potentially-divergent representation.
    "ALTER TABLE governance_history ADD COLUMN signing_public_key TEXT",
    # Embedded at signing time, NOT a reference to look one up
    # elsewhere — self-contained verification per ADR-0002.
    # An auditor with nothing but this database file must be
    # able to verify a signature years later, even if the
    # signer's key has since been rotated out of their active
    # keyring.
    "ALTER TABLE governance_history ADD COLUMN signing_key_fingerprint TEXT",
    # For display and for detecting whether the SAME key was
    # used across multiple entries attributed to one identity
    # — the "key consistency" claim ADR-0002 is honest is the
    # real guarantee here, not verified identity binding.
    "ALTER TABLE governance_history ADD COLUMN signing_method TEXT",
    # "gpg" | "ssh" — which SigningBackend produced this
    # signature, so verify_signature() knows which backend's
    # verify() logic to invoke.
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
