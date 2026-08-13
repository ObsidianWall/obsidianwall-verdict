# telemetry/governance_records.py
#
# Purpose:
# The canonical Governance Record repository — the stable,
# queryable object representing one governance decision.
# create_governance_record() also writes that record's FIRST
# history entry (category="decision", action="created") in
# the same transaction — see governance_history.py for every
# subsequent lifecycle event.

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from telemetry.config import is_telemetry_enabled
from telemetry.governance_db import init_governance_db
from telemetry.governance_hashing import hash_history_data, hash_objective_statement
from telemetry.identity import resolve_actor_identity, resolve_execution_host
from telemetry.policy_classifier import classify_policy_family


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
        history_hash = hash_history_data(history_data)

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
    Return the single most recently created governance record,
    regardless of which policy produced it.

    NOTE: verdict sentinel scan does NOT use this as its
    default lookup — see get_most_recent_record_for_policy()
    below. Using this unscoped lookup as a default led to a
    real bug: scanning policy A while the most recent decision
    in the whole database happened to be from unrelated
    policy B produced a nonsensical cross-policy comparison
    (e.g. a budget condition appearing to "resolve" simply
    because it was never re-evaluated at all, having nothing
    to do with the policy actually being scanned).
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


def get_most_recent_record_for_policy(
    policy_name: str,
    db_path: Path | None = None,
) -> dict[str, Any] | None:
    """
    Return the most recently created governance record for a
    SPECIFIC policy — the correct default comparison target for
    verdict sentinel scan, fixing the cross-policy comparison
    bug get_most_recent_record() was silently exposed to.

    Args:
        policy_name: the policy's metadata.name — matched
            against governance_records.policy_name exactly.
    """
    conn = None
    try:
        conn = init_governance_db(db_path)
        cursor = conn.execute(
            "SELECT * FROM governance_records "
            "WHERE policy_name = ? "
            "ORDER BY created_at DESC LIMIT 1",
            (policy_name,),
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
