# telemetry/governance_evidence.py
#
# Purpose:
# Full JSON evidence payloads linked to a governance record
# by record_id + evidence_type. Not limited to Verdict's own
# output — Sentinel, Compass, and future systems can all
# write evidence here. Renamed from decision_artifacts in
# v0.5.2.

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from telemetry.config import is_telemetry_enabled
from telemetry.governance_db import init_governance_db


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
