# telemetry/governance_ledger.py
#
# Purpose:
# The Risk Acceptance Ledger — CONFIRMED risk acceptance only
# (a DENY_WITH_OVERRIDE decision that was subsequently
# approved). Kept separate from governance_records.py
# deliberately: Ledger semantics ("what risk did the
# organization actually accept, signed and dated") are a
# distinct concern from generic record storage, and this
# module is expected to grow (pending/denied/expired exception
# queries) without generic record CRUD growing alongside it.

from __future__ import annotations

from pathlib import Path
from typing import Any

from telemetry.governance_db import init_governance_db


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
