# telemetry/governance_hashing.py
#
# Purpose:
# Shared hashing helpers used across the governance store
# split. Pulled into their own module rather than left inside
# whichever module happened to define them first, because
# BOTH hash_history_data() and hash_objective_statement() are
# genuine cross-module dependencies — hash_history_data() is
# needed by both governance_records.py (create_governance_record's
# first history entry) and governance_history.py
# (add_history_entry), and hash_objective_statement() is
# needed by governance_records.py, governance_objectives.py,
# AND telemetry/migration.py externally. Leaving either inside
# one of those modules would just relocate the same
# leading-underscore-crossing-a-module-boundary problem that
# existed when migration.py imported hash_history_data
# directly from governance_store.py.
#
# hash_history_data() is renamed here from the original
# hash_history_data — it was never actually private in
# practice (migration.py already imported it across a module
# boundary before this split), so the underscore was
# misleading about its real visibility.

from __future__ import annotations

import hashlib
import json
from typing import Any


def hash_history_data(history_data: dict[str, Any]) -> str:
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
