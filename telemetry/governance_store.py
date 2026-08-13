# telemetry/governance_store.py
#
# RE-EXPORT SHIM. governance_store.py has been split into
# focused sibling modules (governance_db, governance_hashing,
# governance_records, governance_history, governance_evidence,
# governance_integrity, governance_ledger, governance_audit,
# governance_outcomes, governance_objectives) — see each
# module's own docstring for its specific responsibility.
#
# This file exists so every EXISTING import of
# "from telemetry.governance_store import X" continues to
# work unchanged, including patch() calls that target this
# exact module path.
#
# get_db_path, is_telemetry_enabled, resolve_actor_identity,
# resolve_execution_host, and classify_policy_family are
# re-exported here too, even though this module's OWN logic
# doesn't need them anymore — the ORIGINAL governance_store.py
# imported all five directly into its own namespace, which
# meant `telemetry.governance_store.is_telemetry_enabled` was
# a real, valid attribute — exactly what a large number of
# tests patch by that specific path.
#
# _hash_history_data is re-exported under its OLD private name
# too — CONFIRMED needed by BOTH telemetry/migration.py AND
# cli/commands/override.py, which each import it directly under
# that exact underscore-prefixed name. Dropping this alias
# during an earlier regeneration of this shim broke every
# command that imports from override.py at module load time
# (verdict sentinel scan, verdict ledger, verdict audit
# --insights, verdict evaluate — all of them route through
# cli/main.py, which imports override_app at startup,
# regardless of which subcommand is actually being run).

from __future__ import annotations

from telemetry.config import get_db_path, is_telemetry_enabled
from telemetry.governance_audit import (
    get_domain_risk_summary,
    get_failed_conditions_summary,
    get_passed_conditions_summary,
    get_policy_effectiveness,
)
from telemetry.governance_db import (
    init_governance_db,
)
from telemetry.governance_evidence import (
    get_governance_evidence,
    get_governance_evidence_metadata,
    record_governance_evidence,
)
from telemetry.governance_hashing import (
    hash_history_data,
    hash_objective_statement,
)
from telemetry.governance_history import (
    add_history_entry,
    get_governance_history,
)
from telemetry.governance_integrity import (
    verify_history_chain,
    verify_signature,
)
from telemetry.governance_ledger import (
    get_risk_acceptance_records,
)
from telemetry.governance_objectives import (
    get_objective_summary,
)
from telemetry.governance_outcomes import (
    get_outcome_correlation,
    get_outcome_summary,
)
from telemetry.governance_records import (
    create_governance_record,
    get_governance_record,
    get_most_recent_record,
    get_most_recent_record_for_policy,
    get_recent_records,
    get_records_by_objective,
    get_records_by_policy,
    resolve_record_id,
)
from telemetry.identity import resolve_actor_identity, resolve_execution_host
from telemetry.policy_classifier import classify_policy_family

__all__ = [
    "get_db_path",
    "is_telemetry_enabled",
    "resolve_actor_identity",
    "resolve_execution_host",
    "classify_policy_family",
    "init_governance_db",
    "hash_history_data",
    "hash_objective_statement",
    "create_governance_record",
    "get_governance_record",
    "get_most_recent_record",
    "get_most_recent_record_for_policy",
    "get_records_by_objective",
    "get_records_by_policy",
    "get_recent_records",
    "resolve_record_id",
    "add_history_entry",
    "get_governance_history",
    "get_governance_evidence",
    "get_governance_evidence_metadata",
    "record_governance_evidence",
    "verify_history_chain",
    "verify_signature",
    "get_risk_acceptance_records",
    "get_domain_risk_summary",
    "get_failed_conditions_summary",
    "get_passed_conditions_summary",
    "get_policy_effectiveness",
    "get_outcome_correlation",
    "get_outcome_summary",
    "get_objective_summary",
]
