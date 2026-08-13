# telemetry/__init__.py
#
# ObsidianWall Verdict — Telemetry Package
#
# Local governance history. Enabled by default (opt-out model).
# Disable: export OW_HISTORY_ENABLED=false
#
# v0.6.0: storage moved from telemetry/store.py (deleted —
# confirmed dead code, nothing in production imported it after
# the governance_records/governance_history/governance_evidence
# rewiring) to telemetry/governance_store.py.
#
# Later in v0.6.0, governance_store.py itself was split into
# focused sibling modules (governance_db, governance_hashing,
# governance_records, governance_history, governance_evidence,
# governance_integrity, governance_ledger, governance_audit,
# governance_outcomes, governance_objectives) once it grew past
# 2,000 lines covering ten largely-unrelated responsibilities.
# governance_store.py now exists as a re-export shim so this
# file's imports below — and every other existing caller's —
# continue working unchanged. The imports here deliberately
# still go through that shim rather than the specific new
# modules directly; migrating every caller (this file, audit.py,
# override.py, scan.py, migration.py) to import from the exact
# module each function now lives in is a separate, later pass,
# done all at once so a break during THAT cleanup is never
# confused with a break caused by the split itself.
#
# Core read/write operations are re-exported here for
# convenience (from telemetry import create_governance_record),
# mirroring the old store.py package-level pattern. More
# specialized aggregate/analytics queries (get_policy_effectiveness,
# get_domain_risk_summary, get_outcome_correlation, etc.) are
# accessed via the full module path — from telemetry.governance_store
# import X — since they're used in fewer places (audit.py, Compass)
# and don't need the shorthand.

from telemetry.config import get_db_path, is_telemetry_enabled
from telemetry.governance_store import (
    add_history_entry,
    create_governance_record,
    get_governance_evidence,
    get_governance_history,
    get_governance_record,
    record_governance_evidence,
    verify_history_chain,
)

__all__ = [
    "is_telemetry_enabled",
    "get_db_path",
    "create_governance_record",
    "add_history_entry",
    "get_governance_record",
    "get_governance_history",
    "record_governance_evidence",
    "get_governance_evidence",
    "verify_history_chain",
]
