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