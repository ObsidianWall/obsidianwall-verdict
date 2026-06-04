# telemetry/__init__.py
#
# ObsidianWall Verdict — Telemetry Package
#
# Opt-in local decision history.
# Disabled by default.
# Enable: export OW_TELEMETRY_ENABLED=true

from telemetry.config import get_db_path, is_telemetry_enabled
from telemetry.store import (
    get_decision_by_id,
    get_domain_risk_summary,
    get_policy_effectiveness,
    get_recent_decisions,
    init_db,
    record_approval,
    record_decision,
    record_override,
)

__all__ = [
    "is_telemetry_enabled",
    "get_db_path",
    "init_db",
    "record_decision",
    "record_override",
    "record_approval",
    "get_recent_decisions",
    "get_policy_effectiveness",
    "get_decision_by_id",
    "get_domain_risk_summary",
]
