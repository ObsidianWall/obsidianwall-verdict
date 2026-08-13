# tests/helpers/telemetry_patching.py
#
# Purpose:
# Centralized telemetry patching for tests, across every
# module that independently binds is_telemetry_enabled and/or
# get_db_path via `from telemetry.config import ...`.
#
# Why this exists:
# Before v0.6.0's governance_store split, patching
# "telemetry.governance_store.is_telemetry_enabled" correctly
# intercepted every call, because every governance function
# lived in that one file and shared its one binding of that
# name. After the split, create_governance_record lives in
# governance_records.py, add_history_entry in
# governance_history.py, get_risk_acceptance_records in
# governance_ledger.py — each with its OWN independent
# `from telemetry.config import is_telemetry_enabled` at its
# own top. Patching only governance_store's copy silently did
# nothing to the others, producing a real, hard-to-diagnose
# bug: functions writing to (or reading from) the real,
# default database instead of the test's isolated tmp_path
# database, with no error — just wrong data.
#
# get_db_path specifically required a SEPARATE fix beyond the
# module list above: unlike is_telemetry_enabled (checked
# independently inside each write function's own body),
# get_db_path is only ever actually CALLED in one place —
# inside governance_db.py's init_governance_db(), via
# `path = db_path or get_db_path()`. Every other module just
# receives db_path as a parameter and passes it through,
# never invoking get_db_path() itself. Missing
# "telemetry.governance_db" from this list meant every real
# CLI command (which never passes an explicit db_path) fell
# through to the REAL default database — the actual cause of
# "No governance decision found" and similarly-confusing
# assertion mismatches against real, pre-existing data.
#
# This is a PARTIAL, immediate fix, not the full long-term
# answer. The real, durable fix is dependency injection —
# these functions should accept telemetry state and db_path
# as real parameters (as db_path already IS, optionally),
# rather than reaching out to module-level global functions
# at all. That's a genuine architectural change, appropriately
# out of scope for a same-night test fix, and worth doing
# deliberately as its own piece of work — especially given the
# planned Verdict/Sentinel/Compass decoupling, which will make
# this exact "which module actually owns this name" question
# recur, likely across process/package boundaries where
# patch() can't reach at all.
#
# Until that refactor happens, this file is the ONE place that
# needs updating when the module structure changes again —
# every test imports patch_telemetry() rather than hand-rolling
# its own list of patch targets, so a future module move means
# editing this list once, not every affected test file
# individually.

from __future__ import annotations

from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

# Every module confirmed (or plausibly) independently binding
# is_telemetry_enabled and/or get_db_path via their own
# `from telemetry.config import ...` line, post-split. Adding
# a module here that doesn't actually have one of these names
# is harmless — see the exception handling below.
_TELEMETRY_BOUND_MODULES: list[str] = [
    "telemetry.governance_store",
    "telemetry.governance_db",
    "cli.main",
    # cli/main.py directly calls create_governance_record() for
    # `verdict evaluate` itself — confirmed as the actual source
    # of a reproducible 17-record leak (test_evaluate_integration.py
    # invoked the real CLI stack end to end with zero telemetry
    # interception at all). Added here defensively, matching the
    # same reasoning already applied to cli.commands.ledger/
    # override/audit/sentinel.scan.
    "telemetry.governance_records",
    "telemetry.governance_history",
    "telemetry.governance_evidence",
    "telemetry.governance_ledger",
    "telemetry.governance_audit",
    "telemetry.governance_outcomes",
    "telemetry.governance_objectives",
    "cli.commands.ledger",
    "cli.commands.override",
    "cli.commands.audit",
    "cli.commands.sentinel.scan",
]


def patch_telemetry(
    db_path: Path | None = None,
    enabled: bool = True,
) -> ExitStack:
    """
    Patch is_telemetry_enabled (and, if db_path is given,
    get_db_path) across every module known to independently
    bind them. Use as a context manager:

        with patch_telemetry(db_path=db):
            create_governance_record(result=result, db_path=db)

    Modules in _TELEMETRY_BOUND_MODULES that don't actually
    have one of these two names bound (e.g. a module that
    only imports get_db_path, not is_telemetry_enabled), or
    that don't exist at all in a given context, are silently
    skipped for that specific name — this makes the list safe
    to over-include rather than requiring exact per-module
    accuracy, which is the whole point: err toward patching
    too much rather than missing one.
    """
    stack = ExitStack()
    for module in _TELEMETRY_BOUND_MODULES:
        try:
            stack.enter_context(
                patch(f"{module}.is_telemetry_enabled", return_value=enabled)
            )
        except (AttributeError, ModuleNotFoundError):
            pass

        if db_path is not None:
            try:
                stack.enter_context(
                    patch(f"{module}.get_db_path", return_value=db_path)
                )
            except (AttributeError, ModuleNotFoundError):
                pass

    return stack
