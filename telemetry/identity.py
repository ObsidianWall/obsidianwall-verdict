# telemetry/identity.py
#
# Purpose:
# Best-effort resolution of "who ran this" — separate from
# --role, which is a CLAIMED authorization level, not an
# identity. Nothing here authenticates anyone; it reports the
# best available signal from the environment, in priority
# order, and is honest about being unable to prove identity.
#
# This exists because governance_records and governance_history
# previously captured a role string (e.g. "budget_owner") with
# no way to know WHO actually typed that role — meaningfully
# weakening the accountability story the Risk Acceptance Ledger
# depends on. "budget_owner approved this" is a much weaker
# claim than "jsmith@company.com, running as budget_owner,
# approved this."
#
# Resolution order:
#   1. CI environment variables — most reliable when Verdict
#      runs in a pipeline, which is its primary deployment
#      context for governance enforcement
#   2. git config user.email / user.name — meaningful for
#      local runs, ties to an identity most developers already
#      have configured
#   3. OS username — last-resort fallback, weak signal but
#      better than nothing
#   4. None — if nothing resolves, callers should treat this
#      as "identity unknown," never fabricate a value

from __future__ import annotations

import os
import subprocess

# CI environment variables that reliably identify the actor
# who triggered a pipeline run, checked in this order.
_CI_ACTOR_ENV_VARS: list[str] = [
    "GITHUB_ACTOR",  # GitHub Actions
    "GITLAB_USER_LOGIN",  # GitLab CI
    "CI_COMMIT_AUTHOR_EMAIL",  # GitLab CI (fallback)
    "BUILD_REQUESTEDFOR",  # Azure Pipelines
    "CIRCLE_USERNAME",  # CircleCI
]


def _resolve_from_ci_env() -> str | None:
    """Check known CI actor environment variables, in priority order."""
    for var in _CI_ACTOR_ENV_VARS:
        value = os.environ.get(var)
        if value:
            return value
    return None


def _resolve_from_git_config() -> str | None:
    """
    Fall back to the local git identity, if this is running
    inside a git repository with user.email or user.name
    configured. Never raises — git may not be installed, the
    directory may not be a repo, or config may be unset.
    """
    for key in ("user.email", "user.name"):
        try:
            result = subprocess.run(
                ["git", "config", key],
                capture_output=True,
                text=True,
                timeout=2,
            )
            value = result.stdout.strip()
            if result.returncode == 0 and value:
                return value
        except Exception:
            continue
    return None


def _resolve_from_os_user() -> str | None:
    """Last-resort fallback — the OS-level username. Weak
    signal (doesn't identify a real person in shared/CI
    environments) but better than no signal at all."""
    try:
        import getpass

        return getpass.getuser()
    except Exception:
        return None


def resolve_actor_identity() -> str | None:
    """
    Best-effort resolution of who is running the current
    command. NOT authentication — this reports the best
    available signal, in priority order, and can be spoofed
    by anyone controlling their own environment variables or
    git config. Callers must not treat this as a security
    control, only as an accountability/audit signal.

    Returns None if nothing could be resolved. Never raises.
    """
    return (
        _resolve_from_ci_env()
        or _resolve_from_git_config()
        or _resolve_from_os_user()
    )


def resolve_execution_host() -> str | None:
    """
    Best-effort hostname of the machine running the current
    command. Deliberately hostname only — NEVER IP address or
    geolocation. This distinction is intentional: a hostname
    answers "was this a known CI runner or a laptop," which is
    a legitimate governance question, without collecting the
    kind of location/network data that would work against
    ObsidianWall's data-minimization commitments (see
    telemetry/config.py and SECURITY.md's privacy section).

    Returns None if the hostname cannot be resolved. Never
    raises.
    """
    try:
        import socket

        return socket.gethostname() or None
    except Exception:
        return None