"""
Family 3 — Concurrency and lifecycle behavior.

Uses real subprocesses — the property under test IS process-
level OS lock behavior. Readiness synchronization uses a
sentinel FILE, polled with a bounded deadline, not a blocking
pipe read — a worker that fails to start correctly must fail
this test fast and clearly, never hang the suite indefinitely.

The crash-recovery test's required property is stated
platform-neutrally: a process FORCIBLY TERMINATED while holding
the lock must not permanently strand the registry. This is
verified on whatever platform the suite runs on (Windows uses
different underlying termination semantics than POSIX SIGKILL,
but Popen.kill() exercises the equivalent "no chance to clean
up" property on both).
"""

import subprocess
import sys
import time
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).parent))
from _wait_for_ready import wait_for_ready  # noqa: E402

_WORKER = str(Path(__file__).parent / "_concurrency_worker.py")
_LOCK_HOLDER = str(Path(__file__).parent / "_lock_holder_worker.py")

# Must exceed the provider's real internal lock timeout —
# imported directly so this test can never silently drift out
# of sync with the actual implementation value again (the
# root cause of the original, incorrect version of this test).
from authority.local_provider import _LOCK_TIMEOUT_SECONDS


def _write_org(path, roles):
    doc = {
        "apiVersion": "obsidianwall.io/v1",
        "kind": "OrganizationAuthority",
        "metadata": {"organization_id": "acme", "version": "0.1"},
        "roles": roles,
    }
    path.write_text(yaml.dump(doc), encoding="utf-8")


def _role(id, name, status="active", members=None):
    return {
        "id": id,
        "name": name,
        "display_name": name.replace("_", " ").title(),
        "status": status,
        "members": ["alice@example.com"] if members is None else members,
    }


def _run_worker(org_path, registry_path=None, timeout=15):
    args = [sys.executable, _WORKER, str(org_path)]
    if registry_path is not None:
        args.append(str(registry_path))
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)


class TestConcurrentNonConflictingLoads:
    def test_two_processes_same_valid_state_both_succeed(self, tmp_path):
        org_path = tmp_path / "organization.yaml"
        _write_org(org_path, [_role("role_a", "role_a_name")])

        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(_run_worker, org_path) for _ in range(2)]
            results = [f.result() for f in futures]

        for result in results:
            assert result.returncode == 0, result.stdout


class TestLockTimeout:
    def test_second_process_times_out_while_first_holds_lock(self, tmp_path):
        """
        Process A holds the lock INDEFINITELY (block mode) — not
        for a fixed duration guessed to exceed the timeout, which
        is exactly the bug that made the original version of this
        test wrong. Process B's real, actual timeout must expire
        and produce PROVIDER_UNAVAILABLE.
        """
        org_path = tmp_path / "organization.yaml"
        registry_path = tmp_path / "history.json"
        lock_path = registry_path.with_suffix(registry_path.suffix + ".lock")
        ready_file = tmp_path / "holder_ready"
        _write_org(org_path, [_role("role_a", "role_a_name")])

        holder = subprocess.Popen(
            [sys.executable, _LOCK_HOLDER, str(lock_path), str(ready_file), "block"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        try:
            wait_for_ready(ready_file, holder, deadline_seconds=10.0)

            start = time.monotonic()
            result = _run_worker(
                org_path, registry_path, timeout=_LOCK_TIMEOUT_SECONDS + 15
            )
            elapsed = time.monotonic() - start

            assert result.returncode == 1, result.stdout
            assert "provider_unavailable" in result.stdout.lower()
            # Must have waited close to the REAL configured timeout,
            # not returned suspiciously early (which would mean it
            # never genuinely contended for the lock).
            assert elapsed >= _LOCK_TIMEOUT_SECONDS * 0.8, (
                f"returned after {elapsed:.2f}s, suspiciously fast "
                f"relative to the {_LOCK_TIMEOUT_SECONDS}s configured "
                f"timeout — may not have genuinely contended"
            )
        finally:
            holder.kill()
            holder.wait(timeout=10)


class TestCrashRecovery:
    def test_forcibly_terminated_holder_does_not_strand_registry(self, tmp_path):
        """
        Required property, stated platform-neutrally: a process
        FORCIBLY TERMINATED while holding the registry lock must
        not permanently strand it. Process B must subsequently
        acquire the lock and complete a valid operation.
        """
        org_path = tmp_path / "organization.yaml"
        registry_path = tmp_path / "history.json"
        lock_path = registry_path.with_suffix(registry_path.suffix + ".lock")
        ready_file = tmp_path / "holder_ready"
        _write_org(org_path, [_role("role_a", "role_a_name")])

        holder = subprocess.Popen(
            [sys.executable, _LOCK_HOLDER, str(lock_path), str(ready_file), "block"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        try:
            wait_for_ready(ready_file, holder, deadline_seconds=10.0)

            # Forcible termination — no chance for the holder to
            # release the lock through normal exception handling.
            holder.kill()
            holder.wait(timeout=10)

            result = _run_worker(org_path, registry_path, timeout=15)
            assert result.returncode == 0, (
                f"registry permanently stranded after holder was "
                f"forcibly terminated — stdout: {result.stdout}"
            )
        finally:
            if holder.poll() is None:
                holder.kill()
                holder.wait(timeout=10)


class TestConcurrentConflictingTransitions:
    def test_only_one_of_two_conflicting_alias_claims_succeeds(self, tmp_path):
        """
        REDESIGNED after review caught a real false-assurance bug:
        the original version's loser could fail via the UNRELATED
        "missing role tombstone" check rather than genuine alias
        contention, because only ONE of the two contested role_ids
        existed in the shared history before the race began.

        Fix: seed BOTH role_a and role_b first, so both are
        already historically known. Both workers' documents then
        contain BOTH roles (satisfying the no-disappearance check
        for both, unconditionally) — the ONLY difference between
        the two documents is which role claims the newly-contested
        alias. This isolates alias-reassignment as the ONLY
        possible source of rejection.
        """
        org_path_a = tmp_path / "org_a.yaml"
        org_path_b = tmp_path / "org_b.yaml"
        shared_registry = tmp_path / "shared-history.json"

        seed_path = tmp_path / "seed.yaml"
        _write_org(
            seed_path,
            [_role("role_a", "original_a"), _role("role_b", "original_b")],
        )
        result = _run_worker(seed_path, shared_registry)
        assert result.returncode == 0, result.stdout

        # Worker A: role_a renamed to claim contested_name; role_b unchanged.
        _write_org(
            org_path_a,
            [_role("role_a", "contested_name"), _role("role_b", "original_b")],
        )
        # Worker B: role_b renamed to claim contested_name; role_a unchanged.
        _write_org(
            org_path_b,
            [_role("role_a", "original_a"), _role("role_b", "contested_name")],
        )

        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            future_a = pool.submit(_run_worker, org_path_a, shared_registry)
            future_b = pool.submit(_run_worker, org_path_b, shared_registry)
            result_a = future_a.result()
            result_b = future_b.result()

        outcomes = [result_a.returncode, result_b.returncode]
        successes = outcomes.count(0)
        rejections = outcomes.count(1)

        assert successes == 1, (
            f"expected exactly one success, got outcomes {outcomes} "
            f"(a: {result_a.stdout}, b: {result_b.stdout})"
        )
        assert rejections == 1, f"expected exactly one rejection, got {outcomes}"

        winner_is_a = result_a.returncode == 0
        loser_output = (result_b if winner_is_a else result_a).stdout

        # Confirm the rejection is SPECIFICALLY alias reassignment,
        # not merely SOME SOURCE_INVALID cause — SOURCE_INVALID
        # covers several distinct temporal violations, and only
        # asserting the category (as an earlier version of this
        # test did) cannot distinguish "correctly rejected for the
        # right reason" from "rejected for an unrelated reason
        # that happened to produce the same exit code."
        assert "authority_error:source_invalid" in loser_output.lower()
        assert "cannot be reassigned" in loser_output.lower()
        assert "contested_name" in loser_output

        # Postcondition: the winning historical fact must actually
        # survive, and must remain enforced afterward — not just
        # "one process exited 0", but that the specific alias
        # binding it created is now permanent, real, persisted
        # state, and a LATER attempt by the loser's role to claim
        # the same alias is still rejected.
        winning_org_path = org_path_a if winner_is_a else org_path_b
        losing_role_id = "role_b" if winner_is_a else "role_a"
        winning_role_id = "role_a" if winner_is_a else "role_b"

        from authority.local_provider import LocalOrganizationAuthorityProvider

        confirm_provider = LocalOrganizationAuthorityProvider(
            organization_path=winning_org_path, registry_path=shared_registry
        )
        resolution = confirm_provider.resolve_role("contested_name")
        assert resolution.resolved
        assert resolution.role.id == winning_role_id

        # STRONGER DURABILITY POSTCONDITION.
        #
        # An earlier draft concluded no clean "later attempt by the
        # loser" test could exist, because having the winner keep
        # its true current name AND the loser claim the identical
        # name in one document is a same-document duplicate-name
        # collision — caught by the schema before ever reaching the
        # registry. That conclusion was too hasty: it shows ONE
        # approach fails, not that no approach exists.
        #
        # The winner can legitimately MOVE AWAY from the contested
        # alias first (a valid rename), which frees the current
        # document to isolate the loser's retry as the ONLY possible
        # temporal violation:
        #
        #   1. Winner renames away from "contested_name" (valid —
        #      "contested_name" no longer appears in the CURRENT
        #      document at all, but the registry still remembers it
        #      belonged to the winning role_id)
        #   2. Loser then tries to claim "contested_name" — now
        #      unique within the current document, so schema-level
        #      validation would allow it — but the historical
        #      registry must still reject it.
        moved_on_name = "moved_on_after_winning"
        moved_path = tmp_path / "winner_moved.yaml"
        if winner_is_a:
            _write_org(
                moved_path,
                [_role("role_a", moved_on_name), _role("role_b", "original_b")],
            )
        else:
            _write_org(
                moved_path,
                [_role("role_a", "original_a"), _role("role_b", moved_on_name)],
            )
        moved_result = _run_worker(moved_path, shared_registry)
        assert moved_result.returncode == 0, (
            f"winner's legitimate rename away from the contested "
            f"alias unexpectedly failed: {moved_result.stdout}"
        )

        loser_retry_path = tmp_path / "loser_retry.yaml"
        if winner_is_a:
            _write_org(
                loser_retry_path,
                [_role("role_a", moved_on_name), _role("role_b", "contested_name")],
            )
        else:
            _write_org(
                loser_retry_path,
                [_role("role_a", "contested_name"), _role("role_b", moved_on_name)],
            )
        retry_result = _run_worker(loser_retry_path, shared_registry)

        assert retry_result.returncode == 1, (
            f"the losing role was able to claim the contested alias "
            f"after the winner moved away from it — the historical "
            f"binding did not durably persist: {retry_result.stdout}"
        )
        assert "authority_error:source_invalid" in retry_result.stdout.lower()
        assert "cannot be reassigned" in retry_result.stdout.lower()
        assert "contested_name" in retry_result.stdout