"""
Shared helper — bounded, cross-platform readiness polling.
Not a test file itself; imported by the concurrency test module.
"""

import time
from pathlib import Path


def wait_for_ready(ready_file: Path, holder_process, deadline_seconds: float = 10.0):
    """
    Polls for the ready sentinel file rather than blocking on
    subprocess pipe I/O. Also checks whether the holder process
    exited unexpectedly (crashed before becoming ready), so a
    startup failure fails fast with a clear message instead of
    silently waiting out the full deadline.

    Raises AssertionError with a clear message on either failure
    mode — never hangs indefinitely.
    """
    start = time.monotonic()
    while time.monotonic() - start < deadline_seconds:
        if ready_file.exists():
            return
        if holder_process.poll() is not None:
            raise AssertionError(
                f"holder process exited unexpectedly before becoming "
                f"ready (exit code {holder_process.returncode}) — "
                f"stdout: {holder_process.stdout.read() if holder_process.stdout else '(none)'}"
            )
        time.sleep(0.05)
    raise AssertionError(
        f"holder process did not become ready within {deadline_seconds}s"
    )