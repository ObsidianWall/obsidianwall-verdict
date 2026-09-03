"""
Standalone worker invoked as a real subprocess. Acquires the
registry's actual filelock.FileLock directly and holds it.

Usage:
  python _lock_holder_worker.py <lock_path> <ready_file_path> block
      Acquires the lock, creates <ready_file_path> as a sentinel
      the moment the lock is truly held, then blocks indefinitely
      until killed. Sentinel-file readiness (not a blocking pipe
      read) is used deliberately for cross-platform reliability —
      a blocking readline() on stdout can hang indefinitely if
      this process fails to start correctly, which is a real risk
      worth avoiding on Windows specifically.
"""

import sys
import time
from pathlib import Path

from filelock import FileLock

if __name__ == "__main__":
    lock_path = sys.argv[1]
    ready_file = Path(sys.argv[2])
    mode = sys.argv[3]

    lock = FileLock(lock_path)
    with lock:
        ready_file.write_text("ready")
        if mode == "block":
            while True:
                time.sleep(1)
        else:
            raise ValueError(f"unknown mode: {mode}")