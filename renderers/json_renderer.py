# renderers/json_renderer.py
#
# Purpose:
# Full JSON artifact renderer.
#
# Produces the complete governance decision artifact
# as JSON to stdout. This is the machine-readable
# representation used by CI/CD pipelines, GitHub
# Actions, Sentinel, and Compass.
#
# This is the current default behavior of verdict evaluate.
# It is preserved exactly — no fields removed, no formatting
# changed — and activated via --format json.
#
# Audience: CI/CD pipelines, GitHub Actions, scripts,
#           ObsidianWall ecosystem (Sentinel, Compass)

from __future__ import annotations

import json
from typing import Any


def render_json(result: dict[str, Any]) -> None:
    """
    Print the complete governance decision artifact
    as formatted JSON to stdout.

    Preserves all fields exactly as produced by the
    evaluation engine. This is the canonical machine-
    readable representation of the governance decision.
    """
    print(json.dumps(result, indent=2, default=str))
