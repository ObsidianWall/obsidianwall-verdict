#!/usr/bin/env python3

# scripts/parse_verdict_output.py
#
# Purpose:
# Parse ObsidianWall Verdict CLI output and extract
# key fields for GitHub Actions output variables.
#
# Usage:
#   python3 parse_verdict_output.py <output_file>
#
# Output:
#   GitHub Actions output variable format:
#   key=value (written to GITHUB_OUTPUT)

from __future__ import annotations

import json
import sys
from pathlib import Path


def parse_verdict_output(content: str) -> dict[str, object]:
    """
    Extract the final verdict artifact from CLI output.

    The CLI outputs structured log lines (single-line JSON
    with event_id) followed by the final audit artifact
    (multi-line JSON with decision_id).

    Finds the boundary between log lines and the artifact
    by tracking the last line containing event_id.
    """

    lines = content.split("\n")
    final_json_start = 0

    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            obj = json.loads(stripped)
            if "event_id" in obj:
                final_json_start = i + 1
        except json.JSONDecodeError:
            pass

    final_content = "\n".join(lines[final_json_start:]).strip()

    if not final_content:
        print("ERROR: No verdict artifact found in output", file=sys.stderr)
        print("Raw output:", file=sys.stderr)
        print(content[:500], file=sys.stderr)
        sys.exit(1)

    try:
        artifact: dict[str, object] = json.loads(final_content)
        return artifact
    except json.JSONDecodeError as e:
        print(f"ERROR: Failed to parse verdict artifact: {e}", file=sys.stderr)
        print("Content attempted to parse:", file=sys.stderr)
        print(final_content[:500], file=sys.stderr)
        sys.exit(1)


def extract_fields(
    artifact: dict[str, object],
) -> dict[str, str]:
    """
    Extract GitHub Actions output fields from the artifact.
    All values converted to strings for GITHUB_OUTPUT format.
    """

    decision = str(artifact.get("decision", "UNKNOWN"))
    conditions_passed = str(artifact.get("conditions_passed", False)).lower()
    decision_id = str(artifact.get("decision_id", ""))
    effective_severity = str(artifact.get("effective_severity", "unknown"))

    risk_summary = artifact.get("risk_summary", {})
    risk_score = str(
        risk_summary.get("overall_risk_score", 0)  # type: ignore[union-attr]
        if isinstance(risk_summary, dict)
        else 0
    )

    return {
        "decision": decision,
        "conditions_passed": conditions_passed,
        "risk_score": risk_score,
        "effective_severity": effective_severity,
        "decision_id": decision_id,
    }


def main() -> None:

    if len(sys.argv) < 2:
        print(
            "Usage: parse_verdict_output.py <output_file>",
            file=sys.stderr,
        )
        sys.exit(1)

    output_file = Path(sys.argv[1])

    if not output_file.exists():
        print(
            f"ERROR: Output file not found: {output_file}",
            file=sys.stderr,
        )
        sys.exit(1)

    content = output_file.read_text(encoding="utf-8")

    artifact = parse_verdict_output(content)
    fields = extract_fields(artifact)

    # Write to stdout in GITHUB_OUTPUT format
    # (caller appends to $GITHUB_OUTPUT)
    for key, value in fields.items():
        print(f"{key}={value}")


if __name__ == "__main__":
    main()
