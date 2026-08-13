# context/observers/observation.py
#
# Purpose:
# A distinct, persistable wrapper around what a CloudObserver
# actually collected — not just a raw context dict.
#
# Why this exists as its own object rather than passing a
# dict straight to PolicyOrchestrator: this checkpoint (what
# was observed, from where, when, with what hash) is exactly
# the shape that later becomes a governance_evidence entry —
# reusing the same SHA-256 hashing pattern already built into
# governance_history tonight. Keeping it as a real object now
# means recording an Observation to governance_evidence later
# needs no redesign, just a new call site.

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class Observation:
    """
    What a CloudObserver actually collected, wrapped with
    enough metadata to be persisted, hashed, and later
    evaluated by PolicyOrchestrator exactly like a
    Terraform-plan-derived context.
    """

    provider: str
    scope: str
    context: dict[str, Any]
    observed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    collector_version: str = "0.6.0"

    @property
    def resource_count(self) -> int:
        return len(self.context.get("resources", []))

    @property
    def resource_hash(self) -> str:
        """
        SHA-256 of the observed resource list — lets two
        observations be compared for "did anything change"
        without diffing full context dicts, and gives this
        Observation the same tamper-evidence property as a
        governance_history entry once it's recorded there.
        """
        serialized = json.dumps(
            self.context.get("resources", []), sort_keys=True, default=str
        )
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "scope": self.scope,
            "observed_at": self.observed_at,
            "collector_version": self.collector_version,
            "resource_count": self.resource_count,
            "resource_hash": self.resource_hash,
            "context": self.context,
        }
