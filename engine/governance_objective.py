# engine/governance_objective.py
#
# Purpose:
# Compute the governance_objective field for a decision.
#
# Governance Objective is a Programmable Assurance concept:
# the organizational outcome a governance policy exists to
# achieve. Policies implement governance objectives.
# Governance decisions determine whether those objectives
# were upheld or violated. Multiple policies may enforce
# the same governance objective — this is the stable anchor
# Compass will eventually correlate across policies,
# decisions, and outcomes over time.
#
# This module computes a single decision's relationship to
# its declared governance objective. It does NOT yet track
# objectives across policies or time — that correlation is
# explicitly Compass's responsibility once outcome telemetry
# exists. This is the v0.5.2 foundation only.
#
# Fully backward compatible: if a policy has no
# governance_objective declared, this field is omitted
# entirely. No existing policy files need to change.
#
# IMPORTANT:
# This is advisory/explanatory only. It NEVER influences
# the enforcement decision — the decision is already final
# by the time this is computed.

from __future__ import annotations

from typing import Any

_UPHELD_DECISIONS = {"ALLOW", "ALLOW_WITH_NOTIFICATION"}
_VIOLATED_DECISIONS = {"DENY", "DENY_WITH_OVERRIDE"}
_PENDING_DECISIONS = {"ALLOW_WITH_APPROVAL_REQUIRED"}


def compute_governance_objective(
    policy_dict: dict[str, Any],
    decision: str,
) -> dict[str, Any] | None:
    """
    Compute the governance objective status for a decision,
    if the policy declares one.

    Reads metadata.governance_objective.statement from the
    policy YAML. If absent, returns None — the field is
    omitted from the artifact entirely rather than showing
    a placeholder.

    Expected policy YAML shape:
        metadata:
          governance_objective:
            statement: "Maintain cloud spend within approved budget"

    Args:
        policy_dict: the loaded policy YAML as a dict
        decision:    the resolved governance decision string

    Returns:
        dict with "statement" and "status" keys, or None if
        the policy has no declared governance objective.
        Never raises — this must not affect the evaluation
        pipeline.
    """
    try:
        metadata: dict[str, Any] = policy_dict.get("metadata", {})
        objective: dict[str, Any] | None = metadata.get("governance_objective")

        if not objective:
            return None

        statement: str | None = objective.get("statement")

        if not statement:
            return None

        if decision in _UPHELD_DECISIONS:
            status = "Upheld"
        elif decision in _VIOLATED_DECISIONS:
            status = "Violated"
        elif decision in _PENDING_DECISIONS:
            status = "Pending Approval"
        else:
            status = "Unknown"

        return {
            "statement": statement,
            "status": status,
        }

    except Exception:
        return None
