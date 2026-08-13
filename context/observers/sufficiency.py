# context/observers/sufficiency.py
#
# Purpose:
# Determine whether an Observation contains enough evidence
# to evaluate a given policy — BEFORE evaluation runs, never
# after. This is what prevents Sentinel from ever manufacturing
# one of the five real governance decisions (ALLOW,
# ALLOW_WITH_NOTIFICATION, ALLOW_WITH_APPROVAL_REQUIRED,
# DENY_WITH_OVERRIDE, DENY) from evidence it doesn't actually
# have.
#
# Design:
# Checks REQUIRED context keys against what the observer
# ACTUALLY RETURNED — not against a separately-maintained
# capability descriptor. AzureObserver never fabricates a
# zero for a resource type it didn't examine; it only
# includes keys it genuinely computed. That means direct
# presence-checking against the real returned dict can never
# drift out of sync with reality, unlike a hand-maintained
# capability map that could silently go stale.
#
# Required keys are inferred from the policy's own condition
# expressions (MVP — no new policy YAML syntax required).
# A future version can add explicit `requires: context: [...]`
# metadata for cases where inference isn't precise enough —
# deliberately not built now, per the same discipline as
# is_risk_acceptance_candidate: ship the lean version, add
# structure only once a real need for it appears.

from __future__ import annotations

import re
from enum import Enum
from typing import Any

# The full, known set of context keys any observer in this
# codebase could ever produce — sourced directly from
# context.translators.terraform_parser.parse_terraform_plan()'s
# return shape, which remains the canonical context contract
# every observer (Terraform-plan-based or live-cloud-based)
# must conform to.
KNOWN_CONTEXT_KEYS: frozenset[str] = frozenset(
    {
        "open_ingress_rules",
        "public_storage_buckets",
        "unencrypted_databases",
        "ssl_not_enforced_count",
        "versioning_disabled_count",
        "untagged_resource_count",
        "total_resource_count",
        "compute_instance_count",
        "gpu_instance_count",
        "ai_gpu_workloads",
        "estimated_cost",
        "current_spend",
    }
)

_IDENTIFIER_PATTERN = re.compile(r"\b[a-zA-Z_][a-zA-Z0-9_]*\b")


class EvaluationOutcome(str, Enum):
    """
    Distinguishes an actual governance decision from a policy
    that was never evaluated at all. POLICY_NOT_EVALUATED is
    deliberately NOT a sixth governance decision value — it
    must never appear anywhere the five real decisions
    (ALLOW, ALLOW_WITH_NOTIFICATION,
    ALLOW_WITH_APPROVAL_REQUIRED, DENY_WITH_OVERRIDE, DENY)
    are counted, classified, or reasoned about (e.g.
    get_objective_summary()'s Upheld/Violated/Pending
    classification must never see this value).
    """

    EVALUATED = "evaluated"
    POLICY_NOT_EVALUATED = "policy_not_evaluated"


class InsufficiencyReason(str, Enum):
    """
    Why a policy could not be evaluated — kept distinct
    because each reason implies a DIFFERENT remediation:
    UNSUPPORTED means "this observer needs a new collector
    built for it." COLLECTION_FAILED means "something broke
    at runtime — check permissions, connectivity, or the
    target resource's existence" — a completely different
    fix, done by a different kind of action.
    """

    UNSUPPORTED = "unsupported"
    # The observer has no collector capable of producing
    # this context key at all, regardless of runtime state.

    COLLECTION_FAILED = "collection_failed"
    # The observer IS capable of producing this key, but the
    # actual collection attempt failed at runtime (e.g. a
    # CloudObserverError was raised during observe()).


class SufficiencyResult:
    """
    The outcome of a pre-evaluation sufficiency check.
    """

    def __init__(
        self,
        outcome: EvaluationOutcome,
        missing_keys: set[str] | None = None,
        reason: InsufficiencyReason | None = None,
        detail: str | None = None,
    ) -> None:
        self.outcome = outcome
        self.missing_keys = missing_keys or set()
        self.reason = reason
        self.detail = detail

    @property
    def sufficient(self) -> bool:
        return self.outcome == EvaluationOutcome.EVALUATED

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome.value,
            "missing_keys": sorted(self.missing_keys),
            "reason": self.reason.value if self.reason else None,
            "detail": self.detail,
        }


def infer_required_context_keys(policy_dict: dict[str, Any]) -> set[str]:
    """
    Extract which observer-producible context keys a policy's
    conditions actually reference.

    MVP approach: scan each condition's "expression" string for
    identifier-like tokens, keep only the ones matching a KNOWN
    context key this codebase's observers can produce. This
    deliberately does not attempt to fully parse the condition
    expression grammar — it doesn't need to. Over-matching (a
    token that happens to share a name with a context key but
    isn't actually used as one) is a false positive that makes
    the sufficiency check slightly more conservative, never
    silently wrong in the dangerous direction — a false
    negative here would be the real risk, and this approach
    doesn't produce those, since every genuine reference is
    guaranteed to appear as a token in the expression text.

    Args:
        policy_dict: a loaded policy dict, as returned by
            engine.policy_loader.load_policy().

    Returns:
        The subset of KNOWN_CONTEXT_KEYS actually referenced
        by this policy's conditions. Empty set if the policy
        has no conditions or none reference a known key.
    """
    # Real schema (confirmed against schemas/policy_schema.py and
    # real working policy files) has NO "policy:" wrapper key —
    # apiVersion/kind/metadata/spec are all top-level. An earlier
    # version of this function incorrectly assumed a wrapper that
    # never existed, which meant this ALWAYS returned an empty
    # set against real policies — the sufficiency gate was
    # silently inert. Fixed here.
    conditions = policy_dict.get("spec", {}).get("conditions", [])

    referenced: set[str] = set()
    for condition in conditions:
        expression = condition.get("expression", "")
        tokens = set(_IDENTIFIER_PATTERN.findall(expression))
        referenced |= tokens & KNOWN_CONTEXT_KEYS

    return referenced


def check_sufficiency(
    policy_dict: dict[str, Any],
    observed_context: dict[str, Any],
    collection_error: str | None = None,
) -> SufficiencyResult:
    """
    The pre-evaluation gate. Call this BEFORE handing
    observed_context to PolicyOrchestrator.evaluate() — never
    after. If this returns an insufficient result, evaluation
    must not proceed, and no governance decision may be
    recorded for this policy/observation pair.

    Args:
        policy_dict: the loaded policy being considered for
            evaluation against this observation.
        observed_context: the context dict an observer's
            observe() call actually returned.
        collection_error: if the observer raised a
            CloudObserverError during collection (rather than
            returning successfully with a partial context),
            pass its message here — this routes the result to
            COLLECTION_FAILED instead of UNSUPPORTED, since the
            remediation is different (a runtime problem, not a
            missing collector).

    Returns:
        A SufficiencyResult. Check .sufficient before
        proceeding to evaluation.
    """
    if collection_error is not None:
        return SufficiencyResult(
            outcome=EvaluationOutcome.POLICY_NOT_EVALUATED,
            reason=InsufficiencyReason.COLLECTION_FAILED,
            detail=collection_error,
        )

    required_keys = infer_required_context_keys(policy_dict)
    missing_keys = {key for key in required_keys if key not in observed_context}

    if missing_keys:
        policy_name = policy_dict.get("metadata", {}).get("name", "unknown")
        return SufficiencyResult(
            outcome=EvaluationOutcome.POLICY_NOT_EVALUATED,
            missing_keys=missing_keys,
            reason=InsufficiencyReason.UNSUPPORTED,
            detail=(
                f"Policy '{policy_name}' requires context key(s) "
                f"{sorted(missing_keys)}, which the current observer "
                f"does not produce. This observer's capabilities "
                f"declare which resource types it examines — see "
                f"CloudObserver.capabilities for what is currently "
                f"supported."
            ),
        )

    return SufficiencyResult(outcome=EvaluationOutcome.EVALUATED)
