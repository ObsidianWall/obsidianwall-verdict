# telemetry/policy_classifier.py
#
# Purpose:
# Classify a governance policy into a high-level
# governance family for telemetry aggregation.
#
# This is a telemetry-only concern — runtime behavior
# uses policy_path directly. This classifier produces
# a stable, privacy-safe label for aggregate analytics.
#
# Families:
#   cost_governance          Budget, spend, cost controls
#   security_compliance      HIPAA, SOC2, PCI, ISO, NIST
#   infrastructure_security  Encryption, open ports,
#                            public access, unencrypted storage
#   identity_governance      IAM, MFA, roles, access
#   operational_governance   Tagging, naming, regions, lifecycle
#   ai_governance            NIST AI RMF, AI systems, model
#   custom                   No recognizable pattern

from __future__ import annotations

from typing import Any

# =====================================================
# FAMILY KEYWORD MAPS
# =====================================================

_FAMILY_PATTERNS: list[tuple[str, list[str]]] = [
    (
        "cost_governance",
        [
            "budget",
            "cost",
            "spend",
            "billing",
            "price",
            "pricing",
            "monthly",
            "expense",
            "financial",
            "overrun",
        ],
    ),
    (
        "security_compliance",
        [
            "hipaa",
            "soc2",
            "soc 2",
            "pci",
            "iso27001",
            "iso 27001",
            "nist",
            "cis",
            "fedramp",
            "gdpr",
            "compliance",
            "regulatory",
            "audit",
            "framework",
        ],
    ),
    (
        "infrastructure_security",
        [
            "encrypt",
            "ingress",
            "egress",
            "public",
            "open port",
            "security group",
            "firewall",
            "tls",
            "ssl",
            "kms",
            "storage",
            "bucket",
            "database",
            "rds",
            "s3",
        ],
    ),
    (
        "identity_governance",
        [
            "iam",
            "mfa",
            "role",
            "permission",
            "access",
            "identity",
            "principal",
            "credential",
            "privilege",
            "entitlement",
            "least privilege",
            "zero trust",
        ],
    ),
    (
        "operational_governance",
        [
            "tag",
            "naming",
            "region",
            "lifecycle",
            "retention",
            "rotation",
            "backup",
            "disaster",
            "availability",
            "maintenance",
            "patch",
        ],
    ),
    (
        "ai_governance",
        [
            "ai",
            "model",
            "llm",
            "machine learning",
            "inference",
            "nist ai",
            "ai rmf",
            "responsible ai",
            "fairness",
            "explainability",
            "bias",
        ],
    ),
]


def classify_policy_family(policy_dict: dict[str, Any]) -> str:
    """
    Classify a loaded policy dict into a governance family.

    Examines policy name, description, and framework mappings
    for recognizable keywords. Returns "custom" if no match.

    Args:
        policy_dict: loaded policy YAML as a dict

    Returns:
        governance family string — one of the _FAMILY_PATTERNS
        keys above, or "custom"
    """
    # Build a single lowercase search corpus from
    # the fields most likely to carry semantic content
    corpus_parts: list[str] = []

    metadata = policy_dict.get("metadata", {})
    if isinstance(metadata, dict):
        corpus_parts.append(str(metadata.get("name", "")))
        corpus_parts.append(str(metadata.get("description", "")))
        corpus_parts.append(str(metadata.get("tags", "")))

    spec = policy_dict.get("spec", {})
    if isinstance(spec, dict):
        governance = spec.get("governance", {})
        if isinstance(governance, dict):
            corpus_parts.append(str(governance.get("framework_mapping", "")))
            corpus_parts.append(str(governance.get("description", "")))
        corpus_parts.append(str(spec.get("description", "")))

    corpus = " ".join(corpus_parts).lower()

    if not corpus.strip():
        return "custom"

    # Score each family by keyword hit count
    scores: dict[str, int] = {}
    for family, keywords in _FAMILY_PATTERNS:
        hits = sum(1 for kw in keywords if kw in corpus)
        if hits:
            scores[family] = hits

    if not scores:
        return "custom"

    # Return the highest-scoring family
    return max(scores, key=lambda k: scores[k])
