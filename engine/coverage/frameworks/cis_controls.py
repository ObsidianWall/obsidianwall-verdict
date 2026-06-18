# engine/coverage/frameworks/cis_controls.py
#
# Purpose:
# CIS Controls v8 mappings for the coverage engine.
# Maps policy condition keywords to specific CIS
# safeguards.
#
# Reference: Center for Internet Security Controls v8

from __future__ import annotations

from typing import Any

CIS_CONTROLS: dict[str, dict[str, Any]] = {
    "CIS.1": {
        "title": "Inventory and Control of Enterprise Assets",
        "description": (
            "Actively manage all enterprise assets connected to the infrastructure."
        ),
        "keywords": [
            "inventory",
            "asset",
            "resource_count",
            "untagged",
            "tagging",
        ],
    },
    "CIS.3": {
        "title": "Data Protection",
        "description": (
            "Develop processes and technical controls to "
            "identify, classify, securely handle, retain, "
            "and dispose of data."
        ),
        "keywords": [
            "encrypt",
            "unencrypt",
            "data_protection",
            "classification",
            "sensitive",
            "public_storage",
            "storage",
            "kms",
            "versioning_disabled",
        ],
    },
    "CIS.4": {
        "title": "Secure Configuration of Enterprise Assets",
        "description": (
            "Establish and maintain the secure configuration "
            "of enterprise assets and software."
        ),
        "keywords": [
            "config",
            "hardening",
            "baseline",
            "secure_config",
            "misconfiguration",
            "default",
        ],
    },
    "CIS.5": {
        "title": "Account Management",
        "description": (
            "Use processes and tools to assign and manage "
            "authorization to credentials for user accounts."
        ),
        "keywords": [
            "account",
            "mfa",
            "privileged",
            "service_account",
            "credential",
            "password",
        ],
    },
    "CIS.6": {
        "title": "Access Control Management",
        "description": (
            "Use processes and tools to create, assign, manage, "
            "and revoke access credentials and privileges."
        ),
        "keywords": [
            "access",
            "rbac",
            "privilege",
            "least_privilege",
            "role",
            "authorization",
            "iam",
        ],
    },
    "CIS.8": {
        "title": "Audit Log Management",
        "description": (
            "Collect, alert, review, and retain audit logs "
            "of events that could help detect, understand, "
            "or recover from an attack."
        ),
        "keywords": [
            "log",
            "audit",
            "logging",
            "monitoring",
            "retention",
            "trail",
        ],
    },
    "CIS.12": {
        "title": "Network Infrastructure Management",
        "description": (
            "Establish, implement, and actively manage "
            "network devices to prevent attackers from "
            "exploiting network services."
        ),
        "keywords": [
            "network",
            "firewall",
            "ingress",
            "egress",
            "segmentation",
            "open_ingress",
            "nsg",
            "security_group",
            "port",
        ],
    },
    "CIS.13": {
        "title": "Network Monitoring and Defense",
        "description": (
            "Operate processes and tooling to establish "
            "and maintain comprehensive network monitoring "
            "and defense."
        ),
        "keywords": [
            "monitor",
            "network_monitor",
            "detection",
            "threat",
            "intrusion",
        ],
    },
    "CIS.16": {
        "title": "Application Software Security",
        "description": (
            "Manage the security lifecycle of in-house "
            "developed, hosted, or acquired software."
        ),
        "keywords": [
            "application",
            "software",
            "vulnerability",
            "secure_coding",
        ],
    },
    "CIS.18": {
        "title": "Penetration Testing",
        "description": (
            "Test the effectiveness and resiliency of "
            "enterprise assets through identifying and "
            "exploiting weaknesses."
        ),
        "keywords": [
            "penetration",
            "pentest",
            "vulnerability_scan",
            "assessment",
        ],
    },
}
