# engine/coverage/frameworks/hipaa.py
#
# Purpose:
# HIPAA Security Rule control mappings for the coverage
# engine. Maps policy condition keywords to specific
# HIPAA technical and administrative safeguards.
#
# Each control entry defines the keywords the coverage
# engine searches for in policy condition identifiers
# and expressions. A match means the policy addresses
# that control.
#
# Reference: 45 CFR § 164.312 (Technical Safeguards)
#            45 CFR § 164.308 (Administrative Safeguards)

from __future__ import annotations

from typing import Any

HIPAA_CONTROLS: dict[str, dict[str, Any]] = {
    "164.312(a)(1)": {
        "title": "Access Control",
        "description": (
            "Implement technical policies and procedures for "
            "electronic information systems that restrict access "
            "to authorized users."
        ),
        "keywords": [
            "mfa",
            "authentication",
            "rbac",
            "role_based",
            "privileged",
            "access_control",
            "least_privilege",
            "iam",
            "identity",
            "authorization",
        ],
    },
    "164.312(a)(2)(iv)": {
        "title": "Encryption and Decryption",
        "description": (
            "Implement a mechanism to encrypt and decrypt "
            "electronic protected health information."
        ),
        "keywords": [
            "encrypt",
            "unencrypt",
            "kms",
            "key_vault",
            "at_rest",
            "decryption",
            "cipher",
        ],
    },
    "164.312(b)": {
        "title": "Audit Controls",
        "description": (
            "Implement hardware, software, and procedural "
            "mechanisms that record and examine activity "
            "in information systems that contain ePHI."
        ),
        "keywords": [
            "audit",
            "log",
            "logging",
            "monitoring",
            "trail",
            "record",
            "retention",
        ],
    },
    "164.312(c)(1)": {
        "title": "Integrity Controls",
        "description": (
            "Protect electronic protected health information "
            "from improper alteration or destruction."
        ),
        "keywords": [
            "integrity",
            "checksum",
            "hash",
            "tamper",
            "immutable",
            "versioning",
            "versioning_disabled",
        ],
    },
    "164.312(d)": {
        "title": "Person or Entity Authentication",
        "description": (
            "Implement procedures to verify that a person or "
            "entity seeking access is who they claim to be."
        ),
        "keywords": [
            "mfa",
            "multi_factor",
            "authentication",
            "identity_verification",
            "certificate",
        ],
    },
    "164.312(e)(1)": {
        "title": "Transmission Security",
        "description": (
            "Implement technical security measures to guard "
            "against unauthorized access to ePHI being "
            "transmitted over electronic communications networks."
        ),
        "keywords": [
            "tls",
            "ssl",
            "transit",
            "transmission",
            "https",
            "secure_transport",
            "in_transit",
            "ssl_not_enforced",
        ],
    },
    "164.312(e)(2)(ii)": {
        "title": "Encryption of Data in Transit",
        "description": (
            "Implement a mechanism to encrypt electronic "
            "protected health information whenever deemed "
            "appropriate."
        ),
        "keywords": [
            "encrypt",
            "tls",
            "ssl",
            "transit_encryption",
            "secure_channel",
            "ssl_not_enforced",
        ],
    },
    "164.308(a)(1)": {
        "title": "Security Management Process",
        "description": (
            "Implement policies and procedures to prevent, "
            "detect, contain, and correct security violations."
        ),
        "keywords": [
            "security_policy",
            "risk_analysis",
            "risk_management",
            "security_measures",
        ],
    },
    "164.308(a)(3)": {
        "title": "Workforce Access Management",
        "description": (
            "Implement policies for authorizing access to "
            "electronic protected health information."
        ),
        "keywords": [
            "workforce_access",
            "access_management",
            "user_access",
            "provisioning",
        ],
    },
    "164.308(a)(5)": {
        "title": "Security Awareness Training",
        "description": (
            "Implement a security awareness and training program "
            "for all workforce members."
        ),
        "keywords": [
            "training",
            "awareness",
            "security_training",
        ],
    },
}
