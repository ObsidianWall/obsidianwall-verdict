# engine/coverage/frameworks/soc2.py

SOC2_CONTROLS = {
    "CC6.1": {
        "title": "Logical Access Controls",
        "description": (
            "Logical access security software, infrastructure, "
            "and architectures are implemented to protect "
            "against threats from sources outside the system."
        ),
        "keywords": [
            "access_control", "authentication", "mfa",
            "rbac", "firewall", "ingress", "network_security",
            "open_ingress",
        ],
    },
    "CC6.2": {
        "title": "Access Credentials",
        "description": (
            "Prior to issuing system credentials and granting "
            "access, new internal and external users are "
            "registered and authorized."
        ),
        "keywords": [
            "credential", "user_access", "provisioning",
            "authorization", "identity",
        ],
    },
    "CC6.3": {
        "title": "Role-Based Access",
        "description": (
            "Role-based access controls limit user access "
            "to authorized transactions."
        ),
        "keywords": [
            "rbac", "role", "permission", "least_privilege",
            "role_based",
        ],
    },
    "CC6.6": {
        "title": "Network Security",
        "description": (
            "Logical access security measures are implemented "
            "to protect against threats transmitted over the "
            "internet and other external networks."
        ),
        "keywords": [
            "network", "segmentation", "firewall", "ingress",
            "egress", "nsg", "security_group",
            "open_ingress_rules", "public",
        ],
    },
    "CC6.7": {
        "title": "Data Encryption",
        "description": (
            "Encryption is used to protect data during "
            "transmission and at rest."
        ),
        "keywords": [
            "encrypt", "tls", "ssl", "kms", "key_vault",
            "unencrypt", "at_rest", "in_transit",
        ],
    },
    "CC7.1": {
        "title": "System Monitoring",
        "description": (
            "To meet its objectives, the entity uses detection "
            "and monitoring procedures."
        ),
        "keywords": [
            "monitor", "log", "alert", "audit",
            "logging", "detection",
        ],
    },
    "CC7.2": {
        "title": "Anomaly Detection",
        "description": (
            "Anomalies and security incidents are identified "
            "and reported."
        ),
        "keywords": [
            "anomaly", "detection", "alert", "incident",
            "threat",
        ],
    },
    "CC8.1": {
        "title": "Change Management",
        "description": (
            "The entity authorizes, designs, develops or "
            "acquires, configures, documents, tests, approves, "
            "and implements changes."
        ),
        "keywords": [
            "change", "approval", "governance", "policy",
            "override", "authorized",
        ],
    },
    "CC9.1": {
        "title": "Risk Mitigation",
        "description": (
            "The entity identifies, selects, and develops "
            "risk mitigation activities."
        ),
        "keywords": [
            "risk", "mitigation", "budget", "cost",
            "overrun", "threshold",
        ],
    },
    "A1.1": {
        "title": "Availability — Performance Monitoring",
        "description": (
            "Availability and performance of the system "
            "are monitored."
        ),
        "keywords": [
            "availability", "performance", "uptime",
            "capacity", "utilization",
        ],
    },
    "C1.1": {
        "title": "Confidentiality — Data Classification",
        "description": (
            "Confidential information is protected "
            "during storage."
        ),
        "keywords": [
            "confidential", "classification", "sensitive",
            "private", "public_storage", "unencrypted",
        ],
    },
    "PI1.1": {
        "title": "Privacy — Data Inventory",
        "description": (
            "Personal information is collected and stored "
            "as required."
        ),
        "keywords": [
            "pii", "personal", "privacy", "data_inventory",
            "phi", "sensitive_data",
        ],
    },
}
