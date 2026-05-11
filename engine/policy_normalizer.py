
# engine/policy_normalizer.py


def normalize_policy(raw: dict) -> dict:
    """
    Normalize incoming policy into DSL format.
    Supports:
    - legacy format (policy: {...})
    - DSL format (apiVersion/kind/metadata/spec)
    """

    # Already DSL → return as-is
    if "apiVersion" in raw and "spec" in raw:
        return raw

    # Legacy format → transform
    if "policy" in raw:
        p = raw["policy"]

        return {
            "apiVersion": "obsidianwall.io/v1",
            "kind": "Policy",
            "metadata": {
                "name": p.get("name"),
                "version": p.get("version"),
                "owner": p.get("parameters", {}).get("budget", {}).get("owner", "unknown"),
                "description": p.get("description"),
            },
            "spec": {
                "inputs": raw.get("inputs", []),
                "parameters": raw.get("parameters", {}),
                "conditions": raw.get("conditions", []),
                "decision": raw.get("decision", {}),
                "override": raw.get("override", {}),
                "actions": raw.get("actions", []),
            },
        }

    raise ValueError("Invalid policy format: unsupported structure")