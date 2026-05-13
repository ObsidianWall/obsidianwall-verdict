
# engine/policy_normalizer.py

# Purpose:
# Normalize policies into canonical runtime-ready structures.
#
# Responsibilities:
# - Legacy policy conversion
# - DSL normalization
# - Runtime parameter flattening
# - Runtime context preparation
#
# IMPORTANT:
# Evaluators should NEVER understand policy structure.
# Evaluators operate ONLY against normalized runtime context.




from schemas.policy_schema import Policy


# =====================================================
# INCOMING POLICY NORMALIZATION
# =====================================================

def normalize_policy(raw: dict) -> dict:
    """
    Normalize incoming policy into canonical DSL format.

    Supports:
    - legacy format (policy: {...})
    - canonical DSL format (apiVersion/kind/metadata/spec)
    """

    # ---------------------------------------------------
    # Boundary validation
    # ---------------------------------------------------

    if not isinstance(raw, dict) or not raw:
        raise ValueError(
            "Policy input must be a non-empty dict"
        )

    # ---------------------------------------------------
    # Already canonical DSL
    # if data Already DSL → return as-is
    # ---------------------------------------------------

    if "apiVersion" in raw and "spec" in raw:
        return raw

    
    # ---------------------------------------------------
    # Legacy policy conversion
    # if data is in Legacy format → transform into DSL format
    # ---------------------------------------------------

    if "policy" in raw:

        legacy_policy = raw["policy"]

        return {
            "apiVersion": "obsidianwall.io/v1",
            "kind": "Policy",

            "metadata": {
                "name": legacy_policy.get("name"),

                "version": legacy_policy.get("version"),

                # NOTE:
                # Legacy policies stored owner under:
                # parameters.budget.owner
                # Preserved for backward compatibility.
                "owner": (
                    raw.get("parameters", {})
                    .get("budget", {})
                    .get("owner", "unknown")
                ),

                "description": legacy_policy.get(
                    "description"
                ),
            },

            "spec": {
                "inputs": raw.get("inputs", []),

                "parameters": raw.get(
                    "parameters",
                    {}
                ),

                "conditions": raw.get(
                    "conditions",
                    []
                ),

                "decision": raw.get(
                    "decision",
                    {}
                ),

                "override": raw.get(
                    "override",
                    {}
                ),

                "actions": raw.get(
                    "actions",
                    []
                ),
            },
        }

    raise ValueError(
        "Invalid policy format: unsupported structure"
    )


# =====================================================
# RUNTIME NORMALIZATION
# =====================================================

def flatten_policy_parameters(
    parameters: dict,
    parent_key: str = "",
    flattened: dict | None = None
) -> dict:
    """
    Flatten nested policy parameters.

    Example:

    Input:
    {
        "budget": {
            "amount": 50
        }
    }

    Output:
    {
        "budget.amount": 50
    }
    """

    if flattened is None:
        flattened = {}

    for key, value in parameters.items():

        full_key = (
            f"{parent_key}.{key}"
            if parent_key
            else key
        )

        # Recursive flattening
        if isinstance(value, dict):

            flatten_policy_parameters(
                value,
                full_key,
                flattened
            )

        else:
            flattened[full_key] = value

    return flattened


def build_policy_runtime_context(
    policy: Policy,
    base_context: dict
) -> dict:
    """
    Build fully normalized runtime evaluation context.

    Responsibilities:
    - Preserve parsed infrastructure context
    - Inject flattened policy parameters
    - Detect context collisions
    - Produce evaluator-ready context
    """

    runtime_context = dict(base_context)

    flattened_parameters = (
        flatten_policy_parameters(
            policy.spec.parameters.model_dump()
        )
    )

    # ---------------------------------------------------
    # Collision detection
    # ---------------------------------------------------

    conflicts = (
        set(flattened_parameters.keys())
        & set(runtime_context.keys())
    )

    if conflicts:
        raise ValueError(
            f"Policy parameters conflict "
            f"with runtime context keys: {conflicts}"
        )

    # ---------------------------------------------------
    # Merge normalized parameters
    # ---------------------------------------------------

    runtime_context.update(
        flattened_parameters
    )

    return runtime_context