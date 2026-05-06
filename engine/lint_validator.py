# engine/lint_validator.py

# Lint Validator (human-readable errors): This sits before Pydantic and catches obvious issues.


def lint_policy(policy: dict) -> list:
    errors = []

    if "apiVersion" not in policy:
        errors.append("Missing 'apiVersion'")

    if "kind" not in policy:
        errors.append("Missing 'kind'")

    if "metadata" not in policy:
        errors.append("Missing 'metadata'")
    else:
        if "name" not in policy["metadata"]:
            errors.append("metadata.name is required")

    if "spec" not in policy:
        errors.append("Missing 'spec'")
    else:
        if "conditions" not in policy["spec"]:
            errors.append("spec.conditions is required")

    return errors