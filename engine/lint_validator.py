# engine/lint_validator.py

# Lint Validator (human-readable errors): This sits before Pydantic and catches obvious issues.

from typing import Any


def lint_policy(policy: dict[str, Any]) -> list[dict[str, Any]]:
    errors: list[dict[str, Any]] = []

    if "apiVersion" not in policy:
        errors.append({"field": "apiVersion", "message": "Missing 'apiVersion'"})

    if "kind" not in policy:
        errors.append({"field": "kind", "message": "Missing 'kind'"})

    if "metadata" not in policy:
        errors.append({"field": "metadata", "message": "Missing 'metadata'"})
    else:
        if "name" not in policy["metadata"]:
            errors.append(
                {"field": "metadata.name", "message": "metadata.name is required"}
            )

    if "spec" not in policy:
        errors.append({"field": "spec", "message": "Missing 'spec'"})
    else:
        if "conditions" not in policy["spec"]:
            errors.append(
                {"field": "spec.conditions", "message": "spec.conditions is required"}
            )

    return errors
