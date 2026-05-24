# engine/validator.py

# Purpose:
# Trusted policy validation gateway.
#
# Responsibilities:
# - Policy normalization
# - Policy lint validation
# - Policy schema validation
#
# IMPORTANT:
# This layer converts untrusted policy input
# into trusted typed policy contracts.


from schemas.policy_schema import Policy

from engine.policy_normalizer import (
    normalize_policy
)

from engine.lint_validator import lint_policy

from audit.audit_logger import get_logger


logger = get_logger()


def validate_policy(
    policy_dict: dict
) -> Policy:

    try:

        # =============================================
        # NORMALIZATION
        # =============================================

        normalized_policy = normalize_policy(
            policy_dict
        )

        # =============================================
        # LINT VALIDATION
        # =============================================

        lint_errors = lint_policy(
            normalized_policy
        )

        if lint_errors:

            raise ValueError(
                f"Lint errors: {lint_errors}"
            )

        # =============================================
        # SCHEMA VALIDATION
        # =============================================

        validated_policy = Policy(
            **normalized_policy
        )

        logger.info(
            "policy_validation_success",
            extra={
                "extra": {
                    "policy": (
                        validated_policy.metadata.name
                    )
                }
            }
        )

        return validated_policy

    except Exception as error:

        logger.error(
            "policy_validation_failed",
            extra={
                "extra": {
                    "error": str(error)
                }
            }
        )

        raise