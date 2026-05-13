# engine/validator.py

# Purpose: Validates Terraform plans against defined policies.


from schemas.policy_schema import Policy
from engine.policy_normalizer import normalize_policy
from engine.lint_validator import lint_policy
from audit.audit_logger import get_logger

logger = get_logger()



def validate_policy(policy_dict: dict) -> Policy:
    try:
        # 1. Normalize
        normalized = normalize_policy(policy_dict)

        # 2. Lint
        lint_errors = lint_policy(normalized)
        if lint_errors:
            raise ValueError(f"Lint errors: {lint_errors}")

        # 3. Schema validation
        policy = Policy(**normalized)

        logger.info("policy_validation_success", extra={
            "extra": {"policy": policy.metadata.name}
        })

        return policy

    except Exception as e:
        logger.error("policy_validation_failed", extra={
            "extra": {"error": str(e)}
        })
        raise   