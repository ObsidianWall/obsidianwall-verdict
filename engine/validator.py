# engine/validator.py

# Purpose: Validates Terraform plans against defined policies.


from schemas.policy_schema import PolicyModel
from audit.audit_logger import get_logger

logger = get_logger()


def validate_policy(policy_dict: dict) -> PolicyModel:
    try:
        policy = PolicyModel(**policy_dict)
        logger.info("Policy validation successful", extra={"policy": policy.name})
        return policy
    except Exception as e:
        logger.error("Policy validation failed", extra={"error": str(e)})
        raise