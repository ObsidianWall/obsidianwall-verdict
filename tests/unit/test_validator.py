# =====================================================
# tests/unit/test_validator.py 
# =====================================================

import pytest
from unittest.mock import patch

from engine.validator import validate_policy


class TestValidatePolicyLintFailure:
    def test_raises_valueerror_when_lint_errors_present(self):
        """
        Covers line 41 — the ValueError raise when lint_policy()
        returns errors. Mocks lint_policy() directly rather than
        constructing a real policy dict that legitimately fails
        linting — this tests validate_policy()'s own handling of
        a failing lint result, independent of lint_validator.py's
        specific rules, which aren't confirmed here.
        """
        fake_policy_dict = {"metadata": {"name": "test"}, "spec": {}}

        with patch(
            "engine.validator.normalize_policy",
            return_value=fake_policy_dict,
        ):
            with patch(
                "engine.validator.lint_policy",
                return_value=["some lint error"],
            ):
                with pytest.raises(ValueError, match="Lint errors"):
                    validate_policy(fake_policy_dict)


