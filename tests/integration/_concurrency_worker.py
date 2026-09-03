"""
Standalone worker script invoked as a REAL subprocess by
test_local_provider_concurrency.py — not imported directly.
Each invocation constructs exactly one LocalOrganizationAuthorityProvider
against a shared organization.yaml/registry path and reports the
outcome via its exit code and stdout, so the parent test process
can observe what actually happened across real process boundaries.

Usage: python _concurrency_worker.py <org_path> [registry_path]

Exit codes:
  0  provider constructed successfully
  1  AuthorityProviderError (prints failure.value to stdout)
  2  unexpected exception (prints repr to stdout)
"""

import sys

from authority.local_provider import LocalOrganizationAuthorityProvider
from authority.provider import AuthorityProviderError

if __name__ == "__main__":
    org_path = sys.argv[1]
    registry_path = sys.argv[2] if len(sys.argv) > 2 else None

    try:
        LocalOrganizationAuthorityProvider(
            organization_path=org_path, registry_path=registry_path
        )
        print("OK")
        sys.exit(0)
    except AuthorityProviderError as exc:
        # Include the actual message, not just the failure
        # category — SOURCE_INVALID covers several distinct
        # temporal violations (missing tombstone, illegal
        # lifecycle transition, alias reassignment...), and a
        # test asserting only the category cannot prove WHICH
        # invariant actually caused the rejection.
        print(f"AUTHORITY_ERROR:{exc.failure.value}:{exc}")
        sys.exit(1)
    except Exception as exc:
        print(f"UNEXPECTED:{exc!r}")
        sys.exit(2)