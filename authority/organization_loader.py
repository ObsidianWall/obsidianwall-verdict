# authority/organization_loader.py
#
# Purpose:
# Load organization.yaml from disk as raw parsed YAML —
# nothing more. Mirrors engine/policy_loader.py's load_policy()
# pattern: bare loading, with validation handled entirely
# separately (schemas/organization_schema.py's
# OrganizationAuthority).
#
# This file deliberately does NOT:
#   - validate structure or shape (schemas/organization_schema.py)
#   - resolve roles, membership, or authority (authority/
#     local_provider.py)
#   - map exceptions to AuthorityProviderFailure (also
#     local_provider.py — this file raises plain Python
#     exceptions, undecorated)
#
# Per ADR-004-R-04 SS6.1: must NOT live under telemetry/.

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


def load_organization(path: str | Path) -> Any:
    """
    Load organization.yaml from the given path as whatever
    yaml.safe_load() produces — genuinely raw, no shape
    guarantee at all.

    Deliberately returns Any, not dict[str, Any]: syntactically
    valid YAML can parse to a list, string, int, bool, or None,
    not only a mapping. Returning a narrower type here would be
    a false promise, and would push callers toward
    OrganizationAuthority(**data) — which fails with a raw
    Python TypeError on non-dict input, BEFORE Pydantic ever
    runs, bypassing the clean ValidationError -> SOURCE_INVALID
    mapping entirely.

    Callers must validate with:

        OrganizationAuthority.model_validate(data)

    NOT:

        OrganizationAuthority(**data)

    model_validate() accepts Any and raises pydantic.ValidationError
    uniformly regardless of whether data is a list, string, int,
    None, or a malformed dict — giving local_provider.py exactly
    one exception type to map to SOURCE_INVALID, rather than a
    ValidationError for some bad inputs and a bare TypeError for
    others.

    Args:
        path: path to the organization.yaml file.

    Returns:
        Whatever yaml.safe_load() produces — a dict for
        well-formed input, but callers must not assume that.

    Raises:
        FileNotFoundError: if path does not exist. Callers
            building an AuthorityProvider map this to
            AuthorityProviderFailure.SOURCE_NOT_FOUND.
        PermissionError: if path exists but cannot be read.
            Callers map this to
            AuthorityProviderFailure.PROVIDER_UNAVAILABLE —
            an unreadable file is an environmental problem,
            not a "missing" or "malformed" one.
        UnicodeDecodeError: if the file's encoding is invalid.
            Callers map this to SOURCE_INVALID.
        yaml.YAMLError: if the file exists and is readable but
            is not valid YAML. Callers map this to
            SOURCE_INVALID.

    None of these are caught or re-raised here — this file
    stays a plain loader. All mapping to the ADR's structured
    failure taxonomy happens in local_provider.py, which needs
    this taxonomy anyway for the pydantic.ValidationError case
    that only arises AFTER this function returns.
    """
    file_path = Path(path)

    with file_path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)
