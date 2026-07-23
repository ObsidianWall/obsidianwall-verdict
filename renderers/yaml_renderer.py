# renderers/yaml_renderer.py
#
# Purpose:
# Full YAML artifact renderer.
#
# Produces the complete governance decision artifact
# as YAML to stdout. More human-readable than JSON
# for manual inspection while remaining machine-parseable.
#
# Audience: engineers who prefer YAML, documentation
#           workflows, policy authoring contexts

from __future__ import annotations

from typing import Any

import yaml


def render_yaml(result: dict[str, Any]) -> None:
    """
    Print the complete governance decision artifact
    as YAML to stdout.

    Produces the same content as --format json but
    formatted as YAML for improved human readability
    during manual inspection or documentation workflows.
    """
    print(
        yaml.dump(
            result,
            default_flow_style=False,
            allow_unicode=True,
            sort_keys=False,
        )
    )
