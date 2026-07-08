# renderers/__init__.py
#
# Purpose:
# Renderer package for governance decision output.
#
# A renderer produces a representation of a governance
# decision for a specific audience. The decision itself
# is the canonical artifact — renderers never alter it.
#
# Available renderers:
#   text    Human-readable terminal summary (default)
#   json    Full JSON artifact (machine-readable)
#   yaml    Full YAML artifact (human-readable machines)
#
# Usage:
#   from renderers import render
#   render(result, fmt="text", output_path="output/result.json")
#   render(result, fmt="json")
#   render(result, fmt="yaml")

from typing import Any, Callable

from renderers.json_renderer import render_json
from renderers.text_renderer import render_text
from renderers.yaml_renderer import render_yaml

_JSON_YAML_RENDERERS: dict[str, Callable[[dict[str, Any]], None]] = {
    "json": render_json,
    "yaml": render_yaml,
}

SUPPORTED_FORMATS: list[str] = ["text", "json", "yaml"]


def render(
    result: dict[str, Any],
    fmt: str = "text",
    output_path: str | None = None,
) -> None:
    """
    Render a governance decision result to stdout.

    Args:
        result:      complete verdict evaluate result dict.
                     NEVER mutated by this function — passed
                     through to renderers as-is. The canonical
                     artifact must never contain CLI bookkeeping
                     fields like output_path.
        fmt:         output format — "text", "json", or "yaml"
                     defaults to "text"
        output_path: path to the full JSON artifact file, shown
                     only in the text renderer's footer. Ignored
                     by json and yaml renderers since they ARE
                     the full artifact already.

    Raises:
        ValueError: if fmt is not a supported format
    """
    if fmt not in SUPPORTED_FORMATS:
        raise ValueError(
            f"Unsupported format: '{fmt}'. "
            f"Supported formats: {', '.join(SUPPORTED_FORMATS)}"
        )

    if fmt == "text":
        render_text(result, output_path=output_path)
    else:
        _JSON_YAML_RENDERERS[fmt](result)
