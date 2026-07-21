# renderers/ansi.py
#
# Purpose:
# Shared terminal ANSI formatting helpers — used by every
# renderer (text_renderer.py, explain_renderer.py) and any
# CLI command that prints formatted output (audit.py,
# sentinel/scan.py).
#
# Extracted here because text_renderer.py and explain_renderer.py
# each independently defined their own private (_-prefixed) copies
# of the same four functions. Depending on another module's
# private functions is fragile — they can change or be renamed
# without warning, since a leading underscore signals "internal
# only, not a stable interface." This module makes the shared
# logic a real, public, single source of truth.

from __future__ import annotations

import sys

_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"


def _supports_color() -> bool:
    """Return True if the terminal supports ANSI color codes."""
    isatty = getattr(sys.stdout, "isatty", None)
    return callable(isatty) and isatty()


def _color(text: str, code: str) -> str:
    """Wrap text in an ANSI code, if the terminal supports color."""
    return f"{code}{text}{_RESET}" if _supports_color() else text


def _bold(text: str) -> str:
    return _color(text, _BOLD)


def _dim(text: str) -> str:
    return _color(text, _DIM)


def _dim_italics(text: str) -> str:
    return _color(text, "\033[2m\033[3m")
