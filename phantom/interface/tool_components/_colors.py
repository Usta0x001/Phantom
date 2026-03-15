"""Shared syntax-highlighting color cache for tool-component renderers.

All renderers that need Pygments token→color mappings should import
``get_style_colors`` from here rather than defining their own copy.
"""

from functools import cache
from typing import Any

from pygments.styles import get_style_by_name


@cache
def get_style_colors() -> dict[Any, str]:
    """Return a cached ``{TokenType: '#rrggbb'}`` mapping for the *native* theme."""
    style = get_style_by_name("native")
    return {token: f"#{style_def['color']}" for token, style_def in style if style_def["color"]}


def get_token_color(token_type: Any) -> str | None:
    """Walk the Pygments token hierarchy and return the first matching hex color, or ``None``."""
    colors = get_style_colors()
    while token_type:
        if token_type in colors:
            return colors[token_type]
        token_type = token_type.parent
    return None
