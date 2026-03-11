"""phantom.interface — CLI, TUI, and non-interactive runners.

All heavy sub-modules (main, tui, cli) are imported lazily to keep the
`phantom` CLI startup time under ~1 second.  Eager import of `main` was
previously triggering a full litellm + docker + textual import chain on
every invocation — even simple `phantom --help` calls.
"""

from __future__ import annotations

__all__ = ["main"]


def __getattr__(name: str) -> object:
    if name == "main":
        from .main import main  # noqa: PLC0415

        return main
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
