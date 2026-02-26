"""
Security Input Sanitizer

Centralised input sanitisation for all security tool wrappers.
Prevents command injection through shell metacharacters, extra_args,
heredoc terminators, and unquoted parameters.
"""

from __future__ import annotations

import re
import secrets
import shlex
from pathlib import PurePosixPath

# ── Shell metacharacters that MUST NOT appear in unquoted tool parameters ──
_SHELL_METACHAR_RE = re.compile(r"[;&|`$(){}!<>\n\r\\]")

# ── Allowed extra-arg prefixes (must begin with '-') ──
_EXTRA_ARG_FLAG_RE = re.compile(r"^--?[a-zA-Z]")


def sanitize_extra_args(extra_args: str | None) -> list[str]:
    """Safely parse *extra_args* into a list of individually-quoted tokens.

    Rules
    -----
    1. ``shlex.split`` is used for proper tokenisation.
    2. Every resulting token is **individually** wrapped with ``shlex.quote``
       so that shell metacharacters cannot escape into the parent command.
    3. Tokens that do not look like CLI flags (``-``/``--`` prefixed) are
       rejected — this blocks bare commands injected via ``;``, ``|``, etc.
    4. Returns an empty list when *extra_args* is ``None`` or empty.
    """
    if not extra_args or not extra_args.strip():
        return []

    try:
        tokens = shlex.split(extra_args)
    except ValueError:
        # Malformed quoting — reject entirely
        return []

    safe_tokens: list[str] = []
    skip_next = False
    for i, token in enumerate(tokens):
        if skip_next:
            # This token is a value for the previous flag → quote it
            safe_tokens.append(shlex.quote(token))
            skip_next = False
            continue

        if _EXTRA_ARG_FLAG_RE.match(token):
            safe_tokens.append(shlex.quote(token))
            # If the flag expects a value (next token doesn't start with -)
            if i + 1 < len(tokens) and not tokens[i + 1].startswith("-"):
                skip_next = True
        else:
            # Non-flag token without a preceding flag → reject (possible injection)
            continue

    return safe_tokens


def quote_param(value: str) -> str:
    """Unconditionally shell-quote a single parameter value."""
    return shlex.quote(value)


def validate_no_metachar(value: str, param_name: str = "parameter") -> str:
    """Raise if *value* contains dangerous shell metacharacters.

    Returns the original value unmodified when safe.
    """
    if _SHELL_METACHAR_RE.search(value):
        raise ValueError(
            f"Unsafe characters in {param_name}: {value!r}. "
            "Shell metacharacters (;&|`$) are not allowed."
        )
    return value


def safe_heredoc_write(filepath: str, content: str) -> str:
    """Build a safe heredoc command that cannot be terminated early.

    Uses a randomised EOF marker so user content cannot match it.
    """
    marker = f"_PHANTOM_EOF_{secrets.token_hex(8)}"
    quoted_path = shlex.quote(filepath)
    return f"cat > {quoted_path} <<'{marker}'\n{content}\n{marker}"


def safe_temp_path(prefix: str, suffix: str = ".json") -> str:
    """Generate an unpredictable temporary file path under ``/tmp``."""
    return f"/tmp/{prefix}_{secrets.token_hex(8)}{suffix}"


def validate_workspace_path(path: str, workspace: str = "/workspace") -> str:
    """Ensure *path* resolves within *workspace*.

    Raises ``ValueError`` on path-traversal attempts.
    """
    import posixpath

    joined = str(PurePosixPath(workspace) / PurePosixPath(path))
    # Properly resolve '..' via normpath (collapses parent references)
    normalised = posixpath.normpath(joined)
    # Ensure the normalised path is inside the workspace
    if normalised != workspace and not normalised.startswith(workspace + "/"):
        raise ValueError(f"Path {path!r} escapes the workspace boundary")
    return normalised
