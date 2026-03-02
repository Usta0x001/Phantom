import logging
import re
from typing import Any

from phantom.tools.registry import register_tool

_logger = logging.getLogger(__name__)

# Patterns that indicate large wordlist/tool downloads we want to block.
# These waste 10-30 minutes downloading multi-GB files at runtime.
_BLOCKED_DOWNLOAD_PATTERNS = [
    re.compile(r"(wget|curl).*SecLists", re.IGNORECASE),
    re.compile(r"(wget|curl).*rockyou", re.IGNORECASE),
    re.compile(r"git\s+clone.*SecLists", re.IGNORECASE),
    re.compile(r"git\s+clone.*wordlist", re.IGNORECASE),
    re.compile(r"git\s+clone.*rockyou", re.IGNORECASE),
    re.compile(r"apt(-get)?\s+install.*seclists", re.IGNORECASE),
    re.compile(r"(wget|curl).*/danielmiessler/", re.IGNORECASE),
]


@register_tool
def terminal_execute(
    command: str,
    is_input: bool = False,
    timeout: float | None = None,
    terminal_id: str | None = None,
    no_enter: bool = False,
) -> dict[str, Any]:
    # Validate command input
    if not command or not command.strip():
        return {
            "error": "Command cannot be empty",
            "command": command,
            "terminal_id": terminal_id or "default",
            "content": "",
            "status": "error",
            "exit_code": None,
            "working_dir": None,
        }

    # Block large wordlist/tool downloads that waste time
    for pattern in _BLOCKED_DOWNLOAD_PATTERNS:
        if pattern.search(command):
            _logger.warning("Blocked large download command: %s", command[:200])
            return {
                "error": (
                    "BLOCKED: Do not download large wordlists. "
                    "Use pre-installed wordlists in /usr/share/wordlists/ "
                    "or generate small custom wordlists inline with: "
                    "printf '%s\\n' word1 word2 word3 > /tmp/my_wordlist.txt"
                ),
                "command": command,
                "terminal_id": terminal_id or "default",
                "content": "",
                "status": "blocked",
                "exit_code": None,
                "working_dir": None,
            }

    from .terminal_manager import get_terminal_manager

    manager = get_terminal_manager()

    try:
        return manager.execute_command(
            command=command,
            is_input=is_input,
            timeout=timeout,
            terminal_id=terminal_id,
            no_enter=no_enter,
        )
    except (ValueError, RuntimeError) as e:
        return {
            "error": str(e),
            "command": command,
            "terminal_id": terminal_id or "default",
            "content": "",
            "status": "error",
            "exit_code": None,
            "working_dir": None,
        }
