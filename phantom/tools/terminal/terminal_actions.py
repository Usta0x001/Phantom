import logging
import re
from typing import Any

from phantom.tools.registry import register_tool

_logger = logging.getLogger(__name__)

# Only block cloning/downloading the FULL SecLists repo (~2GB) or rockyou (~14GB).
# Individual small wordlist files are fine to download.
_BLOCKED_DOWNLOAD_PATTERNS = [
    re.compile(r"git\s+clone.*danielmiessler/SecLists", re.IGNORECASE),
    re.compile(r"git\s+clone.*SecLists\.git", re.IGNORECASE),
    re.compile(r"apt(-get)?\s+install.*seclists", re.IGNORECASE),
    re.compile(r"(wget|curl).*rockyou\.txt\.gz", re.IGNORECASE),
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

    # Block only full SecLists repo clone (~2GB) and rockyou (~14GB)
    for pattern in _BLOCKED_DOWNLOAD_PATTERNS:
        if pattern.search(command):
            _logger.warning("Blocked large download: %s", command[:200])
            return {
                "error": (
                    "BLOCKED: Do not clone the full SecLists repo (2GB+). "
                    "Instead, download only the specific wordlist file you need, e.g.: "
                    "wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt -O /tmp/params.txt"
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
