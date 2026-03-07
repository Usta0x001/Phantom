"""
Command Allowlist — V2-ARCH-001 / FIX-001

Centralized command validation for terminal execution.
Only known penetration testing tools are permitted.
All commands are parsed via shlex to extract the base binary,
then validated against the allowlist before execution.

This is the primary defense against arbitrary command execution
via prompt injection through tool outputs.
"""

from __future__ import annotations

import logging
import re
import shlex
from pathlib import PurePosixPath
from typing import Final

_logger = logging.getLogger(__name__)

# ── Allowed base commands for penetration testing ──
# Only these binaries may be invoked via terminal_execute().
# To add a new tool, add it here AND document the security review.
ALLOWED_COMMANDS: Final[frozenset[str]] = frozenset({
    # Reconnaissance
    "nmap", "masscan", "ping", "traceroute", "dig", "nslookup",
    "whois", "host", "dnsrecon", "fierce", "amass", "subfinder",
    "assetfinder", "theharvester",
    # Web scanning
    "nuclei", "nikto", "whatweb", "wafw00f", "wappalyzer",
    "httpx", "httprobe", "katana", "hakrawler", "gau",
    # Fuzzing / brute-force
    "ffuf", "gobuster", "dirb", "dirsearch", "wfuzz", "feroxbuster",
    # Exploitation
    "sqlmap", "hydra", "medusa", "john", "hashcat",
    # SSL/TLS
    "testssl.sh", "testssl", "sslscan", "sslyze",
    # Network utilities
    "curl", "wget", "nc", "ncat", "netcat", "socat",
    "openssl", "ssh", "scp", "telnet",
    # SMB/AD
    "enum4linux", "enum4linux-ng", "smbclient", "rpcclient",
    "ldapsearch", "crackmapexec", "impacket-smbclient",
    "impacket-psexec", "impacket-wmiexec",
    # Container-safe utilities
    "cat", "head", "tail", "grep", "awk", "sed", "sort", "uniq",
    "wc", "cut", "tr", "find", "ls", "echo", "printf", "tee",
    "base64", "xxd", "hexdump", "file", "strings", "less", "more",
    "jq", "yq", "xargs",
    # Python (controlled — separate sandbox validates code)
    "python3", "python",
    # Misc pentest
    "msfconsole", "msfvenom", "searchsploit",
    "responder", "bettercap",
    "arp-scan", "arping",
})

# ── Commands that are ALWAYS blocked regardless of allowlist ──
BLOCKED_COMMANDS: Final[frozenset[str]] = frozenset({
    "rm", "rmdir", "mkfs", "dd", "shred",
    "reboot", "shutdown", "poweroff", "halt", "init",
    "iptables", "ip6tables", "nft",  # Prevent egress filter bypass
    "docker", "podman", "kubectl",  # Prevent container escape
    "mount", "umount", "chroot",
    "useradd", "userdel", "passwd", "chown", "chmod",
    "systemctl", "service", "journalctl",
    "crontab", "at",
    "kill", "killall", "pkill",
})

# ── Shell operators that indicate chaining (injection attempts) ──
_SHELL_CHAIN_RE = re.compile(r"[;&|`$]|\$\(|>\s*/")

# ── Maximum command length to prevent abuse ──
MAX_COMMAND_LENGTH: Final[int] = 4096


class CommandValidationError(Exception):
    """Raised when a command fails allowlist validation."""

    def __init__(self, command: str, reason: str) -> None:
        self.command = command
        self.reason = reason
        super().__init__(f"Command blocked: {reason}")


def validate_command(command: str) -> str:
    """Validate a command against the allowlist.

    Returns the command unchanged if valid.
    Raises CommandValidationError if the command is not permitted.
    """
    if not command or not command.strip():
        raise CommandValidationError(command, "Command cannot be empty")

    if len(command) > MAX_COMMAND_LENGTH:
        raise CommandValidationError(
            command[:100] + "...",
            f"Command exceeds maximum length ({MAX_COMMAND_LENGTH} chars)",
        )

    # Extract the base command (first token)
    try:
        tokens = shlex.split(command)
    except ValueError:
        raise CommandValidationError(command[:100], "Malformed command (unparseable quoting)")

    if not tokens:
        raise CommandValidationError(command[:100], "Command parsed to empty token list")

    # Resolve the base binary name (strip path prefix)
    base_cmd = PurePosixPath(tokens[0]).name

    # Check blocked list first (highest priority)
    if base_cmd in BLOCKED_COMMANDS:
        _logger.warning(
            "BLOCKED command (blocklist): %s → %s", base_cmd, command[:200]
        )
        raise CommandValidationError(
            command[:100],
            f"Command '{base_cmd}' is explicitly blocked for security reasons",
        )

    # Check allowlist
    if base_cmd not in ALLOWED_COMMANDS:
        _logger.warning(
            "BLOCKED command (not in allowlist): %s → %s", base_cmd, command[:200]
        )
        raise CommandValidationError(
            command[:100],
            f"Command '{base_cmd}' is not in the allowed pentest tool list. "
            f"Only known penetration testing tools may be executed.",
        )

    # Check for shell chaining operators in the raw command
    # Allow pipes (|) only between allowed commands
    if _has_unsafe_shell_operators(command):
        _logger.warning(
            "BLOCKED command (shell operators): %s", command[:200]
        )
        raise CommandValidationError(
            command[:100],
            "Command contains unsafe shell operators (;, &, `, $()). "
            "Use separate terminal_execute calls instead of chaining.",
        )

    return command


def _has_unsafe_shell_operators(command: str) -> bool:
    """Check for dangerous shell operators while allowing safe pipes.

    Allows: cmd1 | cmd2 (pipe between commands)
    Blocks: ;, &&, ||, `, $(), >, >> to sensitive paths
    """
    # Split by pipe and validate each segment
    segments = command.split("|")

    for i, segment in enumerate(segments):
        segment = segment.strip()
        if not segment:
            continue

        # Check for dangerous operators within each segment
        # Allow > and >> for output redirection to /tmp and /workspace only
        if re.search(r"[;&`]|\$\(", segment):
            return True

        # Check output redirection targets
        redir_match = re.search(r">\s*(\S+)", segment)
        if redir_match:
            target = redir_match.group(1)
            if not _is_safe_redirect_target(target):
                return True

        # For piped segments after the first, validate the command
        if i > 0:
            try:
                pipe_tokens = shlex.split(segment)
                if pipe_tokens:
                    pipe_cmd = PurePosixPath(pipe_tokens[0]).name
                    if pipe_cmd in BLOCKED_COMMANDS:
                        return True
                    if pipe_cmd not in ALLOWED_COMMANDS:
                        return True
            except ValueError:
                return True

    return False


def _is_safe_redirect_target(target: str) -> bool:
    """Check if an output redirection target is in a safe location."""
    safe_prefixes = ("/tmp/", "/workspace/", "/dev/null")
    return any(target.startswith(p) for p in safe_prefixes)
