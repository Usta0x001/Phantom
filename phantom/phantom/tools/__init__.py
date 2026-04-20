import os

from phantom.config import Config

from .executor import (
    execute_tool,
    execute_tool_invocation,
    execute_tool_with_validation,
    extract_screenshot_from_result,
    process_tool_invocations,
    remove_screenshot_from_result,
    validate_tool_availability,
)
from .registry import (
    ImplementedInClientSideOnlyError,
    get_tool_by_name,
    get_tool_names,
    get_tools_prompt,
    needs_agent_state,
    register_tool,
    tools,
)


TOOL_SUBSET_MODE = (Config.get("phantom_tool_subset") or "full").strip().lower()
EXTENDED_TOOLS_ENABLED = TOOL_SUBSET_MODE == "full"

HAS_PERPLEXITY_API = bool(Config.get("perplexity_api_key"))

DISABLE_BROWSER = (Config.get("phantom_disable_browser") or "false").lower() == "true"

from .agents_graph import *  # noqa: F403

if not DISABLE_BROWSER:
    from .browser import *  # noqa: F403
from .file_edit import *  # noqa: F403
from .finish import *  # noqa: F403
from .fuzzer import *  # noqa: F403
from .proxy import *  # noqa: F403
from .python import *  # noqa: F403
from .reporting import *  # noqa: F403
from .recon import *  # noqa: F403
from .terminal import *  # noqa: F403
from .todo import *  # noqa: F403
from .thinking import *  # noqa: F403

# Hypothesis ledger - critical for tracking tested hypotheses
from .hypothesis import *  # noqa: F403

# Scan status - critical for LLM reasoning
from .scan_status import *  # noqa: F403

from .notes import *  # noqa: F403
from .oast import *  # noqa: F403
from .scan_registry import *  # noqa: F403
from .session import *  # noqa: F403
from .web_search import *  # noqa: F403

# Phase 1 Enhancement Tools
from .osint import *  # noqa: F403
from .vuln_intel import *  # noqa: F403
from .waf import *  # noqa: F403

# Phase 2 Enhancement Tools
from .payload_gen import *  # noqa: F403
from .response_analysis import *  # noqa: F403
from .session_mgmt import *  # noqa: F403
from .api_schema import *  # noqa: F403

# Detection module
from .detection import *  # noqa: F403

# Always register non-browser core tools.
from .file_edit import *  # noqa: F403
from .fuzzer import *  # noqa: F403
from .proxy import *  # noqa: F403
from .python import *  # noqa: F403
from .terminal import *  # noqa: F403

__all__ = [
    "ImplementedInClientSideOnlyError",
    "execute_tool",
    "execute_tool_invocation",
    "execute_tool_with_validation",
    "extract_screenshot_from_result",
    "get_tool_by_name",
    "get_tool_names",
    "get_tools_prompt",
    "needs_agent_state",
    "process_tool_invocations",
    "register_tool",
    "remove_screenshot_from_result",
    "tools",
    "validate_tool_availability",
]
