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


TOOL_SUBSET_MODE = (Config.get("phantom_tool_subset") or "core").strip().lower()
EXTENDED_TOOLS_ENABLED = TOOL_SUBSET_MODE == "full"

HAS_PERPLEXITY_API = bool(Config.get("perplexity_api_key"))

DISABLE_BROWSER = (Config.get("phantom_disable_browser") or "false").lower() == "true"

from .agents_graph import (
    agent_finish,
    create_agent,
    send_message_to_agent,
    view_agent_graph,
    wait_for_message,
    wait_for_agents,
    reset_all_state,
)

if not DISABLE_BROWSER:
    from .browser import (
        browser_action,
    )

from .file_edit import (
    list_files,
    search_files,
    str_replace_editor,
)

from .finish import (
    finish_scan,
)

from .proxy import (
    repeat_request,
    scope_rules,
    send_request,
    list_requests,
    view_request,
)

from .python import (
    python_action,
)

from .reporting import (
    create_vulnerability_report,
)

from .recon import (
    comprehensive_js_analysis,
)

from .terminal import (
    terminal_execute,
)

from .thinking import (
    think,
)

from .hypothesis import (
    add_hypothesis,
    confirm_hypothesis,
    get_hypothesis_summary,
    has_tested_payload,
    query_hypotheses,
    record_payload_test,
    reject_hypothesis,
    set_ledger,
)

from .scan_status import (
    get_scan_status,
    set_scan_status_context,
)

from .web_search import (
    web_search,
)

from .osint import (
    shodan_search,
    crtsh_search,
    dns_enum,
    github_dork,
)

from .vuln_intel import (
    cve_search,
    exploit_search,
)

from .waf import (
    detect_waf,
)

from .payload_gen import (
    generate_smart_payloads,
)

from .response_analysis import (
    analyze_response,
)

from .session_mgmt import (
    automate_login,
    extract_csrf_token,
    manage_cookies,
)

from .api_schema import (
    extract_api_endpoints,
)

from .detection import (
    detect_pattern,
    detect_error_based,
)

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
    "agent_finish",
    "create_agent",
    "send_message_to_agent",
    "view_agent_graph",
    "wait_for_message",
    "wait_for_agents",
    "reset_all_state",
    "browser_action",
    "list_files",
    "search_files",
    "str_replace_editor",
    "finish_scan",
    "repeat_request",
    "scope_rules",
    "send_request",
    "list_requests",
    "view_request",
    "python_action",
    "create_vulnerability_report",
    "comprehensive_js_analysis",
    "terminal_execute",
    "add_hypothesis",
    "confirm_hypothesis",
    "get_hypothesis_summary",
    "has_tested_payload",
    "query_hypotheses",
    "record_payload_test",
    "reject_hypothesis",
    "set_ledger",
    "get_scan_status",
    "set_scan_status_context",
    "web_search",
    "shodan_search",
    "crtsh_search",
    "dns_enum",
    "github_dork",
    "cve_search",
    "exploit_search",
    "detect_waf",
    "generate_smart_payloads",
    "analyze_response",
    "automate_login",
    "extract_csrf_token",
    "manage_cookies",
    "extract_api_endpoints",
    "detect_pattern",
    "detect_error_based",
]
