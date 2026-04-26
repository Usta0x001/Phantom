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

from .fuzzer import (
    execute_fuzz_batch,
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
from .reporting import (
    create_elite_report,
    export_elite_report,
)

from .recon import (
    bruteforce_directories,
    comprehensive_js_analysis,
)

from .terminal import (
    terminal_execute,
)

from .todo import (
    create_todo,
    list_todos,
    update_todo,
    delete_todo,
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

from .notes import (
    create_note,
    list_notes,
    update_note,
    delete_note,
)

from .oast import (
    generate_oast_payload,
    check_oast_interactions,
)

from .scan_registry import (
    check_scan_registry,
    register_scan_target,
)

from .session import (
    session_login,
    session_get,
    session_refresh,
)

from .web_search import (
    web_search,
)

from .osint import (
    shodan_search,
    crtsh_search,
    dns_enum,
    github_dork,
    bruteforce_subdomains,
)

from .vuln_intel import (
    cve_search,
    exploit_search,
    auto_queue_cve_exploits,
)

from .waf import (
    detect_waf,
)

from .payload_gen import (
    generate_xss_payloads,
    generate_sqli_payloads,
    generate_xxe_payloads,
    generate_ssti_payloads,
    generate_cmd_injection_payloads,
)

from .response_analysis import (
    analyze_response,
    detect_errors,
    extract_secrets,
    identify_tech_stack,
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
    "execute_fuzz_batch",
    "repeat_request",
    "scope_rules",
    "send_request",
    "list_requests",
    "view_request",
    "python_action",
    "create_vulnerability_report",
    "create_elite_report",
    "export_elite_report",
    "bruteforce_directories",
    "comprehensive_js_analysis",
    "terminal_execute",
    "create_todo",
    "list_todos",
    "update_todo",
    "delete_todo",
    "think",
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
    "create_note",
    "list_notes",
    "update_note",
    "delete_note",
    "generate_oast_payload",
    "check_oast_interactions",
    "check_scan_registry",
    "register_scan_target",
    "session_login",
    "session_get",
    "session_refresh",
    "web_search",
    "shodan_search",
    "crtsh_search",
    "dns_enum",
    "github_dork",
    "bruteforce_subdomains",
    "cve_search",
    "exploit_search",
    "auto_queue_cve_exploits",
    "detect_waf",
    "generate_xss_payloads",
    "generate_sqli_payloads",
    "generate_xxe_payloads",
    "generate_ssti_payloads",
    "generate_cmd_injection_payloads",
    "analyze_response",
    "detect_errors",
    "extract_secrets",
    "identify_tech_stack",
    "automate_login",
    "extract_csrf_token",
    "manage_cookies",
    "extract_api_endpoints",
    "detect_pattern",
    "detect_error_based",
]
