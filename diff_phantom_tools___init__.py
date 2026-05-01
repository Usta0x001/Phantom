diff --git a/phantom/tools/__init__.py b/phantom/tools/__init__.py
index ca00643..6a01d84 100644
--- a/phantom/tools/__init__.py
+++ b/phantom/tools/__init__.py
@@ -22,63 +22,133 @@ from .registry import (
 )
 
 
-SANDBOX_MODE = os.getenv("PHANTOM_SANDBOX_MODE", "false").lower() == "true"
-
-TOOL_SUBSET_MODE = (Config.get("phantom_tool_subset") or "full").strip().lower()
+TOOL_SUBSET_MODE = (Config.get("phantom_tool_subset") or "core").strip().lower()
 EXTENDED_TOOLS_ENABLED = TOOL_SUBSET_MODE == "full"
 
 HAS_PERPLEXITY_API = bool(Config.get("perplexity_api_key"))
 
 DISABLE_BROWSER = (Config.get("phantom_disable_browser") or "false").lower() == "true"
 
-if not SANDBOX_MODE:
-    from .agents_graph import *  # noqa: F403
-
-    if not DISABLE_BROWSER:
-        from .browser import *  # noqa: F403
-    from .file_edit import *  # noqa: F403
-    from .finish import *  # noqa: F403
-    from .fuzzer import *  # noqa: F403
-    from .proxy import *  # noqa: F403
-    from .python import *  # noqa: F403
-    from .reporting import *  # noqa: F403
-    from .recon import *  # noqa: F403
-    from .terminal import *  # noqa: F403
-    from .todo import *  # noqa: F403
-    from .thinking import *  # noqa: F403
-
-    # Hypothesis ledger - critical for tracking tested hypotheses
-    from .hypothesis import *  # noqa: F403
-
-    # Scan status - critical for LLM reasoning
-    from .scan_status import *  # noqa: F403
-
-    from .notes import *  # noqa: F403
-    from .oast import *  # noqa: F403
-    from .scan_registry import *  # noqa: F403
-    from .session import *  # noqa: F403
-    from .web_search import *  # noqa: F403
-
-    # Phase 1 Enhancement Tools
-    from .osint import *  # noqa: F403
-    from .vuln_intel import *  # noqa: F403
-    from .waf import *  # noqa: F403
-
-    # Phase 2 Enhancement Tools
-    from .payload_gen import *  # noqa: F403
-    from .response_analysis import *  # noqa: F403
-    from .session_mgmt import *  # noqa: F403
-    from .api_schema import *  # noqa: F403
-
-    # Detection module
-    from .detection import *  # noqa: F403
-
-    # Always register non-browser core tools in non-sandbox mode.
-    from .file_edit import *  # noqa: F403
-    from .fuzzer import *  # noqa: F403
-    from .proxy import *  # noqa: F403
-    from .python import *  # noqa: F403
-    from .terminal import *  # noqa: F403
+from .agents_graph import (
+    agent_finish,
+    create_agent,
+    send_message_to_agent,
+    view_agent_graph,
+    wait_for_message,
+    wait_for_agents,
+    reset_all_state,
+)
+
+if not DISABLE_BROWSER:
+    from .browser import (
+        browser_action,
+    )
+
+from .file_edit import (
+    list_files,
+    search_files,
+    str_replace_editor,
+)
+
+from .finish import (
+    finish_scan,
+)
+
+from .fuzzer import (
+    execute_fuzz_batch,
+)
+
+from .proxy import (
+    repeat_request,
+    scope_rules,
+    send_request,
+    list_requests,
+    view_request,
+)
+
+from .python import (
+    python_action,
+)
+
+from .reporting import (
+    create_vulnerability_report,
+)
+
+from .recon import (
+    comprehensive_js_analysis,
+)
+
+from .terminal import (
+    terminal_execute,
+)
+
+from .thinking import (
+    think,
+)
+
+from .hypothesis import (
+    add_hypothesis,
+    confirm_hypothesis,
+    get_hypothesis_summary,
+    has_tested_payload,
+    query_hypotheses,
+    record_payload_test,
+    reject_hypothesis,
+    set_ledger,
+)
+
+from .scan_status import (
+    get_scan_status,
+    set_scan_status_context,
+)
+
+from .oast import (
+    generate_oast_payload,
+    check_oast_interactions,
+)
+
+from .web_search import (
+    web_search,
+)
+
+from .osint import (
+    shodan_search,
+    crtsh_search,
+    dns_enum,
+    github_dork,
+)
+
+from .vuln_intel import (
+    cve_search,
+    exploit_search,
+)
+
+from .waf import (
+    detect_waf,
+)
+
+from .payload_gen import (
+    generate_smart_payloads,
+)
+
+from .response_analysis import (
+    analyze_response,
+)
+
+from .session_mgmt import (
+    automate_login,
+    extract_csrf_token,
+    manage_cookies,
+)
+
+from .api_schema import (
+    extract_api_endpoints,
+)
+
+from .detection import (
+    detect_pattern,
+    detect_error_based,
+)
 
 __all__ = [
     "ImplementedInClientSideOnlyError",
@@ -95,4 +165,54 @@ __all__ = [
     "remove_screenshot_from_result",
     "tools",
     "validate_tool_availability",
+    "agent_finish",
+    "create_agent",
+    "send_message_to_agent",
+    "view_agent_graph",
+    "wait_for_message",
+    "wait_for_agents",
+    "reset_all_state",
+    "browser_action",
+    "list_files",
+    "search_files",
+    "str_replace_editor",
+    "finish_scan",
+    "execute_fuzz_batch",
+    "repeat_request",
+    "scope_rules",
+    "send_request",
+    "list_requests",
+    "view_request",
+    "python_action",
+    "create_vulnerability_report",
+    "comprehensive_js_analysis",
+    "terminal_execute",
+    "add_hypothesis",
+    "confirm_hypothesis",
+    "get_hypothesis_summary",
+    "has_tested_payload",
+    "query_hypotheses",
+    "record_payload_test",
+    "reject_hypothesis",
+    "set_ledger",
+    "get_scan_status",
+    "set_scan_status_context",
+    "generate_oast_payload",
+    "check_oast_interactions",
+    "web_search",
+    "shodan_search",
+    "crtsh_search",
+    "dns_enum",
+    "github_dork",
+    "cve_search",
+    "exploit_search",
+    "detect_waf",
+    "generate_smart_payloads",
+    "analyze_response",
+    "automate_login",
+    "extract_csrf_token",
+    "manage_cookies",
+    "extract_api_endpoints",
+    "detect_pattern",
+    "detect_error_based",
 ]
