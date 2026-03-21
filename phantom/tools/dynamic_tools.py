"""
Dynamic Tool Loading - Load only the tools the agent needs, not all 37 tools.

This is the KEY optimization for reducing token usage from ~25K to ~5K per call.

Instead of sending ALL 37 tool schemas (18K tokens), we send only the tools
relevant to the current task.
"""

from typing import Any


TOOL_CATEGORIES = {
    "web_testing": [
        "send_request",
        "repeat_request",
        "scope_rules",
        "list_requests",
        "view_request",
    ],
    "terminal": [
        "terminal_execute",
    ],
    "browser": [
        "browser_action",
    ],
    "agent_management": [
        "create_agent",
        "wait_for_message",
        "view_agent_graph",
        "send_message_to_agent",
        "agent_finish",
    ],
    "reporting": [
        "create_vulnerability_report",
        "finish_scan",
    ],
    "files": [
        "list_files",
        "search_files",
        "str_replace_editor",
    ],
    "notes": [
        "create_note",
        "list_notes",
        "update_note",
        "delete_note",
    ],
    "todo": [
        "create_todo",
        "list_todos",
        "update_todo",
        "delete_todo",
    ],
    "thinking": [
        "think",
    ],
    "web_search": [
        "web_search",
    ],
    "python": [
        "python_action",
    ],
    "session": [
        "session_login",
        "session_get",
        "session_refresh",
    ],
    "scan_registry": [
        "check_scan_registry",
        "register_scan_target",
    ],
}


DEFAULT_TOOL_CATEGORIES = {
    # FIX-5: Excluded 'files', 'notes', 'todo' from the default main_agent schema.
    # These are low-signal for pentesting but cost ~5K tokens per LLM call to describe.
    # 300 iterations * 5K tokens = 1.5M tokens saved per scan.
    "main_agent": ["web_testing", "terminal", "browser", "reporting", "agent_management"],
    "sub_agent": ["web_testing", "terminal", "browser", "files"],
    "quick_scan": ["web_testing", "terminal", "reporting"],
}


def get_tools_for_context(
    agent_name: str | None = None,
    scan_mode: str = "standard",
    is_subagent: bool = False,
    excluded_modules: list[str] | None = None,
) -> list[str]:
    """
    Select tools based on agent context available at init time.
    
    This is the key integration point - it uses available context to choose
    a minimal but sufficient tool set instead of loading all 37 tools.
    """
    _excluded = set(excluded_modules or [])
    
    # Determine which categories to include
    categories = set()
    
    if is_subagent:
        categories.update(DEFAULT_TOOL_CATEGORIES.get("sub_agent", DEFAULT_TOOL_CATEGORIES["main_agent"]))
    elif scan_mode == "quick":
        categories.update(DEFAULT_TOOL_CATEGORIES.get("quick_scan", DEFAULT_TOOL_CATEGORIES["main_agent"]))
    else:
        categories.update(DEFAULT_TOOL_CATEGORIES.get("main_agent", DEFAULT_TOOL_CATEGORIES["main_agent"]))
    
    # Handle excluded modules from the caller
    if "finish" in _excluded or "reporting" in _excluded:
        categories.discard("reporting")
    if "todo" in _excluded:
        categories.discard("todo")
    if "notes" in _excluded:
        categories.discard("notes")
    
    # Collect tools from selected categories
    needed_tools = set()
    for cat in categories:
        if cat in TOOL_CATEGORIES:
            needed_tools.update(TOOL_CATEGORIES[cat])
    
    return list(needed_tools)


def get_tools_for_task(task_description: str, available_tools: list[str] | None = None) -> list[str]:
    """
    Analyze the task description and return only the tools needed.
    
    This uses simple keyword matching to determine which tools are relevant.
    """
    task_lower = task_description.lower()
    
    # Map keywords to tool categories
    keyword_map = {
        "sqli": ["web_testing", "terminal"],
        "sql injection": ["web_testing", "terminal"],
        "xss": ["web_testing", "browser"],
        "cross-site": ["web_testing", "browser"],
        "ssrf": ["web_testing", "terminal"],
        "idor": ["web_testing"],
        "auth": ["web_testing", "terminal"],
        "login": ["web_testing", "browser"],
        "register": ["web_testing", "browser"],
        "password": ["web_testing", "terminal"],
        "rce": ["web_testing", "terminal"],
        "exec": ["terminal"],
        "command": ["terminal"],
        "file upload": ["web_testing", "files"],
        "upload": ["web_testing", "files"],
        "directory": ["web_testing"],
        "scan": ["web_testing", "agent_management"],
        "nmap": ["terminal"],
        "naabu": ["terminal"],
        "nikto": ["terminal"],
        "ffuf": ["terminal"],
        "gobuster": ["terminal"],
        "dirsearch": ["terminal"],
        "sqlmap": ["terminal"],
        "xsstrike": ["terminal"],
        "browser": ["browser"],
        "click": ["browser"],
        "fill": ["browser"],
        "navigate": ["browser"],
        "report": ["reporting"],
        "vulnerability": ["reporting"],
        "finish": ["reporting"],
        "agent": ["agent_management"],
        "spawn": ["agent_management"],
    }
    
    # Determine which categories to include
    categories = set()
    categories.add("agent_management")  # Always include for orchestration
    
    for keyword, cats in keyword_map.items():
        if keyword in task_lower:
            categories.update(cats)
    
    # Collect tools from selected categories
    needed_tools = set()
    for cat in categories:
        if cat in TOOL_CATEGORIES:
            needed_tools.update(TOOL_CATEGORIES[cat])
    
    # If available_tools specified, filter to only those
    if available_tools:
        needed_tools = needed_tools.intersection(set(available_tools))
    
    return list(needed_tools)


def get_minimal_tools() -> list[str]:
    """Get the absolute minimum tools needed for any scan."""
    return [
        "send_request",
        "terminal_execute",
        "create_vulnerability_report",
        "finish_scan",
    ]


def get_tools_prompt_subset(tool_names: list[str]) -> str:
    """
    Get tool schemas for only the specified tools.
    
    This is the key function that replaces the full get_tools_prompt().
    """
    from phantom.tools.registry import tools
    
    xml_sections = []
    
    # Group tools by module
    tools_by_module: dict[str, list[dict[str, Any]]] = {}
    
    for tool in tools:
        if tool.get("name") in tool_names:
            module = tool.get("module", "unknown")
            if module not in tools_by_module:
                tools_by_module[module] = []
            tools_by_module[module].append(tool)
    
    for module, module_tools in sorted(tools_by_module.items()):
        section_parts = [f"<!-- {module} tools -->"]
        for tool in module_tools:
            tool_xml = tool.get("xml_schema", "")
            if tool_xml:
                indented_tool = "\n".join(f"  {line}" for line in tool_xml.split("\n"))
                section_parts.append(indented_tool)
        section_parts.append(f"<!-- end {module} tools -->")
        xml_sections.append("\n".join(section_parts))
    
    return "\n\n".join(xml_sections)
