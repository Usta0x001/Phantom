"""
Dynamic Tool Loading - Load only the tools the agent needs, not all 37 tools.

This is the KEY optimization for reducing token usage from ~25K to ~5K per call.

Instead of sending ALL 37 tool schemas (18K tokens), we send only the tools
relevant to the current task.
"""

import re
from html import unescape as html_unescape
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
        "wait_for_agents",
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
    "memory": [
        "get_scan_status",
        "add_hypothesis",
        "record_payload_test",
        "confirm_hypothesis",
        "reject_hypothesis",
        "query_hypotheses",
        "get_hypothesis_summary",
        "has_tested_payload",
    ],
}


TOOL_SUBSET_CATEGORIES = {
    "minimal": ["web_testing", "terminal", "browser", "reporting", "python"],
    "core": [
        "web_testing",
        "terminal",
        "browser",
        "reporting",
        "agent_management",
        "memory",
        "files",
        "thinking",
        "python",
    ],
    "core-fast": [
        "web_testing",
        "terminal",
        "browser",
        "reporting",
        "agent_management",
        "memory",
        "files",
        "python",
    ],
    "web": [
        "web_testing",
        "terminal",
        "browser",
        "reporting",
        "agent_management",
        "memory",
        "files",
        "thinking",
        "python",
        "web_search",
    ],
}


DEFAULT_TOOL_CATEGORIES = {
    # FIX-5: Excluded 'files', 'notes', 'todo' from the default main_agent schema.
    # These are low-signal for pentesting but cost ~5K tokens per LLM call to describe.
    # 300 iterations * 5K tokens = 1.5M tokens saved per scan.
    # notes and todo excluded: low pentesting signal, ~4K tokens wasted per call
    "main_agent": ["web_testing", "terminal", "browser", "reporting", "agent_management", "memory", "files"],
    "sub_agent": ["web_testing", "terminal", "browser", "files", "memory"],
    "quick_scan": ["web_testing", "terminal", "reporting", "memory"],
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
        "vuln": ["web_testing", "browser"],
        "exploit": ["web_testing", "browser"],
        "cve": ["web_testing", "terminal"],
        "test": ["web_testing", "browser"],
        "pollution": ["web_testing", "browser"],
        "web": ["web_testing", "browser"],
    }
    
    # Determine which categories to include
    categories = set()
    # Only include agent_management for orchestrator/coordinator tasks, not leaf agents.
    # Leaf agents (fuzzing, validation) don't need create_agent/view_agent_graph.
    orchestrator_keywords = ["scan", "agent", "spawn", "coordinat", "orchestrat"]
    if any(kw in task_lower for kw in orchestrator_keywords):
        categories.add("agent_management")
    
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


def get_tool_subset_categories(mode: str) -> list[str]:
    return TOOL_SUBSET_CATEGORIES.get(mode, [])


def get_tools_for_subset_mode(mode: str) -> list[str]:
    """Resolve runtime tool names for a configured subset mode.

    Returns the intersection with currently registered tools so runtime
    enforcement and prompt exposure share the same concrete set.
    """
    from phantom.tools.registry import get_tool_names

    available = set(get_tool_names())
    if mode == "full":
        return sorted(available)

    categories = get_tool_subset_categories(mode)
    if not categories:
        return sorted(available)

    needed_tools: set[str] = set()
    for cat in categories:
        needed_tools.update(TOOL_CATEGORIES.get(cat, []))

    return sorted(needed_tools.intersection(available))


def get_related_tools_for_name(tool_name: str) -> list[str]:
    """Return the tool family for a specific tool name."""
    from phantom.tools.registry import get_tool_names

    available = set(get_tool_names())
    for tools in TOOL_CATEGORIES.values():
        if tool_name in tools:
            return sorted(set(tools).intersection(available))
    if tool_name in available:
        return [tool_name]
    return []


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


_TOOL_NAME_RE = re.compile(r'<tool\b[^>]*\bname="([^"]+)"', re.IGNORECASE)
_TAG_TEXT_RE = re.compile(r'<(?P<tag>description|details)\b[^>]*>(.*?)</(?P=tag)>', re.IGNORECASE | re.DOTALL)
_PARAM_RE = re.compile(
    r'<parameter\b[^>]*\bname="([^"]+)"[^>]*\brequired="([^"]+)"',
    re.IGNORECASE,
)


def _normalize_prompt_text(text: str, max_chars: int = 140) -> str:
    text = html_unescape(text)
    text = re.sub(r'<[^>]+>', ' ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    text = text.replace('<', '').replace('>', '')
    if len(text) > max_chars:
        text = text[: max_chars - 1].rstrip() + '…'
    return text


def _first_tag_text(xml: str, tag: str) -> str:
    match = re.search(
        rf'<{tag}\b[^>]*>(.*?)</{tag}>',
        xml,
        re.IGNORECASE | re.DOTALL,
    )
    if not match:
        return ""
    return _normalize_prompt_text(match.group(1))


def _tool_placeholder(param_name: str) -> str:
    return f"<{param_name}>"


def _build_compact_tool_example(tool_name: str, params: list[tuple[str, bool]]) -> str:
    if not params:
        return f"<function={tool_name}></function>"

    selected = [name for name, _required in params if _required][:3]
    if not selected:
        selected = [name for name, _required in params[:2]]

    inner = "".join(
        f"<parameter={param}>{_tool_placeholder(param)}</parameter>" for param in selected
    )
    return f"<function={tool_name}>{inner}</function>"


def _compact_tool_entry(tool: dict[str, Any]) -> str:
    xml = str(tool.get("xml_schema", "") or "")
    name_match = _TOOL_NAME_RE.search(xml)
    tool_name = name_match.group(1) if name_match else str(tool.get("name", "unknown"))

    description = _first_tag_text(xml, "description") or _first_tag_text(xml, "details")
    if not description:
        description = _normalize_prompt_text(tool_name.replace("_", " "), max_chars=120)

    params: list[tuple[str, bool]] = []
    for match in _PARAM_RE.finditer(xml):
        param_name = match.group(1).strip()
        required = match.group(2).strip().lower() == "true"
        if param_name:
            params.append((param_name, required))

    if not params:
        from phantom.tools.registry import get_tool_param_schema

        param_schema = get_tool_param_schema(tool_name) or {}
        required_params = sorted(str(p) for p in param_schema.get("required", set()))
        optional_params = sorted(str(p) for p in param_schema.get("params", set()) - param_schema.get("required", set()))
        params = [(name, True) for name in required_params] + [(name, False) for name in optional_params]

    param_text = ", ".join(f"{name}{'*' if required else ''}" for name, required in params)
    example = _build_compact_tool_example(tool_name, params)
    return (
        f'<tool name="{tool_name}">'
        f"{description}. Params: {param_text or 'none'}. Example: {example}"
        f"</tool>"
    )


def get_compact_tools_prompt_subset(tool_names: list[str]) -> str:
    from phantom.tools.registry import tools

    selected = [name for name in tool_names if name]
    by_name = {str(tool.get("name")): tool for tool in tools}
    entries = [
        _compact_tool_entry(by_name[name])
        for name in selected
        if name in by_name
    ]

    if not entries:
        return "<tool_catalog_note>Use exact tool names. * = required. Example shows the canonical call form.</tool_catalog_note>"

    return (
        "<tool_catalog_note>Use exact tool names. * = required. Example shows the canonical call form.</tool_catalog_note>\n"
        + "\n".join(entries)
    )


def get_compact_tools_prompt() -> str:
    from phantom.tools.registry import get_tool_names

    return get_compact_tools_prompt_subset(get_tool_names())
