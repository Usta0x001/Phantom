"""Tool-Level RBAC Permissions System - SECURITY REC LOW-7

This module provides role-based access control (RBAC) for tool execution.
It allows fine-grained control over which tools can be executed by which agents.

Role Hierarchy:
- admin: Full access to all tools
- senior_pentester: Most offensive tools + reporting
- junior_pentester: Limited tools, requires approval for dangerous ops
- observer: Read-only tools only (scopes, history, etc.)

Tool Categories:
- read: Tools that only read data (safe)
- write: Tools that modify state (moderate risk)
- offensive: Tools that perform attack operations (high risk)
- admin: Tools for system administration (highest risk)
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from phantom.config.config import Config


class ToolRole(Enum):
    """Available RBAC roles."""
    ADMIN = "admin"
    SENIOR_PENTESTER = "senior_pentester"
    JUNIOR_PENTESTER = "junior_pentester"
    OBSERVER = "observer"


class ToolCategory(Enum):
    """Tool risk categories."""
    READ = "read"
    WRITE = "write"
    OFFENSIVE = "offensive"
    ADMIN = "admin"


# Default role permissions matrix
_ROLE_PERMISSIONS: dict[ToolRole, set[ToolCategory]] = {
    ToolRole.ADMIN: {
        ToolCategory.READ,
        ToolCategory.WRITE,
        ToolCategory.OFFENSIVE,
        ToolCategory.ADMIN,
    },
    ToolRole.SENIOR_PENTESTER: {
        ToolCategory.READ,
        ToolCategory.WRITE,
        ToolCategory.OFFENSIVE,
    },
    ToolRole.JUNIOR_PENTESTER: {
        ToolCategory.READ,
        ToolCategory.WRITE,
    },
    ToolRole.OBSERVER: {
        ToolCategory.READ,
    },
}

# Tool category mappings (simplified - in production, this would be more granular)
_TOOL_CATEGORIES: dict[str, ToolCategory] = {
    # Read-only tools
    "read_file": ToolCategory.READ,
    "list_directory": ToolCategory.READ,
    "glob_files": ToolCategory.READ,
    "search_files": ToolCategory.READ,
    "file_search": ToolCategory.READ,
    "get_scope_rules": ToolCategory.READ,
    "scope_rules": ToolCategory.READ,
    "list_scan_notes": ToolCategory.READ,
    "get_scan_notes": ToolCategory.READ,
    "list_todos": ToolCategory.READ,
    "get_todos": ToolCategory.READ,
    "get_proxy_history": ToolCategory.READ,
    "proxy_history": ToolCategory.READ,
    "get_request_details": ToolCategory.READ,
    "send_request": ToolCategory.READ,
    "get_tool_help": ToolCategory.READ,
    "list_tools": ToolCategory.READ,
    
    # Write tools
    "add_scan_note": ToolCategory.WRITE,
    "update_todo": ToolCategory.WRITE,
    
    # Offensive tools
    "terminal_execute": ToolCategory.OFFENSIVE,
    "browser_action": ToolCategory.OFFENSIVE,
    "send_oast_payload": ToolCategory.OFFENSIVE,
    "python_execute": ToolCategory.OFFENSIVE,
    "file_edit": ToolCategory.OFFENSIVE,
    "file_write": ToolCategory.OFFENSIVE,
    "spawn_agent": ToolCategory.OFFENSIVE,
    "create_vulnerability_report": ToolCategory.OFFENSIVE,
    "finish_scan": ToolCategory.OFFENSIVE,
    "agent_finish": ToolCategory.OFFENSIVE,
}


@dataclass
class ToolPermission:
    """Permission for a specific tool."""
    tool_name: str
    category: ToolCategory
    requires_approval: bool = False  # For junior pentesters on offensive tools


@dataclass
class RBACContext:
    """Current RBAC context for an agent."""
    role: ToolRole = ToolRole.SENIOR_PENTESTER
    approved_tools: set[str] = field(default_factory=set)  # Tools approved for this session
    session_id: str | None = None


# Global RBAC state
_RBAC_CONTEXT: RBACContext | None = None


def _get_default_role() -> ToolRole:
    """Get the default role from config or use SENIOR_PENTESTER."""
    enabled = (Config.get("phantom_rbac_enabled") or "").lower()
    if enabled != "true":
        # RBAC disabled - return admin to allow all
        return ToolRole.ADMIN
    
    role_str = Config.get("phantom_rbac_default_role") or "senior_pentester"
    try:
        return ToolRole(role_str)
    except ValueError:
        return ToolRole.SENIOR_PENTESTER


def get_rbac_context() -> RBACContext:
    """Get or create the global RBAC context."""
    global _RBAC_CONTEXT
    if _RBAC_CONTEXT is None:
        _RBAC_CONTEXT = RBACContext(role=_get_default_role())
    return _RBAC_CONTEXT


def set_rbac_role(role: ToolRole) -> None:
    """Set the current RBAC role."""
    ctx = get_rbac_context()
    ctx.role = role


def can_execute_tool(tool_name: str) -> bool:
    """Check if the current role can execute a tool.
    
    Args:
        tool_name: Name of the tool to check
        
    Returns:
        True if tool can be executed, False otherwise
    """
    ctx = get_rbac_context()
    
    # Admin role has full access
    if ctx.role == ToolRole.ADMIN:
        return True
    
    # Check if tool is explicitly approved for this session
    if tool_name in ctx.approved_tools:
        return True
    
    # Get tool category
    category = _TOOL_CATEGORIES.get(tool_name, ToolCategory.WRITE)
    
    # Get role's allowed categories
    allowed = _ROLE_PERMISSIONS.get(ctx.role, set())
    
    return category in allowed


def approve_tool(tool_name: str) -> None:
    """Approve a tool for the current session (for tools requiring approval)."""
    ctx = get_rbac_context()
    ctx.approved_tools.add(tool_name)


def reset_rbac_context() -> None:
    """Reset RBAC context (for testing or new sessions)."""
    global _RBAC_CONTEXT
    _RBAC_CONTEXT = None


def get_tool_category(tool_name: str) -> ToolCategory:
    """Get the category/risk level of a tool."""
    return _TOOL_CATEGORIES.get(tool_name, ToolCategory.WRITE)


def check_tool_permission(tool_name: str) -> tuple[bool, str]:
    """Check tool permission and return (allowed, reason).
    
    Returns:
        Tuple of (allowed: bool, reason: str)
    """
    if can_execute_tool(tool_name):
        return True, "allowed"
    
    category = get_tool_category(tool_name)
    role = get_rbac_context().role
    
    return False, f"Role '{role.value}' cannot execute '{tool_name}' (category: {category.value})"
