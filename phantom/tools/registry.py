import inspect
import logging
import os
import re
from collections.abc import Callable
from functools import wraps
from inspect import signature
from pathlib import Path
from typing import Any

from phantom.utils.resource_paths import get_phantom_resource_path


tools: list[dict[str, Any]] = []
_tools_by_name: dict[str, Callable[..., Any]] = {}
_tool_param_schemas: dict[str, dict[str, Any]] = {}
logger = logging.getLogger(__name__)

RICH_TOOL_NAMES = {
    "create_vulnerability_report",
    "generate_smart_payloads",
    "agent_finish",
    "browser_action",
}


class ImplementedInClientSideOnlyError(Exception):
    def __init__(
        self,
        message: str = "This tool is implemented in the client side only",
    ) -> None:
        self.message = message
        super().__init__(self.message)


def _process_dynamic_content(content: str) -> str:
    if "{{DYNAMIC_SKILLS_DESCRIPTION}}" in content:
        try:
            from phantom.skills import generate_skills_description

            skills_description = generate_skills_description()
            content = content.replace("{{DYNAMIC_SKILLS_DESCRIPTION}}", skills_description)
        except ImportError:
            logger.warning("Could not import skills utilities for dynamic schema generation")
            content = content.replace(
                "{{DYNAMIC_SKILLS_DESCRIPTION}}",
                "List of skills to load for this agent (max 5). Skill discovery failed.",
            )

    return content


_TOOL_BLOCK_RE = re.compile(r'<tool\b[^>]*\bname="([^"]+)"[^>]*>(.*?)</tool>', re.DOTALL)
_PARAM_BLOCK_RE = re.compile(
    r"<parameter\b(?![^>]*\/>)" r"([^>]*)>(.*?)</parameter>", re.IGNORECASE | re.DOTALL
)
_SELF_CLOSING_PARAM_RE = re.compile(r"<parameter\b([^>]*)\s*/>", re.IGNORECASE | re.DOTALL)


def _load_xml_schema(path: Path) -> Any:
    if not path.exists():
        return None
    try:
        content = path.read_text(encoding="utf-8")

        content = _process_dynamic_content(content)
        tools_dict: dict[str, str] = {}

        for tool_match in _TOOL_BLOCK_RE.finditer(content):
            tool_name = tool_match.group(1)
            tool_block = tool_match.group(0)
            tools_dict[tool_name] = tool_block.strip()
    except (IndexError, ValueError, UnicodeError, re.error) as e:
        logger.warning(f"Error loading schema file {path}: {e}")
        return None
    else:
        return tools_dict


def _parse_param_schema(tool_xml: str) -> dict[str, Any]:
    params: set[str] = set()
    required: set[str] = set()

    params_start = tool_xml.find("<parameters>")
    params_end = tool_xml.find("</parameters>")

    if params_start == -1 or params_end == -1:
        return {"params": set(), "required": set(), "has_params": False}

    params_section = tool_xml[params_start : params_end + len("</parameters>")]

    def _consume_param(attr_text: str, body_text: str) -> None:
        nonlocal params, required

        name_match = re.search(r'\bname="([^"]+)"', attr_text, re.IGNORECASE)
        if not name_match:
            return
        name = name_match.group(1).strip()
        if not name:
            return

        params.add(name)

        is_required = False
        required_match = re.search(r'\brequired="([^"]+)"', attr_text, re.IGNORECASE)
        if required_match:
            is_required = required_match.group(1).strip().lower() == "true"
        else:
            nested_required = re.search(
                r"<required>\s*(true|false)\s*</required>", body_text, re.IGNORECASE
            )
            if nested_required:
                is_required = nested_required.group(1).strip().lower() == "true"

        if is_required:
            required.add(name)

    for match in _PARAM_BLOCK_RE.finditer(params_section):
        _consume_param(match.group(1) or "", match.group(2) or "")

    for match in _SELF_CLOSING_PARAM_RE.finditer(params_section):
        _consume_param(match.group(1) or "", "")

    return {"params": params, "required": required, "has_params": bool(params or required)}


def _infer_param_schema_from_signature(func: Callable[..., Any]) -> dict[str, Any]:
    params: set[str] = set()
    required: set[str] = set()

    try:
        sig = signature(func)
    except (TypeError, ValueError):
        return {"params": set(), "required": set(), "has_params": False}

    for name, param in sig.parameters.items():
        if name == "agent_state":
            continue
        if param.kind in {param.VAR_POSITIONAL, param.VAR_KEYWORD}:
            continue

        params.add(name)
        if param.default is inspect._empty:
            required.add(name)

    return {"params": params, "required": required, "has_params": bool(params or required)}


def _get_module_name(func: Callable[..., Any]) -> str:
    module = inspect.getmodule(func)
    if not module:
        return "unknown"

    module_name = module.__name__
    if ".tools." in module_name:
        parts = module_name.split(".tools.")[-1].split(".")
        if len(parts) >= 1:
            return parts[0]
    return "unknown"


def _get_schema_path(func: Callable[..., Any]) -> Path | None:
    module = inspect.getmodule(func)
    if not module or not module.__name__:
        return None

    module_name = module.__name__

    if ".tools." not in module_name:
        return None

    parts = module_name.split(".tools.")[-1].split(".")
    if len(parts) < 2:
        return None

    folder = parts[0]
    file_stem = parts[1]
    schema_file = f"{file_stem}_schema.xml"

    return get_phantom_resource_path("tools", folder, schema_file)


def _extract_tools_folder(func: Callable[..., Any]) -> str | None:
    module = inspect.getmodule(func)
    if not module or not module.__name__ or ".tools." not in module.__name__:
        return None
    parts = module.__name__.split(".tools.")[-1].split(".")
    if not parts:
        return None
    return parts[0]


def _resolve_schema_for_tool(func: Callable[..., Any]) -> str | None:
    """Resolve schema XML for a tool with fallback file scanning.

    Primary lookup uses the canonical stem-derived path. If that misses, scan
    all `*_schema.xml` files in the module folder and return the one containing
    the tool name.
    """
    preferred_path = _get_schema_path(func)
    tool_name = func.__name__

    if preferred_path:
        xml_tools = _load_xml_schema(preferred_path)
        if xml_tools is not None and tool_name in xml_tools:
            return xml_tools[tool_name]

    folder = _extract_tools_folder(func)
    if not folder:
        return None

    folder_path = get_phantom_resource_path("tools", folder)
    for schema_path in sorted(folder_path.glob("*_schema.xml")):
        xml_tools = _load_xml_schema(schema_path)
        if xml_tools is not None and tool_name in xml_tools:
            return xml_tools[tool_name]

    return None


def register_tool(
    func: Callable[..., Any] | None = None, *, sandbox_execution: bool = True
) -> Callable[..., Any]:
    def decorator(f: Callable[..., Any]) -> Callable[..., Any]:
        func_dict = {
            "name": f.__name__,
            "function": f,
            "module": _get_module_name(f),
            "sandbox_execution": sandbox_execution,
        }

        sandbox_mode = os.getenv("PHANTOM_SANDBOX_MODE", "false").lower() == "true"
        if not sandbox_mode:
            try:
                schema_xml = _resolve_schema_for_tool(f)

                if schema_xml is not None:
                    func_dict["xml_schema"] = schema_xml
                else:
                    func_dict["xml_schema"] = (
                        f'<tool name="{f.__name__}">'
                        "<description>Schema not found for tool.</description>"
                        "</tool>"
                    )
            except (TypeError, FileNotFoundError) as e:
                logger.warning(f"Error loading schema for {f.__name__}: {e}")
                func_dict["xml_schema"] = (
                    f'<tool name="{f.__name__}">'
                    "<description>Error loading schema.</description>"
                    "</tool>"
                )

        if not sandbox_mode:
            xml_schema = func_dict.get("xml_schema")
            param_schema = _parse_param_schema(xml_schema if isinstance(xml_schema, str) else "")
            if not param_schema.get("has_params"):
                param_schema = _infer_param_schema_from_signature(f)
            _tool_param_schemas[str(func_dict["name"])] = param_schema

        tools.append(func_dict)
        _tools_by_name[str(func_dict["name"])] = f

        # Preserve coroutine-function identity so inspect.iscoroutinefunction()
        # returns True for async tools — needed by tool_server._run_tool and
        # by _execute_tool_locally to correctly await results.
        if inspect.iscoroutinefunction(f):

            @wraps(f)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                return await f(*args, **kwargs)

            return async_wrapper

        @wraps(f)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            return f(*args, **kwargs)

        return wrapper

    if func is None:
        return decorator
    return decorator(func)


def get_tool_by_name(name: str) -> Callable[..., Any] | None:
    return _tools_by_name.get(name)


def get_tool_names() -> list[str]:
    return list(_tools_by_name.keys())


def get_tool_param_schema(name: str) -> dict[str, Any] | None:
    return _tool_param_schemas.get(name)


def needs_agent_state(tool_name: str) -> bool:
    normalized_name = tool_name.replace("-", "_")
    tool_func = get_tool_by_name(normalized_name)
    if not tool_func:
        return False
    sig = signature(tool_func)
    return "agent_state" in sig.parameters


def should_execute_in_sandbox(tool_name: str) -> bool:
    for tool in tools:
        if tool.get("name") == tool_name:
            return bool(tool.get("sandbox_execution", True))
    return True


def get_tools_prompt() -> str:
    tools_by_module: dict[str, list[dict[str, Any]]] = {}
    for tool in tools:
        module = tool.get("module", "unknown")
        if module not in tools_by_module:
            tools_by_module[module] = []
        tools_by_module[module].append(tool)

    xml_sections = []
    for module, module_tools in sorted(tools_by_module.items()):
        # Use XML comments instead of wrapper tags so LLMs cannot misread the
        # section header as a tool namespace prefix (e.g. won't call
        # "proxy_tools.scope_rules" instead of "scope_rules").
        section_parts = [f"<!-- {module} tools -->"]
        for tool in module_tools:
            tool_xml = tool.get("xml_schema", "")
            if tool_xml:
                indented_tool = "\n".join(f"  {line}" for line in tool_xml.split("\n"))
                section_parts.append(indented_tool)
        section_parts.append(f"<!-- end {module} tools -->")
        xml_sections.append("\n".join(section_parts))

    return "\n\n".join(xml_sections)


def clear_registry() -> None:
    tools.clear()
    _tools_by_name.clear()
    _tool_param_schemas.clear()
