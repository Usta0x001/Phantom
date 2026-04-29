import html
import re
from typing import Any


_INVOKE_OPEN = re.compile(r'<invoke\s+name=["\']([^"\']+)["\']>')
_PARAM_NAME_ATTR = re.compile(r'<parameter\s+name=["\']([^"\']+)["\']>')
_FUNCTION_CALLS_TAG = re.compile(r"</?function_calls>")
_STRIP_TAG_QUOTES = re.compile(r"<(function|parameter)\s*=\s*([^>]*?)>")


def normalize_tool_format(content: str) -> str:
    """Convert alternative tool-call XML formats to the expected one.

    Handles:
      <function_calls>...</function_calls>  → stripped
      <invoke name="X">                     → <function=X>
      <parameter name="X">                  → <parameter=X>
      </invoke>                             → </function>
      <function="X">                        → <function=X>
      <parameter="X">                       → <parameter=X>
    """
    if "<invoke" in content or "<function_calls" in content:
        content = _FUNCTION_CALLS_TAG.sub("", content)
        content = _INVOKE_OPEN.sub(r"<function=\1>", content)
        content = content.replace("</invoke>", "</function>")

    # FIX: Always normalize <parameter name="X"> → <parameter=X>
    # regardless of whether <invoke> is present. The LLM may output
    # schema-native parameter tags even when using <function=...>.
    content = _PARAM_NAME_ATTR.sub(r"<parameter=\1>", content)

    return _STRIP_TAG_QUOTES.sub(
        lambda m: f"<{m.group(1)}={m.group(2).strip().strip(chr(34) + chr(39))}>", content
    )


PHANTOM_MODEL_MAP: dict[str, str] = {
    # FIX: Removed fictional/non-existent models (gpt-5.x, glm-5, gemini-3).
    # These caused cryptic litellm failures. Only map verified existing models.
    "claude-sonnet-4": "anthropic/claude-sonnet-4-20250514",
    "claude-opus-4": "anthropic/claude-opus-4-20250514",
    "gpt-4.1": "openai/gpt-4.1",
    "gpt-4o": "openai/gpt-4o",
    "o3-mini": "openai/o3-mini",
    "gemini-2.5-pro": "gemini/gemini-2.5-pro-preview-03-25",
    "gemini-2.5-flash": "gemini/gemini-2.5-flash-preview-04-17",
}


def resolve_phantom_model(model_name: str | None) -> tuple[str | None, str | None]:
    """Resolve a phantom/ model into names for API calls and capability lookups.

    Returns (api_model, canonical_model):
    - api_model: openai/<base> for API calls (Phantom API is OpenAI-compatible)
    - canonical_model: actual provider model name for litellm capability lookups
    Non-phantom models return the same name for both.
    """
    if not model_name or not model_name.startswith("phantom/"):
        return model_name, model_name

    # "phantom/" prefix is 8 characters (not 6 — fixed off-by-one bug)
    base_model = model_name[len("phantom/") :]
    api_model = f"openai/{base_model}"
    canonical_model = PHANTOM_MODEL_MAP.get(base_model, api_model)
    return api_model, canonical_model


def _extract_params_xml(body: str) -> dict[str, str]:
    """Extract parameters using a lightweight XML parser for robustness."""
    args: dict[str, str] = {}
    try:
        from xml.etree import ElementTree as ET

        root = ET.fromstring(f"<root>{body}</root>")
        for param in root.findall("parameter"):
            name = param.get("name")
            if name:
                args[name] = (param.text or "").strip()
    except Exception:
        # Fallback to regex for malformed XML
        fn_param_regex_pattern = r"<parameter=([^>]+)>(.*?)</parameter>"
        for param_match in re.finditer(fn_param_regex_pattern, body, re.DOTALL):
            param_name = param_match.group(1).strip()
            if re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]*", param_name):
                param_value = html.unescape(param_match.group(2).strip())
                args[param_name] = param_value
    return args


def parse_tool_invocations(content: str) -> list[dict[str, Any]] | None:
    content = normalize_tool_format(content)
    content = fix_incomplete_tool_call(content)

    tool_invocations: list[dict[str, Any]] = []

    # FIX: Use a stricter regex that requires <function=NAME> to be immediately
    # followed by parameter tags or a closing tag. This prevents matching
    # </function> that appears in LLM reasoning text without a real opening tag.
    fn_regex_pattern = r"<function=([a-zA-Z_][a-zA-Z0-9_-]*)>\s*(?:<parameter[^>]*>.*?</parameter>\s*)*</function>"

    # First pass: find all well-formed function blocks
    for match in re.finditer(fn_regex_pattern, content, re.DOTALL):
        block = match.group(0)
        # Extract the tool name from the opening tag
        name_match = re.search(r"<function=([a-zA-Z_][a-zA-Z0-9_-]*)>", block)
        if not name_match:
            continue
        fn_name = name_match.group(1).strip()

        # Reject literal placeholder from system prompt examples
        if fn_name == "tool_name":
            continue

        # Extract body between opening tag and closing tag
        body_match = re.search(r"<function=[^>]+>(.*?)</function>\s*$", block, re.DOTALL)
        if not body_match:
            continue
        fn_body = body_match.group(1)
        args = _extract_params_xml(fn_body)

        if not args:
            # Last-ditch regex for incomplete parameter
            incomplete_match = re.search(r"<parameter=([^>]+)>(.*)$", fn_body, re.DOTALL)
            if incomplete_match:
                param_name = incomplete_match.group(1).strip()
                if re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]*", param_name):
                    param_value = html.unescape(incomplete_match.group(2).strip())
                    args[param_name] = param_value

        tool_invocations.append({"toolName": fn_name, "args": args})

    return tool_invocations if tool_invocations else None


def fix_incomplete_tool_call(content: str) -> str:
    """Fix incomplete tool calls by adding missing closing tag.

    Handles both ``<function=…>`` and ``<invoke name="…">`` formats.
    Fixes the LAST incomplete call if it appears at the end of the content
    and looks like a real tool call (has parameter tags).
    """
    stripped = content.strip()

    # Find the last opening tag
    last_func = stripped.rfind("<function=")
    last_invoke = stripped.rfind("<invoke ")
    last_open = max(last_func, last_invoke)

    if last_open == -1:
        return content

    # Check if there's a closing tag after the last opening
    suffix = stripped[last_open:]
    if "</function>" in suffix or "</invoke>" in suffix:
        return content  # Already complete

    # The last tag is incomplete. Only fix if it looks like a real tool call
    # (contains <parameter=, not just a mention in reasoning text).
    if "<parameter=" not in suffix:
        return content

    # Fix it
    if stripped.endswith("</"):
        return stripped + "function>"
    return stripped + "\n</function>"


def format_tool_call(tool_name: str, args: dict[str, Any]) -> str:
    xml_parts = [f"<function={tool_name}>"]

    for key, value in args.items():
        # FIX: XML-escape parameter values to prevent malformed XML.
        # If value contains <, >, or &, the generated XML breaks parsing.
        safe_value = html.escape(str(value))
        xml_parts.append(f"<parameter={key}>{safe_value}</parameter>")

    xml_parts.append("</function>")

    return "\n".join(xml_parts)


def strip_thinking_blocks(content: str) -> str:
    """Remove <thinking>...</thinking> blocks from content.

    Thinking blocks may contain tool calls that would bypass deduplication
    checks (e.g. create_vulnerability_report inside a think tool's thought
    parameter). Stripping them prevents duplicate vulnerability submissions.
    """
    if not content:
        return content
    return re.sub(r"<thinking\b[^>]*>.*?</thinking>", "", content, flags=re.DOTALL | re.IGNORECASE)


def clean_content(content: str) -> str:
    if not content:
        return ""

    content = normalize_tool_format(content)
    content = fix_incomplete_tool_call(content)

    tool_pattern = r"<function=[^>]+>.*?</function>"
    cleaned = re.sub(tool_pattern, "", content, flags=re.DOTALL)

    incomplete_tool_pattern = r"<function=[^>]+>.*$"
    cleaned = re.sub(incomplete_tool_pattern, "", cleaned, flags=re.DOTALL)

    partial_tag_pattern = r"<f(?:u(?:n(?:c(?:t(?:i(?:o(?:n(?:=(?:[^>]*)?)?)?)?)?)?)?)?)?$"
    cleaned = re.sub(partial_tag_pattern, "", cleaned)

    hidden_xml_patterns = [
        r"<inter_agent_message>.*?</inter_agent_message>",
        r"<agent_completion_report>.*?</agent_completion_report>",
    ]
    for pattern in hidden_xml_patterns:
        cleaned = re.sub(pattern, "", cleaned, flags=re.DOTALL | re.IGNORECASE)

    cleaned = re.sub(r"\n\s*\n", "\n\n", cleaned)

    return cleaned.strip()
