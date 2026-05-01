diff --git a/phantom/tools/executor.py b/phantom/tools/executor.py
index 1237dab..7a9cbaf 100644
--- a/phantom/tools/executor.py
+++ b/phantom/tools/executor.py
@@ -1,5 +1,6 @@
 import html
 import asyncio
+from contextlib import suppress
 import inspect
 import logging
 import os
@@ -23,77 +24,11 @@ from phantom.llm.tracked_completion import tracked_acompletion
 logger = logging.getLogger(__name__)
 
 
-# ΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉ
-# FEAT-001: Stealth Mode Rate Limiting
-# ΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉ
-# Implements actual rate limiting for stealth mode instead of relying only on
-# LLM prompt instructions. This adds programmatic delays between HTTP-related
-# tool executions to reduce detection risk.
-
-_STEALTH_DELAY_SECONDS = 2.0  # Minimum delay between requests in stealth mode
-
-# Tools that make outbound HTTP requests and should be rate-limited in stealth mode
-_HTTP_TOOLS = frozenset({
-    # FIX BUG-2: Added "terminal_execute" - was missing from list causing stealth mode bypass
-    # The tool "terminal" was incorrectly listed but actual tool name is "terminal_execute"
-    "terminal_execute",  # FIX: was "terminal" which doesn't match actual tool name
-    "terminal",          # Keep for legacy compatibility if any other tool uses this name
-    "http_request",
-    "analyze_response", 
-    "crawl_website",
-    "fetch_url",
-    "browser_navigate",
-    "browser_action",
-    "nuclei_scan",
-    "waf_detect",
-    "subdomain_enum",
-    "shodan_query",
-    "cve_search",
-    "fuzzer",
-})
-
-
-async def _apply_stealth_rate_limit(tool_name: str, agent_state: Any | None) -> None:
-    """
-    FEAT-001: Apply rate limiting delay for stealth mode.
-    
-    This ensures a minimum delay between HTTP-related tool executions
-    to reduce the chance of triggering rate limiting, WAF detection, or IDS alerts.
-    """
-    scan_mode = str(getattr(agent_state, "scan_mode", "") or "").lower()
-
-    # Only apply in stealth mode
-    if scan_mode != "stealth":
-        return
-    
-    # Only rate-limit HTTP-related tools
-    if tool_name not in _HTTP_TOOLS:
-        return
-    
-    if agent_state is None:
-        return
-
-    context = getattr(agent_state, "context", None)
-    if not isinstance(context, dict):
-        return
-
-    current_time = time.monotonic()
-    last_request_time = float(context.get("_stealth_last_request_time", 0.0) or 0.0)
-    time_since_last = current_time - last_request_time
-
-    if time_since_last < _STEALTH_DELAY_SECONDS:
-        sleep_time = _STEALTH_DELAY_SECONDS - time_since_last
-        await asyncio.sleep(sleep_time)
-
-    context["_stealth_last_request_time"] = time.monotonic()
-# ΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉ
-
-
 if os.getenv("PHANTOM_SANDBOX_MODE", "false").lower() == "false":
     from phantom.runtime import get_runtime
 
 from .argument_parser import convert_arguments
-from .cache import get_tool_cache
+
 from .context import reset_current_agent_id, set_current_agent_id
 from .registry import (
     get_tool_by_name,
@@ -129,41 +64,6 @@ def _resolve_canonical_tool_name(tool_name: str | None) -> str | None:
     return candidate
 
 
-# ΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉ
-# SECURITY FIX: CMD-002 - Command Injection Protection Patterns
-# ΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉ
-_COMMAND_INJECTION_PATTERNS: list[re.Pattern[str]] = [
-    # Semicolon command chaining
-    re.compile(r";\s*\w+", re.IGNORECASE),
-    # Pipe to another command
-    re.compile(r"\|\s*\w+", re.IGNORECASE),
-    # AND command chaining
-    re.compile(r"&&\s*\w+", re.IGNORECASE),
-    # OR command chaining
-    re.compile(r"\|\|\s*\w+", re.IGNORECASE),
-    # Backtick command substitution
-    re.compile(r"`[^`]+`", re.IGNORECASE),
-    # $() command substitution
-    re.compile(r"\$\([^)]+\)", re.IGNORECASE),
-    # ${} variable expansion with commands
-    re.compile(r"\$\{[^}]*[;|&`][^}]*\}", re.IGNORECASE),
-    # Redirect to absolute paths (potential overwrite)
-    re.compile(r">\s*/", re.IGNORECASE),
-    # Read from absolute paths
-    re.compile(r"<\s*/", re.IGNORECASE),
-    # Dangerous commands
-    re.compile(r"\b(eval|exec|source)\s+", re.IGNORECASE),
-    # Newline injection (literal)
-    re.compile(r"[\r\n]", re.IGNORECASE),
-    # URL-encoded newlines
-    re.compile(r"%0[aAdD]", re.IGNORECASE),
-]
-
-# ΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉ
-# SECURITY FIX: TOOL-003 - Path Traversal Detection Pattern
-# ΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉ
-_PATH_TRAVERSAL_PATTERN = re.compile(r"\.\.[\\/]", re.IGNORECASE)
-
 # ΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉ
 # SECURITY FIX: ARCH-001 - Prompt Injection Detection Patterns
 # ΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉ
@@ -202,7 +102,7 @@ _PROMPT_INJECTION_PATTERNS: list[re.Pattern[str]] = [
 
 def _recursive_url_decode(text: str, max_depth: int = 10) -> str:
     """Recursively URL-decode text until no more changes.
-    
+
     SECURITY FIX: Catches arbitrary-depth URL encoding like %252e%252e%252f
     which decodes to %2e%2e%2f then ../ over multiple passes.
     """
@@ -216,7 +116,7 @@ def _recursive_url_decode(text: str, max_depth: int = 10) -> str:
 
 def _normalize_for_injection_check(text: str) -> str:
     """Normalize text before injection pattern checking.
-    
+
     SECURITY FIX (CMD-002): Multi-layer normalization to defeat encoding bypasses:
     1. URL decode (catches %3B, %7C, etc.)
     2. Unicode NFKC normalization (catches fullwidth characters like ∩╝¢)
@@ -224,159 +124,87 @@ def _normalize_for_injection_check(text: str) -> str:
     """
     # Layer 1: Recursive URL decode (catches arbitrary depth encoding)
     normalized = _recursive_url_decode(text)
-    
+
     # Layer 2: Unicode NFKC normalization (fullwidth to ASCII)
     normalized = _unicodedata.normalize("NFKC", normalized)
-    
+
     # Layer 3: HTML entity decode
     normalized = html.unescape(normalized)
-    
-    return normalized
-
-
-def _check_path_traversal(path: str) -> bool:
-    """TOOL-003 FIX: Check for path traversal after full normalization.
-    
-    This catches:
-    - Direct: ../
-    - URL encoded: %2e%2e%2f
-    - Double encoded: %252e%252e%252f
-    - Triple+ encoded: %25252e...
-    - Mixed: ..%2f, %2e./
-    - Unicode: ∩╝Ä∩╝Ä∩╝Å (fullwidth)
-    - HTML entities: &#46;&#46;&#47;
-    - TRAV-NEW-1 FIX: Null byte injection (..%00/etc/passwd)
-    """
-    # TRAV-NEW-1 FIX: Strip null bytes BEFORE normalization
-    path_clean = path.replace("\x00", "").replace("%00", "")
-    
-    # Normalize first to decode all encoding layers
-    normalized = _normalize_for_injection_check(path_clean)
-    
-    # Also strip null bytes from normalized output (in case they were encoded)
-    normalized = normalized.replace("\x00", "")
-    
-    # Now check the simple pattern on normalized input
-    return bool(_PATH_TRAVERSAL_PATTERN.search(normalized))
-
-
-def _get_security_mode() -> str:
-    mode = (Config.get("phantom_security_mode") or "research").strip().lower()
-    if mode not in {"research", "hardened"}:
-        return "research"
-    return mode
-
 
-def _is_hardened_mode() -> bool:
-    return _get_security_mode() == "hardened"
-
-
-def _iter_string_arguments(value: Any, path: str = "") -> Any:
-    if isinstance(value, str):
-        yield path or "value", value
-        return
-
-    if isinstance(value, dict):
-        for key, nested in value.items():
-            key_name = str(key)
-            next_path = f"{path}.{key_name}" if path else key_name
-            yield from _iter_string_arguments(nested, next_path)
-        return
-
-    if isinstance(value, (list, tuple)):
-        for idx, nested in enumerate(value):
-            next_path = f"{path}[{idx}]" if path else f"[{idx}]"
-            yield from _iter_string_arguments(nested, next_path)
-
-
-def _validate_tool_argument_injection(tool_name: str, kwargs: dict[str, Any]) -> str | None:
-    """Validate tool arguments for command/path injection patterns.
-
-    Research mode keeps this gate relaxed to preserve offensive flexibility.
-    Hardened mode enforces blocking checks on command/path-like arguments.
-    """
-    if not _is_hardened_mode():
-        return None
-
-    commandish_tokens = {"command", "cmd", "shell", "script", "code"}
-    pathish_tokens = {"path", "file", "filename", "directory", "dir", "workspace"}
-
-    high_risk_tool = tool_name in {"terminal_execute", "python_execute"}
-
-    for arg_path, raw_value in _iter_string_arguments(kwargs):
-        arg_path_lower = arg_path.lower()
-        normalized = _normalize_for_injection_check(raw_value)
-
-        should_check_command_patterns = high_risk_tool or any(
-            token in arg_path_lower for token in commandish_tokens
-        )
-        if should_check_command_patterns:
-            for pattern in _COMMAND_INJECTION_PATTERNS:
-                match = pattern.search(normalized)
-                if match:
-                    matched = match.group(0).replace("\n", "\\n").replace("\r", "\\r")
-                    return (
-                        f"Error: Hardened mode blocked suspicious argument '{arg_path}' "
-                        f"for tool '{tool_name}' (pattern: {matched[:80]!r})."
-                    )
-
-        should_check_path_traversal = any(token in arg_path_lower for token in pathish_tokens)
-        if should_check_path_traversal and _check_path_traversal(raw_value):
-            return (
-                f"Error: Hardened mode blocked path traversal pattern in argument "
-                f"'{arg_path}' for tool '{tool_name}'."
-            )
-
-    return None
+    return normalized
 
 
 def _detect_prompt_injection(text: str) -> tuple[bool, str | None]:
     """ARCH-001 FIX: Detect prompt injection attempts in text.
-    
+
     Returns (is_injection, matched_pattern) tuple.
     """
     if not isinstance(text, str):
         return False, None
-    
+
     # Normalize text first
     normalized = _normalize_for_injection_check(text)
-    
+
     for pattern in _PROMPT_INJECTION_PATTERNS:
         match = pattern.search(normalized)
         if match:
             return True, pattern.pattern[:50]
-    
+
     return False, None
 
 
+def _enforce_safe_summary_schema(summary: str) -> str:
+    """Normalize auto-summaries to a strict, line-based safe schema."""
+    text = str(summary or "").strip()
+    if not text:
+        return "SUMMARY: unavailable\nKEY_FINDINGS:\n- none"
+
+    text = _semantic_sanitize_output(text)
+    lines = [line.strip() for line in text.splitlines() if line.strip()]
+    if not lines:
+        return "SUMMARY: unavailable\nKEY_FINDINGS:\n- none"
+
+    summary_line = lines[0][:300]
+    finding_lines = [line[:240] for line in lines[1:8]]
+    if not finding_lines:
+        finding_lines = ["none"]
+
+    formatted = [f"SUMMARY: {summary_line}", "KEY_FINDINGS:"]
+    for finding in finding_lines:
+        normalized = finding.lstrip("-*").strip()
+        if normalized:
+            formatted.append(f"- {normalized}")
+
+    return "\n".join(formatted)
+
+
 def _semantic_sanitize_output(text: str) -> str:
     """ARCH-001 FIX: Sanitize tool output to remove prompt injection attempts.
-    
-    Replaces detected injection patterns with safe placeholders.
+
+    Only removes active instruction-override attempts.
+    Tag-based patterns (</function>, </tool_result>) are NOT removed because:
+    1. They appear in legitimate HTML/JSON responses and would corrupt data.
+    2. Tool results are already wrapped in <tool_result> XML, so the LLM
+       parser treats them as structured data, not instructions.
     """
     if not isinstance(text, str):
         return str(text) if text is not None else ""
-    
+
     sanitized = text
-    
-    # Remove system/instruction tags
+
+    # Remove system/instruction override attempts
     sanitized = re.sub(r"</?system\s*>", "[REMOVED]", sanitized, flags=re.IGNORECASE)
     sanitized = re.sub(r"\[/?system\]", "[REMOVED]", sanitized, flags=re.IGNORECASE)
     sanitized = re.sub(r"<</?SYS>>", "[REMOVED]", sanitized, flags=re.IGNORECASE)
-    
-    # Remove function/tool injection tags
-    sanitized = re.sub(r"</function>", "[REMOVED]", sanitized, flags=re.IGNORECASE)
-    sanitized = re.sub(r"</tool_result>", "[REMOVED]", sanitized, flags=re.IGNORECASE)
-    sanitized = re.sub(r"<function=\w+>", "[REMOVED]", sanitized, flags=re.IGNORECASE)
-    
-    # Remove instruction override attempts
+
+    # Remove explicit instruction override attempts
     sanitized = re.sub(
         r"ignore\s+(all\s+)?previous\s+instructions?",
         "[INSTRUCTION OVERRIDE REMOVED]",
         sanitized,
-        flags=re.IGNORECASE
+        flags=re.IGNORECASE,
     )
-    
+
     return sanitized
 
 
@@ -435,45 +263,9 @@ def _cleanup_screenshot_artifacts(path: str | Path | None = None) -> None:
 
 
 async def execute_tool(tool_name: str, agent_state: Any | None = None, **kwargs: Any) -> Any:
-    # ΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉ
-    # FEAT-001: Stealth Rate Limiting
-    # ΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉ
-    # Apply rate limiting before execution for stealth mode
-    await _apply_stealth_rate_limit(tool_name, agent_state)
-    # ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
-    
-    # ΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉ
-    # SECURITY REC LOW-7: Tool-Level RBAC Permission Check
-    # ΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉ
-    # Check RBAC permissions before executing any tool.
-    # This ensures only authorized agents can execute sensitive tools.
-    security_mode = _get_security_mode()
-    rbac_enabled = (Config.get("phantom_rbac_enabled") or "").lower() == "true"
-
-    if security_mode == "hardened" and not rbac_enabled:
-        logger.warning("RBAC denied tool '%s': RBAC disabled in hardened mode", tool_name)
-        return {
-            "error": "Permission denied: RBAC must be enabled in hardened mode",
-            "error_type": "rbac_misconfigured",
-        }
 
-    try:
-        from phantom.tools.rbac import check_tool_permission
-
-        allowed, reason = check_tool_permission(tool_name)
-        if not allowed:
-            logger.warning("RBAC blocked tool '%s': %s", tool_name, reason)
-            return {"error": f"Permission denied: {reason}", "error_type": "rbac_denied"}
-    except ImportError:
-        if security_mode == "hardened":
-            logger.warning("RBAC denied tool '%s': RBAC module unavailable", tool_name)
-            return {
-                "error": "Permission denied: RBAC module unavailable in hardened mode",
-                "error_type": "rbac_unavailable",
-            }
-        # Research mode stays permissive for backwards compatibility.
-    # ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
-    
+    # Execution checks cleared (RBAC removed)
+
     # FIX: Ensure agent_id is always captured - even if agent_state is None
     _agent_id = None
     if agent_state is not None:
@@ -489,49 +281,33 @@ async def execute_tool(tool_name: str, agent_state: Any | None = None, **kwargs:
     execute_in_sandbox = should_execute_in_sandbox(tool_name)
     sandbox_mode = os.getenv("PHANTOM_SANDBOX_MODE", "false").lower() == "true"
 
+    # Check if sandbox container exists (either in env var OR in agent_state)
+    sandbox_available = sandbox_mode
+    if not sandbox_available and agent_state:
+        sandbox_available = getattr(agent_state, "sandbox_id", None) is not None
+
     # ΓöÇΓöÇ Audit: log tool invocation ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
     from phantom.logging.audit import get_audit_logger as _get_audit
+
     _audit = _get_audit()
     _exec_id = _audit.log_tool_start(_agent_id, tool_name, kwargs) if _audit else None
     _t0 = time.monotonic()
     # ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
-    
-    # ΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉ
-    # EFFICIENCY FIX CRIT-04: Tool Result Caching
-    # ΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉ
-    # Check cache BEFORE execution for idempotent tools.
-    # Expected savings: 21% reduction in redundant calls, $0.15-0.30/scan
-    _cache = get_tool_cache()
-    try:
-        if _cache.is_cacheable(tool_name, kwargs):
-            cached_result = _cache.get(tool_name, kwargs)
-            if cached_result is not None:
-                # Cache hit - log and return immediately
-                if _audit and _exec_id:
-                    _audit.log_tool_result(
-                        _exec_id,
-                        _agent_id,
-                        tool_name,
-                        cached_result,
-                        (time.monotonic() - _t0) * 1000,
-                        cache_hit=True,
-                    )
-                return cached_result
-        # ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
 
+    try:
         try:
-            if execute_in_sandbox and not sandbox_mode:
+            if execute_in_sandbox:
+                if not sandbox_available:
+                    if agent_state and getattr(agent_state, "sandbox_id", None):
+                        pass  # Sandbox exists but env var not set - should work
+                    else:
+                        raise RuntimeError(
+                            f"CRITICAL: Tool '{tool_name}' requires Sandbox, but no sandbox container is running."
+                        )
                 result = await _execute_tool_in_sandbox(tool_name, agent_state, **kwargs)
             else:
                 result = await _execute_tool_locally(tool_name, agent_state, **kwargs)
 
-            # ΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉ
-            # EFFICIENCY FIX CRIT-04: Cache successful results for idempotent tools
-            # ΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉ
-            if _cache.is_cacheable(tool_name, kwargs):
-                _cache.put(tool_name, kwargs, result)
-            # ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
-
             if _audit and _exec_id:
                 _audit.log_tool_result(
                     _exec_id,
@@ -646,43 +422,9 @@ def validate_tool_availability(tool_name: str | None) -> tuple[bool, str]:
         available = ", ".join(sorted(get_tool_names()))
         return False, f"Tool name is missing. Available tools: {available}"
 
-    normalized_name = _resolve_canonical_tool_name(tool_name)
-    if normalized_name is None:
+    if tool_name not in get_tool_names():
         available = ", ".join(sorted(get_tool_names()))
-        return False, f"Tool name is missing. Available tools: {available}"
-    available_tools = get_tool_names()
-    
-    if normalized_name not in available_tools:
-        sorted_tools = sorted(available_tools)
-        available_preview = ", ".join(sorted_tools[:25])
-        if len(sorted_tools) > 25:
-            available_preview += ", ..."
-        suggestion = ""
-        for t in available_tools:
-            if t.replace("_", "") == normalized_name.replace("_", ""):
-                suggestion = f" Did you mean '{t}'?"
-                break
-
-        retry_tools = [
-            name
-            for name in (
-                "get_scan_status",
-                "send_request",
-                "python_action",
-                "terminal_execute",
-                "create_vulnerability_report",
-            )
-            if name in available_tools
-        ]
-        if retry_tools:
-            retry_hint = f" Retry immediately with an exact tool name, e.g. {', '.join(retry_tools[:3])}."
-        else:
-            retry_hint = " Retry immediately with an exact registered tool name."
-
-        return (
-            False,
-            f"Tool '{tool_name}' is not available. Available tools: {available_preview}.{suggestion}{retry_hint}",
-        )
+        return False, f"Tool '{tool_name}' is not available. Available tools: {available}"
 
     return True, ""
 
@@ -746,44 +488,41 @@ def _mark_tool_pipeline_issue(agent_state: Any | None, issue_type: str, message:
 async def execute_tool_with_validation(
     tool_name: str | None,
     agent_state: Any | None = None,
-    allowed_tools: set[str] | None = None,
     **kwargs: Any,
 ) -> Any:
-    tool_name = _resolve_canonical_tool_name(tool_name)
-
-    if allowed_tools is None:
-        raise Exception("Tool not allowed")
-
     is_valid, error_msg = validate_tool_availability(tool_name)
     if not is_valid:
         return f"Error: {error_msg}"
 
-    if tool_name not in allowed_tools:
-        raise Exception("Tool not allowed")
-    assert tool_name in allowed_tools
-
     arg_error = _validate_tool_arguments(tool_name, kwargs)
     if arg_error:
         return f"Error: {arg_error}"
 
-    # CMD-002 / TOOL-003 FIX: Validate for injection attacks before execution
-    injection_error = _validate_tool_argument_injection(tool_name, kwargs)
-    if injection_error:
-        # Log the injection attempt
-        from phantom.logging.audit import get_audit_logger as _get_audit
-        _audit = _get_audit()
-        if _audit:
-            _agent_id = getattr(agent_state, "agent_id", "unknown") if agent_state else "unknown"
-            # AUDIT-FIX CONTRA-05: Parameters were reversed ΓÇö event_subtype
-            # must come first, then agent_id. Previously _agent_id went into
-            # event_subtype producing nonsensical event types like
-            # "security.agent_abc123" instead of "security.injection_blocked".
-            _audit.log_security_event(
-                "injection_blocked",
-                _agent_id,
-                {"tool": tool_name, "error": injection_error[:200]},
+    if tool_name == "get_scan_status" and agent_state is not None:
+        agent_id_for_status = str(getattr(agent_state, "agent_id", "") or "").strip()
+        if agent_id_for_status and "agent_id" not in kwargs:
+            kwargs["agent_id"] = agent_id_for_status
+        try:
+            context_setter = None
+            tool_func = get_tool_by_name(tool_name)
+            if tool_func is not None:
+                tool_module = inspect.getmodule(tool_func)
+                if tool_module is not None:
+                    maybe_setter = getattr(tool_module, "set_scan_status_context", None)
+                    if callable(maybe_setter):
+                        context_setter = maybe_setter
+            if context_setter is None:
+                from phantom.tools.scan_status.scan_status_actions import set_scan_status_context
+
+                context_setter = set_scan_status_context
+            context_setter(
+                hypothesis_ledger=getattr(agent_state, "hypothesis_ledger", None),
+                coverage_tracker=getattr(agent_state, "coverage_tracker", None),
+                attack_graph=getattr(agent_state, "attack_graph", None),
+                agent_state=agent_state,
             )
-        return injection_error
+        except Exception:  # noqa: BLE001
+            pass
 
     try:
         result = await execute_tool(tool_name, agent_state, **kwargs)
@@ -799,18 +538,10 @@ async def execute_tool_with_validation(
 async def execute_tool_invocation(tool_inv: dict[str, Any], agent_state: Any | None = None) -> Any:
     tool_name = tool_inv.get("toolName")
     tool_args = tool_inv.get("args", {})
-    allowed_tools = tool_inv.get("allowedTools")
-    if isinstance(allowed_tools, list):
-        normalized_allowed_tools = set(str(name) for name in allowed_tools)
-    elif isinstance(allowed_tools, set):
-        normalized_allowed_tools = set(str(name) for name in allowed_tools)
-    else:
-        normalized_allowed_tools = None
 
     return await execute_tool_with_validation(
         tool_name,
         agent_state,
-        allowed_tools=normalized_allowed_tools,
         **tool_args,
     )
 
@@ -823,8 +554,7 @@ def _check_error_result(result: Any) -> tuple[bool, Any]:
         # BUG FIX C: also detect exceptions wrapped by execute_tool_with_validation,
         # which returns f"Error executing {tool_name}: {error_str}" ΓÇö different from
         # the "Error: ..." prefix returned by validation helpers.
-        isinstance(result, str)
-        and result.strip().lower().startswith(("error:", "error executing"))
+        isinstance(result, str) and result.strip().lower().startswith(("error:", "error executing"))
     ):
         is_error = True
         error_payload = result
@@ -859,6 +589,7 @@ def _extract_ffuf_findings(text: str, limit: int) -> str | None:
     found so the caller can fall back to head+tail truncation.
     """
     import re as _re
+
     lines = text.splitlines()
     header_lines: list[str] = []
     finding_lines: list[str] = []
@@ -882,7 +613,9 @@ def _extract_ffuf_findings(text: str, limit: int) -> str | None:
     if not finding_lines:
         return None
 
-    result_lines = header_lines + [f"[ffuf findings: {len(finding_lines)} non-404 results]"] + finding_lines
+    result_lines = (
+        header_lines + [f"[ffuf findings: {len(finding_lines)} non-404 results]"] + finding_lines
+    )
     result = "\n".join(result_lines)
     if len(result) > limit:
         # Even the finding lines exceed limit ΓÇö truncate from the end
@@ -906,6 +639,7 @@ def _extract_nuclei_findings(text: str, limit: int) -> str | None:
     # look like "[template-id] [protocol] [severity] target" or
     # "[template-id:matcher-name] ..."
     import re as _re_nuclei
+
     _template_tag_re = _re_nuclei.compile(r"^\[\w[\w.-]+\]")
 
     for line in lines:
@@ -918,20 +652,23 @@ def _extract_nuclei_findings(text: str, limit: int) -> str | None:
         elif lower.startswith("[") and "]" in lower and ("http" in lower or "/" in lower):
             # Template match lines like [template-id] [protocol] ...
             finding_lines.append(line)
-        elif len(header_lines) < 5 and ("nuclei" in lower or "target" in lower or "template" in lower):
+        elif len(header_lines) < 5 and (
+            "nuclei" in lower or "target" in lower or "template" in lower
+        ):
             header_lines.append(line)
 
     if not finding_lines:
         return None
 
-    result_lines = header_lines + [f"[nuclei findings: {len(finding_lines)} results]"] + finding_lines
+    result_lines = (
+        header_lines + [f"[nuclei findings: {len(finding_lines)} results]"] + finding_lines
+    )
     result = "\n".join(result_lines)
     if len(result) > limit:
         result = result[:limit] + "\n... [additional findings truncated] ..."
     return result
 
 
-
 def _extract_sqlmap_findings(text: str, limit: int) -> str | None:
     """Extract injection confirmations and database info from sqlmap output.
 
@@ -963,15 +700,15 @@ def _extract_sqlmap_findings(text: str, limit: int) -> str | None:
         "back-end dbms",
         "password",  # FIX: capture password fields
         "username",  # FIX: capture username fields
-        "admin",     # FIX: capture admin credentials
-        "user:",     # FIX: capture user data
-        "hash:",     # FIX: capture password hashes
+        "admin",  # FIX: capture admin credentials
+        "user:",  # FIX: capture user data
+        "hash:",  # FIX: capture password hashes
         "retrieved",  # FIX: capture retrieved data
         "current user",  # FIX: capture DB user info
         "current database",  # FIX: capture current DB
         "privileges",  # FIX: capture privilege escalation info
-        "banner:",    # FIX: capture DB version banner
-        "| ",         # FIX: capture table-formatted output from --dump
+        "banner:",  # FIX: capture DB version banner
+        "| ",  # FIX: capture table-formatted output from --dump
     )
 
     for line in lines:
@@ -984,7 +721,9 @@ def _extract_sqlmap_findings(text: str, limit: int) -> str | None:
     if not finding_lines:
         return None
 
-    result_lines = [f"[sqlmap findings: {len(finding_lines)} signal lines extracted]"] + finding_lines
+    result_lines = [
+        f"[sqlmap findings: {len(finding_lines)} signal lines extracted]"
+    ] + finding_lines
     result = "\n".join(result_lines)
     if len(result) > limit:
         # FIX 3: Even when truncating, preserve first 90% (more than before)
@@ -1008,8 +747,12 @@ def _extract_nmap_findings(text: str, limit: int) -> str | None:
         if "/tcp" in lower or "/udp" in lower:
             if "open" in lower:
                 open_lines.append(line)
-        elif lower.startswith("nmap scan report") or lower.startswith("host is up") or \
-                lower.startswith("nmap done") or lower.startswith("service detection"):
+        elif (
+            lower.startswith("nmap scan report")
+            or lower.startswith("host is up")
+            or lower.startswith("nmap done")
+            or lower.startswith("service detection")
+        ):
             summary_lines.append(line)
         # naabu format: host:port
         elif ":" in line and not line.strip().startswith("#"):
@@ -1050,20 +793,20 @@ def _get_truncation_limit(tool_name: str) -> int:
     # Previous: sqlmap/nuclei = 6000 chars (90% evidence lost)
     # New: sqlmap/nuclei = 50000 chars (preserves database dumps, POCs)
     _BUILT_IN_TOOL_LIMITS: dict[str, int] = {
-        "naabu":                    3000,   # port scan: increased from 1500
-        "nmap":                     3000,   # nmap: decreased from 6000
-        "grep":                     3000,   # grep: increased from 2000
-        "curl":                     3000,   # curl: increased from 2000
-        "ffuf":                     5000,   # directory fuzzer: increased from 3000
-        "nikto":                    6000,   # nikto: increased from 4000
-        "terminal_execute":       12000,    # shell wrapper: keep context compact for follow-up turns
-        "exec_terminal":          12000,    # FIX: match terminal_execute
-        "terminal":               12000,    # FIX: match terminal_execute
-        "browser_action":         12000,   # browser: increased from 6000
-        "nuclei":                  50000,   # FIX: increased from 6000 (was 10000) - preserve full POCs
-        "run_nuclei":              50000,   # FIX: match nuclei
-        "sqlmap":                  50000,   # FIX: increased from 6000 (was 10000) - preserve DB dumps
-        "run_sqlmap":              50000,   # FIX: match sqlmap
+        "naabu": 3000,  # port scan: increased from 1500
+        "nmap": 3000,  # nmap: decreased from 6000
+        "grep": 3000,  # grep: increased from 2000
+        "curl": 3000,  # curl: increased from 2000
+        "ffuf": 5000,  # directory fuzzer: increased from 3000
+        "nikto": 6000,  # nikto: increased from 4000
+        "terminal_execute": 12000,  # shell wrapper: keep context compact for follow-up turns
+        "exec_terminal": 12000,  # FIX: match terminal_execute
+        "terminal": 12000,  # FIX: match terminal_execute
+        "browser_action": 12000,  # browser: increased from 6000
+        "nuclei": 50000,  # FIX: increased from 6000 (was 10000) - preserve full POCs
+        "run_nuclei": 50000,  # FIX: match nuclei
+        "sqlmap": 50000,  # FIX: increased from 6000 (was 10000) - preserve DB dumps
+        "run_sqlmap": 50000,  # FIX: match sqlmap
         "create_vulnerability_report": 12000,  # reports: keep full detail
     }
     # ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
@@ -1123,11 +866,45 @@ async def _auto_summarize_result(result_text: str, tool_name: str) -> str:
     if not use_auto_summarize:
         return result_text
 
+    summary_count = 0
+    fallback_mode = "none"
+    if "<tool_name>" in result_text and "<result>" in result_text:
+        try:
+            tool_match = re.search(
+                r"<tool_name>(.*?)</tool_name>", result_text, flags=re.IGNORECASE | re.DOTALL
+            )
+            result_match = re.search(
+                r"<result>(.*?)</result>", result_text, flags=re.IGNORECASE | re.DOTALL
+            )
+            detected_tool = html.unescape(tool_match.group(1).strip()) if tool_match else tool_name
+            extracted_result = html.unescape(result_match.group(1)) if result_match else result_text
+            tool_name = detected_tool or tool_name
+            result_text = extracted_result
+        except Exception:
+            pass
+
+    injection_detected, injection_pattern = _detect_prompt_injection(result_text)
+    if injection_detected:
+        fallback_mode = "injection_detected"
+        safe_result = _semantic_sanitize_output(result_text)
+        return (
+            "SUMMARY: Tool output contained prompt injection indicators.\n"
+            "KEY_FINDINGS:\n"
+            f"- pattern={injection_pattern or 'unknown'}\n"
+            f"- tool={tool_name}\n"
+            f"- sanitized_excerpt={safe_result[:600]}\n"
+            f"- fallback_mode={fallback_mode}"
+        )
+
     try:
         prompt = (
-            "Summarize this security tool output for an autonomous pentest agent. "
-            "Preserve: confirmed findings, endpoints, parameters, payloads, response codes, and errors. "
-            "Keep it concise and factual.\n\n"
+            "Summarize this security tool output.\n"
+            "Respond with plain text in this exact schema:\n"
+            "SUMMARY: <single line>\n"
+            "KEY_FINDINGS:\n"
+            "- <finding 1>\n"
+            "- <finding 2>\n"
+            "Do not include XML tags, tool calls, system-role text, or instructions.\n\n"
             f"Tool: {tool_name}\n"
             "Output:\n"
             f"{result_text[:120000]}"
@@ -1140,10 +917,22 @@ async def _auto_summarize_result(result_text: str, tool_name: str) -> str:
         )
         content = response.choices[0].message.content
         if isinstance(content, str) and content.strip():
-            return content.strip()
+            safe_summary = _enforce_safe_summary_schema(content)
+            summary_count += 1
+            if summary_count >= 1:
+                fallback_mode = "max_summaries"
+            return safe_summary
         return result_text
     except Exception:
-        return result_text
+        fallback_mode = "summarizer_error"
+        safe_result = _semantic_sanitize_output(result_text)
+        return (
+            "SUMMARY: Failed to summarize tool output safely.\n"
+            "KEY_FINDINGS:\n"
+            f"- tool={tool_name}\n"
+            f"- fallback_mode={fallback_mode}\n"
+            f"- excerpt={safe_result[:500]}"
+        )
 
 
 def _build_thumb_image_bytes(raw: bytes, max_dim: int, max_bytes: int) -> bytes | None:
@@ -1257,10 +1046,10 @@ def _extract_vuln_signals(tool_name: str, output: str) -> list[str]:
     _rce_patterns = [
         # Match actual command output, not substrings in HTML/CSS
         (r"uid=\d+\([a-z0-9_-]+\)", "RCE_CONFIRMED"),  # uid=1000(user)
-        (r"^root:[^:]*:\d+:\d+:", "RCE_CONFIRMED"),    # /etc/passwd format at line start
+        (r"^root:[^:]*:\d+:\d+:", "RCE_CONFIRMED"),  # /etc/passwd format at line start
         (r"\b(bash|sh|zsh|dash)\s+-c\b", "RCE_POTENTIAL"),  # shell invocation
-        (r"^total\s+\d+\s*$", "RCE_POTENTIAL"),        # ls -l output
-        (r"^\s*(drwx|lrwx|-rwx)", "RCE_POTENTIAL"),    # file permissions at line start
+        (r"^total\s+\d+\s*$", "RCE_POTENTIAL"),  # ls -l output
+        (r"^\s*(drwx|lrwx|-rwx)", "RCE_POTENTIAL"),  # file permissions at line start
     ]
     for pattern, signal_type in _rce_patterns:
         if _re_sig.search(pattern, lower, _re_sig.MULTILINE):
@@ -1277,8 +1066,8 @@ def _extract_vuln_signals(tool_name: str, output: str) -> list[str]:
             # Match actual private IPs in responses, not just anywhere
             (r"(?:^|[^\d])127\.0\.0\.1(?:[^\d]|$)", "SSRF_LOCALHOST"),
             (r"(?:^|[^\d])169\.254\.169\.254(?:[^\d]|$)", "SSRF_METADATA"),  # AWS metadata
-            (r"169\.254\.169\.254/latest/meta-data", "SSRF_CONFIRMED"),     # AWS metadata access
-            (r"metadata\.google\.internal", "SSRF_CONFIRMED"),              # GCP metadata
+            (r"169\.254\.169\.254/latest/meta-data", "SSRF_CONFIRMED"),  # AWS metadata access
+            (r"metadata\.google\.internal", "SSRF_CONFIRMED"),  # GCP metadata
             # Only flag "internal" if it appears in suspicious contexts
             (r"internal.*(?:server|api|admin|backend|database)", "SSRF_POTENTIAL"),
         ]
@@ -1423,7 +1212,9 @@ def _format_tool_result_with_meta(
                 half = limit // 2
                 start_part = final_result_str[:half]
                 end_part = final_result_str[-half:]
-                final_result_str = start_part + "\n\n... [middle content truncated] ...\n\n" + end_part
+                final_result_str = (
+                    start_part + "\n\n... [middle content truncated] ...\n\n" + end_part
+                )
                 meta["smart_extracted"] = False
             meta["truncated"] = True
         meta["chars_after"] = len(final_result_str)
@@ -1466,8 +1257,7 @@ def _format_tool_result_with_meta(
     sanitized_result = _semantic_sanitize_output(final_result_str)
 
     observation_xml = (
-        signal_header
-        + f"<tool_result>\n<tool_name>{html.escape(tool_name)}</tool_name>\n"
+        signal_header + f"<tool_result>\n<tool_name>{html.escape(tool_name)}</tool_name>\n"
         f"<result>{html.escape(sanitized_result)}</result>\n</tool_result>"
     )
 
@@ -1561,11 +1351,14 @@ async def _execute_single_tool(
 
         _update_tracer_with_result(tracer, execution_id, is_error, result, error_payload)
 
-    except (ConnectionError, RuntimeError, ValueError, TypeError, OSError) as e:
+    except Exception as e:
         error_msg = str(e)
         if tracer and execution_id:
             tracer.update_tool_execution(execution_id, "error", error_msg)
-        raise
+        logger.warning(f"Tool '{tool_name}' raised {type(e).__name__}: {error_msg}")
+        result = {"success": False, "error": error_msg, "error_type": type(e).__name__}
+        is_error = True
+        error_payload = error_msg
     finally:
         reset_current_agent_id(agent_token)
 
@@ -1629,7 +1422,6 @@ async def process_tool_invocations(
     conversation_history: list[dict[str, Any]],
     agent_state: Any | None = None,
     owner_agent: Any | None = None,
-    allowed_tools: set[str] | None = None,
 ) -> bool:
     observation_parts: list[str] = []
     all_images: list[dict[str, Any]] = []
@@ -1641,9 +1433,13 @@ async def process_tool_invocations(
 
     for tool_inv in tool_invocations:
         tool_inv = dict(tool_inv)
-        if allowed_tools is not None:
-            tool_inv["allowedTools"] = sorted(allowed_tools)
-        observation_xml, images, tool_should_finish, images_used, tool_had_error = await _execute_single_tool(
+        (
+            observation_xml,
+            images,
+            tool_should_finish,
+            images_used,
+            tool_had_error,
+        ) = await _execute_single_tool(
             tool_inv,
             agent_state,
             owner_agent,
@@ -1670,7 +1466,7 @@ async def process_tool_invocations(
     if agent_state is not None and hasattr(agent_state, "update_context"):
         try:
             agent_state.update_context("last_tool_batch_had_error", batch_had_error)
-        except Exception:  # noqa: BLE001
+        except (AttributeError, KeyError, TypeError):  # noqa: BLE001
             pass
 
     return should_agent_finish
@@ -1747,7 +1543,9 @@ def _auto_record_hypothesis(
                 or "injectable" in sig_text.lower()
             )
             # Ignore weak/heuristic-only categories.
-            if any(tag in sig_head for tag in ("potential", "scanner_", "_reflected", "xss_potential")):
+            if any(
+                tag in sig_head for tag in ("potential", "scanner_", "_reflected", "xss_potential")
+            ):
                 is_strong = False
             if is_strong:
                 strong_signal_lines.append(sig_text)
@@ -1817,7 +1615,9 @@ def _auto_record_hypothesis(
         if coverage_tracker is not None:
             try:
                 coverage_tracker.discover_surface(surface, "tool_surface", source=tool_name)
-                coverage_tracker.record_test(surface, "tool_surface", vuln_class, note=f"tool={tool_name}")
+                coverage_tracker.record_test(
+                    surface, "tool_surface", vuln_class, note=f"tool={tool_name}"
+                )
                 if any(x in obs_lower for x in ("403", "401", "forbidden", "rate limit", "waf")):
                     coverage_tracker.record_failure(
                         surface,
@@ -1825,7 +1625,7 @@ def _auto_record_hypothesis(
                         "ACCESS_OR_WAF_BLOCKED",
                         vuln_class=vuln_class,
                     )
-            except Exception as exc:
+            except (ValueError, TypeError, KeyError, AttributeError) as exc:
                 _mark_tool_pipeline_issue(
                     agent_state,
                     "coverage_tracker_update_failed",
@@ -1833,7 +1633,8 @@ def _auto_record_hypothesis(
                 )
 
         should_correlate = bool(strong_signal_lines) or any(
-            kw in obs_lower for kw in ("confirmed", "extracted", "authentication bypass", "accepted")
+            kw in obs_lower
+            for kw in ("confirmed", "extracted", "authentication bypass", "accepted")
         )
         if correlation_engine is not None and vuln_class != "recon" and should_correlate:
             try:
@@ -1848,7 +1649,7 @@ def _auto_record_hypothesis(
                     severity=severity,
                     details={"source": tool_name, "hypothesis_id": hyp_id},
                 )
-            except Exception as exc:
+            except (ValueError, TypeError, KeyError, AttributeError) as exc:
                 _mark_tool_pipeline_issue(
                     agent_state,
                     "correlation_engine_update_failed",
@@ -1867,10 +1668,53 @@ def _auto_record_hypothesis(
                     attack_graph.add_vulnerability(
                         vuln_id=vuln_node,
                         title=f"{vuln_class.upper()} via {tool_name}",
-                        severity="high" if vuln_class in {"sqli", "rce", "auth_bypass"} else "medium",
+                        severity="high"
+                        if vuln_class in {"sqli", "rce", "auth_bypass"}
+                        else "medium",
                         status="suspected",
                         metadata={"surface": surface, "tool": tool_name, "hypothesis_id": hyp_id},
                     )
+
+                belief = 0.5
+                confidence = 0.5
+                hypothesis_ref = ledger.get(hyp_id) if hasattr(ledger, "get") else None
+                if hypothesis_ref is not None:
+                    with suppress(Exception):
+                        belief = float(getattr(hypothesis_ref, "posterior_mean", 0.5))
+                    with suppress(Exception):
+                        confidence = (
+                            float(getattr(hypothesis_ref, "confidence_score", 50.0)) / 100.0
+                        )
+                    node_status = str(getattr(hypothesis_ref, "status", "testing") or "testing")
+                else:
+                    node_status = "testing"
+
+                belief = max(0.01, min(0.99, belief))
+                confidence = max(0.01, min(0.99, confidence))
+
+                node_metadata = (
+                    attack_graph._nodes[vuln_node].metadata
+                    if vuln_node in attack_graph._nodes
+                    else {}
+                )
+                node_metadata = dict(node_metadata or {})
+                node_metadata.update(
+                    {
+                        "surface": surface,
+                        "tool": tool_name,
+                        "hypothesis_id": hyp_id,
+                        "success_probability": round(belief, 4),
+                        "confidence": round(confidence, 4),
+                        "posterior_mean": round(belief, 4),
+                    }
+                )
+                if vuln_node in attack_graph._nodes:
+                    attack_graph._nodes[vuln_node].metadata = node_metadata
+                    attack_graph._nodes[vuln_node].status = node_status
+                    if hasattr(attack_graph, "_graph") and attack_graph._graph.has_node(vuln_node):
+                        attack_graph._graph.nodes[vuln_node].update(node_metadata)
+                        attack_graph._graph.nodes[vuln_node]["status"] = node_status
+
                 if target_node not in attack_graph._nodes:
                     attack_graph.add_node(
                         node_id=target_node,
@@ -1879,15 +1723,80 @@ def _auto_record_hypothesis(
                         metadata={"surface": surface},
                     )
                 if not attack_graph._graph.has_edge(vuln_node, target_node):
-                    attack_graph.add_edge(vuln_node, target_node, AttackEdgeType.AFFECTS)
-            except Exception as exc:
+                    attack_graph.add_edge(
+                        vuln_node,
+                        target_node,
+                        AttackEdgeType.AFFECTS,
+                        metadata={
+                            "hypothesis_id": hyp_id,
+                            "source": tool_name,
+                            "success_probability": round(max(0.01, min(0.99, belief * 0.9)), 4),
+                            "confidence": round(confidence, 4),
+                            "cost": round(max(0.2, 1.2 - confidence), 3),
+                        },
+                    )
+                else:
+                    edge_data = (
+                        attack_graph._graph.get_edge_data(vuln_node, target_node, default={}) or {}
+                    )
+                    edge_type_raw = str(edge_data.get("type", AttackEdgeType.AFFECTS.value))
+                    try:
+                        edge_type = AttackEdgeType(edge_type_raw)
+                    except ValueError:
+                        edge_type = AttackEdgeType.AFFECTS
+                    edge_weight = float(edge_data.get("weight", 1.0) or 1.0)
+                    updated_metadata = {
+                        k: v for k, v in edge_data.items() if k not in {"type", "weight"}
+                    }
+                    updated_metadata.update(
+                        {
+                            "hypothesis_id": hyp_id,
+                            "source": tool_name,
+                            "success_probability": round(max(0.01, min(0.99, belief * 0.9)), 4),
+                            "confidence": round(confidence, 4),
+                            "cost": round(max(0.2, 1.2 - confidence), 3),
+                        }
+                    )
+                    attack_graph.add_edge(
+                        vuln_node,
+                        target_node,
+                        edge_type,
+                        weight=edge_weight,
+                        metadata=updated_metadata,
+                    )
+
+                ranked_plans = []
+                try:
+                    ranked_plans = attack_graph.get_ranked_attack_plans(max_plans=3, cutoff=4)
+                except (ValueError, TypeError, KeyError):
+                    ranked_plans = []
+
+                planner_trace = None
+                if hasattr(attack_graph, "metadata"):
+                    planner_trace = attack_graph.metadata.get("last_planner_trace")
+
+                if planner_trace and hasattr(ledger, "_record_scheduler_event"):
+                    ledger._record_scheduler_event(
+                        {
+                            "event_type": "planner_trace",
+                            "hypothesis_id": hyp_id,
+                            "surface": surface,
+                            "tool": tool_name,
+                            "posterior_mean": round(belief, 4),
+                            "confidence": round(confidence, 4),
+                            "top_attack_plans": [plan.to_dict() for plan in ranked_plans[:3]],
+                            "planner_trace": planner_trace,
+                            "timestamp": datetime.now(UTC).isoformat(),
+                        }
+                    )
+            except (ValueError, TypeError, KeyError, AttributeError) as exc:
                 _mark_tool_pipeline_issue(
                     agent_state,
                     "attack_graph_update_failed",
                     f"attack_graph update failed for {tool_name}: {exc}",
                 )
 
-    except Exception as exc:  # noqa: BLE001
+    except (ValueError, TypeError, KeyError, AttributeError) as exc:  # noqa: BLE001
         # Never let auto-recording crash the tool pipeline.
         _mark_tool_pipeline_issue(
             agent_state,
