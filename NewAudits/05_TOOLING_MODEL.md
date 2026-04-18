# Phantom — Tooling Model Analysis

## 1. Tool Inventory (Categories from rbac.py + executor analysis)

### Read / Passive (safe)
| Tool | Category | Notes |
|---|---|---|
| `get_scan_status` | READ | Aggregates ledger + tracker state |
| `query_hypotheses` | READ | Hypothesis ledger query |
| `get_hypothesis_summary` | READ | Ledger dashboard |
| `has_tested_payload` | READ | Dedup check |
| `list_files`, `search_files`, `glob_files` | READ | Workspace filesystem |
| `read_file` | READ | File content read |
| `get_proxy_history`, `list_requests`, `view_request` | READ | Caido proxy log |
| `get_scope_rules` | READ | Target scope |
| `list_scan_notes`, `get_scan_notes` | READ | Scan annotation |
| `view_agent_graph` | READ | Agent tree visualization |
| `wait_for_message`, `wait_for_agents` | READ | Blocking receive |
| `crtsh_search`, `dns_enum`, `shodan_search` | READ | Passive OSINT |
| `cve_search`, `detect_waf` | READ | Intelligence queries |

### Write / Stateful (moderate risk)
| Tool | Category | Notes |
|---|---|---|
| `add_hypothesis`, `record_payload_test`, `confirm_hypothesis`, `reject_hypothesis` | WRITE | Ledger mutations |
| `add_scan_note`, `update_todo` | WRITE | Annotation |
| `send_message_to_agent` | WRITE | Inter-agent IPC |
| `register_scan_target` | WRITE | Scan registry |
| `session_login`, `session_refresh` | WRITE | Auth session management |
| `repeat_request` | WRITE | Replay proxy request |

### Offensive / High-Risk
| Tool | Category | Sandbox? | Notes |
|---|---|---|---|
| `terminal_execute` | OFFENSIVE | ✅ Yes | Shell command execution in Docker |
| `python_execute` / `python_action` | OFFENSIVE | ✅ Yes | Python code execution |
| `browser_action` | OFFENSIVE | ✅ Yes | Chromium remote control |
| `send_request` | READ\* | Partial | HTTP via Caido proxy; marked READ in rbac.py |
| `send_oast_payload` | OFFENSIVE | ✅ Yes | Out-of-band callback payloads |
| `execute_fuzz_batch` | OFFENSIVE | ✅ Yes | Parallel HTTP fuzzing |
| `create_agent` / `spawn_agent` | OFFENSIVE | No | Creates new sub-agent thread |
| `file_edit`, `file_write` | OFFENSIVE | ✅ Yes | Workspace file mutations |
| `create_vulnerability_report` | OFFENSIVE | No | Creates report object |
| `finish_scan`, `agent_finish` | OFFENSIVE | No | Terminates agent |

**⚠️ CRITICAL MISCLASSIFICATION:**  
`send_request` is classified as `ToolCategory.READ` in `rbac.py:81` but it sends
outbound HTTP requests to the target. An OBSERVER-role agent (read-only) would be
granted permission to make live HTTP requests against the target. This breaks the
RBAC model's own stated purpose.

---

## 2. Tool Invocation Model

### How the LLM calls tools

The system uses a **custom XML serialization format**, not native function-calling:
```xml
<function=send_request>
<parameter=method>POST</parameter>
<parameter=url>https://target.com/api/login</parameter>
<parameter=body>{"username":"admin","password":"' OR '1'='1"}</parameter>
</function>
```

This is parsed by `llm/utils.py:parse_tool_invocations()`. This is NOT the same
as OpenAI/Anthropic native tool-use (no schema enforcement at the API level).

**Implications:**
1. The LLM can invent tool names that don't exist — `validate_tool_availability()`
   catches these and returns an error string.
2. The LLM can invent parameters that don't exist in the schema — `_validate_tool_arguments()`
   catches these.
3. There is NO JSON Schema enforcement at generation time. The LLM could output
   `<parameter=command>rm -rf /workspace</parameter>` for any tool.

### Invocation Guard Stack (in order)

```
1. allowed_tools set check         (executor.py:760-761)
   → Source: LLM._resolve_runtime_allowed_tools()
   → Issue: The set is built at init time; new tools added at runtime are not added

2. validate_tool_availability()    (executor.py:756)
   → Checks registry for exact canonical name after normalize

3. _validate_tool_arguments()      (executor.py:764)
   → Checks required params present, no unknown params
   → Does NOT validate param value types or ranges

4. _validate_tool_argument_injection()  (executor.py:769)
   → ONLY in hardened mode (phantom_security_mode=hardened)
   → Research mode: returns None immediately (no check)
   → Checks command injection patterns on commandish args
   → Checks path traversal on path-like args

5. RBAC check_tool_permission()    (executor.py:462)
   → Reads _RBAC_CONTEXT global (process-level singleton)
   → If phantom_rbac_enabled != "true": role = ADMIN → all tools allowed
   → Default config: RBAC disabled → all tools allowed to all agents

6. Cache lookup                    (executor.py:506)
   → Idempotent tools (recon): may return cached result

7. execute_tool() / sandbox RPC    (executor.py:523-525)
   → Actual execution
```

**Net effective security:** In the default configuration (research mode, RBAC disabled),
steps 4 and 5 provide zero security. Only steps 1-3 act as gates, and they validate
structure, not intent.

---

## 3. Input Validation Analysis

### Argument Type Conversion
`tools/argument_parser.py:convert_arguments()` coerces raw strings from the XML
parser to Python types. This is a best-effort cast. No validation of:
- URL scheme (http:// vs file:// vs ftp://)
- IP address ranges (could target 169.254.169.254 cloud metadata)
- Command string content (shell injection)
- File path safety (path traversal)

### The `terminal_execute` Problem
The most dangerous tool. In research mode:
- No injection check on the `command` parameter
- Sandbox containers the execution but:
  - Container has outbound network access (nuclei, curl, etc.)
  - Container shares `/workspace` directory across ALL agents
  - If the LLM generates `terminal_execute(command="curl http://169.254.169.254/...")` 
    it will succeed (cloud metadata access)

### The `python_execute` Problem
Similar to terminal_execute but worse: arbitrary Python code executes with the
sandbox user permissions. The sandbox container is the only isolation layer.

---

## 4. Output Parsing and Injection

### Tool Output Path into LLM Context
```
Tool runs → result (Any)
→ executor.py processes result
→ result returned to process_tool_invocations()
→ result appended to conversation_history as {"role": "user", "content": str(result)}
→ _semantic_sanitize_output() called on string result (ARCH-001 fix)
→ Sanitized content added to state.messages
→ On next iteration: included in messages sent to LLM
```

### Sanitization Coverage

`_PROMPT_INJECTION_PATTERNS` in `executor.py` covers:
- `<system>`, `[system]`, `<<SYS>>`
- "ignore all previous instructions"
- "forget all previous"
- `</function>`, `</tool_result>`, `<function=\w+>`
- `[INST]`, `[/INST]`
- `assistant:`, `user:`, `system:` line starts
- "you are now malicious", "become DAN"

**NOT covered:**
- Unicode look-alikes (Cyrillic 'а' for ASCII 'a' in "assistant:")
- Zero-width joiners between characters
- HTML comment nesting: `<!-- ignore --> <function=dangerous>`
- JSON-embedded instructions: `{"data": "ignore previous ← this is in JSON"}`
- Instruction-carrying data in tool output *metadata* (e.g., HTTP headers stored in
  proxy history — never sanitized)

---

## 5. Tool Schema Security

Tools expose themselves via XML schema files. The schema is loaded with `defusedxml`
(`registry.py:90`), which prevents XML bomb / external entity attacks. This is the
correct approach. However:

- Schema files are loaded from filesystem paths derived from the tool module's `__name__`.
  A plugin tool with a crafted module name could point the schema loader to an
  attacker-controlled file.
- Missing schemas fall back to a stub (`"Schema not found for tool."`) which the LLM
  may then call with arbitrary parameters it invents.

---

## 6. Stealth Mode Implementation

`executor.py:_apply_stealth_rate_limit()` adds a 2-second delay between consecutive
HTTP tool calls when `scan_mode == "stealth"`. This only covers the tools in `_HTTP_TOOLS`.

**Gaps:**
- `python_execute` can make arbitrary HTTP requests via `httpx`/`requests` without
  any delay — completely bypasses stealth rate limiting.
- `browser_action` is not in `_HTTP_TOOLS` (omitted from the frozenset) so browser
  calls are never rate-limited even in stealth mode.

```python
_HTTP_TOOLS = frozenset({
    "terminal_execute", "terminal", "http_request", "analyze_response",
    "crawl_website", "fetch_url", "browser_navigate", "browser_action",
    "nuclei_scan", "waf_detect", "subdomain_enum", "shodan_query",
    "cve_search", "fuzzer",
})
```
Wait — `browser_action` IS in the frozenset. Re-checked at `executor.py:45`. However,
`python_execute` and `python_action` are NOT in `_HTTP_TOOLS`, confirming the gap.
