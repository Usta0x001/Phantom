# Phantom Tooling and Execution Model (Step 9)

## Scope and evidence basis

This report reconstructs how tools are exposed, selected, validated, and executed at runtime.
It is implementation-grounded only.

Primary anchors:

- Tool loading and registry: `phantom/tools/__init__.py:31`, `phantom/tools/registry.py:152`, `phantom/tools/registry.py:233`
- Prompt-time tool exposure: `phantom/llm/llm.py:277`, `phantom/tools/dynamic_tools.py:86`, `phantom/tools/dynamic_tools.py:204`
- Tool call parsing: `phantom/llm/utils.py:81`, `phantom/llm/utils.py:95`
- Execution gate and dispatch: `phantom/tools/executor.py:579`, `phantom/tools/executor.py:593`, `phantom/tools/executor.py:617`, `phantom/tools/executor.py:427`
- Sandbox RPC boundary: `phantom/tools/executor.py:457`, `phantom/runtime/tool_server.py:137`
- Runtime/container substrate: `phantom/runtime/docker_runtime.py:201`, `phantom/runtime/docker_runtime.py:230`, `phantom/runtime/docker_runtime.py:240`
- Tool server execution model: `phantom/runtime/tool_server.py:115`, `phantom/runtime/tool_server.py:151`
- Installed scanner/toolchain binaries: `containers/Dockerfile:41`, `containers/Dockerfile:42`, `containers/Dockerfile:88`, `containers/Dockerfile:111`

---

## 1) Tool inventory (what is actually available)

## 1.1 Python tool surface (registry-level)

Phantom exposes tool functions via `@register_tool` and stores metadata in a global registry:

- Decorator registration and metadata capture: `phantom/tools/registry.py:152`
- Runtime lookup by name: `phantom/tools/registry.py:213`
- Sandbox preference per tool (`sandbox_execution`): `phantom/tools/registry.py:153`, `phantom/tools/registry.py:233`

Major tool families observed in active imports:

- Core web and proxy tools (`send_request`, history, scope): `phantom/tools/__init__.py:41`, `phantom/tools/proxy/proxy_actions.py:50`
- Terminal and Python execution tools: `phantom/tools/__init__.py:42`, `phantom/tools/__init__.py:46`, `phantom/tools/terminal/terminal_actions.py:6`, `phantom/tools/python/python_actions.py:9`
- Browser automation tools: `phantom/tools/__init__.py:35`, `phantom/tools/browser/browser_actions.py:217`
- Agent graph/delegation tools: `phantom/tools/__init__.py:32`, `phantom/tools/agents_graph/agents_graph_actions.py:265`
- Reporting and finish controls: `phantom/tools/__init__.py:43`, `phantom/tools/finish/finish_actions.py:95`, `phantom/tools/reporting/reporting_actions.py:543`
- Strategic memory/status tools: `phantom/tools/__init__.py:63`, `phantom/tools/__init__.py:69`, `phantom/tools/scan_status/scan_status_actions.py:50`

## 1.2 External binary tooling inside sandbox image

The sandbox image installs a broad pentest toolchain, mostly consumed via `terminal_execute`:

- Network and scanner binaries (`nmap`, `ncat`, `sqlmap`, `nuclei`, `subfinder`, `naabu`, `ffuf`): `containers/Dockerfile:41`, `containers/Dockerfile:42`
- Additional Go-installed tools (`httpx`, `katana`, `cvemap`, `gospider`, `interactsh-client`): `containers/Dockerfile:88`
- Additional cloned/custom script repos (`JS-Snooper`, `jsniper.sh`, `jwt_tool`): `containers/Dockerfile:111`, `containers/Dockerfile:117`

## 1.3 Proxy substrate: Caido, not Burp

- The runtime entrypoint starts `caido-cli` and configures system proxy env vars: `containers/docker-entrypoint.sh:12`, `containers/docker-entrypoint.sh:115`
- Proxy tool module talks to Caido GraphQL API: `phantom/tools/proxy/proxy_manager.py:359`, `phantom/tools/proxy/proxy_manager.py:370`

No Burp integration path is present in the inspected execution flow.

---

## 2) Invocation model (intent to side effect)

End-to-end path:

1. System prompt is built with full or subset tool XML schemas: `phantom/llm/llm.py:277`, `phantom/tools/dynamic_tools.py:204`
2. LLM emits XML tool calls; parser normalizes and validates tool/parameter token syntax: `phantom/llm/utils.py:12`, `phantom/llm/utils.py:81`, `phantom/llm/utils.py:95`
3. Agent loop sends parsed actions to executor: `phantom/agents/base_agent.py:798`, `phantom/tools/executor.py:1441`
4. Executor validates availability and schema, then executes: `phantom/tools/executor.py:589`, `phantom/tools/executor.py:593`, `phantom/tools/executor.py:617`
5. Executor dispatches to sandbox RPC or local function path: `phantom/tools/executor.py:427`, `phantom/tools/executor.py:457`, `phantom/tools/executor.py:515`
6. Tool results are shaped/sanitized and appended as the next `user` observation: `phantom/tools/executor.py:1284`, `phantom/tools/executor.py:1480`

This is a ReAct loop with an explicit executor chokepoint.

---

## 3) AI-driven vs deterministic behavior

## 3.1 AI-driven control planes

- Action selection and sequencing are model policy decisions per turn: `phantom/agents/base_agent.py:691`
- Parameter content is model-generated unless constrained by schema/type conversion: `phantom/llm/utils.py:101`, `phantom/tools/argument_parser.py:19`
- Task decomposition into sub-agents is model-triggered via tool calls (`create_agent`): `phantom/tools/agents_graph/agents_graph_actions.py:265`
- Fuzz manager expects payloads from model strategy rather than static executor lists: `phantom/tools/fuzzer/fuzzer_actions.py:4`, `phantom/tools/fuzzer/fuzzer_actions.py:29`

## 3.2 Deterministic enforcement layers

- Tool-name existence and schema checks are deterministic: `phantom/tools/executor.py:532`, `phantom/tools/executor.py:544`
- Argument conversion to declared Python types is deterministic: `phantom/tools/argument_parser.py:19`, `phantom/tools/argument_parser.py:75`
- Sandbox authentication and timeout behavior are deterministic at transport layer: `phantom/runtime/tool_server.py:85`, `phantom/runtime/tool_server.py:152`
- Result formatting/truncation/sanitization pipeline is deterministic: `phantom/tools/executor.py:1249`, `phantom/tools/executor.py:1284`

## 3.3 Mixed (soft) controls

- `phantom_tool_subset` reduces model-visible schema surface but does not remove runtime-registered tools: `phantom/llm/llm.py:277`, `phantom/tools/executor.py:537`

Result: strategy is AI-first; execution mechanics are deterministic; capability minimization is currently soft.

---

## 4) Execution substrate and isolation model

## 4.1 Default host orchestration mode (`PHANTOM_SANDBOX_MODE=false`)

- Root agent creates a sandbox container via runtime: `phantom/agents/base_agent.py:584`, `phantom/agents/base_agent.py:589`
- Tools marked `sandbox_execution=True` are executed through tool-server RPC: `phantom/tools/executor.py:427`, `phantom/tools/executor.py:457`
- Tools marked `sandbox_execution=False` execute directly in host process: `phantom/tools/registry.py:233`, `phantom/tools/executor.py:429`

## 4.2 Sandbox process mode (`PHANTOM_SANDBOX_MODE=true`)

- Tool server process enforces sandbox-mode-only startup: `phantom/runtime/tool_server.py:17`
- In this mode, executor local path is used (no extra RPC hop): `phantom/tools/executor.py:427`, `phantom/tools/executor.py:429`

## 4.3 Container isolation shape

- Container is launched with explicit added network capabilities and selected drops: `phantom/runtime/docker_runtime.py:240`, `phantom/runtime/docker_runtime.py:244`
- Resource limits are applied (memory, CPU quota, PID cap): `phantom/runtime/docker_runtime.py:257`, `phantom/runtime/docker_runtime.py:262`
- Tool server token is provisioned and used for authenticated RPC: `phantom/runtime/docker_runtime.py:227`, `phantom/tools/executor.py:488`

---

## 5) Critical execution control points

- Prompt schema exposure: `phantom/llm/llm.py:277`
- Tool parse normalization: `phantom/llm/utils.py:12`
- Validation and dispatch gate: `phantom/tools/executor.py:579`
- Sandbox RPC adapter: `phantom/tools/executor.py:457`
- Sandbox request handler: `phantom/runtime/tool_server.py:137`
- Observation feedback injection into next turn: `phantom/tools/executor.py:1480`

---

## 6) Architectural implications

Strengths:

- Clear chokepoint between model intent and side effects (`execute_tool_with_validation`): `phantom/tools/executor.py:579`
- Split between tool metadata, schema exposure, and runtime function dispatch: `phantom/tools/registry.py:152`, `phantom/tools/registry.py:240`
- Authenticated sandbox RPC with per-agent timeout/cancellation semantics: `phantom/runtime/tool_server.py:94`, `phantom/runtime/tool_server.py:146`, `phantom/runtime/tool_server.py:152`

Constraints and tradeoffs:

- A substantial set of tools are explicitly host-local (`sandbox_execution=False`), so isolation is partial by design: examples at `phantom/tools/reporting/reporting_actions.py:543`, `phantom/tools/agents_graph/agents_graph_actions.py:265`, `phantom/tools/web_search/web_search_actions.py:193`
- Prompt-level subsetting does not equal runtime least privilege: `phantom/llm/llm.py:277`, `phantom/tools/executor.py:537`

---

## Step 9 reconstruction statement

Phantom uses an AI-driven action planner with a deterministic executor gate. Tooling is broad: Python tool plugins plus a Kali-based scanner stack invoked mainly through terminal execution. Isolation is hybrid: many side-effect tools run inside a sandbox container, while numerous management/intelligence tools execute directly on the host process. The architecture has a strong execution chokepoint and transport boundary, but runtime capability boundaries are not yet hard-enforced by allowlist contracts.
