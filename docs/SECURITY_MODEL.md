# Phantom Security Model (Step 10)

## Scope and evidence basis

This report reconstructs the implemented security model (not intended model) for tool execution, runtime boundaries, trust controls, and attack surface.

Primary anchors:

- Tool-call parse and validation gates: `phantom/llm/utils.py:81`, `phantom/llm/utils.py:95`, `phantom/tools/executor.py:589`, `phantom/tools/executor.py:593`, `phantom/tools/executor.py:617`
- Sandbox transport and auth: `phantom/tools/executor.py:457`, `phantom/tools/executor.py:487`, `phantom/runtime/tool_server.py:85`, `phantom/runtime/tool_server.py:94`, `phantom/runtime/tool_server.py:152`
- Runtime/container security controls: `phantom/runtime/docker_runtime.py:240`, `phantom/runtime/docker_runtime.py:244`, `phantom/runtime/docker_runtime.py:257`, `phantom/runtime/docker_runtime.py:548`
- Network/SSRF guardrails: `phantom/tools/proxy/proxy_manager.py:150`, `phantom/tools/proxy/proxy_manager.py:322`, `phantom/tools/proxy/proxy_manager.py:590`
- Filesystem/path controls: `phantom/tools/file_edit/file_edit_actions.py:13`
- Output/telemetry sanitization: `phantom/tools/executor.py:271`, `phantom/tools/executor.py:1284`, `phantom/telemetry/utils.py:27`, `phantom/telemetry/utils.py:93`
- High-risk disabled controls: `phantom/tools/executor.py:238`, `phantom/tools/python/python_instance.py:22`, `phantom/config/config.py:96`, `phantom/tools/executor.py:383`

---

## 1) Trust boundaries and attack surface

## 1.1 Model-to-execution boundary

- LLM output is parsed into tool invocations with regex-enforced tool/parameter token names (`[a-zA-Z_][a-zA-Z0-9_]*`): `phantom/llm/utils.py:95`, `phantom/llm/utils.py:108`.
- All parsed tool calls still pass host-side validation in executor (availability, argument schema) before side effects: `phantom/tools/executor.py:589`, `phantom/tools/executor.py:593`.
- Side effects happen only through `execute_tool(...)` dispatch (local or sandbox): `phantom/tools/executor.py:364`, `phantom/tools/executor.py:427`.

## 1.2 Host-to-sandbox boundary

- For tools marked `sandbox_execution=True`, host sends authenticated RPC to `/execute`: `phantom/tools/executor.py:427`, `phantom/tools/executor.py:499`.
- Sandbox tool server enforces bearer auth with constant-time compare: `phantom/runtime/tool_server.py:85`, `phantom/runtime/tool_server.py:94`.
- Per-request hard timeout is enforced with `asyncio.wait_for(...)`: `phantom/runtime/tool_server.py:152`.

## 1.3 Untrusted input surfaces

- User mission constraints are sanitized before inclusion in task prompt: `phantom/agents/PhantomAgent/phantom_agent.py:103`, `phantom/skills/__init__.py:23`.
- Target-originated tool outputs are re-injected into the next turn as user observation, so output sanitization is a critical boundary: `phantom/tools/executor.py:1286`, `phantom/tools/executor.py:1480`.
- Direct network-facing tools include proxy request/repeat and terminal-driven scanners: `phantom/tools/proxy/proxy_actions.py:50`, `phantom/tools/terminal/terminal_actions.py:7`.

---

## 2) Enforced controls (implemented)

## 2.1 Invocation integrity and schema checks

- Tool name existence is checked against runtime registry: `phantom/tools/executor.py:537`.
- Unknown/missing parameters are rejected using XML-derived schemas: `phantom/tools/executor.py:544`, `phantom/tools/executor.py:555`, `phantom/tools/registry.py:187`.
- Typed argument conversion is enforced before function execution: `phantom/tools/argument_parser.py:19`, `phantom/tools/argument_parser.py:75`.

## 2.2 Transport/authn/time controls for sandbox execution

- Tool server requires bearer token and rejects invalid scheme/token: `phantom/runtime/tool_server.py:86`, `phantom/runtime/tool_server.py:95`.
- Older in-flight task for same `agent_id` is cancelled before new task starts: `phantom/runtime/tool_server.py:146`, `phantom/runtime/tool_server.py:149`.
- Per-agent minimum request interval returns HTTP 429 on bursts: `phantom/runtime/tool_server.py:69`, `phantom/runtime/tool_server.py:78`.

## 2.3 Container and network controls

- Sandbox container starts with explicit capability additions and drops: `phantom/runtime/docker_runtime.py:240`, `phantom/runtime/docker_runtime.py:244`.
- Resource limits are applied (memory/cpu/pids): `phantom/runtime/docker_runtime.py:257`, `phantom/runtime/docker_runtime.py:262`.
- Scope-firewall intent is enabled by default in config, but target-specific runtime enforcement depends on `scan_config` being passed into `create_sandbox(...)`. Current root call path does not pass that argument, so this control is not consistently activated: `phantom/config/config.py:175`, `phantom/agents/base_agent.py:589`, `phantom/runtime/docker_runtime.py:521`, `phantom/runtime/docker_runtime.py:548`.
- Entrypoint also applies egress filtering rules (loopback/DNS/gateway allow, default drop): `containers/docker-entrypoint.sh:213`, `containers/docker-entrypoint.sh:225`.

## 2.4 SSRF protections in proxy manager

- Requests are blocked unless `_is_ssrf_safe(url)` returns true: `phantom/tools/proxy/proxy_manager.py:590`, `phantom/tools/proxy/proxy_manager.py:777`.
- Guard includes private/loopback/link-local checks, encoded IP bypass handling, IPv6 checks, and hostname resolution checks: `phantom/tools/proxy/proxy_manager.py:171`, `phantom/tools/proxy/proxy_manager.py:274`, `phantom/tools/proxy/proxy_manager.py:327`.
- DNS pinning is implemented and verified for rebinding/TOCTOU resistance: `phantom/tools/proxy/proxy_manager.py:52`, `phantom/tools/proxy/proxy_manager.py:78`, `phantom/tools/proxy/proxy_manager.py:322`.

## 2.5 Filesystem/path and data sanitization

- File edit tools enforce `/workspace` boundary and reject traversal: `phantom/tools/file_edit/file_edit_actions.py:13`, `phantom/tools/file_edit/file_edit_actions.py:31`.
- Tool output is semantically sanitized before XML escaping/reinjection: `phantom/tools/executor.py:271`, `phantom/tools/executor.py:1284`, `phantom/tools/executor.py:1289`.
- Telemetry sanitizer redacts sensitive keys/tokens and omits screenshot payloads: `phantom/telemetry/utils.py:27`, `phantom/telemetry/utils.py:81`, `phantom/telemetry/utils.py:97`.

---

## 3) Security controls present but currently soft/disabled

## 3.1 Command/tool-argument injection gate is disabled

- `_validate_tool_argument_injection(...)` returns `None` unconditionally: `phantom/tools/executor.py:238`, `phantom/tools/executor.py:249`.
- Executor still calls this hook, but it cannot block any payload in current implementation: `phantom/tools/executor.py:598`.

## 3.2 Python code safety gate is disabled

- Python safety validator returns `None` for all code: `phantom/tools/python/python_instance.py:22`, `phantom/tools/python/python_instance.py:34`.

## 3.3 RBAC is optional and fail-open on missing module import

- RBAC default config is disabled: `phantom/config/config.py:96`.
- Executor swallows RBAC import failure and allows execution: `phantom/tools/executor.py:383`, `phantom/tools/executor.py:384`.

## 3.4 Prompt-surface minimization is not runtime least privilege

- `phantom_tool_subset` changes prompt schema visibility only: `phantom/llm/llm.py:277`.
- Executor capability check remains registry-based; no run-scoped allowlist is enforced: `phantom/tools/executor.py:537`.

## 3.5 Some detector helpers are implemented but not wired as hard gates

- Prompt-injection detector exists (`_detect_prompt_injection`) but is not used in the execution path: `phantom/tools/executor.py:252`.
- Path traversal helper exists (`_check_path_traversal`) but is not referenced in execution path: `phantom/tools/executor.py:212`.

---

## 4) Unsafe execution and hallucinated command posture

## 4.1 What blocks malformed hallucinated tool calls

- Parser rejects non-conforming tool/param names: `phantom/llm/utils.py:95`, `phantom/llm/utils.py:108`.
- Executor rejects unknown tools/params: `phantom/tools/executor.py:537`, `phantom/tools/executor.py:555`.

## 4.2 What does not block dangerous-but-valid commands

- Disabled injection validator means semantically dangerous command arguments are not blocked at executor layer: `phantom/tools/executor.py:238`, `phantom/tools/executor.py:249`.
- Terminal layer blocks metacharacters in quarantine mode, but this is shell-character filtering rather than policy-level intent validation: `phantom/tools/terminal/terminal_session.py:35`, `phantom/tools/terminal/terminal_session.py:415`.

## 4.3 Isolation is partial by design

- Many tools are explicitly host-local (`sandbox_execution=False`), so not all actions traverse sandbox boundary: examples `phantom/tools/reporting/reporting_actions.py:543`, `phantom/tools/agents_graph/agents_graph_actions.py:265`, `phantom/tools/web_search/web_search_actions.py:193`.

---

## 5) Security model conclusion (implementation truth)

Implemented security posture is mixed:

- Strong points are transport auth/timeouts, SSRF guard depth, workspace path boundaries, and telemetry/output sanitization.
- Weak points are disabled argument/code validators, optional RBAC with fail-open behavior, partial host-local execution, and prompt-only (not runtime) capability minimization.

In current code, the architecture has real boundaries and controls, but not yet a strict fail-closed policy envelope suitable for hardened production expert-system operation.
