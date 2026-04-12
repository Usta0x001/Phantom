# Phantom Failure Modes (Step 11)

## Scope and evidence basis

This report documents failure modes that are directly observable in current implementation, with emphasis on runtime brittleness, scaling limits, coupling risks, and token/efficiency behavior.

Primary anchors:

- Agent loop and tool pipeline: `phantom/agents/base_agent.py:615`, `phantom/agents/base_agent.py:799`, `phantom/tools/executor.py:1441`
- LLM retry/rate-limit/circuit behavior: `phantom/llm/llm.py:336`, `phantom/llm/llm.py:370`, `phantom/llm/llm.py:446`, `phantom/llm/llm.py:1286`
- Memory compression and context controls: `phantom/llm/memory_compressor.py:657`, `phantom/llm/memory_compressor.py:750`, `phantom/llm/memory_compressor.py:752`
- Global/shared state points: `phantom/runtime/__init__.py:15`, `phantom/telemetry/tracer.py:32`, `phantom/tools/agents_graph/agents_graph_actions.py:10`, `phantom/tools/cache.py:383`, `phantom/tools/scan_status/scan_status_actions.py:22`
- Session-scoped manager context: `phantom/tools/context.py:4`, `phantom/runtime/tool_server.py:122`, `phantom/tools/terminal/terminal_manager.py:30`, `phantom/tools/python/python_manager.py:20`
- Checkpoint/resume path: `phantom/checkpoint/checkpoint.py:344`, `phantom/interface/cli.py:266`, `phantom/agents/base_agent.py:914`

---

## 1) Logical and correctness failure modes

## F1) Auto-hypothesis enrichment has conflicting pathways (one active, one inert)

- Active enrichment runs in `_execute_single_tool()` and writes extracted signals to `agent_state.hypothesis_ledger`: `phantom/tools/executor.py:1399`, `phantom/tools/executor.py:1404`.
- Legacy helper `_auto_record_hypothesis()` imports non-existent `_ledger`, so that branch no-ops: `phantom/tools/executor.py:1507`, `phantom/tools/hypothesis/hypothesis_actions.py:84`.
- Result: behavior is partially functional but internally inconsistent, increasing drift risk and confusing root-cause analysis.

## F2) Scan-status recommendation can crash due to type mismatch

- Recommendation code slices `top[:50]` where `top` comes from `get_untested_surfaces()` and is a `DiscoveredSurface` object: `phantom/tools/scan_status/scan_status_actions.py:209`, `phantom/tools/scan_status/scan_status_actions.py:212`, `phantom/agents/coverage_tracker.py:57`.
- Caller catches broadly, which can suppress signal and degrade guidance quality without hard failure: `phantom/agents/base_agent.py:627`, `phantom/agents/base_agent.py:635`.

## F3) Dormant checkpoint support for sub-agent state

- `CheckpointManager.build(...)` supports `active_sub_agents`: `phantom/checkpoint/checkpoint.py:344`.
- Current call site does not pass `active_sub_agents`: `phantom/agents/base_agent.py:914`.
- Resume path stores `_restored_sub_agent_states` in config: `phantom/interface/cli.py:266`.
- No consumption path exists in agents runtime (no matches under `phantom/agents` for `_restored_sub_agent_states`/`active_sub_agents`).

---

## 2) Coupling and state-leak failure modes

## F4) Heavy process-global mutable state increases cross-run contamination risk

- Global runtime singleton: `phantom/runtime/__init__.py:15`.
- Global tracer singleton: `phantom/telemetry/tracer.py:32`.
- Global LLM counters/rate-limiter/circuit breaker: `phantom/llm/llm.py:70`, `phantom/llm/llm.py:72`, `phantom/llm/llm.py:181`.
- Global tool cache: `phantom/tools/cache.py:383` (no production reset callsite found).
- Global agent graph stores and maps: `phantom/tools/agents_graph/agents_graph_actions.py:10`, `phantom/tools/agents_graph/agents_graph_actions.py:24`.
- Global scan-status context pointers: `phantom/tools/scan_status/scan_status_actions.py:22`.

Impact: isolation depends on careful lifecycle cleanup rather than strict run-scoped ownership.

## F5) Agent context var scoping differs by execution path

- Tool-server path explicitly sets `current_agent_id`: `phantom/runtime/tool_server.py:122`.
- Local executor path does not set it before calling tool functions: `phantom/tools/executor.py:515`.
- Terminal/python/browser managers key state by `get_current_agent_id()`: `phantom/tools/terminal/terminal_manager.py:30`, `phantom/tools/python/python_manager.py:20`, `phantom/tools/browser/tab_manager.py:19`.

Impact: in host-local path, tools can fall back to default context and collide across agents/sessions.

## F6) Duplicate session stacks increase inconsistent-auth risk

- Independent process-global stores coexist:
  - `session` tools `_SESSIONS`: `phantom/tools/session/session_actions.py:26`
  - `session_mgmt` tools `_SESSIONS`: `phantom/tools/session_mgmt/session_mgmt_actions.py:31`
  - auth automation caches `_JWT_CACHE`/`_OAUTH_SESSIONS`: `phantom/tools/session_mgmt/auth_automation.py:40`, `phantom/tools/session_mgmt/auth_automation.py:43`

Impact: credentials and auth state can diverge depending on which tool family is used.

---

## 3) Throughput/scaling failure modes

## F7) Single in-flight task per agent on tool server can cancel legitimate parallelism

- New request for same `agent_id` cancels prior task unconditionally: `phantom/runtime/tool_server.py:146`, `phantom/runtime/tool_server.py:149`.

Impact: overlapping tool operations for one agent are non-queueing and cancellation-prone.

## F8) Process-global LLM backoff can cause herd stalls

- Global rate-limit backoff timer shared for all agents: `_GLOBAL_RATE_LIMIT_UNTIL`: `phantom/llm/llm.py:72`, `phantom/llm/llm.py:338`, `phantom/llm/llm.py:446`.

Impact: one model/provider burst can delay unrelated agents in same process.

## F9) Process-global circuit breaker can fail all agents together

- Single `_CIRCUIT_BREAKER` instance for process: `phantom/llm/llm.py:181`.
- Failures record into shared breaker: `phantom/llm/llm.py:1286`.

Impact: repeated failures from one route/agent can trip shared breaker and block unrelated work.

## F10) Compression path can trigger nested-loop/runtime complexity

- `compress_history` may call `asyncio.run(...)` from sync context and relies on `nest_asyncio` fallback when loop already exists: `phantom/llm/memory_compressor.py:752`, `phantom/llm/memory_compressor.py:757`, `phantom/llm/memory_compressor.py:770`.

Impact: async orchestration complexity and dependency on fallback behavior under load.

---

## 4) Token/cost inefficiency and reasoning brittleness

## F11) Prompt-level tool subsetting does not reduce runtime capability risk

- Subsetting only changes visible XML schema prompt: `phantom/llm/llm.py:277`.
- Runtime dispatch still keyed to full registry: `phantom/tools/executor.py:537`.

Impact: token reduction helps cost, but capability safety is not strengthened.

## F12) Large tool outputs remain a major context pressure source

- Even with truncation and extraction logic, tool outputs are appended into next-turn user messages: `phantom/tools/executor.py:1120`, `phantom/tools/executor.py:1480`.
- Auto-summary of tool results is optional by env flag: `phantom/tools/executor.py:938`.

Impact: scans with verbose terminal/browser traffic remain sensitive to context bloat and summarization quality.

## F13) High dependence on injected status summaries for strategy continuity

- Periodic injected synthetic status/ledger/coverage/correlation messages steer reasoning: `phantom/agents/base_agent.py:620`, `phantom/agents/base_agent.py:646`, `phantom/agents/base_agent.py:661`, `phantom/agents/base_agent.py:673`.

Impact: if these injections fail or drift, strategy quality degrades even if core loop remains up.

---

## 5) Operational resilience gaps

## F14) OAST interaction ingestion is incomplete in inspected runtime path

- OAST manager supports `record_interaction(...)`: `phantom/tools/oast/oast_manager.py:168`.
- No callsites found beyond definition (no external ingestion path wired in inspected code).

Impact: blind-vuln workflows can generate payloads but may miss callback evidence ingestion.

## F15) Long-lived allowlists and caches lack explicit per-run reset discipline

- SSRF allowlist and DNS pin caches are module globals: `phantom/tools/proxy/proxy_manager.py:49`, `phantom/tools/proxy/proxy_manager.py:106`.
- Global tool cache persists unless reset function is explicitly called; production path has no clear reset usage: `phantom/tools/cache.py:383`, `phantom/tools/cache.py:394`.

Impact: stale state can bleed across runs in long-lived processes.

---

## Failure-mode conclusion

Current implementation is functional but exhibits production-critical brittleness around global state coupling, partial context scoping, non-wired resilience hooks, and shared-fate control primitives (global rate limiter/circuit breaker). These are not theoretical risks; they are direct consequences of present call paths and ownership boundaries.
