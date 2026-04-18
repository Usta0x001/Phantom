# Phantom — System Overview (Code-Grounded)

## 1. What Phantom Actually Is

Phantom is an **LLM-orchestrated, multi-agent penetration testing system** that uses an iterative
thought-act-observe loop to autonomously discover and prove web application vulnerabilities. It is
NOT a description-based scanner; its intelligence is entirely provided by an external large language
model called through the `litellm` abstraction layer.

**Entry point** (`PhantomAgent.execute_scan`) receives a `scan_config` dict containing target
descriptors (`web_application`, `repository`, `local_code`, `ip_address`). It builds a natural-
language task string and calls `agent_loop(task)` in `BaseAgent`.

**Key claim (validated):**  
The system is architecturally a *reactive tool-use loop* wrapped around an external LLM;
"autonomous" here means "unattended iteration until a stop condition", not "deterministic
planning".

---

## 2. Physical Code Layout (Verified)

```
phantom/
├── agents/
│   ├── base_agent.py          # Core loop (1421 lines) — THE engine
│   ├── state.py               # AgentState pydantic model
│   ├── hypothesis_ledger.py   # External memory for hypotheses
│   ├── coverage_tracker.py    # Attack surface coverage
│   ├── correlation_engine.py  # Vulnerability chain suggestions
│   └── PhantomAgent/
│       ├── phantom_agent.py   # Root agent (thin wrapper, 115 lines)
│       └── system_prompt.jinja  # 827-line system prompt template
├── llm/
│   ├── llm.py                 # LLM wrapper, 1870 lines (streaming, retries,
│   │                            circuit breaker, budget tracking)
│   ├── memory_compressor.py   # Context compression (1075 lines)
│   ├── dedupe.py              # Tool call deduplication
│   └── config.py              # LLMConfig
├── tools/
│   ├── executor.py            # Tool dispatch (1919 lines)
│   ├── registry.py            # Tool registry + XML schema loader
│   ├── rbac.py                # Role-based access control
│   ├── dynamic_tools.py       # Tool subset selection
│   └── <28 tool subdirs>      # One module per tool category
├── config/
│   └── config.py              # Phantom config + secrets
├── runtime/
│   └── docker_runtime.py      # Docker sandbox management
└── checkpoint/                # Checkpoint save/restore
```

---

## 3. Core Dependencies (Verified from imports)

| Dependency | Role |
|---|---|
| `litellm` | LLM API abstraction (all model calls go through this) |
| `jinja2` | System prompt templating |
| `pydantic` | `AgentState` serialization / deserialization |
| `httpx` | HTTP client for sandbox RPC calls |
| `defusedxml` | Safe XML parsing for tool schemas |
| `asyncio` | All agent loops and tool calls are async |
| `threading` | Sub-agents run in daemon threads (NOT coroutines) |
| `networkx` | Optional; `AttackGraph` if installed |

---

## 4. Validated System Claims vs. Evidence

| Claim | Evidence | Status |
|---|---|---|
| "Autonomous" agent | Reactive loop with LLM decisions; no symbolic planner | ⚠️ Partially true — reactive, not autonomous in formal sense |
| "Multi-agent tree" | `create_agent` → thread per sub-agent | ✅ Confirmed |
| "Hypothesis-driven testing" | `HypothesisLedger` is real, LLM must explicitly call ledger tools | ✅ Confirmed but depends on LLM compliance |
| "Memory compression" | `MemoryCompressor` with LLM-generated summaries | ✅ Confirmed |
| "Prompt injection protection" | Regex-based output sanitizer + system prompt rules | ⚠️ Partial — regex bypassable |
| "RBAC" | `rbac.py` exists but defaults to `SENIOR_PENTESTER`; disabled in research mode | ⚠️ Effectively not enforced in default config |
| "Sandbox isolation" | Docker runtime; tool calls go over HTTP RPC | ✅ Confirmed |
| "Circuit breaker" | `CircuitBreaker` class in `llm.py` | ✅ Confirmed |
