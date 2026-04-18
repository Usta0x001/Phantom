# Phantom — Component Graph

## Component Responsibility Matrix

| Component | File(s) | Responsibility | Inputs | Outputs | Hard Constraints |
|---|---|---|---|---|---|
| **PhantomAgent** | `phantom_agent.py` | Entry point; target ingestion | `scan_config` dict | `agent_loop()` call | Max 300 iterations |
| **BaseAgent** | `base_agent.py` | Agent loop, iteration control, state management | `task: str` | `dict[str, Any]` result | asyncio event loop |
| **AgentState** | `state.py` | Persistent in-process state machine | mutations from BaseAgent | Pydantic model (serializable) | SHA-256 message dedup |
| **LLM** | `llm.py` | LLM interaction; streaming; retries; token budget | `messages: list[dict]` | `AsyncIterator[LLMResponse]` | Circuit breaker; rate limiter |
| **MemoryCompressor** | `memory_compressor.py` | Context compression when token limit approached | `messages list` | Compressed `messages list` | Model context ceiling |
| **ToolExecutor** | `executor.py` | Tool dispatch; RBAC; stealth timing; injection check | `tool_name, kwargs` | Any (tool result) | RBAC; sandbox routing |
| **ToolRegistry** | `registry.py` | Tool registration; XML schema loading | `@register_tool` decorator | `get_tool_by_name()` | defusedxml parsing |
| **HypothesisLedger** | `hypothesis_ledger.py` | External memory for vulnerability hypotheses | LLM-triggered tool calls | Scored hypothesis list | Survives compression |
| **CoverageTracker** | `coverage_tracker.py` | Attack surface coverage tracking | Surface+vuln class records | Coverage report | Facts only, no commands |
| **CorrelationEngine** | `correlation_engine.py` | Vulnerability chain detection | Confirmed findings | Chain suggestions | Suggestions only; LLM decides |
| **AttackGraph** | `core/attack_graph.py` | Directed graph of vuln relationships | Findings + chains | Graph metrics | Requires `networkx` |
| **DockerRuntime** | `runtime/docker_runtime.py` | Sandbox lifecycle; tool server URL resolution | Agent config | Sandbox metadata | Docker socket access |
| **AgentsGraphActions** | `tools/agents_graph/` | Agent spawning; inter-agent messaging | `create_agent()` calls | Thread + graph node | One thread per sub-agent |
| **RBAC** | `tools/rbac.py` | Tool permission control | `tool_name` | `(bool, reason)` | Disabled in research mode |
| **AuditLogger** | `logging/audit.py` | Tamper-evident event log | All major events | Append-only log | Best-effort; silent failures |
| **CheckpointManager** | `checkpoint/` | Periodic state persistence | `AgentState` | JSON checkpoint file | Root agent only |
| **Tracer** | `telemetry/tracer.py` | Execution telemetry | All events | Tracing store | Global singleton |

---

## Component Graph (Dependency Direction = "depends on")

```
PhantomAgent
    └─depends─► BaseAgent
                    ├─► AgentState           (owns / mutates)
                    ├─► LLM                  (calls for generation)
                    │     ├─► MemoryCompressor  (pre-request compression)
                    │     └─► litellm           (external API)
                    ├─► HypothesisLedger     (shared external memory)
                    ├─► CoverageTracker      (shared tracking)
                    ├─► CorrelationEngine    (chain detection)
                    ├─► AttackGraph          (optional, networkx)
                    ├─► ToolExecutor         (tool dispatch)
                    │     ├─► ToolRegistry   (lookup)
                    │     ├─► RBAC           (permission gate)
                    │     └─► DockerRuntime  (sandbox RPC)
                    ├─► AgentsGraphActions   (sub-agent spawning)
                    ├─► AuditLogger          (event logging)
                    ├─► CheckpointManager    (state persistence)
                    └─► Tracer              (telemetry)
```

---

## Threading Model (CRITICAL for security analysis)

```
Main Thread (asyncio event loop)
│
├── BaseAgent.agent_loop()           ← async, runs here
│     ├── LLM.generate()             ← async streaming
│     └── process_tool_invocations() ← async tool dispatch
│
└── Sub-agents (one daemon thread per create_agent() call)
      └── agents_graph_actions._run_agent_in_thread()
            └── asyncio.run(sub_agent.agent_loop())  ← NEW event loop per thread
```

**⚠️ Critical observation:** Sub-agents each create their own asyncio event loop in a separate
OS thread. The `HypothesisLedger`, `CoverageTracker`, `CorrelationEngine`, and `AttackGraph`
are shared Python objects between these threads. If these objects use any non-thread-safe
collections (lists, dicts), concurrent writes from parallel sub-agents can corrupt state.

---

## Global Singleton Risk Register

| Singleton | Location | Thread Safety |
|---|---|---|
| `_RBAC_CONTEXT` | `rbac.py:145` | ❌ Global mutable dict, no lock |
| `_GLOBAL_TOTAL_STATS` | `llm.py:88` | ✅ Protected by `_GLOBAL_STATS_LOCK` |
| `_GLOBAL_RATE_LIMIT_UNTIL` | `llm.py:90` | ❌ Bare float, no lock on write path |
| `_CIRCUIT_BREAKER` | `llm.py:478` | ❌ Dataclass, no lock |
| `_agent_graph` / `_agent_messages` | `agents_graph_actions.py` | ✅ Uses `_GRAPH_LOCK` / `_RUNNING_AGENTS_LOCK` |
| Tool cache | `tools/cache.py` | Unknown (not read in depth) |
