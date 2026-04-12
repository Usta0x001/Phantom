# Phantom Layered Breakdown (Step 3)

## Scope and Evidence Basis

This breakdown is reconstructed from executable code paths and runtime wiring, not intended design claims.

Primary anchors used:

- Interface and startup: `phantom/interface/cli_app.py:130`, `phantom/interface/main.py:523`, `phantom/interface/cli.py:46`, `phantom/interface/tui.py:2221`
- Agent orchestration: `phantom/agents/PhantomAgent/phantom_agent.py:23`, `phantom/agents/base_agent.py:247`, `phantom/tools/agents_graph/agents_graph_actions.py:265`
- Reasoning/AI: `phantom/llm/llm.py:209`, `phantom/llm/llm.py:333`, `phantom/llm/memory_compressor.py:608`, `phantom/llm/utils.py:81`
- Execution and runtime: `phantom/tools/executor.py:364`, `phantom/tools/executor.py:579`, `phantom/tools/executor.py:1441`, `phantom/runtime/docker_runtime.py:521`, `phantom/runtime/tool_server.py:137`
- Memory and recovery: `phantom/agents/state.py:13`, `phantom/checkpoint/checkpoint.py:134`, `phantom/checkpoint/models.py:10`
- Monitoring/logging: `phantom/telemetry/tracer.py:47`, `phantom/telemetry/tracer.py:711`, `phantom/logging/audit.py:81`

---

## 1) Interface Layer (CLI, API, UI)

### Responsibilities

- Accept operator intent (targets, mode, profile, auth headers, resume flags).
- Validate and normalize user input into runtime-ready structures.
- Perform preflight checks (Docker, env, model warm-up), then launch scan loop.
- Present runtime progress and completion status (CLI/TUI, quiet/json modes).

### Internal components

- Typer command surface: `scan(...)` and CLI options in `phantom/interface/cli_app.py:130`.
- Startup/preflight + warm-up pipeline in `phantom/interface/main.py:50` and `phantom/interface/main.py:207`.
- Non-interactive execution path in `phantom/interface/cli.py:46`.
- Interactive Textual UI path in `phantom/interface/tui.py:2221`.
- Target inference and workspace mapping in `phantom/interface/utils.py:565` and `phantom/interface/utils.py:662`.

### Inputs / Outputs

- Inputs:
  - CLI args and flags (`--target`, `--scan-mode`, `--profile`, `--resume`, etc.) from `phantom/interface/cli_app.py:132`.
  - Instruction text/file and environment-backed config.
- Outputs:
  - Normalized `targets_info`, run metadata, and `scan_config` handed to orchestration (`phantom/interface/cli.py:232`).
  - Operator-facing output (panels, stream updates, exit code behavior) in `phantom/interface/cli.py:207` and `phantom/interface/cli_app.py:413`.

### Dependencies

- Config/state bootstrap: `phantom/config/config.py:32`.
- Docker and runtime readiness checks via `phantom/interface/main.py:532`.
- Orchestration handoff to `run_cli/run_tui` and then `PhantomAgent` (`phantom/interface/cli_app.py:444`, `phantom/interface/cli.py:15`).

---

## 2) Orchestration Layer

### Responsibilities

- Construct root mission task from multi-target scan context.
- Execute the iterative control loop (iteration caps, stop/wait states, error handling).
- Coordinate sub-agent creation, communication, and completion.
- Trigger periodic checkpoint persistence for resumability.

### Internal components

- Root agent task builder: `PhantomAgent.execute_scan()` in `phantom/agents/PhantomAgent/phantom_agent.py:23`.
- Core loop and lifecycle control: `BaseAgent.agent_loop()` in `phantom/agents/base_agent.py:247`.
- Action execution bridge: `_execute_actions()` in `phantom/agents/base_agent.py:757`.
- Sub-agent graph/message bus globals and tooling in `phantom/tools/agents_graph/agents_graph_actions.py:10`, `phantom/tools/agents_graph/agents_graph_actions.py:24`, `phantom/tools/agents_graph/agents_graph_actions.py:265`.
- Periodic checkpoint hook: `phantom/agents/base_agent.py:901`.

### Inputs / Outputs

- Inputs:
  - Normalized `scan_config` and user mission constraints from Interface Layer.
  - Agent state, tool observations, and inter-agent messages (`phantom/agents/base_agent.py:833`).
- Outputs:
  - LLM calls via Reasoning Layer (`phantom/agents/base_agent.py:691`).
  - Tool invocation batches into Execution Layer (`phantom/agents/base_agent.py:799`).
  - Final completion state and checkpoint snapshots.

### Dependencies

- Reasoning/AI (`phantom/llm/llm.py:333`).
- Execution fabric (`phantom/tools/executor.py:1441`).
- Runtime bootstrap for sandbox (`phantom/agents/base_agent.py:581`).
- Memory systems (`HypothesisLedger`, `CoverageTracker`, `CorrelationEngine`, `AttackGraph`) in `phantom/agents/base_agent.py:100`.

---

## 3) Reasoning / AI Layer

### Responsibilities

- Build system prompt and tool schema context.
- Execute model requests with retries, rate-limit handling, and circuit-breaker logic.
- Parse and normalize structured tool invocations from model output.
- Compress long context to stay within model limits.

### Internal components

- `LLM` client wrapper and request pipeline in `phantom/llm/llm.py:209` and `phantom/llm/llm.py:333`.
- Prompt construction and dynamic tool-schema selection in `phantom/llm/llm.py:258` and `phantom/llm/llm.py:277`.
- Tool-call parsing and normalization in `phantom/llm/utils.py:12` and `phantom/llm/utils.py:81`.
- Memory compression engine in `phantom/llm/memory_compressor.py:608` and `phantom/llm/memory_compressor.py:657`.
- LLM configuration resolver in `phantom/llm/config.py:8`.

### Inputs / Outputs

- Inputs:
  - Conversation history from `AgentState` (`phantom/agents/state.py:252`).
  - Tool schemas from registry/dynamic subset (`phantom/tools/dynamic_tools.py:204`).
- Outputs:
  - `LLMResponse` content + parsed tool invocations to orchestration (`phantom/llm/llm.py:582`).
  - Budget/usage stats stored in global counters (`phantom/llm/llm.py:70`).

### Dependencies

- External model providers through LiteLLM (`phantom/llm/llm.py:10`).
- Skills and prompt resources (`phantom/llm/llm.py:27`, `phantom/utils/resource_paths.py`).
- Tool registry prompt generation (`phantom/tools/registry.py:240`).

---

## 4) Execution Layer (tools, exploits, scanners)

### Responsibilities

- Register capabilities as tools and expose schemas to the model.
- Validate tool availability/arguments, enforce RBAC, dispatch execution.
- Execute actions either locally or through sandbox RPC.
- Convert tool results to observations and feed back into agent loop.

### Internal components

- Tool registration and schema loading: `phantom/tools/registry.py:152`.
- Tool module loading by mode: `phantom/tools/__init__.py:31`.
- Validation + dispatch pipeline: `phantom/tools/executor.py:579`, `phantom/tools/executor.py:364`, `phantom/tools/executor.py:427`.
- Invocation batching and observation append: `phantom/tools/executor.py:1441`, `phantom/tools/executor.py:1476`.
- Capability managers:
  - Proxy/web requests: `phantom/tools/proxy/proxy_actions.py:50`, SSRF guard in `phantom/tools/proxy/proxy_manager.py:150`.
  - Terminal sessions: `phantom/tools/terminal/terminal_manager.py:12`.
  - Python sessions: `phantom/tools/python/python_manager.py:11`.
  - Browser sessions: `phantom/tools/browser/tab_manager.py:11`.
  - Parallel fuzzing/OAST: `phantom/tools/fuzzer/fuzzer_manager.py:63`, `phantom/tools/oast/oast_manager.py:58`.
- Completion gate: `phantom/tools/finish/finish_actions.py:95`.

### Inputs / Outputs

- Inputs:
  - Tool invocation list from Reasoning Layer (`toolName`, args) parsed in `phantom/llm/utils.py:81`.
  - Agent and sandbox context (agent_id, sandbox token/ports).
- Outputs:
  - Tool results/errors and structured observation text into conversation history (`phantom/tools/executor.py:1480`).
  - Side effects on target systems via HTTP, browser, terminal/scanner commands.

### Dependencies

- RBAC policy checks in `phantom/tools/rbac.py:196` and executor integration `phantom/tools/executor.py:377`.
- Runtime layer for sandbox routing (`phantom/runtime/__init__.py:18`).
- Third-party binaries and libraries inside sandbox/local environment (nmap/nuclei/sqlmap, requests/httpx, browser engine).

---

## 5) Memory Layer (state, history, knowledge)

### Responsibilities

- Maintain per-agent mutable execution state across iterations.
- Persist structured knowledge outside chat history to survive compression.
- Provide resumable durable state (checkpoint + HMAC + optional encryption).
- Supply compact strategic summaries back into prompt context.

### Internal components

- Core state model: `AgentState` in `phantom/agents/state.py:13`.
- Knowledge stores:
  - Hypothesis ledger: `phantom/agents/hypothesis_ledger.py:58`.
  - Coverage tracker: `phantom/agents/coverage_tracker.py:84`.
  - Correlation engine: `phantom/agents/correlation_engine.py:163`.
  - Attack graph: `phantom/core/attack_graph.py:97`.
- Unified status summarization: `phantom/tools/scan_status/scan_status_actions.py:50`.
- Durable checkpoint persistence: `CheckpointManager` in `phantom/checkpoint/checkpoint.py:134`, schema in `phantom/checkpoint/models.py:10`.

### Inputs / Outputs

- Inputs:
  - Tool outcomes and observations from Execution Layer.
  - Iteration metadata and agent actions from Orchestration Layer.
- Outputs:
  - Prompt injections for strategy steering (`phantom/agents/base_agent.py:646`, `phantom/agents/base_agent.py:661`, `phantom/agents/base_agent.py:673`).
  - Checkpoint artifacts for resume (`checkpoint.json`, `.hmac`) via `phantom/checkpoint/checkpoint.py:210`.

### Dependencies

- Pydantic/dataclass serialization for in-memory and checkpoint models.
- Tracer snapshots (vulns/stats) included during checkpoint build (`phantom/checkpoint/checkpoint.py:353`).
- Global/shared registries used by tools (`phantom/tools/hypothesis/hypothesis_actions.py:27`, `phantom/tools/scan_status/scan_status_actions.py:22`).

---

## 6) Integration Layer (external services, APIs)

### Responsibilities

- Connect Phantom to external systems (LLM endpoints, Docker, OSINT APIs, Git repos).
- Resolve credentials and secure secret material retrieval.
- Normalize external responses into internal data structures.

### Internal components

- Config resolution and environment precedence in `phantom/config/config.py:32` and `phantom/config/config.py:384`.
- Secure secret storage/keyring fallback in `phantom/config/secrets.py:234`.
- Docker daemon integration in `phantom/runtime/docker_runtime.py:67`.
- External passive intelligence connectors:
  - crt.sh: `phantom/tools/osint/osint_actions.py:165`
  - Shodan: `phantom/tools/osint/osint_actions.py:335`
  - Whois/XML + API Ninjas: `phantom/tools/osint/osint_actions.py:507`, `phantom/tools/osint/osint_actions.py:531`
  - GitHub search API: `phantom/tools/osint/osint_actions.py:765`
  - NVD CVE feed: `phantom/tools/payload_gen/payload_gen_actions.py:462`
- Repository clone via Git subprocess: `phantom/interface/utils.py:776`.

### Inputs / Outputs

- Inputs:
  - API keys/base URLs and runtime credentials from config/secrets.
  - External target descriptors (URLs/domains/repos).
- Outputs:
  - Remote API data and cloned codebases consumed by Execution/Memory layers.
  - Runtime handles and endpoints (container IDs, tool server URLs).

### Dependencies

- External infrastructure: Docker daemon, model providers, OSINT APIs, Git hosting.
- Local platform services: OS keyring, filesystem permissions, subprocess environment.

---

## 7) Monitoring / Logging Layer

### Responsibilities

- Capture run-time observability across agents, tools, and LLM traffic.
- Persist durable scan artifacts and event streams.
- Provide audit trail for debugging, replay, and governance.

### Internal components

- Global tracer + event emitter: `Tracer` in `phantom/telemetry/tracer.py:47`.
- Artifact persistence path: `save_run_data()` in `phantom/telemetry/tracer.py:711`.
- Structured audit subsystem: `AuditLogger` in `phantom/logging/audit.py:81`.
- Telemetry feature flag: `phantom/telemetry/flags.py:1` (currently hard-disabled OTEL path).

### Inputs / Outputs

- Inputs:
  - Agent lifecycle events (`phantom/agents/base_agent.py:297`).
  - Tool execution events (`phantom/tools/executor.py:401`).
  - LLM request/response/error events (`phantom/llm/llm.py:494`, `phantom/llm/llm.py:568`).
- Outputs:
  - `events.jsonl`, `scan_stats.json`, `vulnerabilities/*.md`, `vulnerabilities.csv`, `penetration_test_report.md` from `phantom/telemetry/tracer.py:721` and `phantom/telemetry/tracer.py:871`.
  - Optional `audit.jsonl` and `audit.log` from `phantom/logging/audit.py:107`.

### Dependencies

- Local filesystem and run directory management (`phantom/telemetry/tracer.py:308`).
- Optional OpenTelemetry/Traceloop plumbing (wired but effectively off under current flag behavior).

---

## Cross-Layer Dependency Spine

`Interface` -> `Orchestration` -> `Reasoning/AI` -> `Execution` -> `Memory` (feedback) -> `Monitoring`

`Integration` is orthogonal and feeds both `Reasoning/AI` (LLM endpoints) and `Execution` (Docker, scanners, external APIs).

This completes Step 3 (Layered Breakdown) with code-grounded responsibilities, component mapping, IO surfaces, and dependency tracing.
