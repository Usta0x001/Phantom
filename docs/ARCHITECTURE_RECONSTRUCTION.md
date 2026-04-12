# Phantom Architecture Reconstruction (Step 2)

## Scope and Evidence Basis

This architecture is reconstructed from executable code paths and runtime wiring, not intended design claims.

Primary evidence anchors:

- Entry and orchestration: `phantom/interface/cli_app.py:130`, `phantom/interface/main.py:523`, `phantom/interface/cli.py:46`
- Root execution loop: `phantom/agents/PhantomAgent/phantom_agent.py:23`, `phantom/agents/base_agent.py:247`
- LLM mediation and context lifecycle: `phantom/llm/llm.py:333`, `phantom/llm/memory_compressor.py:608`
- Tool pipeline and dispatch: `phantom/tools/executor.py:364`, `phantom/tools/executor.py:1441`
- Runtime boundary: `phantom/runtime/docker_runtime.py:521`, `phantom/runtime/tool_server.py:137`
- Persistence and recovery: `phantom/telemetry/tracer.py:711`, `phantom/checkpoint/checkpoint.py:210`, `phantom/logging/audit.py:69`

Legend:

- [E] explicit code component
- [I] implicit runtime component (global/singleton/process-wide state)
- [M] inferred missing abstraction (derived from coupling/repetition hotspots)

---

## Hierarchical Architecture (Layers)

### Layer 0 - Operator and Interface Surface

- [E] CLI command boundary (`scan`, `config`, `report`) via Typer: `phantom/interface/cli_app.py:130`
- [E] Startup/preflight path (Docker, env validation, LLM warmup): `phantom/interface/main.py:523`
- [E] Execution UIs: non-interactive CLI loop and Textual TUI loop: `phantom/interface/cli.py:46`, `phantom/interface/tui.py:32`
- Responsibility: collect mission input, normalize targets, choose run mode, then hand off to root agent.

### Layer 1 - Run Context and Configuration Assembly

- [E] Target typing and workspace mapping: `phantom/interface/utils.py:565`, `phantom/interface/utils.py:662`
- [E] Profile presets and scan-mode tuning: `phantom/core/scan_profiles.py:29`
- [E] Configuration resolution and env precedence: `phantom/config/config.py:32`, `phantom/config/config.py:222`, `phantom/config/config.py:384`
- [E] Secrets storage path (keyring/encrypted file fallback): `phantom/config/secrets.py:234`
- Responsibility: turn user intent into normalized `scan_config` and `agent_config` objects.

### Layer 2 - Agent Orchestration and Execution Control

- [E] Root agent task construction from mixed targets and mission constraints: `phantom/agents/PhantomAgent/phantom_agent.py:23`
- [E] Iterative control loop (iteration gating, stop conditions, warnings, error handling): `phantom/agents/base_agent.py:247`
- [E] Agent state object (messages, iterations, sandbox refs, anchors): `phantom/agents/state.py:13`
- [E] Checkpoint hook in loop: `phantom/agents/base_agent.py:901`
- [I] Process-wide agent graph, message queues, and instance registries: `phantom/tools/agents_graph/agents_graph_actions.py:10`, `phantom/tools/agents_graph/agents_graph_actions.py:24`, `phantom/tools/agents_graph/agents_graph_actions.py:28`
- Responsibility: run the autonomous loop and coordinate sub-agents.

### Layer 3 - LLM Mediation and Context Engineering

- [E] LLM request/stream/retry pipeline: `phantom/llm/llm.py:333`, `phantom/llm/llm.py:482`
- [E] Prompt construction with skill loading and tool-schema rendering: `phantom/llm/llm.py:258`, `phantom/llm/llm.py:277`
- [E] Memory compression and context reduction policy: `phantom/llm/memory_compressor.py:608`
- [E] Tool-call XML normalization/parsing: `phantom/llm/utils.py:12`, `phantom/llm/utils.py:81`
- [I] Global LLM budget/rate/circuit state: `phantom/llm/llm.py:70`, `phantom/llm/llm.py:72`, `phantom/llm/llm.py:181`
- Responsibility: translate agent state into model calls and recover structured tool intents.

### Layer 4 - Tool Fabric (Registry, Policy, Dispatch)

- [E] Tool registration and schema loading by module: `phantom/tools/registry.py:152`
- [E] Mode-driven tool imports and registration: `phantom/tools/__init__.py:31`
- [E] Invocation pipeline (validate -> execute -> format observation): `phantom/tools/executor.py:579`, `phantom/tools/executor.py:1441`
- [E] RBAC policy check in execution path: `phantom/tools/executor.py:377`, `phantom/tools/rbac.py:196`
- [E] Prompt-level dynamic tool subset generation: `phantom/tools/dynamic_tools.py:86`, `phantom/tools/dynamic_tools.py:204`
- [I] Process-wide tool-result cache singleton: `phantom/tools/cache.py:383`
- [I] Agent context propagation via `ContextVar`: `phantom/tools/context.py:4`
- Responsibility: expose capabilities to the model while enforcing execution mechanics and policy checks.

### Layer 5 - Capability Providers (Tool Modules and Managers)

- [E] HTTP/proxy capability with SSRF and DNS pinning checks: `phantom/tools/proxy/proxy_manager.py:150`, `phantom/tools/proxy/proxy_manager.py:322`
- [E] Terminal manager with per-agent sessions: `phantom/tools/terminal/terminal_manager.py:12`
- [E] Python execution manager with per-agent sessions: `phantom/tools/python/python_manager.py:11`
- [E] Browser tab manager with per-agent browser instances: `phantom/tools/browser/tab_manager.py:11`
- [E] OAST and fuzzer managers as parallel execution helpers: `phantom/tools/oast/oast_manager.py:58`, `phantom/tools/fuzzer/fuzzer_manager.py:63`
- [E] Scan-completion gate and finalization tool: `phantom/tools/finish/finish_actions.py:95`
- [I] Manager singletons (proxy/terminal/python/browser/fuzzer/oast) created at module scope, e.g. `phantom/tools/proxy/proxy_manager.py:1202`, `phantom/tools/terminal/terminal_manager.py:177`, `phantom/tools/python/python_manager.py:145`, `phantom/tools/browser/tab_manager.py:435`
- Responsibility: perform concrete operations requested by dispatcher.

### Layer 6 - Runtime and Sandbox Boundary

- [E] Runtime backend selector and global runtime singleton: `phantom/runtime/__init__.py:15`, `phantom/runtime/__init__.py:18`
- [E] Docker sandbox lifecycle (container, ports, token, source copy, cleanup): `phantom/runtime/docker_runtime.py:201`, `phantom/runtime/docker_runtime.py:521`, `phantom/runtime/docker_runtime.py:630`
- [E] In-container tool server (auth, rate-limit, execution endpoint): `phantom/runtime/tool_server.py:85`, `phantom/runtime/tool_server.py:137`
- [E] Host-to-sandbox invocation with bearer token over HTTP: `phantom/tools/executor.py:457`, `phantom/tools/executor.py:487`
- Responsibility: isolate execution plane and provide authenticated tool RPC.

### Layer 7 - Persistence, Telemetry, Audit, and Recovery

- [E] Run tracer and artifact writer (`events.jsonl`, reports, vulnerability files): `phantom/telemetry/tracer.py:47`, `phantom/telemetry/tracer.py:711`, `phantom/telemetry/tracer.py:733`
- [E] Audit logger with structured event taxonomy: `phantom/logging/audit.py:81`
- [E] Checkpoint manager with atomic writes, HMAC validation, optional encryption: `phantom/checkpoint/checkpoint.py:210`, `phantom/checkpoint/checkpoint.py:255`
- [I] Global tracer singleton used across layers: `phantom/telemetry/tracer.py:32`
- [I] OTEL is effectively disabled in current code path: `phantom/telemetry/flags.py:1`
- Responsibility: preserve run history, support resume, and make execution observable.

### Layer 8 - Domain State and Analysis Models

- [E] Scan and vulnerability models: `phantom/models/scan.py:29`, `phantom/models/vulnerability.py:28`, `phantom/models/host.py:9`
- [E] Structured hypothesis, coverage, and correlation state: `phantom/agents/hypothesis_ledger.py:58`, `phantom/agents/coverage_tracker.py:84`, `phantom/agents/correlation_engine.py:163`
- [E] Attack graph model and analytics: `phantom/core/attack_graph.py:97`
- [E] Unified scan status synthesis tool: `phantom/tools/scan_status/scan_status_actions.py:50`
- Responsibility: represent security findings and test coverage in machine-usable structures.

---

## Component Interaction Map (textual)

### A) Primary end-to-end control flow

`Operator`  
-> `CLI command surface` (`phantom/interface/cli_app.py:130`)  
-> `run_cli/run_tui` (`phantom/interface/cli.py:46`, `phantom/interface/tui.py:32`)  
-> `PhantomAgent.execute_scan()` (`phantom/agents/PhantomAgent/phantom_agent.py:23`)  
-> `BaseAgent.agent_loop()` (`phantom/agents/base_agent.py:247`)  
-> `LLM.generate()` (`phantom/llm/llm.py:333`)  
-> `parse_tool_invocations()` (`phantom/llm/utils.py:81`)  
-> `process_tool_invocations()` (`phantom/tools/executor.py:1441`)  
-> `execute_tool_with_validation()` (`phantom/tools/executor.py:579`)  
-> `(local manager call OR sandbox RPC)` (`phantom/tools/executor.py:427`, `phantom/tools/executor.py:457`)  
-> `tool result formatted into observation XML` (`phantom/tools/executor.py:1286`)  
-> `observation appended to conversation history` (`phantom/tools/executor.py:1476`)  
-> loop back to `LLM.generate()` until finish condition.

### B) Sandbox execution path (host -> isolated runtime)

`BaseAgent._initialize_sandbox_and_state()` requests sandbox (`phantom/agents/base_agent.py:581`)  
-> `runtime.get_runtime()` singleton lookup (`phantom/runtime/__init__.py:18`)  
-> `DockerRuntime.create_sandbox()` allocates container + token + ports (`phantom/runtime/docker_runtime.py:521`)  
-> Executor posts `tool_name/kwargs` with bearer token to `/execute` (`phantom/tools/executor.py:487`)  
-> Tool server verifies token constant-time (`phantom/runtime/tool_server.py:85`, `phantom/runtime/tool_server.py:94`)  
-> Tool server executes tool function and returns JSON result (`phantom/runtime/tool_server.py:115`, `phantom/runtime/tool_server.py:151`).

### C) Sub-agent delegation and inter-agent messaging

`create_agent` tool creates child state/thread (`phantom/tools/agents_graph/agents_graph_actions.py:265`, `phantom/tools/agents_graph/agents_graph_actions.py:488`)  
-> child runs its own `BaseAgent.agent_loop()` via thread event loop (`phantom/tools/agents_graph/agents_graph_actions.py:145`)  
-> parent/child messages pass through `_agent_messages` queue (`phantom/tools/agents_graph/agents_graph_actions.py:24`, `phantom/tools/agents_graph/agents_graph_actions.py:551`)  
-> parent consumes messages in `_check_agent_messages()` (`phantom/agents/base_agent.py:833`)  
-> child completion reported via `agent_finish` (`phantom/tools/agents_graph/agents_graph_actions.py:609`).

### D) State enrichment and strategy feedback loops

At iteration boundaries, agent injects compact state summaries into prompt:

- `scan_status` snapshot (`phantom/agents/base_agent.py:620`, `phantom/tools/scan_status/scan_status_actions.py:50`)
- hypothesis ledger summary (`phantom/agents/base_agent.py:637`)
- coverage summary (`phantom/agents/base_agent.py:653`)
- correlation/chain summary (`phantom/agents/base_agent.py:665`)

This forms a closed control loop: tool outcomes -> structured state stores -> compact prompt injections -> next model decision.

### E) Reporting and run finalization

`create_vulnerability_report` updates tracer findings set (through reporting path, persisted by tracer)  
-> `finish_scan` validates root-agent ownership and active-agent quiescence (`phantom/tools/finish/finish_actions.py:9`, `phantom/tools/finish/finish_actions.py:20`)  
-> `tracer.update_scan_final_fields()` and `save_run_data()` write final artifacts (`phantom/telemetry/tracer.py:467`, `phantom/telemetry/tracer.py:711`).

### F) Checkpoint and resume interaction map

`BaseAgent._maybe_save_checkpoint()` builds and saves checkpoint periodically (`phantom/agents/base_agent.py:901`)  
-> `CheckpointManager.build()` captures root state + derived subsystems (`phantom/checkpoint/checkpoint.py:332`)  
-> `CheckpointManager.save()` writes checkpoint atomically + HMAC (`phantom/checkpoint/checkpoint.py:210`, `phantom/checkpoint/checkpoint.py:233`)  
-> resume path in CLI restores state, ledger, coverage, correlation, attack graph (`phantom/interface/cli.py:62`, `phantom/interface/cli.py:101`, `phantom/interface/cli.py:135`).

### G) Trust and policy enforcement points in interactions

- LLM output is authoritative for tool intents, then passed to executor validation: `phantom/llm/utils.py:81`, `phantom/tools/executor.py:579`
- RBAC gate before tool execution: `phantom/tools/executor.py:377`, `phantom/tools/rbac.py:196`
- SSRF scope checks before outbound proxy requests: `phantom/tools/proxy/proxy_manager.py:150`
- Sandbox bearer-token auth for host-to-container tool RPC: `phantom/runtime/tool_server.py:85`
- Checkpoint integrity verification on load: `phantom/checkpoint/checkpoint.py:255`

---

## Explicit + Implicit + Inferred Components

### Explicit components (implemented directly)

- CLI/TUI interface stack
- Root and sub-agent execution loops
- LLM wrapper with retries/compression/routing
- Tool registry and executor pipeline
- Tool module managers (proxy, terminal, browser, python, oast, fuzzer)
- Docker runtime and in-sandbox tool server
- Tracer, audit logger, checkpoint manager
- Domain models and attack-graph analysis

### Implicit components (emerge from module-level state)

- Global runtime singleton (`phantom/runtime/__init__.py:15`)
- Global tracer singleton (`phantom/telemetry/tracer.py:32`)
- Global agent-graph and message bus (`phantom/tools/agents_graph/agents_graph_actions.py:10`, `phantom/tools/agents_graph/agents_graph_actions.py:24`)
- Global cache (`phantom/tools/cache.py:383`)
- Global tool context variable for per-agent session partitioning (`phantom/tools/context.py:4`)

### Inferred missing abstractions [M]

- [M] `RunContextService` to unify process-wide state ownership (runtime, tracer, agent graph, ledgers) and reduce global coupling.
  - Rationale: many cross-layer globals currently coordinate implicitly.
- [M] `UnifiedSessionStore` to merge overlapping session mechanisms in `session_actions` and `session_mgmt_actions`.
  - Evidence of overlap: `phantom/tools/session/session_actions.py:26` and `phantom/tools/session_mgmt/session_mgmt_actions.py:31`.
- [M] `PolicyEngine` to centralize RBAC, SSRF, scope enforcement, and output sanitization policies.
  - Current controls are distributed across executor, proxy manager, runtime firewall, and tool server.
- [M] `CapabilityContract` for hard runtime tool-scoping, not only prompt-level schema subset.
  - Evidence: dynamic tooling currently shapes prompt schemas (`phantom/tools/dynamic_tools.py:204`) while full registry exists in process.

---

## Architecture Reconstruction Statement

Phantom is a layered host orchestrator where the root agent loop is the control core, the LLM is the decision core, the tool fabric is the execution router, and Docker sandbox/tool-server forms the isolation boundary. The system relies heavily on process-wide implicit state and singleton registries, which function as de facto infrastructure components and should be treated as first-class architecture elements in future hardening and refactoring.
