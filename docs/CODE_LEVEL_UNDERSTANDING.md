# Phantom Code-Level Understanding (Step 5)

## Scope and Evidence Basis

This report is a code-grounded reconstruction of how Phantom actually behaves at runtime.
It focuses on **logic and intent**, not file inventory.

Primary anchors used:

- Control plane: `phantom/interface/cli_app.py:131`, `phantom/interface/cli.py:46`, `phantom/interface/main.py:50`, `phantom/interface/utils.py:565`
- Agent control core: `phantom/agents/PhantomAgent/phantom_agent.py:23`, `phantom/agents/base_agent.py:247`, `phantom/agents/state.py:13`
- Reasoning/context pipeline: `phantom/llm/llm.py:258`, `phantom/llm/llm.py:333`, `phantom/llm/llm.py:588`, `phantom/llm/memory_compressor.py:657`, `phantom/llm/utils.py:81`
- Tool fabric and policy path: `phantom/tools/registry.py:152`, `phantom/tools/executor.py:579`, `phantom/tools/executor.py:1441`, `phantom/tools/rbac.py:196`, `phantom/tools/context.py:4`
- Runtime boundary: `phantom/runtime/__init__.py:18`, `phantom/runtime/docker_runtime.py:521`, `phantom/runtime/tool_server.py:137`
- Persistence and telemetry: `phantom/checkpoint/checkpoint.py:210`, `phantom/checkpoint/checkpoint.py:333`, `phantom/telemetry/tracer.py:47`, `phantom/telemetry/tracer.py:711`
- Analysis state models: `phantom/core/attack_graph.py:97`, `phantom/agents/hypothesis_ledger.py:58`, `phantom/agents/coverage_tracker.py:84`, `phantom/agents/correlation_engine.py:163`, `phantom/models/vulnerability.py:28`

---

## 1) Control Plane Intent (How a scan request is transformed)

### `phantom/interface/cli_app.py`

Intent: act as the **operator-facing command router** and normalize many UX paths into one execution pipeline.

What it does in practice:

- Accepts rich scan controls (`scan`, `resume`, `resumes`, `report`, `cleanup`, `diff`) and profile-driven presets (`phantom/interface/cli_app.py:131`, `phantom/interface/cli_app.py:265`, `phantom/interface/cli_app.py:517`, `phantom/interface/cli_app.py:1145`, `phantom/interface/cli_app.py:1457`).
- Converts Typer options into a legacy argparse namespace for backward compatibility with existing execution logic (`phantom/interface/cli_app.py:302`).
- Applies deterministic run preprocessing: target typing, workspace subdirs, localhost rewrite, config precedence, Docker/env preflight (`phantom/interface/cli_app.py:381`, `phantom/interface/cli_app.py:396`, `phantom/interface/cli_app.py:399`).
- Runs async warm-up and scan dispatch in one loop, including repo cloning and local-source gathering (`phantom/interface/cli_app.py:420`, `phantom/interface/cli_app.py:435`, `phantom/interface/cli_app.py:444`).

Design intent: keep the CLI layer as a **control adapter**, not the place where scan reasoning happens.

### `phantom/interface/cli.py`

Intent: be the **execution supervisor** for non-interactive runs.

What it does in practice:

- Restores checkpoints into runnable root-state context (root agent state + hypothesis ledger + coverage tracker + correlation engine + attack graph). Sub-agent snapshots are loaded into config but are not rehydrated into active loops in the current runtime path (`phantom/interface/cli.py:62`, `phantom/interface/cli.py:108`, `phantom/interface/cli.py:153`, `phantom/agents/base_agent.py:63`).
- Rebuilds agent config and iteration budget on resume, then wires checkpoint manager and tracer (`phantom/interface/cli.py:245`, `phantom/interface/cli.py:269`, `phantom/interface/cli.py:276`, `phantom/interface/cli.py:286`).
- Owns interruption safety: signal handlers trigger interrupt checkpoint + runtime cleanup (`phantom/interface/cli.py:317`, `phantom/interface/cli.py:343`, `phantom/interface/cli.py:351`).
- Supports quiet/json modes for automation while preserving the same orchestration path (`phantom/interface/cli.py:49`, `phantom/interface/cli.py:378`, `phantom/interface/cli.py:439`).

Design intent: this is an **operational shell** around the agent loop, not the loop itself.

### `phantom/interface/main.py` and `phantom/interface/utils.py`

Intent: provide reusable preflight and input-normalization primitives.

- `main.py` centralizes environment validation, Docker checks/image pull, and LLM reachability warm-up (`phantom/interface/main.py:50`, `phantom/interface/main.py:185`, `phantom/interface/main.py:469`, `phantom/interface/main.py:207`).
- `utils.py` is the target normalization engine (type inference, workspace naming, localhost-to-host-gateway rewrite, repo clone, local-source collection) (`phantom/interface/utils.py:565`, `phantom/interface/utils.py:662`, `phantom/interface/utils.py:730`, `phantom/interface/utils.py:754`, `phantom/interface/utils.py:686`).

---

## 2) Agent Core Intent (How decisions are executed)

### `phantom/agents/PhantomAgent/phantom_agent.py`

Intent: specialize `BaseAgent` into a **root mission constructor**.

- Classifies targets into repos/local code/URLs/IPs and builds a single mission text (`phantom/agents/PhantomAgent/phantom_agent.py:27`, `phantom/agents/PhantomAgent/phantom_agent.py:76`, `phantom/agents/PhantomAgent/phantom_agent.py:100`).
- Registers scan-target hosts with SSRF allowlisting before exploitation begins (`phantom/agents/PhantomAgent/phantom_agent.py:60`, `phantom/agents/PhantomAgent/phantom_agent.py:65`).
- Elevates user instructions as high-priority constraints in the root task (`phantom/agents/PhantomAgent/phantom_agent.py:102`).

### `phantom/agents/base_agent.py`

Intent: implement the system’s **stateful ReAct runtime loop**.

Key runtime logic:

- Bootstraps LLM identity/state, shared memory modules, scan-status context, tracer registration (`phantom/agents/base_agent.py:85`, `phantom/agents/base_agent.py:100`, `phantom/agents/base_agent.py:153`, `phantom/agents/base_agent.py:166`).
- Main iterative controller with waiting/stop/error/max-iteration governance (`phantom/agents/base_agent.py:247`, `phantom/agents/base_agent.py:276`, `phantom/agents/base_agent.py:280`, `phantom/agents/base_agent.py:416`).
- Injects strategic summaries before calls (scan status, ledger, coverage, correlations) to keep policy awareness under compression (`phantom/agents/base_agent.py:620`, `phantom/agents/base_agent.py:646`, `phantom/agents/base_agent.py:661`, `phantom/agents/base_agent.py:673`).
- Executes tool actions through executor, then loops on observations (`phantom/agents/base_agent.py:757`, `phantom/agents/base_agent.py:798`).
- Handles inter-agent messages from shared message bus (`phantom/agents/base_agent.py:833`).
- Saves root checkpoints periodically with attached structured memory subsystems (`phantom/agents/base_agent.py:901`, `phantom/agents/base_agent.py:919`).

Operational intent: this file is the **true control kernel** of Phantom.

### `phantom/agents/state.py`

Intent: hold durable per-agent execution state and resist context drift.

- Tracks lifecycle, loop counters, message history, and stop/wait semantics (`phantom/agents/state.py:31`, `phantom/agents/state.py:219`, `phantom/agents/state.py:225`).
- Applies hash + short-window dedup to reduce repeated message poisoning/noise (`phantom/agents/state.py:21`, `phantom/agents/state.py:139`, `phantom/agents/state.py:147`).
- Maintains finding anchors and expiration cycles so critical findings survive compression (`phantom/agents/state.py:84`, `phantom/agents/state.py:110`, `phantom/agents/state.py:127`).

---

## 3) Reasoning and Context Intent (How the model is constrained)

### `phantom/llm/llm.py`

Intent: be the **LLM mediation layer** between mutable agent state and provider APIs.

Core behaviors:

- Builds system prompt from agent templates + scan-mode skill + tool schema prompt (`phantom/llm/llm.py:258`, `phantom/llm/llm.py:270`, `phantom/llm/llm.py:277`).
- Runs generation with global cooldown, circuit breaker, retry/backoff, fallback model, routing, budget gating (`phantom/llm/llm.py:333`, `phantom/llm/llm.py:343`, `phantom/llm/llm.py:370`, `phantom/llm/llm.py:451`, `phantom/llm/llm.py:1019`, `phantom/llm/llm.py:809`).
- Builds request context in fixed order: system prompt -> identity block -> compressed history -> anchor reinjection -> continuation guard (`phantom/llm/llm.py:588`, `phantom/llm/llm.py:591`, `phantom/llm/llm.py:607`, `phantom/llm/llm.py:618`, `phantom/llm/llm.py:653`).
- Applies preflight request-size reduction staircase before provider call (`phantom/llm/llm.py:702`, `phantom/llm/llm.py:729`, `phantom/llm/llm.py:747`, `phantom/llm/llm.py:765`).
- Normalizes malformed tool-call outputs and emits corrective feedback if model produced unparsable tool intent (`phantom/llm/llm.py:548`, `phantom/llm/llm.py:555`).

### `phantom/llm/memory_compressor.py`

Intent: make long-running scans feasible by **compressing history without losing exploit signal**.

- Uses model-aware context thresholding and retains recent tail (`phantom/llm/memory_compressor.py:43`, `phantom/llm/memory_compressor.py:657`, `phantom/llm/memory_compressor.py:697`).
- Extracts high-signal anchors from old chunks before summarization (`phantom/llm/memory_compressor.py:169`, `phantom/llm/memory_compressor.py:734`).
- Summarizes old messages in parallel chunk mode with bounded concurrency, plus sequential fallback (`phantom/llm/memory_compressor.py:518`, `phantom/llm/memory_compressor.py:752`, `phantom/llm/memory_compressor.py:781`).

### `phantom/llm/utils.py` and `phantom/llm/config.py`

- `utils.py` is the parser/normalizer bridge converting model XML variants into validated tool invocations (`phantom/llm/utils.py:12`, `phantom/llm/utils.py:81`).
- `config.py` resolves provider-facing vs canonical model identity and scan-mode config (`phantom/llm/config.py:8`, `phantom/llm/config.py:23`).

---

## 4) Tool Fabric Intent (How model intent becomes action)

### Registry and Tool Surface

- `phantom/tools/__init__.py` performs import-time tool registration and mode-gated module loading (`phantom/tools/__init__.py:31`, `phantom/tools/__init__.py:70`).
- `phantom/tools/registry.py` uses decorator-based plugin registration, XML schema loading, and per-tool parameter schema extraction (`phantom/tools/registry.py:152`, `phantom/tools/registry.py:167`, `phantom/tools/registry.py:187`).
- `phantom/tools/dynamic_tools.py` provides prompt-time subset selection by categories/context (`phantom/tools/dynamic_tools.py:86`, `phantom/tools/dynamic_tools.py:204`).

Intent: decouple tool implementation from model-visible schema and execution path.

### Execution Pipeline (`phantom/tools/executor.py`)

Intent: be the **policy-and-dispatch chokepoint**.

Actual flow:

1. Validate tool existence and argument schema (`phantom/tools/executor.py:532`, `phantom/tools/executor.py:544`).
2. Run RBAC gate (`phantom/tools/executor.py:377`, `phantom/tools/rbac.py:196`).
3. Apply cache and dispatch local vs sandbox (`phantom/tools/executor.py:412`, `phantom/tools/executor.py:427`, `phantom/tools/executor.py:457`).
4. Format/sanitize/truncate/extract signals from tool output (`phantom/tools/executor.py:1120`, `phantom/tools/executor.py:1284`).
5. Build observation payload and append as next user message (`phantom/tools/executor.py:1441`, `phantom/tools/executor.py:1476`, `phantom/tools/executor.py:1480`).

Notable behavior:

- Injection validator exists but currently returns `None` unconditionally (disabled), so protection relies on other controls (`phantom/tools/executor.py:238`, `phantom/tools/executor.py:247`).

### Context and Session Isolation

- `phantom/tools/context.py` provides per-execution `agent_id` context variable (`phantom/tools/context.py:4`).
- Terminal/Python/Browser managers partition sessions by current agent id while using process-global manager instances (`phantom/tools/terminal/terminal_manager.py:12`, `phantom/tools/python/python_manager.py:11`, `phantom/tools/browser/tab_manager.py:11`).

### High-Impact Tool Modules

- `phantom/tools/proxy/proxy_manager.py` centralizes SSRF checks, allowlist registration, DNS pinning, and encoded-IP bypass handling (`phantom/tools/proxy/proxy_manager.py:52`, `phantom/tools/proxy/proxy_manager.py:134`, `phantom/tools/proxy/proxy_manager.py:150`, `phantom/tools/proxy/proxy_manager.py:322`).
- `phantom/tools/agents_graph/agents_graph_actions.py` implements sub-agent graph, thread runners, message bus, and delegation limits (`phantom/tools/agents_graph/agents_graph_actions.py:10`, `phantom/tools/agents_graph/agents_graph_actions.py:93`, `phantom/tools/agents_graph/agents_graph_actions.py:265`, `phantom/tools/agents_graph/agents_graph_actions.py:317`).
- `phantom/tools/finish/finish_actions.py` enforces root-only completion and prevents finish with active sub-agents (`phantom/tools/finish/finish_actions.py:9`, `phantom/tools/finish/finish_actions.py:20`, `phantom/tools/finish/finish_actions.py:95`).
- `phantom/tools/reporting/reporting_actions.py` validates/dedupes reports, assigns confidence tiers, and triggers async PoC replay state updates (`phantom/tools/reporting/reporting_actions.py:544`, `phantom/tools/reporting/reporting_actions.py:637`, `phantom/tools/reporting/reporting_actions.py:653`, `phantom/tools/reporting/reporting_actions.py:817`).
- `phantom/tools/scan_status/scan_status_actions.py` composes unified status from ledger/coverage/correlation/attack graph for periodic prompt injection (`phantom/tools/scan_status/scan_status_actions.py:50`, `phantom/tools/scan_status/scan_status_actions.py:118`, `phantom/tools/scan_status/scan_status_actions.py:137`).

---

## 5) Runtime Boundary Intent (Isolation and execution substrate)

### `phantom/runtime/__init__.py`

Intent: service-locator style runtime backend provider with singleton lifecycle (`phantom/runtime/__init__.py:18`, `phantom/runtime/__init__.py:35`).

### `phantom/runtime/docker_runtime.py`

Intent: provision and maintain a **per-scan isolated container execution environment**.

Key mechanics:

- Connect/start Docker client and verify image (`phantom/runtime/docker_runtime.py:71`, `phantom/runtime/docker_runtime.py:131`).
- Create/reuse scan container, allocate ports/token, write token secret file, wait for tool-server health (`phantom/runtime/docker_runtime.py:201`, `phantom/runtime/docker_runtime.py:225`, `phantom/runtime/docker_runtime.py:279`, `phantom/runtime/docker_runtime.py:314`).
- Copy local sources to `/workspace`; scope-firewall code exists but activation is conditional on `scan_config` being supplied to `create_sandbox(...)` (not done in the current root call path) (`phantom/runtime/docker_runtime.py:489`, `phantom/runtime/docker_runtime.py:521`, `phantom/agents/base_agent.py:589`, `phantom/runtime/docker_runtime.py:548`).
- Register agent and return sandbox connection descriptor (`phantom/runtime/docker_runtime.py:588`, `phantom/runtime/docker_runtime.py:579`).
- Cleanup path supports blocking signal-safe removal and zombie cleanup sweep (`phantom/runtime/docker_runtime.py:630`, `phantom/runtime/docker_runtime.py:676`).

### `phantom/runtime/tool_server.py`

Intent: execute sandbox tools behind a strict API gate.

- Runs only in sandbox mode (`phantom/runtime/tool_server.py:17`).
- Verifies bearer token with constant-time compare (`phantom/runtime/tool_server.py:85`, `phantom/runtime/tool_server.py:94`).
- Applies per-agent request pacing and hard timeout wrappers (`phantom/runtime/tool_server.py:72`, `phantom/runtime/tool_server.py:152`).
- Cancels older in-flight task for the same agent before new one (`phantom/runtime/tool_server.py:146`).

---

## 6) Persistence and Recovery Intent

### `phantom/checkpoint/checkpoint.py`

Intent: provide tamper-detecting, crash-safe scan resumability.

- Sanitizes run naming/path joins to reduce traversal risk (`phantom/checkpoint/checkpoint.py:64`, `phantom/checkpoint/checkpoint.py:89`).
- Saves atomically (`.tmp` then replace) with HMAC signature and optional encryption (`phantom/checkpoint/checkpoint.py:210`, `phantom/checkpoint/checkpoint.py:233`, `phantom/checkpoint/checkpoint.py:187`).
- Loads with integrity/version checks and legacy migration (`phantom/checkpoint/checkpoint.py:246`, `phantom/checkpoint/checkpoint.py:176`, `phantom/checkpoint/checkpoint.py:310`).
- `build(...)` supports optional `sub_agent_states`, but the current root checkpoint call does not pass `active_sub_agents`; default persisted checkpoints therefore contain root + strategic state with sandbox-token redaction (`phantom/checkpoint/checkpoint.py:344`, `phantom/agents/base_agent.py:914`, `phantom/checkpoint/checkpoint.py:387`, `phantom/checkpoint/checkpoint.py:426`).

### `phantom/telemetry/tracer.py`

Intent: be the **single run artifact authority**.

- Maintains agents, tool executions, chat timeline, vulnerability registry (`phantom/telemetry/tracer.py:54`, `phantom/telemetry/tracer.py:55`, `phantom/telemetry/tracer.py:56`, `phantom/telemetry/tracer.py:60`).
- Emits event records and lifecycle status updates (`phantom/telemetry/tracer.py:192`, `phantom/telemetry/tracer.py:512`, `phantom/telemetry/tracer.py:610`, `phantom/telemetry/tracer.py:652`).
- Persists vulnerability markdown/CSV/final report/scan stats (`phantom/telemetry/tracer.py:711`, `phantom/telemetry/tracer.py:733`, `phantom/telemetry/tracer.py:830`, `phantom/telemetry/tracer.py:870`).
- Aggregates global LLM metrics and derived scan efficiency summaries (`phantom/telemetry/tracer.py:931`, `phantom/telemetry/tracer.py:1004`).

---

## 7) Analysis-State Intent (Beyond raw chat history)

### `phantom/core/attack_graph.py`

Intent: model vulnerabilities as a directed graph for chain and critical-node analysis.

- Supports node/edge construction, chain insertion, path discovery, centrality ranking, export/import (`phantom/core/attack_graph.py:124`, `phantom/core/attack_graph.py:232`, `phantom/core/attack_graph.py:243`, `phantom/core/attack_graph.py:253`, `phantom/core/attack_graph.py:343`, `phantom/core/attack_graph.py:392`).

### `hypothesis_ledger.py`, `coverage_tracker.py`, `correlation_engine.py`

These three are the system’s structured strategic memory trio:

- Hypothesis lifecycle/evidence/payload learning (`phantom/agents/hypothesis_ledger.py:58`, `phantom/agents/hypothesis_ledger.py:161`, `phantom/agents/hypothesis_ledger.py:651`, `phantom/agents/hypothesis_ledger.py:817`).
- Surface discovery/test/failure coverage matrix (`phantom/agents/coverage_tracker.py:110`, `phantom/agents/coverage_tracker.py:159`, `phantom/agents/coverage_tracker.py:209`, `phantom/agents/coverage_tracker.py:409`).
- Chain suggestion detection from finding patterns and combination analysis (`phantom/agents/correlation_engine.py:182`, `phantom/agents/correlation_engine.py:221`, `phantom/agents/correlation_engine.py:302`, `phantom/agents/correlation_engine.py:359`).

Intent: keep decisions grounded even when conversation history is compressed.

### `phantom/models/vulnerability.py`

Intent: define canonical vulnerability structure and enums used by analysis/reporting layers (`phantom/models/vulnerability.py:11`, `phantom/models/vulnerability.py:20`, `phantom/models/vulnerability.py:28`).

---

## 8) Design Patterns Reconstructed from Code

1. **ReAct controller pattern**: iterative LLM reasoning + tool action + observation feedback (`phantom/agents/base_agent.py:247`, `phantom/agents/base_agent.py:691`, `phantom/tools/executor.py:1480`).
2. **Decorator-based plugin registry** for tools and schema reflection (`phantom/tools/registry.py:152`, `phantom/tools/registry.py:240`).
3. **Prompt-scoped capability exposure** (tool subset mostly influences model visibility, not registry existence) (`phantom/llm/llm.py:277`, `phantom/tools/dynamic_tools.py:204`, `phantom/tools/registry.py:217`).
4. **Hybrid concurrency model**: async agent loop + thread-backed sub-agents + shared process state (`phantom/agents/base_agent.py:334`, `phantom/tools/agents_graph/agents_graph_actions.py:145`).
5. **Singleton/service-locator runtime style**: global runtime, tracer, and manager instances (`phantom/runtime/__init__.py:15`, `phantom/telemetry/tracer.py:32`, `phantom/tools/terminal/terminal_manager.py:177`, `phantom/tools/browser/tab_manager.py:435`).
6. **Session sharding by ContextVar**: shared managers with per-agent session maps (`phantom/tools/context.py:4`, `phantom/tools/python/python_manager.py:19`).
7. **Pipeline-with-policy-gates** in executor (availability -> schema -> RBAC -> dispatch -> sanitize/shape) (`phantom/tools/executor.py:579`, `phantom/tools/executor.py:617`, `phantom/tools/executor.py:1284`).
8. **Memento/checkpoint pattern** for resumable long-running autonomous flows (`phantom/checkpoint/checkpoint.py:333`, `phantom/interface/cli.py:95`).

---

## 9) Critical Control Points (Highest architecture leverage)

- `BaseAgent.agent_loop` (`phantom/agents/base_agent.py:247`): changes here alter global reasoning cadence, safety exits, and checkpoint frequency.
- `LLM.generate` (`phantom/llm/llm.py:333`): central for provider behavior, retry resilience, budget compliance, and routing/fallback decisions.
- `process_tool_invocations` (`phantom/tools/executor.py:1441`): determines how model intent becomes authoritative observation history.
- `execute_tool_with_validation` (`phantom/tools/executor.py:579`): last host-side policy gate before side effects.
- `DockerRuntime.create_sandbox` (`phantom/runtime/docker_runtime.py:521`): defines isolation guarantees and agent runtime identity.
- `create_vulnerability_report` (`phantom/tools/reporting/reporting_actions.py:544`): controls evidence quality gates and persisted finding semantics.
- `CheckpointManager.save/load/build` (`phantom/checkpoint/checkpoint.py:210`, `phantom/checkpoint/checkpoint.py:246`, `phantom/checkpoint/checkpoint.py:333`): governs resumability correctness.
- `Tracer.save_run_data` (`phantom/telemetry/tracer.py:711`): governs what constitutes final truth in run artifacts.

---

## 10) Architectural Implications from Code Reality

### Strengths

- Clear host/sandbox boundary with authenticated RPC and health checks (`phantom/tools/executor.py:487`, `phantom/runtime/tool_server.py:85`).
- Rich resumability including strategic memory components (`phantom/interface/cli.py:108`, `phantom/checkpoint/checkpoint.py:467`).
- Strong observability and artifact persistence primitives (`phantom/telemetry/tracer.py:192`, `phantom/telemetry/tracer.py:711`).

### Coupling/Hotspots

- Heavy global mutable state and singleton coupling across orchestration, tools, and telemetry (`phantom/tools/agents_graph/agents_graph_actions.py:10`, `phantom/telemetry/tracer.py:32`, `phantom/runtime/__init__.py:15`).
- Tool-subset control is prompt-facing; runtime capability gating is not the same abstraction (`phantom/llm/llm.py:277`, `phantom/tools/registry.py:217`).
- Security checks are uneven: robust SSRF logic exists, but command injection validator path is explicitly disabled (`phantom/tools/proxy/proxy_manager.py:150`, `phantom/tools/executor.py:247`).
- Async + thread shared-state model increases race/coupling complexity around agent graph and session managers (`phantom/tools/agents_graph/agents_graph_actions.py:22`, `phantom/tools/agents_graph/agents_graph_actions.py:488`).

---

## 11) Continuation Map: Where to look for each behavior

- "Why did the agent decide this next step?" -> `phantom/agents/base_agent.py:615`, `phantom/llm/llm.py:588`.
- "Why did a tool call fail or get blocked?" -> `phantom/tools/executor.py:579`, `phantom/tools/rbac.py:196`.
- "Why is this target classified as repo/web/ip/local?" -> `phantom/interface/utils.py:565`.
- "Why did scan resume with/without previous memory?" -> `phantom/interface/cli.py:62`, `phantom/checkpoint/checkpoint.py:333`.
- "Why did report confidence/replay status look this way?" -> `phantom/tools/reporting/reporting_actions.py:637`, `phantom/tools/reporting/reporting_actions.py:653`.
- "Why did container behavior/network scope differ?" -> `phantom/runtime/docker_runtime.py:417`, `phantom/runtime/docker_runtime.py:521`.

---

## Step 5 Reconstruction Statement

Phantom’s runtime is centered on `BaseAgent` as a host-side ReAct controller, `LLM` as decision mediation and context governor, `executor` as policy+dispatch chokepoint, and Docker runtime/tool-server as isolation boundary. Strategic memory is not just chat history; it is externalized into ledger/coverage/correlation/graph subsystems and reinjected periodically. The architecture is operationally strong but highly coupled through process-wide singletons and shared mutable registries, which should be treated as first-class design constraints for any future refactor.
