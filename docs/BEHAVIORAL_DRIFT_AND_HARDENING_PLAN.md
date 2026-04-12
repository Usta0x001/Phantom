# Phantom Behavioral Drift and Hardening Plan (Step 6)

## Scope and Evidence Basis

This phase continues from Step 5 by focusing on where implemented behavior drifts from intended architecture, and what to fix first with minimal blast radius.

Primary anchors used:

- Agent loop and status injection: `phantom/agents/base_agent.py:615`, `phantom/agents/base_agent.py:627`
- LLM governance and toggles: `phantom/llm/llm.py:343`, `phantom/config/config.py:89`
- Tool policy and dispatch chokepoint: `phantom/tools/executor.py:579`, `phantom/tools/executor.py:1507`
- Hypothesis tool bridge: `phantom/tools/hypothesis/hypothesis_actions.py:84`
- Scan-status synthesis: `phantom/tools/scan_status/scan_status_actions.py:186`, `phantom/tools/scan_status/scan_status_actions.py:209`
- Runtime boundary and scope controls: `phantom/runtime/docker_runtime.py:521`, `phantom/runtime/docker_runtime.py:548`, `phantom/runtime/tool_server.py:85`

---

## 1) Runtime Invariants to Preserve

These are the architectural truths that future changes should not break:

1. **Decision loop invariant**: `BaseAgent.agent_loop()` remains the control kernel for stop/governance and observation feedback (`phantom/agents/base_agent.py:247`, `phantom/agents/base_agent.py:757`).
2. **Policy-before-side-effects invariant**: all tool calls pass through executor validation/gating before local or sandbox execution (`phantom/tools/executor.py:579`, `phantom/tools/executor.py:617`).
3. **Boundary invariant**: host orchestration executes through token-authenticated sandbox RPC for sandbox tools (`phantom/tools/executor.py:487`, `phantom/runtime/tool_server.py:137`).
4. **Durability invariant**: resumability correctness depends on checkpoint build/save/load and tracer artifacts (`phantom/checkpoint/checkpoint.py:333`, `phantom/checkpoint/checkpoint.py:210`, `phantom/telemetry/tracer.py:711`).

---

## 2) Confirmed Behavioral Drift (Code-Observed)

## D1) Injection argument validator is intentionally inactive

- `_validate_tool_argument_injection(...)` returns `None` unconditionally, with checks disabled (`phantom/tools/executor.py:238`, `phantom/tools/executor.py:247`).
- Impact: command-argument abuse protection is not coming from this gate; safety is delegated to other layers.

## D2) Tool subset is prompt visibility, not runtime least privilege

- Subset mode changes schema exposure in system prompt (`phantom/llm/llm.py:277`, `phantom/tools/dynamic_tools.py:204`).
- Executor availability checks still consult runtime registry (`phantom/tools/registry.py:217`, `phantom/tools/executor.py:537`).
- Impact: capability minimization is soft (model-facing), not hard (runtime-facing).

## D3) Auto-hypothesis implementation is split: one active path, one broken legacy path

- Active path: `_execute_single_tool()` records extracted vulnerability signals directly into `agent_state.hypothesis_ledger` (`phantom/tools/executor.py:1399`, `phantom/tools/executor.py:1404`).
- Broken legacy path: `_auto_record_hypothesis()` still imports non-existent `_ledger` and silently returns (`phantom/tools/executor.py:1507`, `phantom/tools/hypothesis/hypothesis_actions.py:84`).
- Impact: enrichment is partially functional but inconsistent; duplicate pathways create maintenance and observability drift.

## D4) Scan-status recommendation path has a type mismatch risk

- `_compute_recommendation()` pulls `top = untested[0]` from `get_untested_surfaces()` and then slices `top[:50]` (`phantom/tools/scan_status/scan_status_actions.py:209`, `phantom/tools/scan_status/scan_status_actions.py:212`).
- Untested entries are `DiscoveredSurface` objects, not strings (`phantom/agents/coverage_tracker.py:57`, `phantom/agents/coverage_tracker.py:288`).
- Caller wraps status injection in broad `try/except`, so failures can degrade guidance silently (`phantom/agents/base_agent.py:627`, `phantom/agents/base_agent.py:635`).

## D5) Circuit-breaker feature flag exists but execution path does not branch on it

- Config exposes `phantom_circuit_breaker_enabled` (`phantom/config/config.py:89`).
- LLM generate path calls breaker directly without flag check (`phantom/llm/llm.py:343`).
- Impact: operational toggle does not currently control breaker behavior.

## D6) RBAC posture is optional and permissive on missing module paths

- RBAC default is disabled (`phantom/config/config.py:96`).
- Executor catches RBAC import failure and allows execution (`phantom/tools/executor.py:383`).
- Impact: authorization guard is present but not guaranteed in all deployments.

---

## 3) Coupling and Blast-Radius Hotspots

1. **Process-global shared state**: runtime singleton, tracer singleton, agent graph globals, cache singleton (`phantom/runtime/__init__.py:15`, `phantom/telemetry/tracer.py:32`, `phantom/tools/agents_graph/agents_graph_actions.py:10`, `phantom/tools/cache.py:383`).
2. **Hybrid async/thread execution**: async loop + thread-run subagents + shared registries raise ordering/race complexity (`phantom/agents/base_agent.py:334`, `phantom/tools/agents_graph/agents_graph_actions.py:488`).
3. **Cross-module implicit wiring**: hypothesis/coverage/correlation/scan-status context is injected through globals rather than explicit run context ownership (`phantom/agents/base_agent.py:151`, `phantom/tools/scan_status/scan_status_actions.py:22`).

---

## 4) Hardening Sequence (Lowest-Risk First)

## Wave A - Correctness-first patches

- Fix dead/ambiguous ledger wiring in executor auto-record path to use supported accessor (`phantom/tools/executor.py:1507`, `phantom/tools/hypothesis/hypothesis_actions.py:50`).
- Fix `scan_status` recommendation type mismatch and add unit coverage around untested-surface recommendations (`phantom/tools/scan_status/scan_status_actions.py:209`).
- Add explicit telemetry/audit marker when scan-status injection fails to avoid silent strategy degradation (`phantom/agents/base_agent.py:627`).

## Wave B - Policy coherence

- Either wire `phantom_circuit_breaker_enabled` into LLM runtime branch or remove the toggle to eliminate false configurability (`phantom/config/config.py:89`, `phantom/llm/llm.py:343`).
- Decide explicit posture for injection validator path: keep disabled by design but codify this as policy, or re-enable with mode-based bypass (`phantom/tools/executor.py:238`).
- Clarify RBAC operating mode defaults for production vs research use (`phantom/config/config.py:96`, `phantom/tools/rbac.py:123`).

## Wave C - Boundary hardening and ownership cleanup

- Introduce hard runtime capability contracts (allowlist per run/agent) in executor, not only prompt subset filtering (`phantom/tools/executor.py:537`, `phantom/tools/dynamic_tools.py:204`).
- Move global context wiring into an explicit run-context owner to reduce implicit cross-module coupling (`phantom/agents/base_agent.py:151`, `phantom/tools/agents_graph/agents_graph_actions.py:10`).

---

## 5) Verification Gates for Future Refactors

- **Loop integrity**: regression tests around no-action stall handling, finish conditions, and checkpoint cadence (`phantom/agents/base_agent.py:345`, `phantom/agents/base_agent.py:901`).
- **Policy gate integrity**: tests that malformed tool args, missing params, and RBAC denial all produce deterministic observation errors (`phantom/tools/executor.py:544`, `phantom/tools/executor.py:377`).
- **Boundary integrity**: tests for token-auth failures, per-agent cancellation semantics, and tool timeout behavior in tool server (`phantom/runtime/tool_server.py:85`, `phantom/runtime/tool_server.py:146`, `phantom/runtime/tool_server.py:152`).
- **Resume integrity**: checkpoint migration/HMAC/encryption and restored subsystem state tests (`phantom/checkpoint/checkpoint.py:246`, `phantom/interface/cli.py:95`).

---

## 6) Data Flow & Control Flow (End-to-End Scenario)

Scenario traced: **target -> scan -> analyze -> decide -> exploit -> report**

Control-flow spine:

`cli_app.scan -> _async_scan -> run_cli -> PhantomAgent.execute_scan -> BaseAgent.agent_loop`

Loop spine:

`_process_iteration -> LLM.generate -> parse_tool_invocations -> process_tool_invocations -> execute_tool_with_validation -> (local or sandbox execution) -> observation appended -> next iteration`

### 6.1 Target -> Scan (ingestion and bootstrap)

- **How data moves**: CLI `--target` values are typed into `args.targets_info` via `infer_target_type`, then normalized (workspace subdirs + localhost rewrite), cloned/collected into `local_sources`, and packed into `scan_config` (`phantom/interface/cli_app.py:131`, `phantom/interface/utils.py:565`, `phantom/interface/cli_app.py:396`, `phantom/interface/cli_app.py:442`, `phantom/interface/cli.py:232`).
- **Where decisions happen**: target classification and validation (`repository/web/ip/local`) in `infer_target_type`; resume-vs-fresh run path in CLI supervisor (`phantom/interface/utils.py:565`, `phantom/interface/cli.py:62`).
- **Where state is stored**: in-memory `args` namespace + `scan_config`; optional restored checkpoint state (`checkpoint.json` + `.hmac`) when resuming (`phantom/interface/cli.py:62`, `phantom/checkpoint/checkpoint.py:246`).

### 6.2 Scan -> Analyze (task materialization and context construction)

- **How data moves**: `PhantomAgent.execute_scan()` transforms typed targets into one mission text; user constraints are appended and sanitized; mission enters `AgentState.messages` as the first user message (`phantom/agents/PhantomAgent/phantom_agent.py:23`, `phantom/agents/PhantomAgent/phantom_agent.py:102`, `phantom/agents/base_agent.py:613`).
- **Where decisions happen**: target bucket routing (repo/local/url/ip), SSRF allowlist registration for web hosts, and sandbox creation branch in `_initialize_sandbox_and_state` (`phantom/agents/PhantomAgent/phantom_agent.py:38`, `phantom/agents/PhantomAgent/phantom_agent.py:60`, `phantom/agents/base_agent.py:581`).
- **Where state is stored**: `AgentState` (`messages`, iteration/lifecycle flags, sandbox refs, anchors), plus strategic stores (`HypothesisLedger`, `CoverageTracker`, `CorrelationEngine`, `AttackGraph`) attached to the agent (`phantom/agents/state.py:13`, `phantom/agents/base_agent.py:100`, `phantom/agents/base_agent.py:114`, `phantom/agents/base_agent.py:123`).

### 6.3 Analyze -> Decide (LLM decision cycle)

- **How data moves**: before each call, periodic summaries (scan status, ledger, coverage, correlation) are injected into history; `LLM._prepare_messages()` builds request context as system -> identity -> compressed history -> finding anchors -> continuation guard (`phantom/agents/base_agent.py:620`, `phantom/agents/base_agent.py:646`, `phantom/llm/llm.py:588`, `phantom/llm/llm.py:618`, `phantom/llm/llm.py:653`).
- **Where decisions happen**: retry/backoff, circuit-breaker check, routing/fallback model selection, and request-size reduction staircase (`phantom/llm/llm.py:343`, `phantom/llm/llm.py:370`, `phantom/llm/llm.py:451`, `phantom/llm/llm.py:702`).
- **Where state is stored**: compressed conversation is written back into `AgentState.messages`; global LLM stats/rate-limit state accumulate in process globals (`phantom/llm/llm.py:615`, `phantom/llm/llm.py:70`, `phantom/llm/llm.py:72`).

### 6.4 Decide -> Exploit (tool invocation and execution)

- **How data moves**: model XML/tool text is normalized and parsed into `[{toolName,args}]`; executor validates availability/args/RBAC, dispatches local or sandbox execution, then formats tool output into observation XML and appends it as next user message (`phantom/llm/utils.py:81`, `phantom/tools/executor.py:579`, `phantom/tools/executor.py:457`, `phantom/tools/executor.py:1441`, `phantom/tools/executor.py:1480`).
- **Where decisions happen**: final host-side policy gates are in executor; completion decision toggles when `finish_scan`/`agent_finish` returns success flags (`phantom/tools/executor.py:589`, `phantom/tools/executor.py:593`, `phantom/tools/executor.py:377`, `phantom/tools/executor.py:1369`).
- **Where state is stored**: tool execution records in tracer (`tool_executions`), chat observations in `AgentState.messages`, optional terminal/python/browser session state keyed by `agent_id` via `ContextVar` (`phantom/telemetry/tracer.py:569`, `phantom/agents/state.py:252`, `phantom/tools/context.py:4`, `phantom/tools/terminal/terminal_manager.py:14`).

### 6.5 Exploit -> Report (finding creation and finalization)

- **How data moves**: `create_vulnerability_report` validates, dedupes, computes CVSS/confidence/replay state, then persists through tracer; `finish_scan` validates root ownership + active-agent quiescence, writes final sections and marks run complete (`phantom/tools/reporting/reporting_actions.py:544`, `phantom/tools/reporting/reporting_actions.py:781`, `phantom/tools/finish/finish_actions.py:96`, `phantom/telemetry/tracer.py:467`).
- **Where decisions happen**: duplicate suppression, confidence tier normalization, replay scheduling, and finish blocking when sub-agents are still active (`phantom/tools/reporting/reporting_actions.py:637`, `phantom/tools/reporting/reporting_actions.py:799`, `phantom/tools/reporting/reporting_actions.py:652`, `phantom/tools/finish/finish_actions.py:20`).
- **Where state is stored**: tracer in-memory registry and disk artifacts (`vulnerabilities/*.md`, `vulnerabilities.csv`, `penetration_test_report.md`, `scan_stats.json`, `events.jsonl`) (`phantom/telemetry/tracer.py:319`, `phantom/telemetry/tracer.py:711`, `phantom/telemetry/tracer.py:830`, `phantom/telemetry/tracer.py:870`).

### 6.6 Cross-cutting durability path (checkpoint)

- **How data moves**: root loop periodically calls checkpoint build/save; snapshot includes root state + strategic subsystems. Sub-agent serialization support exists in `CheckpointManager.build(...)` but is not supplied by the current root call path (`phantom/checkpoint/checkpoint.py:344`, `phantom/agents/base_agent.py:914`, `phantom/interface/cli.py:95`).
- **Where decisions happen**: save cadence (`should_save`), integrity verification, version migration on load (`phantom/checkpoint/checkpoint.py:158`, `phantom/checkpoint/checkpoint.py:255`, `phantom/checkpoint/checkpoint.py:310`).
- **Where state is stored**: atomic checkpoint files `checkpoint.json` + `checkpoint.json.hmac` (optionally encrypted) in run directory (`phantom/checkpoint/checkpoint.py:210`, `phantom/checkpoint/checkpoint.py:233`).

### 6.7 Decision and state map (condensed)

- **Primary decision authorities**: `infer_target_type` (target semantics), `LLM.generate` (next action policy), `execute_tool_with_validation` (side-effect gate), `create_vulnerability_report` (finding semantics), `finish_scan` (termination authority).
- **Primary state stores**: `AgentState` (loop memory), strategic stores (ledger/coverage/correlation/graph), tracer runtime registries, manager session maps, checkpoint files, run artifact files.
- **Boundary state**: sandbox runtime/container identity + token-auth tool server interface (`phantom/runtime/docker_runtime.py:521`, `phantom/runtime/tool_server.py:85`).

---

## Step 6 Reconstruction Statement

The architecture is functionally strong but contains several code-level drift points where intended controls are softer than they appear (prompt-scoped tool subset, disabled injection validator, split/fragile cross-module wiring). The safest continuation path is a staged hardening plan: first correct behavior drift, then align policy toggles with runtime truth, then reduce global-coupling through explicit run-context ownership and hard capability boundaries.
