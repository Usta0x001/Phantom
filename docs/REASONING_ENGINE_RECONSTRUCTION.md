# Phantom Reasoning Engine Reconstruction (Step 4 - CRITICAL)

## Scope and Evidence Basis

This report reconstructs Phantom's reasoning core from executable control flow and runtime wiring, not intended behavior claims.

Primary evidence anchors:

- Agent control loop: `phantom/agents/base_agent.py:247`, `phantom/agents/base_agent.py:615`, `phantom/agents/base_agent.py:757`
- Prompt loading and message preparation: `phantom/llm/llm.py:258`, `phantom/llm/llm.py:588`
- Context compression and anchor extraction: `phantom/llm/memory_compressor.py:169`, `phantom/llm/memory_compressor.py:657`
- Tool-call parsing and execution routing: `phantom/llm/utils.py:81`, `phantom/tools/executor.py:579`, `phantom/tools/executor.py:1441`
- Task decomposition and agent graph: `phantom/agents/PhantomAgent/phantom_agent.py:23`, `phantom/tools/agents_graph/agents_graph_actions.py:265`
- Uncertainty/evidence state models: `phantom/agents/hypothesis_ledger.py:58`, `phantom/agents/coverage_tracker.py:84`, `phantom/agents/correlation_engine.py:163`
- Confidence/replay handling for reports: `phantom/tools/reporting/reporting_actions.py:544`

Legend:

- [E] explicit implemented component/behavior
- [I] implicit emergent behavior from process-wide state/policies
- [M] inferred missing abstraction from coupling/drift

---

## 1) Decision-Making Architecture (How decisions are made)

### 1.1 Core runtime decision loop [E]

Phantom's decision engine is a tight iterative loop, not a separate planner service:

1. `BaseAgent.agent_loop()` initializes sandbox/state and enters a `while True` loop (`phantom/agents/base_agent.py:247`, `phantom/agents/base_agent.py:581`).
2. Each iteration calls `_process_iteration()` (`phantom/agents/base_agent.py:334`, `phantom/agents/base_agent.py:615`).
3. `_process_iteration()` streams model output via `LLM.generate(...)` (`phantom/agents/base_agent.py:691`, `phantom/llm/llm.py:333`).
4. Parsed actions are executed through `_execute_actions()` -> `process_tool_invocations()` (`phantom/agents/base_agent.py:742`, `phantom/tools/executor.py:1441`).
5. Tool observations are appended as a new `user` message, closing the feedback loop (`phantom/tools/executor.py:1476`, `phantom/tools/executor.py:1480`).

This forms a ReAct-style cycle:

`history -> LLM decision -> tool action -> observation -> updated history -> next decision`

### 1.2 Iteration governance and stop behavior [E]

- Stop conditions are explicit (`stop_requested`, `completed`, max-iteration) (`phantom/agents/state.py:197`, `phantom/agents/base_agent.py:280`).
- Finish is tool-driven (`finish_scan`/`agent_finish` result toggles loop completion) (`phantom/tools/executor.py:1369`, `phantom/tools/finish/finish_actions.py:96`, `phantom/tools/agents_graph/agents_graph_actions.py:609`).
- No-action stall handling adds corrective pressure and may abort non-interactive runs after prolonged stagnation (`phantom/agents/base_agent.py:345`, `phantom/agents/base_agent.py:352`).

### 1.3 Decision shaping at iteration boundaries [E]

Before each model call, the agent injects strategic state summaries into history:

- Scan status snapshot (`phantom/agents/base_agent.py:620`, `phantom/tools/scan_status/scan_status_actions.py:50`)
- Hypothesis ledger summary (`phantom/agents/base_agent.py:640`, `phantom/agents/hypothesis_ledger.py:817`)
- Coverage summary (`phantom/agents/base_agent.py:655`, `phantom/agents/coverage_tracker.py:409`)
- Correlation/chain opportunities (`phantom/agents/base_agent.py:667`, `phantom/agents/correlation_engine.py:359`)

These are decision inputs (facts/suggestions), not imperative commands.

---

## 2) Prompt Template Anatomy (How the model is instructed)

### 2.1 Prompt assembly pipeline [E]

- `LLM._load_system_prompt()` builds the system prompt using Jinja templates and loaded skills (`phantom/llm/llm.py:258`).
- It always includes scan-mode skill (`scan_modes/<mode>`) plus configured skills (`phantom/llm/llm.py:270`, `phantom/llm/llm.py:274`).
- Tool schemas are injected via either full registry prompt or category subset prompt (`phantom/llm/llm.py:277`, `phantom/tools/dynamic_tools.py:204`, `phantom/tools/registry.py:240`).

### 2.2 Active vs inactive prompt templates [E]

- Active template resolution: loader uses `system_prompt.jinja` by default; when `PHANTOM_USE_CONDENSED_PROMPT=true`, it first tries `system_prompt_condensed.jinja` and falls back to `system_prompt.jinja` if missing or load fails (`phantom/llm/llm.py:293`, `phantom/llm/llm.py:295`, `phantom/llm/llm.py:297`).
- In the current repo, `phantom/agents/PhantomAgent/system_prompt.jinja` and `phantom/agents/PhantomAgent/system_prompt_enhanced.jinja` exist, while `system_prompt_condensed.jinja` is not present; so condensed mode is currently a dormant fallback branch unless that template is added.

### 2.3 Prompt constraints that directly affect reasoning [E]

`system_prompt.jinja` enforces behavior that strongly shapes decision policy:

- "proof or no report" and signal-vs-proof separation (`phantom/agents/PhantomAgent/system_prompt.jinja:28`, `phantom/agents/PhantomAgent/system_prompt.jinja:43`).
- Mandatory memory/status usage protocols (`phantom/agents/PhantomAgent/system_prompt.jinja:88`).
- Multi-agent decomposition and validation workflow mandates (`phantom/agents/PhantomAgent/system_prompt.jinja:472`).
- Tool call formatting and autonomy constraints (`phantom/agents/PhantomAgent/system_prompt.jinja:756`, `phantom/agents/PhantomAgent/system_prompt.jinja:747`).

---

## 3) Context Construction Strategy (How context is built and trimmed)

### 3.1 Message assembly order [E]

`LLM._prepare_messages()` builds request context in a fixed sequence (`phantom/llm/llm.py:588`):

1. System prompt (`phantom/llm/llm.py:591`)
2. Agent identity metadata block (`phantom/llm/llm.py:593`)
3. Compressed conversation history (`phantom/llm/llm.py:607`, `phantom/llm/llm.py:610`)
4. Finding-anchor reinjection (`phantom/llm/llm.py:618`)
5. Assistant-tail guard (`<meta>Continue the task.</meta>`) if last role is assistant (`phantom/llm/llm.py:653`)

### 3.2 Compression lifecycle [E]

`MemoryCompressor.compress_history()` strategy (`phantom/llm/memory_compressor.py:657`):

- Preserve all system messages
- Keep recent tail (minimum 15 non-system messages) (`phantom/llm/memory_compressor.py:22`, `phantom/llm/memory_compressor.py:697`)
- Summarize older chunks (parallelizable) (`phantom/llm/memory_compressor.py:742`, `phantom/llm/memory_compressor.py:752`)
- Extract finding anchors before compression and persist in agent state (`phantom/llm/memory_compressor.py:734`, `phantom/agents/state.py:84`)

### 3.3 Preflight request-size guardrails [E]

After preparation, `_enforce_request_size_limits()` applies staged reductions (`phantom/llm/llm.py:702`):

1. Drop old images (`phantom/llm/llm.py:729`, `phantom/llm/llm.py:670`)
2. Force-compress history (`phantom/llm/llm.py:747`, `phantom/llm/llm.py:1229`)
3. Hard trim non-system history tail (`phantom/llm/llm.py:765`)
4. Fail request if still oversized (`phantom/llm/llm.py:787`)

### 3.4 Context poisoning/noise dampening [E][I]

- Agent state deduplicates repeated message content via hashes and a recent-window check (`phantom/agents/state.py:21`, `phantom/agents/state.py:139`).
- Executor sanitizes tool output for prompt-injection patterns before observation formatting (`phantom/tools/executor.py:252`, `phantom/tools/executor.py:271`).

---

## 4) Planning vs Reactive Execution Model

### 4.1 Predominantly reactive (implemented) [E]

The system is primarily reactive:

- No explicit planner object or plan executor sits between model output and tool execution.
- Decisions are made per-turn from current compressed context + latest observations (`phantom/agents/base_agent.py:691`, `phantom/tools/executor.py:1475`).

### 4.2 Planning scaffolds (prompt/state-driven) [E][I]

Planning behavior is injected indirectly via:

- System-prompt mandates (phase model, decomposition, reporting criteria) (`phantom/agents/PhantomAgent/system_prompt.jinja:214`, `phantom/agents/PhantomAgent/system_prompt.jinja:492`).
- Periodic status/ledger/coverage/correlation injections (`phantom/agents/base_agent.py:620`, `phantom/agents/base_agent.py:646`, `phantom/agents/base_agent.py:661`, `phantom/agents/base_agent.py:673`).
- Optional reflector on empty/no-tool responses (`phantom/agents/base_agent.py:704`, `phantom/llm/pentager/reflector.py:113`).

### 4.3 Notable non-planning realities [E]

- `think` tool records acknowledgement only; it does not create executable plan state (`phantom/tools/thinking/thinking_actions.py:7`).
- A task-plan helper exists (`_generate_task_plan`) but is not wired into runtime loop orchestration (`phantom/tools/agents_graph/agents_graph_actions.py:586`).
- `ChainSummarizer` is imported but explicitly commented as removed from active compression path (`phantom/llm/memory_compressor.py:9`, `phantom/llm/memory_compressor.py:712`).

---

## 5) Task Decomposition and Sub-Agent Strategy

### 5.1 Root task construction [E]

- Root mission text is assembled from targets (repos, local code, URLs, IPs) and user constraints in `execute_scan()` (`phantom/agents/PhantomAgent/phantom_agent.py:23`).
- User constraints are sanitized and elevated as high-priority mission instructions (`phantom/agents/PhantomAgent/phantom_agent.py:102`).

### 5.2 Decomposition mechanism [E]

- Decomposition is tool-mediated through `create_agent(...)` (`phantom/tools/agents_graph/agents_graph_actions.py:265`).
- Hard validation enforces non-trivial context summaries (min length and target cues) (`phantom/tools/agents_graph/agents_graph_actions.py:295`, `phantom/tools/agents_graph/agents_graph_actions.py:307`).
- Governance limits constrain concurrency/total/depth (`phantom/tools/agents_graph/agents_graph_actions.py:319`, `phantom/tools/agents_graph/agents_graph_actions.py:347`, `phantom/tools/agents_graph/agents_graph_actions.py:367`).

### 5.3 Coordination model [E][I]

- Sub-agents run independent event loops in threads (`phantom/tools/agents_graph/agents_graph_actions.py:145`).
- Parent/child communication uses shared in-process queues (`phantom/tools/agents_graph/agents_graph_actions.py:24`, `phantom/agents/base_agent.py:833`).
- Some state stores are intentionally shared (hypothesis ledger/coverage/correlation/attack graph) through agent config propagation (`phantom/agents/base_agent.py:100`, `phantom/tools/agents_graph/agents_graph_actions.py:432`).

---

## 6) Tool Selection Logic and Execution Gating

### 6.1 Selection source (LLM side) [E]

- LLM can only "see" tool names/schemas placed in system prompt (`phantom/agents/PhantomAgent/system_prompt.jinja:797`).
- Tool-call parsing normalizes multiple XML variants and extracts function+parameters (`phantom/llm/utils.py:12`, `phantom/llm/utils.py:81`).
- Invalid tool/parameter names are dropped during parse by regex validation (`phantom/llm/utils.py:96`, `phantom/llm/utils.py:108`).

### 6.2 Execution validation (host side) [E]

Executor path is: availability -> argument schema -> injection check hook -> execute (`phantom/tools/executor.py:579`):

- Tool existence checks (`phantom/tools/executor.py:532`)
- Argument schema checks (`phantom/tools/executor.py:544`)
- RBAC policy gate (`phantom/tools/executor.py:378`, `phantom/tools/rbac.py:196`)
- Dispatch local vs sandbox (`phantom/tools/executor.py:427`, `phantom/tools/executor.py:457`)

### 6.3 Runtime boundary and auth [E]

- Sandbox RPC uses bearer token to `/execute` (`phantom/tools/executor.py:487`, `phantom/runtime/tool_server.py:137`).
- Tool server enforces constant-time token verification (`phantom/runtime/tool_server.py:85`, `phantom/runtime/tool_server.py:94`).

### 6.4 Tool subset reality (important) [E][I]

- `phantom_tool_subset` changes prompt-visible schemas (`phantom/llm/llm.py:277`, `phantom/config/config.py:144`).
- Runtime capability remains full registered set unless otherwise blocked (`phantom/tools/registry.py:217`, `phantom/tools/executor.py:537`).

So subset mode is primarily prompt-shaping, not hard runtime capability isolation.

---

## 7) Uncertainty Handling and Evidence Policy

### 7.1 In-loop uncertainty strategy [E][I]

- Prompt policy explicitly separates "signals" from "proof" (`phantom/agents/PhantomAgent/system_prompt.jinja:392`, `phantom/agents/PhantomAgent/system_prompt.jinja:424`).
- Hypotheses carry structured states (`open/testing/confirmed/rejected`) and evidence-for/against (`phantom/agents/hypothesis_ledger.py:18`, `phantom/agents/hypothesis_ledger.py:161`).
- Coverage tracker reports factual tested/untested surfaces (no commands) (`phantom/agents/coverage_tracker.py:10`, `phantom/agents/coverage_tracker.py:409`).
- Correlation engine reports chain suggestions (not mandatory actions) (`phantom/agents/correlation_engine.py:168`, `phantom/agents/correlation_engine.py:363`).

### 7.2 Reporting confidence and replay [E]

- Vulnerability reports support confidence tiers (`VERIFIED`, `LIKELY`, `SUSPECTED`) (`phantom/tools/reporting/reporting_actions.py:561`, `phantom/tools/reporting/reporting_actions.py:637`).
- PoC replay runs asynchronously and can upgrade confidence to VERIFIED on exploit-confirmed replay (`phantom/tools/reporting/reporting_actions.py:648`, `phantom/tools/reporting/reporting_actions.py:704`).
- Replay status is surfaced explicitly (`PENDING`, `FAILED`, `SKIPPED`, etc.) (`phantom/tools/reporting/reporting_actions.py:643`, `phantom/tools/reporting/reporting_actions.py:880`).

### 7.3 Malformed/ambiguous tool intent handling [E]

- If output looks like a tool call but parse fails, the system prepends a corrective message saying call was not executed (`phantom/llm/llm.py:555`, `phantom/llm/llm.py:562`).

---

## 8) Resilience and Governance in the Reasoning Path

### 8.1 Retry/backoff/cooldown [E]

- Model call retries classify rate-limit vs unknown vs non-retryable errors (`phantom/llm/llm.py:370`, `phantom/llm/llm.py:402`, `phantom/llm/llm.py:1259`).
- Process-wide rate-limit cooldown is shared across agent calls (`phantom/llm/llm.py:72`, `phantom/llm/llm.py:336`, `phantom/llm/llm.py:446`).

### 8.2 Circuit breaker [E][I]

- Global circuit breaker state (CLOSED/OPEN/HALF_OPEN) blocks calls after repeated failures (`phantom/llm/llm.py:89`, `phantom/llm/llm.py:181`, `phantom/llm/llm.py:344`).
- Config includes `phantom_circuit_breaker_enabled`, but current LLM flow does not branch on that flag; breaker is effectively always active when code path runs (`phantom/config/config.py:89`, `phantom/llm/llm.py:343`).

### 8.3 Budget and model adaptation [E]

- Budget thresholds: warn at 80%, degrade at 90%, abort/advisory at 100% (`phantom/llm/llm.py:848`, `phantom/llm/llm.py:876`, `phantom/llm/llm.py:925`).
- Routing can split reasoning vs tool-heavy turns by message-shape heuristic (`phantom/llm/llm.py:1019`).
- Adaptive scan mode can downgrade deep -> standard -> quick under budget pressure (`phantom/llm/llm.py:210`, `phantom/llm/llm.py:1044`).
- Fallback model can be used after primary retry exhaustion (`phantom/llm/llm.py:451`).

### 8.4 Notable dormant/partial constructs [E][M]

- `_TokenRateLimiter` exists but is not integrated into `generate()` path (`phantom/llm/llm.py:186`).
- This suggests an incomplete/abandoned per-model throttle abstraction.

---

## 9) Inferred Architecture (what is implicit or missing)

### 9.1 [M] ReasoningPolicyEngine

Rationale: policy logic is spread across prompt mandates, loop heuristics, and reporting constraints. A unified policy engine would centralize:

- proof thresholds
- stall/no-action policy
- phase gating and wrap-up triggers
- confidence/replay promotion rules

Evidence of current dispersion:

- Prompt mandates (`system_prompt.jinja`), loop warnings (`phantom/agents/base_agent.py:307`), report confidence logic (`phantom/tools/reporting/reporting_actions.py:637`).

### 9.2 [M] CapabilityContract (hard tool scope)

Rationale: tool subset currently shapes prompt exposure but does not enforce runtime least-privilege boundaries.

- Prompt subset logic: `phantom/llm/llm.py:277`, `phantom/tools/dynamic_tools.py:204`
- Runtime still validates against full registry: `phantom/tools/registry.py:217`, `phantom/tools/executor.py:537`

### 9.3 [M] DeliberatePlanner module

Rationale: explicit long-horizon planning is currently emergent from prompt text and periodic status injections, not represented as durable plan state with execution checkpoints.

- No active planner object in core loop (`phantom/agents/base_agent.py:247`)
- Existing helper plan function is disconnected (`phantom/tools/agents_graph/agents_graph_actions.py:586`)

### 9.4 [M] UncertaintyManager

Rationale: uncertainty is handled across multiple subsystems (ledger evidence, correlation suggestions, reporting confidence/replay). A dedicated abstraction could unify confidence propagation from signal -> hypothesis -> confirmed finding.

---

## Reasoning Engine Reconstruction Statement

Phantom's reasoning engine is a host-side, iterative ReAct controller in which the LLM is the decision policy, the tool executor is the action runtime, and tool observations are the feedback signal. Planning is mostly prompt-driven and state-injected (ledger/coverage/correlation), not implemented as a first-class planner object. Reliability and governance are substantial (retry, cooldown, circuit breaker, budget degradation, fallback/routing), but capability scoping and uncertainty handling remain distributed across layers and are best modeled as implicit architecture rather than a unified subsystem.
