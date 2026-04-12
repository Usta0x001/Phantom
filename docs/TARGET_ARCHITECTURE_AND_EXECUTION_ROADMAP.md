# Phantom Target Architecture and Execution Roadmap (Step 8)

## Scope and Evidence Basis

This phase converts Steps 1-7 into an execution-ready architecture roadmap: what to fix first, what to refactor later, and what must be true before calling the architecture stable.

Primary anchors used:

- Control kernel and state injection points: `phantom/agents/base_agent.py:615`, `phantom/agents/base_agent.py:901`
- Decision/runtime policy chokepoints: `phantom/llm/llm.py:333`, `phantom/tools/executor.py:579`
- Drift hotspots identified in Step 6: `phantom/tools/executor.py:238`, `phantom/tools/executor.py:1507`, `phantom/tools/scan_status/scan_status_actions.py:212`, `phantom/llm/llm.py:343`, `phantom/tools/executor.py:383`
- Memory/durability constraints from Step 7: `phantom/llm/llm.py:588`, `phantom/llm/llm.py:702`, `phantom/checkpoint/checkpoint.py:210`
- Global/shared-state coupling points: `phantom/runtime/__init__.py:15`, `phantom/telemetry/tracer.py:32`, `phantom/tools/agents_graph/agents_graph_actions.py:10`, `phantom/tools/scan_status/scan_status_actions.py:22`

---

## 1) Target Architecture (What "good" looks like)

## 1.1 Control and decision model

- Keep `BaseAgent.agent_loop` as the control kernel (iteration governance, stop conditions, checkpoint cadence).
- Keep `LLM.generate` as decision policy, but make policy toggles truthful and runtime-enforced.
- Keep executor as side-effect gate, but harden it into a strict capability contract instead of soft prompt-only scoping.

## 1.2 Runtime boundary model

- Preserve host orchestrator -> sandbox tool server token-auth boundary (`phantom/tools/executor.py:487`, `phantom/runtime/tool_server.py:85`).
- Make boundary posture explicit by mode: local-host execution (research) vs sandbox-required execution (hardened).

## 1.3 State ownership model

- Replace cross-module implicit globals with explicit run-scoped ownership.
- Keep `AgentState` as short-term loop memory, but make strategic stores (`hypothesis_ledger`, `coverage_tracker`, `correlation_engine`, `attack_graph`) explicitly run-bound and injectable without module globals.

---

## 2) Gap-to-Target Mapping

1. **Soft capability minimization**
   - Current: tool subsets mainly reduce prompt surface (`phantom/llm/llm.py:277`, `phantom/tools/dynamic_tools.py:204`).
   - Target: prompt subset + runtime allowlist enforced in executor before dispatch.

2. **Policy toggle drift**
   - Current: `phantom_circuit_breaker_enabled` exists but generate path does not branch on it (`phantom/config/config.py:89`, `phantom/llm/llm.py:343`).
   - Target: config toggles either control behavior or are removed.

3. **Strategic-memory enrichment fragility**
   - Current: signal-derived enrichment exists (`agent_state.hypothesis_ledger`) but legacy `_auto_record_hypothesis` still imports missing `_ledger`, leaving a broken parallel path (`phantom/tools/executor.py:1399`, `phantom/tools/executor.py:1507`, `phantom/tools/hypothesis/hypothesis_actions.py:84`).
   - Target: single deterministic ledger write path bound to agent/run context.

4. **Silent reasoning-quality degradation risk**
   - Current: scan-status recommendation path can fail from type mismatch and upstream injection catches broadly (`phantom/tools/scan_status/scan_status_actions.py:212`, `phantom/agents/base_agent.py:627`).
   - Target: typed-safe recommendation path + explicit telemetry on injection failure.

5. **Authorization posture ambiguity**
   - Current: RBAC disabled by default and permissive if module import fails (`phantom/config/config.py:96`, `phantom/tools/executor.py:383`).
   - Target: explicit mode-aware RBAC policy (strict in hardened mode, permissive only in research mode).

---

## 3) Execution Plan (Sequenced, low blast radius first)

## Wave A: Correctness Patches (immediate)

- Fix `_auto_record_hypothesis` to use explicit ledger source (`agent_state.hypothesis_ledger` first, then supported accessor) instead of `_ledger` import guess.
- Fix `scan_status` recommendation to use `top.surface` for `DiscoveredSurface` entries instead of slicing object.
- Emit a structured event when auto-status injection fails so strategy degradation is visible in artifacts.

Acceptance gates:

- Unit tests for hypothesis auto-record path with real `AgentState` fixture.
- Unit test for recommendation when `get_untested_surfaces()` returns dataclass objects.
- Event emission assertion for status-injection exception path.

## Wave B: Policy Truth Alignment

- Wire `phantom_circuit_breaker_enabled` into request admission path in `LLM.generate`.
- Decide and codify injection validator posture by mode:
  - research mode: relaxed
  - hardened mode: enabled gate
- Make RBAC import failure behavior explicit by mode (fail-closed for hardened mode).

Acceptance gates:

- Config-driven behavior tests proving toggle on/off changes execution.
- Deterministic executor tests for RBAC denied, missing RBAC module, and mode-dependent outcomes.

## Wave C: Hard Capability Contracts

- Introduce run-scoped capability allowlist (tool names) and enforce in `execute_tool_with_validation` before registry dispatch.
- Keep dynamic prompt subsets for token efficiency, but treat them as optimization only.

Acceptance gates:

- Integration test: model can request hidden tool name but executor denies if not in allowlist.
- Regression test: allowed tools still operate in both local and sandbox execution paths.

## Wave D: State Ownership Refactor

- Create explicit run context owner for shared subsystems currently attached through globals.
- Remove or isolate module-level mutable state where feasible (`scan_status` globals, agent graph global maps, tracer singleton usage points).

Acceptance gates:

- Resume test with sub-agents + shared strategic stores restored without relying on module-global wiring.
- Parallel run isolation test: two concurrent runs do not leak scan-status or ledger context.

---

## 4) Verification Matrix

- **Loop integrity**: no-action stalls, finish semantics, checkpoint cadence (`phantom/agents/base_agent.py:345`, `phantom/agents/base_agent.py:823`, `phantom/agents/base_agent.py:909`).
- **Decision integrity**: circuit-breaker and retry behavior by config (`phantom/llm/llm.py:343`, `phantom/llm/llm.py:370`, `phantom/llm/llm.py:1286`).
- **Policy integrity**: availability/arg-schema/RBAC/capability-allowlist ordering in executor (`phantom/tools/executor.py:589`, `phantom/tools/executor.py:593`, `phantom/tools/executor.py:377`).
- **Boundary integrity**: sandbox auth failures, per-agent cancellation semantics, timeout behavior (`phantom/runtime/tool_server.py:85`, `phantom/runtime/tool_server.py:146`, `phantom/runtime/tool_server.py:152`).
- **Durability integrity**: checkpoint size, integrity, migration, and restore paths (`phantom/checkpoint/checkpoint.py:217`, `phantom/checkpoint/checkpoint.py:277`, `phantom/interface/cli.py:95`).

---

## 5) Rollout and Safety Strategy

- Ship Wave A behind no flag (bug fixes).
- Ship Wave B/C behind explicit config flags first, then flip defaults after test soak.
- Preserve rollback by retaining legacy behavior flags for one release window.
- Record per-wave telemetry counters (policy denials, status-injection failures, capability-contract denials) in run artifacts for rollout confidence.

---

## 6) Definition of Done for Architecture Stabilization

Architecture is considered stabilized when all of the following are true:

1. Runtime capability boundaries are enforced by executor, not only prompt shaping.
2. Config toggles match runtime behavior (no false toggles).
3. Strategic-memory enrichment and scan-status guidance are deterministic and observable on failure.
4. Hardened mode has explicit fail-closed behavior for missing policy components.
5. Shared state is run-scoped enough to prevent cross-run/context leakage.

---

## Step 8 Reconstruction Statement

The next practical step after Steps 6-7 is not broad redesign; it is a staged convergence program: fix correctness drifts first, align policy toggles with runtime truth, then enforce hard capability contracts, then reduce global-state coupling with explicit run-scoped ownership. This preserves current strengths (loop control, boundary model, resumability) while removing the highest-risk architecture gaps with controlled blast radius.
