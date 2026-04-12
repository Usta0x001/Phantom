# Phantom Gap Analysis for Production-Grade Expert-System Readiness (Step 12)

## Scope and proof standard

This analysis identifies concrete gaps between current implementation and production-grade expert-system requirements. Each gap includes implementation proof and why it blocks readiness.

Primary anchors:

- Executor and policy gates: `phantom/tools/executor.py:579`, `phantom/tools/executor.py:598`, `phantom/tools/executor.py:238`
- Capability shaping path: `phantom/llm/llm.py:277`, `phantom/tools/dynamic_tools.py:204`, `phantom/tools/executor.py:537`
- Authorization and config truth: `phantom/config/config.py:96`, `phantom/tools/executor.py:383`, `phantom/config/config.py:89`, `phantom/llm/llm.py:343`
- Session/context isolation: `phantom/runtime/tool_server.py:122`, `phantom/tools/executor.py:515`, `phantom/tools/context.py:4`
- Shared global state: `phantom/runtime/__init__.py:15`, `phantom/llm/llm.py:70`, `phantom/telemetry/tracer.py:32`, `phantom/tools/agents_graph/agents_graph_actions.py:10`
- Checkpoint/resume parity: `phantom/checkpoint/checkpoint.py:344`, `phantom/agents/base_agent.py:914`, `phantom/interface/cli.py:266`

---

## 1) Readiness blocker matrix (proof-based)

## G1) No hard runtime capability contract

Required for readiness:

- Runtime allowlist enforcement independent of prompt visibility.

Implementation proof of gap:

- Tool subset is prompt-surface filtering only: `phantom/llm/llm.py:277`, `phantom/tools/dynamic_tools.py:204`.
- Runtime availability is still entire registry: `phantom/tools/executor.py:537`.

Why this blocks production-grade posture:

- Capability minimization is soft and model-dependent; not fail-closed at dispatch boundary.

## G2) Critical input safety gates are disabled

Required for readiness:

- Active argument/code safety gates (or explicit hardened-mode equivalents) on side-effecting tools.

Implementation proof of gap:

- Injection validator always returns `None`: `phantom/tools/executor.py:238`, `phantom/tools/executor.py:249`.
- Python code safety validator always returns `None`: `phantom/tools/python/python_instance.py:22`, `phantom/tools/python/python_instance.py:34`.

Why this blocks production-grade posture:

- Dangerous-but-schema-valid inputs are not blocked by executor policy layer.

## G3) Authorization posture is optional/fail-open

Required for readiness:

- Explicit fail-closed authorization in hardened mode.

Implementation proof of gap:

- RBAC disabled by default: `phantom/config/config.py:96`.
- RBAC import failure path allows execution: `phantom/tools/executor.py:383`, `phantom/tools/executor.py:384`.

Why this blocks production-grade posture:

- Access-control guarantees are conditional and can silently disappear.

## G4) Config-to-runtime truth drift exists

Required for readiness:

- Feature toggles that reliably control behavior.

Implementation proof of gap:

- `phantom_circuit_breaker_enabled` exists in config: `phantom/config/config.py:89`.
- Generate path checks breaker unconditionally without flag branch: `phantom/llm/llm.py:343`.

Why this blocks production-grade posture:

- Operational controls cannot be trusted to represent actual behavior.

## G5) Session/tool state isolation is not guaranteed across execution paths

Required for readiness:

- Deterministic per-agent context propagation in all tool execution modes.

Implementation proof of gap:

- Tool-server path sets `current_agent_id`: `phantom/runtime/tool_server.py:122`.
- Local executor path does not set it before manager/tool execution: `phantom/tools/executor.py:515`.
- Managers key session state by context var: `phantom/tools/terminal/terminal_manager.py:30`, `phantom/tools/python/python_manager.py:20`, `phantom/tools/context.py:4`.

Why this blocks production-grade posture:

- Cross-agent/session contamination can occur in host-local path.

## G6) Shared mutable globals create cross-run coupling and shared-fate failures

Required for readiness:

- Run-scoped ownership for mutable execution, policy, and telemetry state.

Implementation proof of gap:

- Global runtime/tracer/LLM stats and controls/agent graph/scan status/cache:
  - `phantom/runtime/__init__.py:15`
  - `phantom/telemetry/tracer.py:32`
  - `phantom/llm/llm.py:70`, `phantom/llm/llm.py:72`, `phantom/llm/llm.py:181`
  - `phantom/tools/agents_graph/agents_graph_actions.py:10`
  - `phantom/tools/scan_status/scan_status_actions.py:22`
  - `phantom/tools/cache.py:383`

Why this blocks production-grade posture:

- Isolation, reproducibility, and concurrency guarantees remain brittle.

## G7) Checkpoint/recovery model is not fully wired for sub-agent continuity

Required for readiness:

- Full parity between serialized state contracts and runtime restore application.

Implementation proof of gap:

- Checkpoint build supports `active_sub_agents`: `phantom/checkpoint/checkpoint.py:344`.
- BaseAgent checkpoint call does not pass `active_sub_agents`: `phantom/agents/base_agent.py:914`.
- CLI stores `_restored_sub_agent_states` into config: `phantom/interface/cli.py:266`.
- No consumption path found in `phantom/agents` for restored sub-agent state.

Why this blocks production-grade posture:

- Recovery completeness is partial; resumed multi-agent scans can lose execution continuity.

## G8) Strategic guidance paths include known correctness defects

Required for readiness:

- Deterministic and typed-safe strategic-state feedback.

Implementation proof of gap:

- `scan_status` recommendation slices object type: `phantom/tools/scan_status/scan_status_actions.py:212`, `phantom/agents/coverage_tracker.py:57`.
- Auto-hypothesis has split behavior: direct signal ingestion is active, but legacy `_auto_record_hypothesis` uses unresolved `_ledger`, creating divergent paths: `phantom/tools/executor.py:1399`, `phantom/tools/executor.py:1507`, `phantom/tools/hypothesis/hypothesis_actions.py:84`.

Why this blocks production-grade posture:

- Silent degradation in strategy quality and memory enrichment under realistic scans.

---

## 2) Alignment with Step 8 roadmap

Roadmap Wave A/B/C/D in `docs/TARGET_ARCHITECTURE_AND_EXECUTION_ROADMAP.md` maps directly to the blockers above:

- Wave A (correctness): closes G8.
- Wave B (policy truth): closes G3 and G4.
- Wave C (hard capability contracts): closes G1.
- Wave D (state ownership refactor): closes G5, G6, and recovery aspects of G7.

This confirms the roadmap direction is implementation-consistent and remains the shortest path to production-grade readiness.

---

## 3) Verification gates required before claiming readiness

Minimum proof gates:

1. Capability-denial integration tests proving executor rejects out-of-contract tools even when model emits valid names (G1).
2. Hardened-mode policy tests proving injection/code guardrails and RBAC fail-closed behavior (G2, G3).
3. Toggle-truth tests proving `phantom_circuit_breaker_enabled` and related flags change behavior deterministically (G4).
4. Cross-agent isolation tests for local and sandbox paths validating session separation in terminal/python/browser managers (G5).
5. Parallel-run isolation tests proving no cross-run leakage through global stores (G6).
6. Checkpoint/resume tests with active sub-agents proving continuity restoration (G7).
7. Regression tests for `scan_status` typed recommendation path and auto-hypothesis ledger wiring (G8).

---

## Production-readiness verdict (code-grounded)

Current implementation is not yet production-grade expert-system ready. The primary blockers are policy hardness gaps (runtime capability contracts, disabled input safety, optional/fail-open authorization), state-isolation coupling, and known correctness defects in strategic feedback/recovery paths.

These blockers are explicit in code paths and are not documentation-only concerns.
