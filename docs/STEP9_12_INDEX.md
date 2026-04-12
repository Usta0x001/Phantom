# Step 9-12 Adversarial Index

## Purpose

This index links the Step 9-12 reports into one blocker-first view so claims can be verified, challenged, and invalidated quickly.

Canonical reports:

- Step 9: `docs/TOOLING_AND_EXECUTION_MODEL.md`
- Step 10: `docs/SECURITY_MODEL.md`
- Step 11: `docs/FAILURE_MODES.md`
- Step 12: `docs/GAP_ANALYSIS.md`

## Blocker Index (cross-report)

| Blocker ID | Claim under test | Code-grounded result | Primary reports | Step 8 wave |
|---|---|---|---|---|
| B1 / G1 | Tool subset provides least privilege | Invalid. Subset is prompt visibility only; executor still uses registry-wide availability. | Step 9, Step 10, Step 12 | Wave C |
| B2 / G2 | Injection and code safety gates actively protect execution | Invalid. Executor injection validator and Python code safety validator are disabled/no-op. | Step 10, Step 12 | Wave B |
| B3 / G3 | Authorization is reliably enforced | Invalid for hardened posture. RBAC is default-off and permissive on import failure. | Step 10, Step 12 | Wave B |
| B4 / G4 | Circuit-breaker toggle controls behavior | Invalid. Config flag exists, but generate path checks breaker unconditionally. | Step 6, Step 8, Step 12 | Wave B |
| B5 / G5 | Per-agent context is consistent across all execution modes | Invalid. `current_agent_id` is set in tool-server path but not in local executor path. | Step 11, Step 12 | Wave D |
| B6 / G6 | Runtime state is run-scoped and isolated | Invalid. Multiple process-global mutable stores create shared-fate coupling. | Step 11, Step 12 | Wave D |
| B7 / G7 | Checkpoint restore fully supports sub-agent continuity | Invalid. Build schema supports sub-agents, but save/load/consume path is not wired end-to-end. | Step 11, Step 12 | Wave D |
| B8 / G8a | Scan-status recommendation is type-safe | Invalid. Recommendation slices a `DiscoveredSurface` object (`top[:50]`). | Step 6, Step 11, Step 12 | Wave A |
| B9 / G8b | Auto-hypothesis path is single and deterministic | Invalid. Active direct path exists, but legacy helper path is broken and divergent. | Step 6, Step 11, Step 12 | Wave A |

## Direct Evidence Anchors (code-first)

- B1 / G1: Prompt subset is applied in prompt build only (`phantom/llm/llm.py:277`, `phantom/llm/llm.py:286`), while runtime availability remains registry-based (`phantom/tools/executor.py:537`, `phantom/tools/registry.py:217`).
- B2 / G2: Injection validator is a hard no-op (`phantom/tools/executor.py:238`, `phantom/tools/executor.py:249`); Python code safety validator is also a no-op (`phantom/tools/python/python_instance.py:22`, `phantom/tools/python/python_instance.py:34`).
- B3 / G3: RBAC defaults to disabled (`phantom/config/config.py:96`), RBAC-disabled path effectively grants admin role (`phantom/tools/rbac.py:125`, `phantom/tools/rbac.py:128`), and executor allows on RBAC import failure (`phantom/tools/executor.py:383`, `phantom/tools/executor.py:384`).
- B4 / G4: Config exposes toggle (`phantom/config/config.py:89`), but `LLM.generate` checks breaker unconditionally (`phantom/llm/llm.py:343`, `phantom/llm/llm.py:344`).
- B5 / G5: Tool server sets context (`phantom/runtime/tool_server.py:122`), local executor path does not (`phantom/tools/executor.py:515`), while managers key on `get_current_agent_id()` (`phantom/tools/terminal/terminal_manager.py:30`, `phantom/tools/python/python_manager.py:20`, `phantom/tools/browser/tab_manager.py:19`).
- B6 / G6: Process-global mutable state exists in runtime/tracer/LLM/graph/status/cache (`phantom/runtime/__init__.py:15`, `phantom/telemetry/tracer.py:32`, `phantom/llm/llm.py:70`, `phantom/llm/llm.py:181`, `phantom/tools/agents_graph/agents_graph_actions.py:10`, `phantom/tools/scan_status/scan_status_actions.py:22`, `phantom/tools/cache.py:383`).
- B7 / G7: Checkpoint build supports sub-agents (`phantom/checkpoint/checkpoint.py:344`, `phantom/checkpoint/checkpoint.py:429`), root save call does not pass active sub-agents (`phantom/agents/base_agent.py:914`), resume stores restored sub-agent states in config (`phantom/interface/cli.py:266`), and no restore-consume path is present under `phantom/agents`.
- B8 / G8a: Recommendation slices object (`phantom/tools/scan_status/scan_status_actions.py:212`) while untested entries are `DiscoveredSurface` dataclasses (`phantom/agents/coverage_tracker.py:57`, `phantom/agents/coverage_tracker.py:61`).
- B9 / G8b: Active enrichment writes to `agent_state.hypothesis_ledger` (`phantom/tools/executor.py:1399`, `phantom/tools/executor.py:1404`), but legacy helper imports missing `_ledger` symbol (`phantom/tools/executor.py:1507`, `phantom/tools/hypothesis/hypothesis_actions.py:84`).
- S1: Firewall derives targets from `scan_config` inside sandbox create path (`phantom/runtime/docker_runtime.py:526`, `phantom/runtime/docker_runtime.py:553`), but root call omits `scan_config` argument (`phantom/agents/base_agent.py:589`).
- S2: OAST callback recorder exists (`phantom/tools/oast/oast_manager.py:168`) with no additional callsites in repository search.
- S3: OTEL enable check hard-returns false (`phantom/telemetry/flags.py:1`, `phantom/telemetry/flags.py:5`).

## High-Risk Supporting Gaps (tracked, not primary Step 12 IDs)

| Gap ID | Observation | Why it matters | Primary reports | Step 8 wave |
|---|---|---|---|---|
| S1 | Scope firewall enforcement is conditional on `scan_config` reaching sandbox creation path | Intended network boundary can be absent in current root call path | Step 10, Code-level report | Wave B/D |
| S2 | OAST callback ingestion is not wired to runtime callsites | Blind callback evidence can be missed | Step 11 | Wave A/D |
| S3 | OTEL path is effectively disabled by flag behavior | Reduced external observability during rollout hardening | System/Architecture layered reports | Wave D |

## Cross-Report Consistency Notes

- Auto-hypothesis wording was normalized from "fully inert" to "split path" to reflect the active enrichment path plus broken legacy helper.
- Sub-agent checkpoint wording was normalized to avoid implying active rehydration in current runtime.
- Scope-firewall wording was normalized to "conditional activation" rather than guaranteed enforcement.

## Step 8 Wave Mapping (execution order)

1. Wave A (correctness): B8, B9 (plus S2 telemetry/ingestion visibility)
2. Wave B (policy truth): B2, B3, B4 (plus S1 enforcement truth)
3. Wave C (hard capability contracts): B1
4. Wave D (state ownership): B5, B6, B7 (plus S1/S3 long-term hardening)

## Recommended Read Path for Auditors

1. Validate runtime mechanics in `docs/TOOLING_AND_EXECUTION_MODEL.md`.
2. Challenge boundary and guard claims in `docs/SECURITY_MODEL.md`.
3. Stress failure behavior in `docs/FAILURE_MODES.md`.
4. Confirm readiness verdict and gates in `docs/GAP_ANALYSIS.md`.
5. Use `docs/STEP8_GO_NO_GO_CHECKLIST.md` as release decision sheet.
