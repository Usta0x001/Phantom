# Wave A/B Fixes Verification and Adversarial Proof

## Scope

This report verifies implementation and attack-tests for:

- Wave A: scan-status typing fix, unified auto-hypothesis path, visible status-injection failure event.
- Wave B gates: hardened-mode injection guard, hardened Python code safety guard, hardened RBAC fail-closed, circuit-breaker toggle truth.

## Code changes applied

1. Wave A scan-status typing fix
   - `phantom/tools/scan_status/scan_status_actions.py:212`
   - Replaced object slicing with typed extraction of `top.surface` fallback to string conversion.

2. Wave A auto-hypothesis path unification
   - `phantom/tools/executor.py:1471`
   - Removed duplicate legacy invocation branch from loop body.
   - Unified to one deterministic `_auto_record_hypothesis(...)` path that uses `agent_state.hypothesis_ledger` only.

3. Wave A status-injection failure visibility
   - `phantom/agents/base_agent.py:635`
   - On scan-status injection exception, now emits `scan_status.injection.failed` with structured payload.
   - Added runtime-safe event path in tracer to ensure event is written even when OTEL is disabled.
   - `phantom/telemetry/tracer.py:275` (`record_runtime_event`).

4. Wave B policy gates (tests required by checklist)
   - Hardened mode config baseline added:
     - `phantom/config/config.py:96` (`phantom_security_mode`, default `research`).
   - Hardened injection validator activated by mode:
     - `phantom/tools/executor.py:267`.
   - Hardened RBAC fail-closed behavior:
     - denies when RBAC disabled/unavailable in hardened mode (`phantom/tools/executor.py:436`, `phantom/tools/executor.py:451`).
   - Hardened Python safety gate by mode:
     - `phantom/tools/python/python_instance.py:22`.
   - Circuit-breaker toggle truth wired:
     - `phantom/llm/llm.py:184`, `phantom/llm/llm.py:348`, `phantom/llm/llm.py:551`, `phantom/llm/llm.py:1292`.

## Test gates added (provable closure)

Added: `tests/test_wave_a_b_gates.py`

- Wave A checks:
  - recommendation handles `DiscoveredSurface` without type crash.
  - auto-hypothesis writes into agent ledger (no legacy global import dependency).
  - status injection failure emits structured event.

- Wave B checks:
  - hardened injection guard blocks semicolon command chaining.
  - hardened Python safety blocks `import os` + `os.system(...)`.
  - hardened mode RBAC denies when RBAC disabled.
  - circuit-breaker toggle tests for enabled/disabled truth paths.

## Command evidence

1. Main Wave A/B gate suite:
   - Command: `python -m pytest tests/test_wave_a_b_gates.py -q`
   - Result: `9 passed`

2. Hardened-mode subset attack tests:
   - Command: `python -m pytest tests/test_wave_a_b_gates.py -q -k "wave_b_hardened_injection_guard_blocks_semicolon_payload or wave_b_hardened_python_safety_blocks_os_system or wave_b_hardened_rbac_denies_when_disabled"`
   - Result: `3 passed`

3. Tool path sanity check:
   - Command: `python -c "... execute_tool('get_scan_status', include_recommendations=False) ..."`
   - Result: successful structured response.

4. Circuit-breaker toggle attack tests:
   - Command: `python -m pytest tests/test_wave_a_b_gates.py -q -k "circuit_breaker_toggle"`
   - Result: `3 passed`
   - Proof: when toggle is false, generate path bypasses OPEN gate and reaches downstream failure path; when toggle is true, OPEN gate blocks early.

5. Runtime-event persistence proof (OTEL-independent):
   - Command: `python -c "... Tracer(...).record_runtime_event(...); ..."`
   - Result: `scan_status.injection.failed` present in `phantom_runs/wave-event-proof/events.jsonl`.

## Adversarial attack outcomes

1. Attack: type-crash recommendation by forcing `DiscoveredSurface` object in untested list.
   - Before: `top[:50]` risks exception.
   - After: typed `surface` extraction; test passes.

2. Attack: exploit legacy auto-hypothesis branch divergence.
   - Before: dual path with broken `_ledger` import branch.
   - After: single path; test verifies ledger mutation through agent state.

3. Attack: hide scan-status injection failures through broad catch.
   - Before: debug log only.
   - After: structured event emitted and captured in test.

4. Attack: command chaining in hardened mode.
   - Payload: `nmap 127.0.0.1; rm -rf /tmp/x`
   - After: blocked by validator in hardened mode.

5. Attack: Python runtime escape in hardened mode.
   - Payload: `import os; os.system('id')`
   - After: blocked by AST-based safety gate.

6. Attack: run with hardened mode but RBAC disabled.
   - After: fail-closed denial (`rbac_misconfigured`).

7. Attack: stale OPEN circuit with toggle disabled should still block.
   - Before: would block unconditionally.
   - After: test proves disabled toggle bypasses OPEN gate, while enabled toggle enforces block.

## Notes on unrelated baseline failures

- Existing repository tests still show unrelated failures in:
  - IPv6 SSRF edge handling in `phantom/tests/test_security_reliability.py`.
  - encoding-sensitive prompt file reads in `phantom/tests/test_reasoning_fixes.py` (Windows cp1252 decode path).
- These were present outside this Wave A/B patch scope and do not invalidate the new gate results.

Additional note:

- `git diff` reveals unrelated existing modifications in several core files (pre-existing in workspace). Verification in this report is strictly scoped to the touched lines and the new gate tests.

## Verdict

- Wave A implementation goals are met and verified with adversarial tests.
- Wave B gate proofs requested in checklist are now concretely test-backed for:
  - injection guard behavior by mode,
  - Python safety guard behavior by mode,
  - RBAC fail-closed hardened posture,
  - circuit-breaker toggle truth.
