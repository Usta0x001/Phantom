# Step 9-12 Auditor Verdict (Adversarial)

## Scope and method

This verdict treats all Step 9-12 claims as untrusted until verified against code paths.
Method applied: claim extraction -> adversarial challenge -> code-path verification -> cross-report contradiction check -> release-impact scoring.

Primary report set:

- `docs/TOOLING_AND_EXECUTION_MODEL.md` (Step 9)
- `docs/SECURITY_MODEL.md` (Step 10)
- `docs/FAILURE_MODES.md` (Step 11)
- `docs/GAP_ANALYSIS.md` (Step 12)

Primary evidence index:

- `docs/STEP9_12_INDEX.md`
- `docs/STEP8_GO_NO_GO_CHECKLIST.md`

## 1) Claim validation (pass/fail)

1. Claim: tool subset equals runtime least privilege -> **FAIL**.
   - Prompt subset is applied at prompt construction (`phantom/llm/llm.py:277`), but executor checks full runtime registry (`phantom/tools/executor.py:537`).
2. Claim: executor injection/code safety gates are active controls -> **FAIL**.
   - Injection validator no-op (`phantom/tools/executor.py:238`, `phantom/tools/executor.py:249`); Python safety validator no-op (`phantom/tools/python/python_instance.py:22`, `phantom/tools/python/python_instance.py:34`).
3. Claim: authorization is reliably enforced -> **FAIL (hardened posture)**.
   - RBAC default disabled (`phantom/config/config.py:96`); import failure allows execution (`phantom/tools/executor.py:383`, `phantom/tools/executor.py:384`).
4. Claim: circuit-breaker flag truthfully controls behavior -> **FAIL**.
   - Flag exists (`phantom/config/config.py:89`), but breaker gate is unconditional (`phantom/llm/llm.py:343`).
5. Claim: context propagation is uniform across execution paths -> **FAIL**.
   - Tool-server sets agent context (`phantom/runtime/tool_server.py:122`); local path does not (`phantom/tools/executor.py:515`).

## 2) Internal consistency audit

- Reports are now consistent on auto-hypothesis behavior: active direct enrichment + broken legacy helper path (`phantom/tools/executor.py:1399`, `phantom/tools/executor.py:1507`).
- Reports are now consistent on sub-agent resume: schema support exists, runtime consumption path is missing (`phantom/checkpoint/checkpoint.py:344`, `phantom/agents/base_agent.py:914`, `phantom/interface/cli.py:266`).
- Reports are now consistent on scope-firewall posture: conditional activation depending on `scan_config` propagation (`phantom/runtime/docker_runtime.py:553`, `phantom/agents/base_agent.py:589`).

## 3) Architecture audit

- Strong boundary primitives exist (auth token, timeout, registry/schemas, output sanitization).
- Architectural weakness is enforcement asymmetry: prompt-level minimization and config toggles overstate hard runtime control.
- Isolation model is hybrid by design (sandbox + host-local tools), so production-hardening must explicitly scope where fail-closed guarantees apply.

## 4) Reasoning engine audit (critical)

- Strategy continuity depends on injected synthetic summaries (`scan_status`, ledger, coverage, correlation) before decisions (`phantom/agents/base_agent.py:620`, `phantom/agents/base_agent.py:646`).
- Known strategic defect remains in recommendation typing (`phantom/tools/scan_status/scan_status_actions.py:212` with `DiscoveredSurface` from `phantom/agents/coverage_tracker.py:57`).
- Auto-hypothesis split paths create non-deterministic memory enrichment quality under load.

## 5) Code analysis validity audit

- Report claims are now anchored to executable call paths, not only helper function existence.
- High-risk false-positive pattern eliminated: "implemented helper" is not treated as "active guard" unless call path proves activation.
- Evidence standard used: runtime entrypoint -> invoked branch -> side-effect location.

## 6) Data-flow verification

- Verified path: parsed tool invocations -> `execute_tool_with_validation` -> `execute_tool` -> local or sandbox dispatch (`phantom/tools/executor.py:579`, `phantom/tools/executor.py:617`, `phantom/tools/executor.py:427`).
- Observation reinjection verified as next-turn user input (`phantom/tools/executor.py:1480`).
- Scope-firewall gap verified at integration point: sandbox create accepts `scan_config`, but root call omits it (`phantom/runtime/docker_runtime.py:526`, `phantom/agents/base_agent.py:589`).

## 7) Memory and context audit

- Global mutable state footprint is broad (runtime/tracer/LLM/graph/status/cache), creating shared-fate risk across runs.
- ContextVar-based manager partitioning depends on consistent propagation; local path asymmetry breaks that assumption.
- Checkpoint durability is strong for root strategic stores, but sub-agent continuity is not restored end-to-end.

## 8) Security audit validity

- Valid strong controls: sandbox auth/timeouts, SSRF guard depth, workspace path boundaries, telemetry/output sanitization.
- Invalidated hardening claims: injection/code gates active, fail-closed RBAC, runtime least privilege.
- Security conclusion remains mixed posture, not fail-closed hardened posture.

## 9) Depth test (anti-shallow)

- Depth passed for blocker discovery: defects proven via call-path mismatch and runtime asymmetry, not naming heuristics.
- Depth gap still open until tests prove closure for each blocker in Wave A-D checklist.

## 10) Gap/failure detection completeness

Confirmed critical blockers B1-B9 (see `docs/STEP9_12_INDEX.md`).
Supporting high-risk gaps also tracked:

- S1 scope firewall conditional activation,
- S2 missing OAST callback ingestion path,
- S3 OTEL effectively disabled (`phantom/telemetry/flags.py:1`).

## 11) Cross-report consistency verdict

- Cross-report contradiction count on high-impact claims is now materially reduced after corrections.
- Remaining risk is not report contradiction; it is unresolved code defects and non-enforced policy contracts.

## 12) Final verdict, score, and rewrite guidance

Readiness verdict: **NO-GO** for production-grade hardened expert-system posture.

Score (0-10, adversarial):

- Architectural clarity: 7
- Runtime policy hardness: 3
- Security fail-closed posture: 3
- State isolation/recovery rigor: 4
- Strategic reasoning robustness: 5
- Overall production-hardening readiness: **4.4 / 10**

Rewrite guidance for future reports:

1. Never treat prompt shaping as capability enforcement; always pair with executor allowlist evidence.
2. Treat guard functions as inactive until call-path + blocking behavior are proven.
3. Distinguish "serialized" from "restored and consumed" for checkpoint claims.
4. Label conditional controls explicitly (scope firewall, RBAC, telemetry toggles).
5. Require one negative proof per control claim (how it fails, not only how it succeeds).
