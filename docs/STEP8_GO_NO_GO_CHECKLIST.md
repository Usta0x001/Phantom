# Step 8 Wave Go/No-Go Checklist

One-page release gate for Step 8 waves A/B/C/D. A wave is GO only if all mandatory checks pass.

## Wave A - Correctness (immediate)

Mandatory checks:

- [ ] `scan_status` recommendation path no longer slices object types; test proves `DiscoveredSurface` handling is typed-safe.
- [ ] Auto-hypothesis path is singular and deterministic (legacy broken helper removed or fully redirected).
- [ ] Status-injection failure emits structured telemetry/event instead of silent degradation.
- [ ] Regression tests pass for recommendation generation and hypothesis enrichment behavior.

No-Go triggers:

- Any remaining divergent hypothesis write path.
- Any broad catch that hides recommendation failure without trace marker.

## Wave B - Policy Truth (security posture alignment)

Mandatory checks:

- [ ] `phantom_circuit_breaker_enabled` deterministically changes runtime breaker behavior (on/off tests).
- [ ] Injection validator posture is explicit by mode and enforced in code (research vs hardened).
- [ ] Python code safety posture is explicit by mode and enforced in code.
- [ ] RBAC behavior is explicit by mode; hardened mode is fail-closed on denied/missing policy module.

No-Go triggers:

- Config flags that do not change behavior.
- Hardened mode allows execution when policy component import fails.

## Wave C - Hard Capability Contracts

Mandatory checks:

- [ ] Executor enforces run-scoped allowlist before registry dispatch.
- [ ] Prompt tool subset is treated as optimization only, not a security boundary.
- [ ] Integration test proves model can request a valid-but-disallowed tool and executor denies.
- [ ] Allowed tools still execute across local and sandbox paths under contract.

No-Go triggers:

- Any dispatch path that bypasses allowlist enforcement.
- Contract enforced only in prompt construction, not in executor.

## Wave D - State Ownership and Isolation

Mandatory checks:

- [ ] `current_agent_id` propagation is consistent for both tool-server and local execution paths.
- [ ] Shared mutable globals are reduced or isolated under run-scoped owner(s).
- [ ] Checkpoint save/load/consume path restores sub-agent continuity end-to-end.
- [ ] Parallel-run isolation tests show no cross-run leakage (ledger/scan-status/session managers/cache).

No-Go triggers:

- Local execution path still lacks deterministic agent context binding.
- Restored sub-agent state exists in checkpoint payload/config but is not consumed by runtime.

## Final Step 8 Decision Rule

GO only when:

1. Every mandatory check in Waves A-D is green.
2. No No-Go trigger is present.
3. Blockers B1-B9 in `docs/STEP9_12_INDEX.md` are closed with test evidence.

Otherwise decision is NO-GO.
