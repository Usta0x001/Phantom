# Phantom v0.9.38 — Recommendations & Next Steps

**Date:** 2026-03-04  
**Baseline:** Zero-base audit (60 findings), 11 fixed in v0.9.38  
**Tests:** 731 passed, 97 skipped, 0 failures  

---

## Summary of v0.9.38 Fixes

| Priority | Found | Fixed | Remaining |
|----------|-------|-------|-----------|
| P0       | 4     | 4     | 0         |
| P1       | 10    | 2     | 8         |
| P2       | 21    | 5     | 16        |
| P3       | 25    | 1     | 24        |
| **Total**| **60**| **12**| **48**    |

---

## Immediate Recommendations (P1 remaining — should fix next)

### 1. Async Memory Compressor (`memory_compressor.py`)
The synchronous `litellm.completion()` call blocks the event loop for 5–15 seconds during compression. Replace with `await litellm.acompletion()` or delegate to a thread via `asyncio.to_thread()`.

### 2. Jinja Autoescape (`base_agent.py:42`)
`autoescape=select_autoescape(enabled_extensions=(), default_for_string=False)` disables HTML escaping. If skill files are user-provided or writable by the agent, this is an SSTI vector. Enable with `default_for_string=True` or validate templates before rendering.

### 3. DNS Pin TTL (`scope_validator.py`)
The DNS resolution cache has no TTL — stale entries persist for the entire scan duration. Add a `max_age` parameter (recommended: 300s) and evict expired entries before DNS checks.

### 4. Regex-to-CLI Passthrough
Several tools accept user-supplied regex patterns that are passed to CLI commands (nuclei, ffuf). Sanitize or allowlist characters to prevent shell injection.

### 5. Plugin Code Execution Without Signing
If the plugin system loads external Python modules, consider adding signature verification (hash whitelist or PGP) to prevent tampered plugins from executing arbitrary code.

### 6. Header Injection in Auth Inject
The `send_request` tool should validate that auth header values don't contain `\r\n` sequences (HTTP header injection / response splitting).

### 7. Dedup LLM Cost Tracking (`dedupe.py`)
LLM calls made by the deduplication engine bypass the `CostController`. Wire `record_usage()` calls after each dedup completion.

### 8. Knowledge Store Indentation
The YAML knowledge store output has inconsistent indentation (2-space vs 4-space) which can cause parse failures on reload. Standardize to 2-space.

---

## Medium-Term Recommendations (P2 remaining)

### Architecture
1. **Checkpoint completeness** — `pending_verification`, priority queues (`_vuln_queue`, `_scan_queue`), and conversation messages are lost on checkpoint restore. These should be serialized in `to_checkpoint()` and restored in `from_checkpoint()`.
2. **`_cumulative_elapsed_seconds` never updated** — Time limit enforcement is broken on resumed scans. Wire the timer update in the main loop.
3. **Stealth delay for host-side tools** — Currently only sandbox tools get rate-limited. Host-side tools (proxy_actions, findings, reporting) should respect the same stealth profile.
4. **TOCTOU in SSRF checks** — DNS is resolved once for the SSRF check, then the HTTP library re-resolves. Pin the IP by passing a custom `resolve` parameter to requests/httpx.
5. **ReDoS in `_search_content`** — Add `re.TIMEOUT` (Python 3.14) or wrap in a thread with a 2-second deadline.
6. **Markdown injection in reports** — User-controlled input that ends up in Markdown reports should escape `[`, `]`, `(`, `)`, and backticks.

### Testing
7. **Integration tests for auth token flow** — The token store, capture, and injection pipeline has no integration test. Add a test that simulates login → capture → re-inject flow.
8. **Checkpoint round-trip tests** — Verify that `to_checkpoint()` → `from_checkpoint()` preserves all state (especially the newly identified missing fields).
9. **Cost controller concurrency test** — Spin up 10 threads calling `record_usage()` and `get_remaining_budget()` simultaneously to verify the lock is working.

---

## Long-Term Recommendations

### 1. Tool Firewall Re-enablement
The tool firewall was disabled (H-02) because it was too restrictive. Rather than disabling it entirely, implement a **soft firewall** that logs violations but allows execution — this gives visibility without blocking scans.

### 2. Structured Auth Token Management
Replace the simple `dict[str, str]` token store with a proper `AuthSession` class:
- Per-domain token scoping (already partially addressed in v0.9.38)
- Token expiration tracking (JWT `exp` claim parsing)
- Automatic refresh flows
- Secure storage (don't persist raw tokens in checkpoints)

### 3. Observability & Cost Dashboard
- Wire ALL LLM calls through `CostController` (compressor, dedup, verification engine)
- Add Prometheus/OpenTelemetry metrics for cost, token usage, tool execution times
- Dashboard showing real-time scan cost vs. budget

### 4. Formal Threat Model
Document the trust boundaries:
- Agent prompt (trusted)
- Scan target responses (untrusted — XSS, header injection, SSRF)  
- User-supplied scan config (semi-trusted)
- Plugin/skill files (trust-level TBD)
- Knowledge store files (semi-trusted, writable by agent)

### 5. Python 3.14 Migration
- Replace deprecated `asyncio.iscoroutinefunction` with `inspect.iscoroutinefunction` (16 warnings in tests)
- Leverage `re.TIMEOUT` for regex safety
- Consider `TaskGroup` for structured concurrency in the agent loop

### 6. Test Coverage Targets
Current: 731 tests, 97 skipped. Recommended targets:
- **Agent core** (base_agent, enhanced_state, state): 90%+ line coverage
- **Tools** (executor, proxy_manager, registry): 85%+ line coverage
- **Security-critical paths** (scope_validator, SSRF, auth): 95%+ line coverage
- **Unskip** the 97 skipped tests incrementally (many are likely stale)

---

## Files Changed in v0.9.38

| File | Changes |
|------|---------|
| `phantom/agents/base_agent.py` | P0 race fix, P1 f-string, P2 stale ref, P2 iter guard, P3 comment |
| `phantom/agents/enhanced_state.py` | P2 mark_endpoint_tested cap |
| `phantom/agents/PhantomAgent/phantom_agent.py` | P0 auth leak, P2 profile guard |
| `phantom/core/cost_controller.py` | P1 lock on getters |
| `phantom/tools/proxy/proxy_manager.py` | P0 token cap, P0 domain scope |
| `phantom/tools/executor.py` | P2 exception log level |
| `pyproject.toml` | Version bump 0.9.37 → 0.9.38 |
| `CHANGELOG.md` | v0.9.38 entry |
| `docs/phantom_system_report.tex` | LaTeX compilation fixes (TikZ, amssymb) |
