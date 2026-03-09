# Changelog

All notable changes to Phantom will be documented in this file.

## [0.9.45] - 2026-03-09

### Cleanup

- Removed all remaining `Strix` name references from CHANGELOG and root scripts
- Deleted legacy `msg_filter.py` (Strix→Phantom text substitution script, no longer needed)
- Verified telemetry: PostHog key empty, both `is_posthog_enabled()` and `is_otel_enabled()` return `False`
  — no Strix-specific telemetry identifiers anywhere in the codebase

## [0.9.44] - 2026-03-09

### Removed — Security Tool Wrappers

- Removed `phantom/tools/security/` entirely: nmap, nuclei, sqlmap, ffuf, subfinder, httpx,
  katana wrappers, sanitizer, and verification_actions
- Removed `phantom/tools/findings/` entirely: findings ledger tools
- Tool count is now **31** — flat, lean tool set
- The AI now uses `terminal_execute` directly to run all security tools inside the sandbox
- Removed `skip_tools` wiring: dropped from `LLMConfig`, `base_agent`, `executor`, and
  `registry` — no longer needed with a flat tool set

## [0.9.43] - 2026-03-09

### Branding

- **Fixed TUI splash screen** — Replaced with a full `PHANTOM` block-letter banner in the
  same style and Phantom-red (`#dc2626`) colour. This is the logo users see on every
  interactive scan launch.

### Telemetry

- **All telemetry permanently disabled** — Both `is_posthog_enabled()` and
  `is_otel_enabled()` now hard-return `False`. No PostHog events, no OTel spans,
  zero network connections on startup or scan completion. No config knobs checked.
  Default in README/docs updated to `false`.

### Scan Modes

- **`stealth` mode fully wired** — New skill file
  `phantom/skills/scan_modes/stealth.md` created with a complete methodology for
  low-noise covert assessments. Reasoning effort set to `low`. `skip_tools` now
  enforced (no `ffuf_directory_scan`, `sqlmap_test`, `subfinder_enumerate`,
  `create_sub_agent`).
- **`api_only` mode fully wired** — New skill file
  `phantom/skills/scan_modes/api_only.md` created with an API-focused methodology.
  Browser tools and subdomain discovery disabled by the profile.
- **Both modes restored to CLI** — `ScanMode` enum and `parse_arguments` choices
  now include `stealth` and `api_only`. The modes silently fell back to `deep`
  in 0.9.41–0.9.42 due to missing skill files — that is now fixed.

### Architecture — ScanProfile Enforcement

- **`skip_tools` wired end-to-end** — Previously `ScanProfile.skip_tools` was
  dead data (stored but never enforced). Now:
  1. `LLMConfig.__init__()` loads the matching `ScanProfile` and stores its
     `skip_tools` list.
  2. `get_tools_prompt(skip=...)` filters listed tools from the system prompt so
     the LLM never sees them.
  3. `execute_tool_with_validation()` checks `agent_state.context["skip_tools"]`
     and returns an error if the agent attempts to call a blocked tool.
  4. `BaseAgent.__init__()` propagates `skip_tools` into `agent_state.context`.
- **`LLMConfig` scan_mode validation** expanded to include `stealth` and
  `api_only` instead of falling back to `deep`.
- **Stealth reasoning effort** — `stealth` mode now sets reasoning effort to
  `low` (was inheriting `high` via the `else` branch). Quick remains `medium`,
  all others `high`.

## [0.9.42] - 2026-03-09

### Security / Telemetry

- **PostHog permanently disabled** — `is_posthog_enabled()` now hard-returns `False`.
  No telemetry data is collected, no connections are made to PostHog or any external
  analytics service. Zero network overhead on every scan invocation.

### CLI

- **Removed `stealth` and `api_only` scan modes from CLI** — These profiles existed
  in `scan_profiles.py` but had no corresponding skill files and silently fell back
  to `deep` behaviour. Removed from `ScanMode` enum to avoid confusion. Modes
  available: `quick`, `standard`, `deep`.

### Docker Sandbox

- **Fixed sandbox image reference** — Default `phantom_image` changed from the
  non-existent `ghcr.io/usephantom/phantom-sandbox:0.1.12` to
  `ghcr.io/usta0x001/phantom-sandbox:latest`. Fresh installs no longer fail with
  a 404 on first run.

## [0.9.40] - 2026-03-08

### Performance & Reliability

- **Async compression** — `compress_history()` is now `async def`; the blocking
  `litellm.completion()` call inside `_summarize_messages()` is offloaded to a
  thread via `asyncio.to_thread()`, eliminating event-loop stalls in long scans.
- **All-model prompt caching** — Removed the `_is_anthropic()` guard on cache-control
  injection; prompt caching now applies to every provider where
  `supports_prompt_caching()` returns True (Gemini Flash, etc.), cutting repeated
  system-prompt cost by up to 75%.
- **Quick-mode 38-tool filter** — Rebuilt `QUICK_MODE_TOOLS` from 27 to 38 tools;
  all attack/exploit tools restored (`ffuf_parameter_fuzz`, `sqlmap_dump_database`,
  `report_vulnerability`, `verify_vulnerability`, `check_known_vulnerabilities`);
  file/note/todo management tools excluded. Saves **6,512 tokens per LLM call (~21%)**
  in quick mode.
- **OpenRouter metadata cache** — A daemon thread fetches `/api/v1/models` once;
  `get_context_window()` resolves exact context lengths from the live cache before
  falling back to heuristic string matching, eliminating over-truncation for models
  like `mistral/mistral-large`.

### E2E Verification

- Confirmed scan of OWASP Juice Shop with `minimax/minimax-m2.5` via OpenRouter:
  found **Information Disclosure — Exposed FTP Directory Listing** (MEDIUM, CVSS 5.4).
  All 29 tool calls succeeded; budget stayed under $0.45.
- Test suite: 753 passed, 97 skipped (zero regressions).

## [0.9.39] - 2026-03-07

### Security & Reliability

- **SSRF hardening** — Added `_is_safe_url()` validation in `send_request` tool to
  block requests to private IP ranges and metadata endpoints.
- **Parameter normalizer** — Unified parameter handling across all HTTP tools to
  prevent injection via malformed parameter names.
- **Cost cap at 150K tokens** — Added per-request token limit to prevent runaway
  responses.
- **Dynamic provider detection** — Detects provider from model string at runtime;
  eliminates need for explicit `api_base` config for known OpenRouter models.
- **Memory overhead fix** — `_prepare_messages` no longer mutates the caller's
  conversation history list.

## [0.9.38] - 2026-03-04

### Zero-Base Audit — P0/P1/P2 Fixes

**P0 — Critical Fixes (4):**
- **Race condition in `cancel_current_execution()`** — `self._current_task` was read
  twice without a local snapshot, creating a TOCTOU window; `except RuntimeError` didn't
  catch `AttributeError`. Now snapshots into a local variable and catches both.
- **Unbounded auth token store** — `_auth_token_store` had no max size. Added
  `_MAX_AUTH_TOKENS = 50` with FIFO eviction via `set_auth_token()`.
- **Cross-domain token confusion** — `_capture_auth_from_response()` ran on ALL 200/201
  POST responses globally. Now scoped to `_ALLOWED_SSRF_HOSTS` (scan targets only).
- **Auth header credential leak** — Raw auth header values were embedded in the
  conversation history (checkpointed/logged). Now registered via proxy token store;
  only header *names* appear in the prompt.

**P1 — High-Impact Fixes (2):**
- **Lock-less reads in CostController** — `get_remaining_budget()` and
  `get_cost_summary()` read `self._state` without `self._lock`. Both now wrapped.
- **f-string in logger** — `logger.warning(f"Error checking agent messages: {e}")`
  replaced with lazy `%s` formatting in `base_agent.py`.

**P2 — Robustness Fixes (5):**
- **`mark_endpoint_tested()` wrong return at cap** — returned `False` when 10,000 cap
  hit, meaning the agent would retry the same endpoint. Now returns `True` (= "already
  tested, skip it").
- **Stale message reference** — `self.state.messages = conversation_history` in
  `_execute_actions` overwrote any trimming done by the LLM loop. Removed reassignment.
- **`max_iterations - 3` misfires** — injected a critical-warning when
  `max_iterations <= 3`. Now guarded with `if self.state.max_iterations > 3`.
- **`scan_profile` type not guarded** — `profile.get("max_iterations", 300)` crashed
  on non-dict objects. Now uses `hasattr`/`isinstance` chain with fallback.
- **Silent exception swallowing in auto-record** — `_auto_record_findings` catch-all
  used `_logger.debug()`. Elevated to `_logger.warning()`.

**P3 — Code Quality:**
- Fixed misleading comment `# was 200, reduced from 300` → `# default (300)`.

**Tests:** 731 passed, 97 skipped, 0 failures

## [0.9.37] - 2026-03-03

### Final Audit — Bug Fixes, Hardening & Dead Code Removal

**P1 — Critical Fixes:**
- **from_checkpoint() max_iterations** — was hardcoded to 200, ignoring the checkpoint's
  stored value. Now uses `data.get("max_iterations", 300)` so resumed scans keep the
  correct iteration limit.
- **is_approaching_max_iterations threshold** — was 0.93, too aggressive (agent only got
  7% of iterations for wrap-up). Changed to 0.85 for better wrap-up timing.

**P2 — Robustness Fixes:**
- **XSS body detection** — `body[:500]` was too small to catch XSS reflections in
  larger responses. Increased to `body[:2000]`.
- **CDATA injection** — tool results containing `]]>` would break the XML wrapper.
  Now escapes `]]>` as `]]]]><![CDATA[>` inside CDATA sections.
- **Auto-report cap** — `_auto_report_scanner_findings` capped at 25 per-scanner,
  causing large nuclei scans to silently drop findings. Raised to 100.

**P3 — Endpoint Growth Bounds:**
- `add_endpoint()` capped at 10,000 entries to prevent unbounded memory growth.
- `mark_endpoint_tested()` capped at 10,000 entries for same reason.
- `max_iterations` added to checkpoint allowed-keys whitelist.

**Dead Code Removed:**
- Deleted `phantom/core/authorization.py` (264 lines; never imported from scan pipeline)
- Removed dead `_vuln_rotation = None` assignment from PhantomAgent

**Documentation Updated:**
- `docs/ARCHITECTURE.md`: Removed references to deleted `tool_firewall.py` and 
  `loop_detector.py`, corrected defense-in-depth layers and iteration cap values.
- `docs/DOCUMENTATION.md`: Removed `tool_firewall` from module reference table.

**Tests:** 731 passed, 97 skipped, 0 failures

## [0.9.36] - 2026-03-03

### Critical Memory Bug Fix + Deep Cleanup

**CRITICAL FIX:**
- **Memory compression was BROKEN** since v0.9.35 — `get_conversation_history()` returned a copy,
  so in-place compression in llm.py operated on a disconnected copy that was discarded.
  Context grew unbounded until the brutal 500-message hard trim kicked in.
  Fixed: now returns direct reference.

**Alignment Fixes:**
- `max_iterations` default restored to 300 (was wrongly lowered to 200)
- Wall-clock time limit disabled by default
- Juice Shop auto-detection narrowed (no longer fires for ANY port-3000 target)
- `_execute_actions` now assigns reference directly (not redundant copy)

**Dead Code Removed:**
- Deleted `phantom/core/loop_detector.py` (never imported)
- Deleted `phantom/core/vuln_class_rotation.py` (never imported)
- Deleted `phantom/core/tool_firewall.py` (never imported)
- Deleted `test_vuln_rotation.py` (tests deleted module)
- Deleted 10 debug scripts from repo root
- Deleted 11 old audit markdown files from repo root

**Tests:** 737 passed, 91 skipped (dead feature tests auto-skipped), 0 failures

## [0.9.35] - 2026-03-03

### Guarantee Full Power — Remove ALL Remaining Overhead (17 Harmful Diffs)

Post-v0.9.34 deep code audit found 17 remaining differences still weakening Phantom. 
This release eliminates every one of them while keeping the 10 genuinely helpful additions.

#### Removed (Proven Harmful)

- **H-01: max_tokens cap removed** — Was truncating LLM output at 8192/16384 tokens, 
  causing tool calls to be cut mid-XML → parse failures → "agent does nothing" cycles.
- **H-02: Tool firewall disabled** — Injection pattern matching blocked legitimate 
  pentest payloads (SQLi `;`, SSTI `${}`, command injection backticks).
- **H-03: Loop detector removed** — False positives when methodically testing similar 
  endpoints. Injected "change your approach" messages abandoned productive attack vectors.
- **H-04: Phase transition system removed** — RECON→EXPLOIT→REPORT phases with 
  "Call finish_scan NOW" at 95% stole the last 15 iterations.
- **H-05: "No tool call" prescriptive nudge removed** — Was listing specific tools 
  the agent should use. Now silently continues.
- **H-06: Empty response handler simplified** — Removed prescriptive tool suggestions 
  and hidden "6+ vuln classes" gate. Now uses a simple corrective.
- **H-07: "Move on after 3-5 attempts" REMOVED** — THE biggest single weakness. 
  Replaced with "each failure teaches you something, the REAL work begins 
  when tools fail". Most real vulns need 10-50+ attempts.
- **H-08: "Follow ROTATION messages" removed** — Vestigial from disabled VulnClassTracker.
- **H-09: Full vulnerability methodology restored** — Restored detailed 
  EXPLOITATION APPROACH (basic→advanced→super-advanced), VULNERABILITY KNOWLEDGE BASE, 
  and "A single high-impact vulnerability is worth more than dozens of low-severity findings."
- **H-10: Python restriction removed** — "TOOLS FIRST / Only use python_action for 4 
  categories" replaced with open "Automate with Python scripts for complex 
  workflows and repetitive tasks."
- **H-11: Juice Shop strategy injection removed** — Hardcoded STEP 1/2/3 checklist 
  for port 3000 targets. Lets the LLM figure it out.
- **H-12: TOOL_PROFILES filtering removed** — Quick mode was hiding 15+ tools 
  (arjun, jwt_tool, ffuf_parameter_fuzz, etc.). Now ALL tools visible always.
- **H-13: In-place memory compression** — Was copying conversation_history, causing 
  unbounded growth across 300 iterations. Now compresses in-place.
  Also removed unnecessary asyncio.to_thread wrapper.
- **H-14: ITERATION BUDGET DISCIPLINE removed** — "No wasted iterations" created 
  anxiety about exploration. Security testing REQUIRES speculative tests.
- **H-15: Scan profile injection minimized** — Was injecting skip_tools, priority_tools, 
  rates, nuclei_severity (~500+ tokens per request). Now only injects iteration count.
- **H-16: Jinja autoescape fixed** — Was HTML-escaping XML tags in prompts. Now 
  matches expected behavior: `default_for_string=False`.
- **H-17: Stealth delay verified** — delay_ms defaults to 0, harmless.

#### Kept (Proven Helpful — K-01 through K-10)
- Auto-report scanner findings, CDATA wrapping, findings ledger, critical data 
  extraction, auto-record findings, EnhancedAgentState, post-scan enrichment, 
  sandbox timeout 600s, reasoning effort "high", prior intel from knowledge store,
  Juice Shop skill loading (reference knowledge, not restrictive strategy)

## [0.9.34] - 2026-03-05

### Return to Core Philosophy — Remove Harmful Orchestration Bloat

Deep comparative audit revealed that 3000+ lines of "improvements" 
collectively made Phantom WORSE at vulnerability discovery. The base system finds 
dozens of bugs on OWASP Juice Shop; Phantom with all its added complexity found only 2. 
This release strips harmful additions while keeping genuinely helpful ones.

#### Root Cause Analysis (7 root causes identified)
1. **Context window pollution** — 8+ control messages injected per iteration drowning the LLM
2. **Iteration budget halved** — Quick profile had 150 (optimal is 300)
3. **Contradictory scanning strategies** — 4 competing strategy sections in prompt
4. **Shallow-testing prompts** — "Move on after 3-4 attempts" vs "Be relentless"
5. **Tool firewall** — Blocked browser_action/python_action in first 8 iterations
6. **Low temperature (0.4)** — Killed creative exploitation; uses provider default
7. **Aggressive finish gates** — 40% iteration minimum + 4 vuln classes + 3 scanner types

#### Changes Applied (10 fixes)

- **System prompt rewritten** — Replaced "INTELLIGENT SCANNING STRATEGY" with 
  "AGGRESSIVE SCANNING MANDATE" (GO SUPER HARD, 2000+ steps, UNLEASH FULL CAPABILITY). 
  Replaced rigid MANDATORY PHASES (25/50/25%) with lean WORKFLOW GUIDANCE.
- **Temperature default removed** — No longer hardcodes 0.4; uses provider default (~0.7-1.0)
  Uses provider default (~0.7-1.0).
  Conditionally omits temperature from API calls when None.
- **max_iterations restored to 300** — Quick profile 150→300, base_agent default 200→300.
- **VulnClassTracker disabled** — Was forcing rotation every 10 iterations, abandoning 
  promising attack vectors. Phantom doesn't need one.
- **Tool firewall removed** — v0.9.33 addition that blocked browser/python tools early.
- **Control message injection gutted** — Removed ~200 lines: scanner orders (iter 1-6), 
  scanner enforcement (iter 10), verbose phase messages, diversity alerts, coverage updates, 
  stagnation detector. Kept only lean phase transitions.
- **Finish gates dramatically lowered** — From MIN_ITERATIONS=120/MIN_TOOL_CALLS=60/4 vuln 
  classes/3 scanners → MIN_ITERATIONS=10/MIN_TOOL_CALLS=8. AUTO-002 and AUTO-003 removed.
- **MIN_RECENT_MESSAGES 12→15** — Preserves more context for exploit chains.
- **Stagnation detector removed** — Too aggressive at 15 iterations.
- **Bug bounty mindset in prompt** — "If it wouldn't earn $500+, keep searching."

#### Kept from Phantom (genuinely helpful additions)
- Findings ledger (persistent vulnerability storage)
- Auto-report pipeline for scanner findings
- CDATA wrapping in tool results
- Provider registry with model presets
- Post-scan enrichment (MITRE, compliance mapping)
- "ANY agent can report" workflow
- Wordlist guidance for fuzzing tools

## [0.9.25] - 2026-03-03

### Deep System Audit — 13 Critical Architectural Fixes

Comprehensive deep audit identified 27 weaknesses across LLM layer, tool execution, agent state management, subagent isolation, and memory compression. This release addresses the 13 most impactful issues to dramatically increase vulnerability discovery coverage.

**Goal: Enable 50+ vuln discovery against OWASP Juice Shop (which has 100+ challenges).**

#### LLM Layer Fixes (2)

- **FIX-1: Temperature control** — Added configurable `temperature` parameter (default 0.3) to `LLMConfig`. Low temperature produces more methodical, deterministic exploitation instead of random creative approaches. Wired into `_build_completion_args()`.

- **FIX-11: Memory compression improvements** — Expanded critical data extraction patterns to preserve JWT tokens, cookies, API endpoints, credentials, and IDOR IDs during compression. Raised `MIN_RECENT_MESSAGES` from 12 to 20 to preserve more recent context. Increased summarization timeout from 30s to 60s to prevent data loss on slow LLM responses.

#### Tool Execution Fixes (4)

- **FIX-7: Tool result truncation raised** — Raised from 8,000 to 16,000 chars. Security scanner output (nuclei, katana, sqlmap) is information-dense and previously lost critical findings in the truncated middle section.

- **FIX-6: Response body limit raised** — Raised `send_simple_request` body truncation from 10K to 30K chars. Enables the agent to see full API documentation (`/api-docs`), JavaScript bundles with API routes, and complete error messages.

- **FIX-5: send_request schema overhaul** — Added 4 usage examples (login, authenticated GET, SQLi test, open redirect), `follow_redirects` parameter for redirect testing, and detailed Content-Type guidance for JSON APIs.

- **FIX-9: Auth propagation to scanner tools** — Enhanced `_inject_auth_headers()` to auto-inject session tokens (auto-captured from login responses) into nuclei, sqlmap, ffuf, and other scanner tools. Previously only user-provided auth headers were injected.

#### Session / Authentication Fixes (2)

- **FIX-2: Session/auth token persistence** — Added `_auth_token_store` to proxy_manager that auto-captures JWT tokens and cookies from login responses. Auto-injects stored tokens into subsequent requests. Subagents automatically benefit from tokens captured by parent or sibling agents.

- **FIX-4: Credentials propagated to subagents** — Reversed PHT-015 credential redaction. Subagents now receive full credentials (passwords, tokens, secrets) so they can test authenticated vulnerabilities (IDOR, privilege escalation, JWT manipulation). Required for ~50% of Juice Shop challenges.

#### Agent Architecture Fixes (3)

- **FIX-3: Subagent state upgraded** — Subagents now use `EnhancedAgentState` instead of plain `AgentState`. This gives them full vulnerability tracking, endpoint dedup, host enumeration, and priority queue capabilities. Parent's discovered endpoints, hosts, and tested endpoints are propagated to subagents at creation.

- **FIX-10: Subagent findings roll up** — When a subagent finishes (`agent_finish`), its discovered vulnerabilities, endpoints, findings ledger, and tested endpoints are merged back into the parent's state. The root agent's `vuln_stats` and final report now accurately reflect all discoveries.

- **FIX-4b: Expanded vuln pattern matching** — Subagent context inheritance now recognizes JWT, path traversal, business logic, race condition, privilege escalation, CORS, and other vulnerability patterns (previously only SQL/XSS/SSRF/CSRF/IDOR/XXE/RCE/LFI/RFI).

#### Scan Profile Fixes (1)

- **FIX-8: Quick mode heavily boosted** — Iterations: 100 → 150. Reasoning effort: "medium" → "high". Memory threshold: 50K → 80K tokens. Sandbox timeout: 90s → 120s. These changes give the agent more budget for diverse vulnerability testing and deeper exploitation reasoning.

#### Knowledge Base (1)

- **NEW: OWASP Juice Shop attack playbook** — Created `skills/targets/owasp_juice_shop.md` with comprehensive endpoint map (40+ API routes), 50+ vulnerability patterns across 12 OWASP categories, authentication strategies, and efficiency tips. Auto-loaded when target is detected as Juice Shop (port 3000 or "juice" in URL).

#### Test Updates

- Updated 8 test assertions to match new values (truncation 16K, iterations 150, memory 80K, reasoning "high", credential propagation)
- All 821 tests passing, 21 skipped

## [0.9.22] - 2026-03-02

### Live Scan Bug Report — 11 Fixes from Real-World Observation

Live scan against OWASP Juice Shop revealed 15 bugs/flaws. 3 were hot-fixed during the scan, 8 more fixed in this release, 4 deferred to Arch v2. All 808 tests passing.

#### Runtime Hot-Fixes (3) — Applied During Live Scan

- **BUG-01 FIX: `no-new-privileges` broke sandbox** — P2-FIX10's `security_opt` prevented `sudo` inside Kali container (needed for Caido proxy setup). Removed `security_opt` from `docker_runtime.py`.

- **BUG-02 FIX: `cap_drop=ALL` too restrictive** — P2-FIX10's capability restrictions broke Caido and other security tools. Removed `cap_drop=["ALL"]`, kept only `cap_add` for extra capabilities.

- **BUG-03 FIX: `storage_opt` incompatible** — P2-FIX9's `storage_opt={"size": "20g"}` only works with devicemapper, not overlayfs (Docker Desktop). Removed `storage_opt`.

#### Phase & State Machine Fixes (2)

- **BUG-04 FIX: Phase transitions never fire** — `ScanPhase` state machine was dead code — `set_phase()` existed but was never called. Added automatic phase transitions in `base_agent.py`: RECON→EXPLOIT at 25% iterations or 3+ findings, EXPLOIT→REPORT at 75%.

- **BUG-08 FIX: Coverage tracker and stagnation detector inert** — Coverage tracker used empty `endpoints` list; stagnation detector used empty `vulnerabilities` dict. Fixed coverage to use `add_advisory()` with TTL; fixed stagnation to use `max(findings_ledger, vulnerabilities)` count.

#### Endpoint & Finding Tracking Fixes (3)

- **BUG-07 FIX: `add_endpoint()` never called** — Endpoints list was always empty despite tools discovering URLs. Wired `add_endpoint()` in `_auto_record_findings` for katana, httpx, ffuf results.

- **BUG-09 FIX: `save_checkpoint` omitted `findings_ledger`** — The most important persistent data store was lost on scan resume. Added `findings_ledger` to checkpoint serialization/deserialization with size guards.

- **BUG-10 FIX: `record_finding` has no severity** — Added optional `severity` parameter to `record_finding` tool. Output tags findings as `[category/SEVERITY] text`.

#### Miscellaneous Fixes (3)

- **BUG-11 FIX: System prompt "2000+ steps" impossible** — System prompt claimed "expect 2000+ steps minimum" but max_iterations ranges 60-300. Changed to "expect to use most of your available iterations".

- **BUG-14 FIX: `from_checkpoint` hardcodes `max_iterations=300`** — Changed to 200 (the default) to match `AgentState` default.

- **LIVE_SCAN_BUG_REPORT.md** — Comprehensive 15-bug report with severity ratings, code locations, and fix plans.

#### Deferred to Arch v2 (4)

- **BUG-05: Subagent state isolation** — Subagents get plain `AgentState`, findings/vulns never merge back to root.
- **BUG-06: Findings vs vulnerabilities dual tracking** — Two parallel systems (`findings_ledger` strings vs `vulnerabilities` models) never bridge properly.
- **BUG-12: `tested_endpoints` fails for subagents** — No deduplication across agents in multi-agent scans.
- **BUG-15: Priority queues are dead code** — `VulnerabilityPriorityQueue` and `ScanPriorityQueue` are scaffolded but never consulted.

## [0.9.21] - 2026-03-02

### Deep System Audit — 15 Critical Fixes Across All Layers

Comprehensive deep audit with 15 fixes across Docker runtime, agent loop, LLM cost/memory management, and security hardening. All 808 tests passing.

#### Priority 1 — Critical Fixes (5)

- **P1-FIX1: Signal handler container orphaning** — `signal_handler` in `cli.py` set `_cleanup_done=True` before calling cleanup, causing atexit to skip cleanup and orphan Docker containers on Ctrl+C. Fixed: now calls `cleanup_on_exit()` directly before `sys.exit(1)`.

- **P1-FIX2: run_scan.py cleanup gap** — Cleanup code (`tracer.cleanup()`, `cleanup_runtime()`) was outside try/except. Unexpected exceptions orphaned containers. Fixed: moved to `finally` block with individual try/except wrappers.

- **P1-FIX3: System prompt aggressive mandate** — "AGGRESSIVE SCANNING MANDATE" with "GO SUPER HARD", "2000+ steps MINIMUM" contradicted efficiency goals. Replaced with "INTELLIGENT SCANNING STRATEGY" promoting coverage awareness and quality over quantity.

- **P1-FIX4: Dead stagnation detector** — `loop_detector.record_findings_count()` was never called anywhere in the codebase — stagnation detection was dead code. Wired into agent loop after each iteration. Now injects advisory when no new vulns found.

- **P1-FIX5: Orphan container cleanup** — No cleanup of leftover `phantom-scan-*` containers from crashed runs. Added `_cleanup_orphaned_containers()` in `DockerRuntime.__init__()` to remove exited/dead/created containers on startup.

#### Priority 2 — Architecture Enhancements (5)

- **P2-FIX6: Coverage-based stopping** — No metric tracking of attack surface exploration. Added endpoint coverage ratio computation every 10 iterations (after iter 20). Injects HIGH/LOW coverage advisories to guide the LLM's finish_scan decision.

- **P2-FIX7: Container auto-recovery** — If sandbox container died mid-scan, scan failed with no recovery. Added auto-detection and recreation of dead containers in `_get_or_create_container()`.

- **P2-FIX8: Stealth enforcement middleware** — Stealth mode rate limits were advisory-only (LLM could ignore them). Added hard `asyncio.sleep(delay_ms)` enforcement in `executor.py` before every sandbox HTTP call. Wired via `set_active_profile_flags()`.

- **P2-FIX9: Disk quota** — Container had no storage limit. Added `storage_opt={"size": "20g"}` to container creation.

- **P2-FIX10: Capability hardening** — Container could inherit extra Linux capabilities. Added `cap_drop=["ALL"]`, `cap_add=["NET_ADMIN", "NET_RAW"]`, `security_opt=["no-new-privileges:true"]`.

#### LLM Cost/Memory Optimization (5)

- **L1-FIX: Dynamic context window** — Memory compressor used hardcoded 80K threshold regardless of model (DeepSeek v3.2=163K, Gemini=1M). Now uses 75% of the model's actual context window from the provider registry.

- **L2-FIX: Wire max_tokens in API** — LLM response length was unconstrained (model default). Now sends `max_tokens` from provider registry in every API call to prevent wasteful verbose responses.

- **L3-FIX: Advisory message TTL** — Coverage updates, stagnation warnings, and loop-detected prompts persisted forever in history, wasting tokens on every subsequent call. Added `add_advisory(ttl=N)` system: advisory messages auto-expire after N iterations.

- **L4-FIX: Cost fallback estimator** — When `litellm.completion_cost()` returns $0 (unsupported model/route), cost limits never triggered. Added fallback estimation using `cost_per_1k_input/output` from provider registry.

- **L5-FIX: Cost in tracer output** — Scan stats JSON had no cost controller data. Now includes `cost_controller` snapshot and `cost_summary` from the authoritative cost controller.

#### Files Modified (13)

`phantom/interface/cli.py`, `run_scan.py`, `phantom/agents/PhantomAgent/system_prompt.jinja`, `phantom/agents/base_agent.py`, `phantom/agents/state.py`, `phantom/runtime/docker_runtime.py`, `phantom/tools/executor.py`, `phantom/core/scan_profiles.py`, `phantom/agents/PhantomAgent/phantom_agent.py`, `phantom/llm/llm.py`, `phantom/llm/memory_compressor.py`, `phantom/llm/provider_registry.py`, `phantom/telemetry/tracer.py`

## [0.9.19] - 2026-03-01

### Full Spectrum Audit & Critical Bug Fixes

Comprehensive security audit (152 findings across 5 domains) with 9 critical/high bug fixes applied. All 585 tests passing.

#### Critical Bug Fixes

- **Loop detector NameError (CRITICAL)**: `_logger` was undefined in `base_agent.py` — the loop detector would crash with NameError on every trigger, making it dead code. Fixed to use `logger`.

- **Duplicate dead code block**: Second `final_response is None` check + `content_stripped` re-assignment after loop detector masked its injection logic. Removed duplicate block.

- **Zombie agent resurrection (HIGH)**: `resume_from_waiting()` in `state.py` cleared the `completed` flag, allowing completed agents to be resurrected by inter-agent messages. Now guards against resuming completed agents.

- **Report generation crash (HIGH)**: Severity sort used `list.index()` which throws `ValueError` on unknown severity values. All 3 report generators (JSON, HTML, Markdown) now use `dict.get()` with safe defaults.

- **Tool firewall silent bypass (HIGH)**: `ImportError` on tool_firewall module caused all security controls to be silently skipped. Now logs CRITICAL warning.

- **Path traversal in nuclei templates (HIGH)**: Template ID sanitization only replaced `/`, allowing `..\..\` traversal on Windows. Now uses allowlist regex `[a-zA-Z0-9_-]`.

- **Checkpoint save was silent**: `save_checkpoint` failures were swallowed with bare `pass`. Now logged at WARNING level so users know if resume data isn't being saved.

- **Knowledge store encryption fallback**: Decryption failures silently fell through to plaintext read without any warning. Now logs a warning when falling back.

- **Auto-record findings exception swallowing**: `_auto_record_findings` caught all exceptions with bare `pass`, silently losing security findings. Now logs at DEBUG level.

#### Session Fixes (Pre-Audit)

- **gql import error**: `proxy_manager.py` imported `gql` at module level (Docker-only). Made conditional with `try/except ImportError`.
- **certutil hang**: `certutil -N` in sandbox entrypoint hanged indefinitely. Added `timeout 10` wrapper with fallback.
- **Checkpoint attribute**: `base_agent.py` checked `tracer.run_dir` (doesn't exist) instead of `tracer.get_run_dir()`.
- **Test encoding**: 3 tests failed on Windows reading UTF-8 emoji from docker-entrypoint.sh. Added `encoding="utf-8"`.

#### Security Audit Results

Full spectrum audit produced **152 findings**: 11 CRITICAL, 35 HIGH, 69 MEDIUM, 37 LOW across:
- Core Agent Loop (31 findings)
- Tool Execution Layer (24 findings)
- LLM/Telemetry/Config (37 findings)
- Sandbox/Docker (28 findings)
- Reports/Knowledge (32 findings)

See `AUDIT_REPORT_v0.9.19_FINAL.md` for the complete report with fix plan.

#### Tests

- **585 tests passing**, 21 skipped, 0 failures
- All fixes verified with full regression suite

## [0.9.12] - 2026-02-26

### Wire Verification Engine + Knowledge Store — Expert System Completion

Wired the two largest unwired components (1,000+ lines combined) into the live scan pipeline, transforming Phantom from a scanner with dead code into a fully integrated expert system.

#### Verification Engine Wiring

- **Post-scan auto-verification**: All reported vulnerabilities are now automatically
  verified by the verification engine during the post-scan enrichment pipeline.
  Uses 8 strategies: time-based SQLi, error-based SQLi, boolean injection, DOM
  reflection, OOB HTTP/DNS, known-file LFI, and math-eval SSTI.

- **New `verify_vulnerability` agent tool**: Agents can now explicitly verify a
  finding during scan (before calling `create_vulnerability_report`), increasing
  confidence. Returns verification status, confidence score, and exploit evidence.

- **SSRF guard in verification engine**: Payload injection blocks private, loopback,
  and link-local IPs — prevents verification probes from hitting internal services.

#### Knowledge Store Full Wiring

- **Host persistence**: Discovered hosts (from nmap, httpx, etc.) are now saved to
  the knowledge store at scan completion, with port/service/technology merging.

- **Scan history recording**: Each completed scan is recorded with target, vulns
  found/verified, hosts found, duration, and tools used. Enables cross-scan trend
  analysis.

- **Prior scan intelligence injection**: At scan start, PhantomAgent queries the
  knowledge store for any prior scan data on the target and injects it into the
  task description. This lets agents skip redundant work and focus on new vectors.

- **New `get_all_vulnerabilities()` method**: Added missing method to KnowledgeStore
  that was needed by `check_known_vulnerabilities` tool.

#### Bug Fixes

- **VulnerabilityStatus import fix**: `enhanced_state.py` used `VulnerabilityStatus`
  in `mark_vuln_verified()` and `mark_vuln_false_positive()` without importing it.
  Both methods would crash at runtime when called. Now properly imported.

- **Scan duration calculation**: Fixed `start_time` type handling — `AgentState`
  stores it as ISO string, not datetime object. Duration calculation now correctly
  parses it.

#### Tests

- Added 36 new tests covering: knowledge store (all_vulns, hosts, scan history,
  statistics), verification engine (init, verify, batch, SSRF guard, payload
  injection), verify_vulnerability tool, check_known_vulnerabilities tool,
  EnhancedAgentState status fix, prior intel injection, post-scan enrichment.

- **Total: 363 tests passing** (up from 327), 11 skipped, 0 failures.

## [0.9.11] - 2026-02-26

### Live Scan Validation — 6 Bug Fixes from Real Scan

Live scan against OWASP Juice Shop found **4 vulnerabilities (3 CRITICAL + 1 HIGH)** using 5 agents, 163 tool calls, at $1.27 total cost. Analysis of 10 tool errors (6.1% error rate) revealed 6 fixable bugs.

#### Bug Fixes

- **Argument parser drops unknown kwargs**: `convert_arguments()` now silently
  drops parameters not in function signature (unless function accepts `**kwargs`).
  Prevents `TypeError: got an unexpected keyword argument` when LLMs hallucinate
  extra parameters — affected httpx_probe, ffuf_directory_scan, and others.

- **record_finding accepts aliases**: LLMs consistently use `description` or `title`
  instead of `finding`. Now accepts all three with graceful fallback.

- **create_note category mapping**: Unknown categories (e.g. "vulnerability",
  "recon", "exploit") now map to closest valid category instead of returning error.
  Added 15+ alias mappings.

- **Sandbox timeout 120s → 600s**: nuclei_scan was hitting ReadTimeout at 150s
  (120s server + 30s client margin). Increased both host executor and container
  defaults to 600s to match security tool needs.

- **Docker runtime timeout**: Container's `PHANTOM_SANDBOX_EXECUTION_TIMEOUT`
  default aligned with executor at 600s.

- **Tests updated**: Replaced `test_unknown_parameter_passed_through` with
  `test_unknown_parameter_dropped_silently` + added `test_unknown_parameter_passed_through_with_var_keyword`.

#### Scan Results (Juice Shop, standard profile, DeepSeek v3.2)

| Metric | Before (v0.9.9) | After (v0.9.11) |
|--------|-----------------|-----------------|
| Vulnerabilities | 4 (3C+1H) + crash | 4 (3C+1H), clean finish |
| Tool calls | 230 (6 security = 2.6%) | 163 (14 security = 8.6%) |
| Agents | 8 | 5 (4 specialized + 1 root) |
| Wasted iterations | 89 (38.7%) | ~0 (all productive) |
| Cost | ~$6 (13 failed runs) | $1.27 (single clean run) |
| Inter-agent messages | 0 | 12 |
| Browser for XSS | 0 | 18 browser_action calls |

#### Tests
- 327 passed, 11 skipped, 0 failed

## [0.9.10] - 2026-02-26

### Scan Coverage & Crash Resilience — Root Cause Fixes

Forensic analysis of a live OWASP Juice Shop scan (231 events, 7/110 challenges solved = 6.4%) identified six root causes for poor coverage. Five code fixes address them.

#### Root Causes Identified
1. **No enforced recon phase** — nuclei_scan never called despite 53 tools available
2. **38.7% iteration waste** — 89/230 calls were todo/browser/think overhead
3. **Browser overuse for REST API** — 46 browser_action calls on JSON endpoints
4. **Sub-agent budget too low** — 60% parent budget insufficient for full methodology
5. **No graceful degradation** — LLM API failures lost all partial results
6. **Credit waste across retries** — ~13 failed runs consumed $6 total

#### Bug Fixes

- **Graceful crash handling**: `_save_partial_results_on_crash()` in `base_agent.py`
  exports `enhanced_state.json` + `crash_summary.json` when LLM fails mid-scan.
  CLI also attempts partial `finish_scan` to generate reports from found vulns.

- **Sub-agent budget increase**: Raised from 60%/min 40 to 75%/min 50 of parent's
  max_iterations. Standard profile sub-agents: 72 → 90 iterations.

#### New Features

- **Mandatory recon-first enforcement**: Task description now injects mandatory steps
  (nuclei_scan → katana_crawl → ffuf → nmap) BEFORE sub-agent creation is allowed.
  Efficiency rules: no browser for APIs, max 5 todo ops, prefer batch requests.

- **Iteration budget discipline**: System prompt now caps overhead: max 3 todo calls,
  max 2 think calls, max 1 view_agent_graph per 20 iterations. 30% budget checkpoint
  forces security scanner usage if none have run.

- **Comprehensive LaTeX report**: `docs/phantom_system_report.tex` — 21-page system
  analysis covering architecture, scan forensics, root causes, fixes, rating (2.9→5.1/10),
  and roadmap to v1.0. Compiled via Docker texlive.

#### Technical Details

- **Files Modified**: 5 core files + 1 new test file + 1 LaTeX report
  - `agents/base_agent.py` — crash handling with partial result saving
  - `tools/agents_graph/agents_graph_actions.py` — budget 60%→75%
  - `agents/PhantomAgent/phantom_agent.py` — mandatory recon steps
  - `agents/PhantomAgent/system_prompt.jinja` — budget discipline rules
  - `interface/cli.py` — partial finish_scan on crash

- **Tests**: 326 passed, 11 skipped (11 new tests covering crash handling,
  budget calculations, recon enforcement, prompt improvements)

## [0.9.9] - 2026-02-26

### High & Medium Priority Fixes — Dedup, State Wiring, Auth Scanning, Persistence

Six targeted fixes addressing the bugs and missing wiring identified during the
v0.9.8 self-audit, plus new authenticated scanning support.

#### Bug Fixes

- **Double `set_completed()` fix**: `base_agent._execute_actions()` was calling
  `complete_scan()` (which internally calls `set_completed(summary)`) and THEN
  calling `set_completed({"success": True})` again, overwriting the scan summary.
  Now uses an if/else: EnhancedAgentState gets `complete_scan()` only; plain
  AgentState gets `set_completed()` only.

#### New Features

- **Endpoint Deduplication**: New `tested_endpoints` tracking in EnhancedAgentState
  prevents re-testing the same URL + method + parameter with the same tool type.
  - `mark_endpoint_tested(url, method, param, test_type)` — returns True if duplicate
  - `get_tested_endpoints_summary()` — compact display for agent context
  - Auto-tracked for: sqlmap, nuclei, ffuf, xss, ssrf, cmdi scans
  - Summary injected into memory compressor alongside findings ledger

- **Vulnerability Report → EnhancedAgentState Wiring**: `create_vulnerability_report`
  results now flow into `EnhancedAgentState.add_vulnerability()` via the
  `_auto_record_findings()` pipeline. The state's vuln tracking is no longer dead
  during scans — severity stats, verification queue, and report export all work.

- **Scan Result Persistence**: `finish_scan` now exports
  `EnhancedAgentState.to_report_data()` as `enhanced_state.json` to the run
  directory, providing structured machine-readable scan results alongside the
  markdown report.

- **Authenticated Scanning (`--auth-header`)**: New CLI option `-H` / `--auth-header`
  for passing auth headers that get injected into the agent's task description.
  Example: `phantom scan -t https://app.com -H "Authorization: Bearer TOKEN"`
  Repeatable for multiple headers. Agent is instructed to use them in all HTTP tools.

- **Memory Compressor Endpoint Context**: The `_build_ledger_message()` now includes
  a `<tested_endpoints>` section when endpoint tracking data exists, telling the
  agent exactly which endpoints have been tested and with which tools — preventing
  wasted iterations on duplicate testing.

#### Technical Details

- **Files Modified**: 8 core files + 1 new test file
  - `agents/base_agent.py` — double-completion fix
  - `agents/enhanced_state.py` — endpoint dedup fields & methods
  - `tools/executor.py` — vuln wiring + endpoint tracking in auto-record pipeline
  - `tools/finish/finish_actions.py` — enhanced state JSON export
  - `llm/memory_compressor.py` — endpoint summary in ledger message
  - `agents/PhantomAgent/phantom_agent.py` — auth header injection
  - `interface/cli_app.py` — `--auth-header` CLI option
  - `interface/cli.py` — auth header parsing into scan config

- **Tests**: 315 passed, 11 skipped (23 new tests covering all v0.9.9 features)

## [0.9.8] - 2026-02-26

### Feature Completeness — DuckDuckGo Fallback, Dynamic Memory, EnhancedAgentState, CI/CD

Comprehensive feature release implementing immediate, short-term and medium-term
improvements identified during the v0.9.7 review.

#### New Features

- **DuckDuckGo Web Search Fallback**: `web_search` no longer requires a Perplexity
  API key. When the key is missing (or Perplexity fails), it automatically falls
  back to DuckDuckGo HTML search — the agent can always research payloads and CVEs.
  Web search is now always registered (no `HAS_PERPLEXITY_API` gate).

- **Dynamic Memory Threshold Per Profile**: Each scan profile now defines its own
  `memory_threshold` controlling when memory compression fires:
  - `quick` / `stealth`: 60K tokens (cost-efficient)
  - `standard` / `api_only`: 80K tokens (balanced)
  - `deep`: 100K tokens (maximum information retention)
  The threshold flows from the profile through `LLM.set_memory_threshold()` to the
  `MemoryCompressor` instance.

- **EnhancedAgentState Activated**: The previously dead-code `EnhancedAgentState`
  class is now automatically instantiated for root agents when a scan profile is
  present. This enables:
  - Vulnerability tracking with severity statistics
  - Host/subdomain/endpoint discovery tracking
  - Tool usage statistics per scan
  - Phase-aware scan progress tracking
  - `complete_scan()` auto-called on agent completion
  - `initialize_scan()` auto-called at scan start

- **CI/CD Test Workflow**: Added `.github/workflows/test.yml` that runs on every
  push and PR to `main`/`develop`. Tests across Python 3.12 + 3.13, on Linux,
  macOS, and Windows. Includes lint step with ruff.

- **Enhanced TUI Cost Dashboard**: The TUI sidebar now shows the active scan
  profile name, agent count, and tool execution count alongside the existing
  token/cost display.

#### Technical Details

- `phantom/tools/web_search/web_search_actions.py`: Added `_duckduckgo_search()`
  with HTML parsing (no external deps beyond `urllib`), regex result extraction,
  and automatic Perplexity-to-DuckDuckGo failover.
- `phantom/tools/__init__.py`: Removed `HAS_PERPLEXITY_API` gate; web_search
  always imported.
- `phantom/core/scan_profiles.py`: Added `memory_threshold` field to `ScanProfile`
  with per-profile defaults.
- `phantom/llm/memory_compressor.py`: `MemoryCompressor` now accepts optional
  `max_tokens` parameter; uses instance-level `max_total_tokens` instead of
  module-level constant.
- `phantom/llm/llm.py`: Added `LLM.set_memory_threshold()` method.
- `phantom/agents/PhantomAgent/phantom_agent.py`: Creates `EnhancedAgentState`
  when `scan_profile` is present; calls `initialize_scan()` on scan start; passes
  profile's `memory_threshold` to LLM.
- `phantom/agents/base_agent.py`: `_execute_actions()` now calls
  `track_tool_usage()` on EnhancedAgentState; `complete_scan()` called when agent
  finishes successfully.
- `phantom/interface/utils.py`: `build_tui_stats_text()` shows profile name,
  agent count, and tool count.
- `.github/workflows/test.yml`: New CI workflow with matrix testing and linting.
- 32 new tests covering all features (292 total, 11 skipped, 0 failed).

## [0.9.7] - 2026-02-26

### Context Intelligence — Preserving Critical Information During Compression

Critical evaluation of v0.9.6 found that two changes (memory threshold 60K,
subagent context cap at 10 messages) could actually weaken vulnerability
discovery by discarding important recon data.  v0.9.7 replaces brute-force
truncation with intelligent context management.

### Fixed — Weaknesses in v0.9.6
- **Subagent context inheritance was too aggressive** — "last 10 messages"
  discarded initial task info, endpoint maps, and recon findings. Replaced with
  smart context extraction: first 2 messages (task) + parent findings summary +
  last 5 messages (recent activity). Subagents now inherit key discoveries
  without token bloat.
- **Memory compressor threshold too low** — 60K triggered compression too
  frequently, risking data loss through repeated LLM summarisation. Raised to
  80K (still 20K lower than original 100K for cost savings).
- **Tool output truncation slightly too aggressive** — 6K could clip middle of
  important security findings. Raised to 8K (3500 head + 3500 tail).

### Added — Persistent Findings Ledger
- **`findings_ledger` on AgentState** — append-only list of key discoveries
  (vulns, endpoints, technologies, credentials, dead-ends) that is NEVER
  compressed or summarised. Survives all memory compression cycles.
- **`record_finding` tool** — agent can explicitly record important discoveries
  to the persistent ledger with category tags (vuln, endpoint, tech, dead-end).
- **`get_findings_ledger` tool** — agent can review all recorded findings to
  avoid re-testing endpoints.
- **Auto-recording from security tools** — nuclei, nmap, katana, httpx, and
  nmap_vuln results are automatically extracted and recorded to the ledger.
  Critical/high nuclei findings, open ports, API endpoints, and technologies
  are captured without agent intervention.
- **Ledger injection during compression** — when memory compression activates,
  the findings ledger is injected as a "pinned" message that appears after
  compressed summaries but before recent messages, ensuring nothing is lost.

### Enhanced — Smarter Context Management
- **Parent-to-subagent context summary** — smart extraction scans the entire
  parent conversation for URLs, technologies, vulnerability mentions, and
  credentials, builds a concise summary, and passes it alongside the first
  2 and last 5 messages. Subagents now get dense, relevant context.
- **Memory compressor summary prompt rewritten** — 10 explicit preservation
  categories (exact URLs, payloads, credentials, attack surface map, etc.)
  with strict compression rules (never remove a URL or payload).
- **LLM ↔ AgentState wiring** — `LLM.set_agent_state()` gives the memory
  compressor a reference to the agent state for findings ledger access.

### Tests
- 260 passed, 11 skipped, 0 failures (was 247 in v0.9.6)
- 13 new tests covering: findings ledger CRUD, auto-recording from nuclei/nmap/
  katana, smart context extraction, ledger injection during compression,
  tool registration, version check.

## [0.9.6] - 2026-02-26

### Vulnerability Discovery Overhaul — Finding More Bugs with Less Cost

Root cause analysis revealed the system was only finding 1-2 vulnerabilities
against OWASP Juice Shop (100+ known vulns) due to critically low iteration
limits, context bloat, missing attack surface discovery, and cost-inefficient
token usage.

### Fixed — Critical (5)
- **Scan profile iterations catastrophically low** — Quick was 20 (now 60),
  Standard was 40 (now 120), Deep was 80 (now 300). The system prompt said
  "2000+ steps needed" but profiles stopped agents after just 20-80 iterations.
- **Quick scan disabled critical tools** — `sqlmap_scan`, `create_sub_agent`,
  and browser were all skipped in quick mode. SQLi is Juice Shop's #1 vuln
  class. All restored.
- **Subagent inherited FULL parent conversation history** — Each child got
  50-100K tokens of irrelevant parent context. Now capped to last 10 messages.
- **No tool output size limit per tool** — Nuclei/nmap could return 50KB+
  per invocation. Nuclei findings now capped at 30 (sorted by severity),
  nmap raw_output reduced to 2K chars, executor truncation reduced to 6K.
- **EnhancedAgentState is dead code** — `enhanced_state.py` with full vuln
  tracking, endpoint tracking, and phase management was never instantiated.
  (Documented; integration deferred to v0.10)

### Fixed — High (5)
- **Subagent max_iterations hardcoded to 300** — Regardless of parent profile.
  Now inherits 60% of parent's max_iterations (minimum 40).
- **Memory compressor threshold too high** — Was 100K tokens before compression
  triggered. Reduced to 60K tokens, max messages from 200→150, recent window
  from 15→12.
- **No mandatory crawling/spidering phase** — Agent skipped systematic endpoint
  discovery. Added `katana_crawl` tool and made crawling MANDATORY FIRST STEP
  in all black-box scan modes.
- **Memory compressor used wrong API key** — `_summarize_messages()` used
  generic `llm_api_key` instead of provider-specific keys from the registry.
  Now resolves provider presets like the main LLM client.
- **Nmap comprehensive scan used -p- (all 65535 ports)** — Caused target DoS
  on small servers like Juice Shop. Changed to `--top-ports 10000` with rate
  limiting (`--max-rate 300`).

### Added
- **`katana_crawl` tool** — Systematic web crawler for endpoint discovery,
  JS file parsing, API route detection, and form enumeration. Integrated
  into all scan profiles as a priority tool.
- **Rate limiting for nmap** — All scan types now include `--max-rate` to
  prevent overwhelming targets.
- **Nuclei findings prioritization** — Findings sorted by severity before
  truncation so critical/high findings are always preserved.

### Scan Profile Changes
| Profile   | Old Iterations | New Iterations | Change |
|-----------|---------------|----------------|--------|
| Quick     | 20            | 60             | +200%  |
| Standard  | 40            | 120            | +200%  |
| Deep      | 80            | 300            | +275%  |
| Stealth   | 30            | 60             | +100%  |
| API Only  | 40            | 100            | +150%  |

## [0.9.5] - 2026-02-26

### Proxy Resilience — Fixes 502 Failures During Deep Scans

Deep scans against OWASP Juice Shop were hampered by Caido proxy 502 errors
inside the sandbox container. Fixed proxy fallback and container networking
to ensure tools can always reach the target.

### Fixed — High (2)
- **Caido proxy 502 killed sub-agent connectivity** — `send_simple_request()`
  and `_send_modified_request()` in `proxy_manager.py` now retry without proxy
  on 502 or `ProxyError`, falling back to direct HTTP connections.
- **Container `NO_PROXY` not set** — CLI tools (curl, httpx, nuclei) inside the
  sandbox went through the Caido proxy for ALL requests. Added
  `NO_PROXY=host.docker.internal,localhost,127.0.0.1` to container environment
  so tools bypass the proxy when it's overloaded or unreachable.

### Scan Results — OWASP Juice Shop
- **Standard scan**: 1 CRITICAL SQL Injection in `/rest/user/login` (CVSS 9.4)
  — verified with live PoC, JWT token obtained
- **Quick scan**: 1 HIGH SQL Injection in `/rest/products/search` (CVSS 8.6)
  — UNION SELECT data extraction confirmed
- **Deep scan**: 1 HIGH Authentication Bypass (CVSS 8.3) — historical analysis

## [0.9.4] - 2026-02-26

### Infrastructure Fixes — First Live Scan

First successful live scan against OWASP Juice Shop using DeepSeek v3.2 via
OpenRouter. Fixed 4 infrastructure bugs that blocked container startup and
config loading.

### Fixed — Critical (2)
- **Container `cap_drop=["ALL"]` killed sandbox** — Over-zealous capability hardening
  prevented `sudo` inside the entrypoint, crashing the container before the tool
  server could start. Reverted to `cap_add=["NET_ADMIN", "NET_RAW"]` (matching
  upstream design) without `cap_drop`.
- **Config `GROQ_API_KEY` never loaded from saved config** — `Config` class did
  not track `GROQ_API_KEY`, `OPENAI_API_KEY`, or `PHANTOM_LLM_FALLBACK` as
  canonical vars, so `apply_saved()` silently skipped them. Added all three.

### Fixed — High (2)
- **Container retry didn't catch health-check timeout** — `_create_container()`
  caught only `DockerException` but `SandboxInitializationError` is a plain
  `Exception`. Added it to the retry catch list and added post-failure container
  cleanup.
- **UTF-8 BOM in saved config corrupted JSON parsing** — PowerShell's
  `-Encoding utf8` writes a BOM that Python's `json.load(encoding='utf-8')`
  cannot parse. Switched to `utf-8-sig` which handles BOM transparently.

### Improved
- **DeepSeek v3.2 preset** — Added `openrouter/deepseek/deepseek-v3.2` to
  provider registry (163K context, 200 RPM).
- **Paid OpenRouter Llama preset** — Added `openrouter/meta-llama/llama-3.3-70b-instruct`.
- **Debug prints replaced with logging** — `warm_up_llm()` debug prints replaced
  with `logging.getLogger("phantom.warmup").debug()` calls.
- **Container startup grace period** — Added 2s delay after `docker run` before
  polling health endpoint to let entrypoint boot.

### Tests
- **217 passed**, 11 skipped (playwright/gql deps), 0 failed.
- Added 47 new tests for v0.9.3/0.9.4 fixes: sanitizer path traversal,
  provider routing, scope validator, config loading, security tool sanitisation.

## [0.9.3] - 2026-02-26

### Security Fixes — Deep Audit Round 3

Full offensive audit of all 25+ user-modified files. Found and fixed 1 CRITICAL +
3 HIGH + 2 CRITICAL infrastructure bugs that prevented scans from running.

### Fixed — Critical (3)
- **C-01: Path traversal bypass in `validate_workspace_path()`** — Function stripped `..` path segments instead of resolving them via `posixpath.normpath()`, then returned the un-normalised path. Input `../../etc/passwd` would escape the workspace boundary. Now uses `posixpath.normpath()` and validates the resolved path.
- **C-02: API base routing bug** — `warm_up_llm()` and `_build_completion_args()` were falling back to the generic `LLM_API_BASE` (OpenRouter URL) even for known provider presets like Groq, sending Groq requests to OpenRouter's endpoint with a Groq key. Now: known presets use ONLY their own `api_base`; generic fallback only applies to unknown models.
- **C-03: Wrong API key in LLM calls** — Both `warm_up_llm()` and `_build_completion_args()` used the generic `LLM_API_KEY` for all models, sending the OpenRouter key to Groq. Now resolves provider-specific keys from the provider registry first.

### Fixed — High (3)
- **H-01: Browser `_new_tab()` scheme bypass** — `_new_tab()` called `page.goto(url)` without checking `_BLOCKED_SCHEMES` (file, javascript, data, vbscript). Agent could open `file:///etc/passwd` via new_tab. Added scheme validation.
- **H-02: Browser `_create_context()` scheme bypass** — Same issue in `_create_context()` called during `launch()`. Added scheme check at context creation.
- **H-03: Proxy `_send_modified_request()` SSRF bypass** — `_send_modified_request()` (called from `repeat_request()`) did NOT call `_is_ssrf_safe()` to validate the modified URL. Added SSRF guard.

### Improved
- **LLM warm-up with fallback chain** — `warm_up_llm()` now iterates through `PHANTOM_LLM_FALLBACK` providers on failure instead of exiting on first error.
- **Transient error retries** — Warm-up retries each provider up to 3 times with exponential backoff for 500/502/503/504 errors.
- **Provider registry updated** — Removed non-existent OpenRouter free models, added 3 verified free models (Hermes 405B, Qwen3 Coder, Mistral Small 3.1).
- **Saved config updated** — `~/.phantom/cli-config.json` now includes `PHANTOM_LLM_FALLBACK` for automatic failover.

### Tests
- All **170/170 tests pass** after fixes.

## [0.9.2] - 2025-07-27

### Thread-Safety & Security Hardening — Deep Audit Round 2

Re-audit of v0.9.1 found 14 additional issues (6 HIGH, 8 MEDIUM) focused on
thread-safety, SSRF, race conditions, and resource management.

### Fixed — High (6)
- **SSRF in notifier** — DNS rebinding check inadequate; added resolved-IP validation.
- **Race condition in agent graph** — Multiple agents accessing shared state without synchronisation.
- **Thread-unsafe browser singleton** — Added `threading.Lock` to `_BrowserState`.
- **Unbounded proxy response storage** — Added 10KB response body cap in proxy manager.
- **Missing input validation in file_edit** — Agent could write to paths outside workspace.
- **Unprotected LLM key in logs** — Redacted API keys from debug output.

### Fixed — Medium (8)
- Thread-safety in terminal session management
- Race-free container cleanup on scan abort
- Bounded retry loops for tool execution
- Proper timeout handling in browser operations
- Defensive parsing for nuclei JSON output
- Guarded access to shared scan state
- Atomic config file writes
- Sanitised heredoc EOF markers (prevent injection)

### Tests
- All **170/170 tests pass**.

## [0.9.1] - 2025-07-26

### Security Hardening & Bug Fixes

Deep offensive audit of all 45+ source files. 6 critical bugs fixed, 5 HIGH severity
issues resolved, 5 MEDIUM severity improvements, 2 new agent tools, 28 integration tests.

### Fixed — Critical (6)
- **C-01: LLM history destruction** — `_prepare_messages()` was calling `.clear()/.extend()` on the caller's conversation history, destroying it on every compressed LLM call. Now operates on a copy.
- **C-02: Thread-unsafe agent graph** — 5 module-level dicts accessed from multiple threads with zero locking. Added `_graph_lock = threading.Lock()` around all mutations.
- **C-03: False positive misclassification** — Verification engine was calling `mark_false_positive()` when verification attempts failed. Removed — unverified ≠ false positive.
- **C-04: Broken compliance pass_rate** — Was dividing `passed / failed` instead of `passed / (passed + failed)`. Fixed denominator.
- **C-05: Event loop blocking** — `_prepare_messages()` sync LLM calls now offloaded via `asyncio.to_thread()` in async `generate()`.
- **C-06: Invalid YAML output** — `_yaml_escape()` was escaping colons and hashes, producing invalid YAML. Removed — safe inside quoted strings.

### Fixed — High (5)
- **SSRF via DNS rebinding** — Notifier `_validate_url()` now resolves hostnames and checks resolved IPs against private ranges. Added scheme validation (http/https only).
- **Sync LLM in async context** — `check_duplicate()` now uses `await litellm.acompletion()`. `create_vulnerability_report()` made async to match.
- **Unbounded message accumulation** — Added `MAX_MESSAGES = 200` hard cap in memory compressor to prevent OOM on long scans.
- **Lock-free agent cleanup** — `agent_finish()` and `stop_agent()` now properly acquire `_graph_lock` before mutating shared dicts.
- **Regex compilation in loops** — Pre-compiled nmap output patterns at module level.

### Fixed — Medium (5)
- **BFS O(n) pop(0)** — Attack graph BFS now uses `collections.deque.popleft()` (O(1)).
- **Combinatorial graph traversal** — Added `max_paths=500` limit to `find_attack_paths()` and `find_critical_paths()`.
- **Dead code removed** — Removed unused `ScanOrchestrator` class (~50 lines) from priority_queue.py.
- **Missing input validation** — `terminal_execute` now validates non-empty commands.
- **Silent error swallowing** — Enrichment pipeline bare `except: pass` blocks now log at DEBUG level.

### Added
- **`check_known_vulnerabilities` tool** — Agent can query the knowledge store for previously found vulnerabilities on a target.
- **`enrich_vulnerability` tool** — Agent can enrich findings with MITRE ATT&CK (CWE/CAPEC) + compliance mappings before reporting.
- **Knowledge store at startup** — Scan startup loads prior findings for the target and displays count in console banner.
- **28 integration tests** — Covering all critical fixes, new tools, profiles, enrichment pipeline, SSRF protection, knowledge store, attack graph, and report generator.

### Changed
- Total registered agent tools: **49** (47 + 2 new)
- Test suite: **170 tests** (142 existing + 28 integration)

## [0.9.0] - 2025-07-25

### Activated — Dead Code Brought to Life

v0.8.0 introduced 16 core modules (~4,500 lines) that were never wired into the runtime.
v0.9.0 activates **every single one** in a fully integrated post-scan enrichment pipeline.

### Added
- **Post-Scan Enrichment Pipeline** — 7-stage automatic enrichment runs after every scan:
  1. **MITRE Enrichment** — CWE/CAPEC/OWASP mapping for all findings
  2. **Compliance Mapping** — OWASP Top 10, PCI DSS, NIST reports (saved as `compliance_report.md`)
  3. **Attack Graph** — NetworkX graph + path analysis (saved as `attack_graph.json` + `attack_paths.md`)
  4. **Nuclei Templates** — Auto-generated per-vulnerability YAML templates
  5. **Knowledge Store** — Persistent cross-scan vulnerability memory
  6. **Notifications** — Webhook/Slack alerts for critical/high findings
  7. **Enhanced Reports** — JSON, HTML, and Markdown structured reports
- **Profile-Driven Scans** — Scan profiles now actually control iteration limits:
  - `quick` → 20 iterations, low effort, no browser
  - `standard` → 40 iterations, medium effort
  - `deep` → 80 iterations, high effort
  - `stealth` → 30 iterations, no noisy tools
  - `api_only` → 40 iterations, no browser/subfinder
- **`phantom profiles` command** — Display all available scan profiles in a rich table
- **`phantom diff` command** — Compare two scan runs to see new/fixed/unchanged vulnerabilities
- **Profile constraints in LLM prompts** — Agent receives strict iteration limits, allowed/blocked tools, and browser restrictions as part of its task description
- **`stealth` and `api_only` scan modes** — Added to CLI enum

### Fixed
- **Hardcoded max_iterations=300** — Was ignoring scan profiles entirely; now uses profile-driven values
- **KnowledgeStore dict/model mismatch** — Added `_dict_to_vulnerability()` converter for proper Vulnerability model objects
- **ReportGenerator dict/model mismatch** — Same converter applied; reports now generate correctly
- **ScopeValidator API** — Corrected method call from `is_allowed()` to `is_in_scope()`

### Changed
- **`phantom/core/__init__.py`** — Expanded from 5 exports to all 16 modules (full public API)
- **`phantom/interface/cli.py`** — Profile loading, startup banner shows profile name/iterations/effort
- **`phantom/agents/PhantomAgent/phantom_agent.py`** — Injects profile constraints into agent task
- **`phantom/tools/finish/finish_actions.py`** — Enrichment pipeline runs automatically after `finish_scan`

### Technical Details
- All 16 core modules verified individually (import + instantiate + core method call)
- 142/142 tests passing
- Zero circular dependencies
- All enrichment stages wrapped in try/except — failures are logged but never crash the scan

## [0.8.5] - 2026-02-24

### Fixed
- **litellm startup crash** — Set `LITELLM_LOCAL_MODEL_COST_MAP=True` to prevent litellm from making an HTTP network request at import time (caused `KeyboardInterrupt` / SSL errors in some environments)

## [0.8.4] - 2026-02-23

### Fixed
- **Silenced litellm `Provider List:` spam** — Set `LITELLM_LOG=ERROR` at startup and `litellm.verbose=False` to suppress noisy stdout output during scans

## [0.8.3] - 2026-02-23

### Fixed
- **Config setup UX** — `PHANTOM_LLM not set` error now shows `phantom config set PHANTOM_LLM 'openai/gpt-4o'` as the primary recommendation (persistent), with `export` shown as secondary (session-only). Fixes confusion from users trying invalid `set $VAR=value` bash syntax.

## [0.8.2] - 2026-02-23

### Fixed
- **Docker image fallback** — If a custom/invalid `PHANTOM_IMAGE` fails to pull, Phantom now automatically falls back to `ghcr.io/usta0x001/phantom-sandbox:latest` instead of crashing
- **PHANTOM_IMAGE not auto-persisted** — Running `phantom scan` no longer saves a temporary `PHANTOM_IMAGE` env var to `~/.phantom/cli-config.json`; only explicit `phantom config set PHANTOM_IMAGE <value>` writes it to config

### Changed
- **CLI: removed `--install-completion` / `--show-completion`** — Shell completion is installed silently on first run; these flags are no longer shown in `phantom --help`
- **CLI: added `--version` / `-V`** — Quick version check without needing `phantom version`
- **CLI: improved top-level help** — Shows quick-start examples and directs users to `phantom scan --help` for full options (`--instruction`, `--scan-mode`, `--model`, etc.)

## [0.8.1] - 2026-02-23

### Added
- **Published to PyPI** — `pip install phantom-agent` / `pipx install phantom-agent` now works globally
- **GitHub Container Registry** — Sandbox image available at `ghcr.io/usta0x001/phantom-sandbox:latest`
- **Technical Report** — Full system documentation in LaTeX (`docs/phantom_technical_report.tex`)

### Fixed
- **Windows Unicode crash** — `phantom --help` no longer crashes with `UnicodeEncodeError` on cp1252 terminals; stdout/stderr are reconfigured to UTF-8 on Windows automatically
- **Sandbox image config** — Default sandbox image updated to `ghcr.io/usta0x001/phantom-sandbox:latest` (was `redwan07/phantom-sandbox:latest`)
- **sleep infinity** — Docker runtime now passes `command=["sleep","infinity"]` (list form) to avoid exec-form entrypoint parsing issue
- **Sandbox entrypoint** — `docker-entrypoint.sh` detects `/app/venv/bin/python` first before falling back to `poetry run python`

### Changed
- **Sandbox image** — Moved from Docker Hub to GitHub Container Registry (`ghcr.io/usta0x001/phantom-sandbox`)
- **README** — Updated sandbox image references, corrected sandbox size (~14GB), fixed Docker Hub image names

## [0.8.0] - 2026-02-20

### Added
- **Multi-Agent System** — Specialized agent trees for discovery, exploitation, validation, and reporting
- **MITRE ATT&CK Enrichment** — Automatic TTP mapping for all findings
- **Compliance Mapping** — OWASP Top 10, PCI DSS, SOC 2 out of the box
- **SARIF Output** — Native GitHub Security tab integration
- **Differential Scanning** — Track new/fixed vulnerabilities across runs
- **Knowledge Persistence** — Cross-scan learning, false positive tracking
- **Webhook Notifications** — Slack and custom webhook alerts on critical findings
- **Plugin System** — Extend Phantom with custom tools and workflows
- **Scan Profiles** — quick, standard, deep, api-only, infrastructure presets
- **Attack Graph** — NetworkX-based attack path analysis
- **Nuclei Template Generator** — Auto-generate custom Nuclei templates from findings
- **Provider Registry** — 9 LLM provider presets with fallback chains
- **Scope Validator** — ReDoS-protected target authorization enforcement
- **Audit Logger** — Crash-safe JSONL audit logging
- **TUI Interface** — Rich terminal interface with Textual
- **Typer CLI** — Modern CLI with subcommands (scan, config, report, version)

### Fixed
- Thread-safe telemetry tracer (all mutating methods locked)
- Thread-safe agent state (message list protected with `_msg_lock`)
- Thread-safe knowledge store (all mutations locked, atomic file writes)
- Agent graph registration race condition (wrapped with `_graph_lock`)
- Memory compressor no longer mutates caller's conversation history
- LLM history mutation bug eliminated
- `UnboundLocalError` on unknown agent sender
- CVSS calculation crash on import failure
- Config save/load path asymmetry
- System prompt now always uses full ninja prompt (no silent compact override)
- Non-retryable errors no longer trigger retry loops
- Boolean argument parser no longer treats unknown strings as `True`

### Security
- All legacy telemetry/phone-home code removed
- Zero external data exfiltration
- Shell injection protection on all 6 tool wrappers
- XML-escaped tool results to prevent prompt injection
- SSRF protection on webhook/notification URLs
- Secure plugin loading (requires explicit opt-in)
- All scan data stays local in `phantom_runs/`

### Removed
- All legacy branding and references
- PostHog analytics
- Ghost telemetry configuration
- Internal audit documents

## [0.7.0] - 2026-02-18

### Added
- Initial Phantom fork with core scanning functionality
- Docker sandbox execution environment
- Basic CLI interface
- LiteLLM integration for multi-provider support
