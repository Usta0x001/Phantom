# Changelog

All notable changes to Phantom will be documented in this file.

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
  upstream Strix) without `cap_drop`.
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
