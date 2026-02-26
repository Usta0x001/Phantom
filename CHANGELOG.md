# Changelog

All notable changes to Phantom will be documented in this file.

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
