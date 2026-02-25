# Changelog

All notable changes to Phantom will be documented in this file.

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
