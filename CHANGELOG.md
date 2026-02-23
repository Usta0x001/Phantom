# Changelog

All notable changes to Phantom will be documented in this file.

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
