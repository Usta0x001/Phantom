# Phantom — Full Continuation Prompt for New Chat Session

> **Copy everything below the line and paste it as your first message in a new GitHub Copilot chat session.**

---

## Context

I'm working on **Phantom** — an autonomous offensive security intelligence platform (AI-powered multi-agent penetration testing). It's a Python 3.12+ project currently at **v0.9.9** (commit `da69186`, tag `v0.9.9`).

**Workspace:** `c:\Users\Gadouri\Desktop\New folder (2)\phantom`
**GitHub:** `https://github.com/Usta0x001/Phantom.git` (remote: origin, branch: main)
**Install:** Editable (`pip install -e .`), entry point: `phantom` CLI

### Architecture

```
phantom/
├── agents/           # Agent system
│   ├── base_agent.py        # Core agent loop, tool execution, action dispatch
│   ├── enhanced_state.py    # EnhancedAgentState — vuln tracking, endpoint dedup, host discovery
│   ├── state.py             # Base AgentState (message history, status)
│   ├── protocol.py          # Agent protocol definition
│   └── PhantomAgent/
│       └── phantom_agent.py # Root Phantom agent (scan config → task description)
├── tools/            # Tool ecosystem
│   ├── executor.py          # Tool execution pipeline (auto-record findings, endpoint tracking)
│   ├── registry.py          # Tool registration & discovery
│   ├── argument_parser.py   # LLM argument parsing
│   ├── context.py           # Tool execution context
│   ├── agents_graph/        # Sub-agent creation/management
│   ├── browser/             # Playwright browser automation
│   ├── findings/            # record_finding, get_findings_ledger
│   ├── finish/              # finish_scan, report generation, enrichment
│   ├── notes/               # Agent note-taking
│   ├── proxy/               # HTTP proxy (mitmproxy-based)
│   ├── python/              # Python code execution in sandbox
│   ├── reporting/           # Vulnerability report creation
│   ├── security/            # nmap, nuclei, sqlmap, ffuf, katana, httpx, etc.
│   ├── terminal/            # Shell command execution in sandbox
│   ├── thinking/            # LLM thinking/reasoning tool
│   ├── todo/                # Agent task planning
│   └── web_search/          # DuckDuckGo + Perplexity web search
├── llm/              # LLM integration
│   └── memory_compressor.py # Memory management with findings ledger preservation
├── models/           # Pydantic data models
├── runtime/          # Docker sandbox management
├── interface/        # CLI (Typer) + TUI (Textual)
│   ├── cli_app.py           # CLI entry point with all options
│   └── cli.py               # CLI logic, scan config building
├── config/           # Scan profiles, YAML config
├── skills/           # Skill definitions for sub-agents
├── telemetry/        # Logging, tracing, metrics
└── utils/            # Shared utilities
```

### Key Technical Details

- **LLM Backend:** LiteLLM ~1.81.1 (supports OpenRouter, OpenAI, Anthropic, Groq, Vertex, etc.)
- **Docker Sandbox:** `ghcr.io/usta0x001/phantom-sandbox:latest` (14GB image with security tools)
- **20+ Security Tools:** nmap, nuclei, sqlmap, ffuf, katana, httpx, semgrep, nikto, gitleaks, arjun, etc.
- **Multi-Agent System:** Root agent spawns specialized sub-agents (SQLi, XSS, IDOR, Auth testing, etc.)
- **Findings Ledger:** Append-only log that survives memory compression — ensures no vuln is forgotten
- **EnhancedAgentState:** Tracks vulns (severity stats), tested endpoints (dedup), hosts, tool usage, scan phases
- **Memory Compressor:** 10-category preservation with priority scoring, dynamic threshold per scan profile
- **Scan Profiles:** quick (60K threshold), standard (80K), deep (100K), stealth, api_only
- **Reports:** Markdown vuln reports, compliance mapping, SARIF, CSV, enhanced_state.json

### Current Configuration

```json
{
  "env": {
    "PHANTOM_IMAGE": "ghcr.io/usta0x001/phantom-sandbox:latest",
    "PHANTOM_SANDBOX_EXECUTION_TIMEOUT": "180",
    "GROQ_API_KEY": "<YOUR_GROQ_API_KEY>",
    "LLM_API_KEY": "<YOUR_LLM_API_KEY>",
    "LLM_API_BASE": "https://openrouter.ai/api/v1",
    "PHANTOM_LLM": "openrouter/deepseek/deepseek-v3.2",
    "PHANTOM_LLM_FALLBACK": "openrouter/meta-llama/llama-3.3-70b-instruct"
  }
}
```
Config file: `~/.phantom/cli-config.json`

### Test Status

**315 tests passing, 11 skipped, 0 failures** (pytest, ~33s)

Test files:
- `tests/test_all_modules.py` — import & module tests
- `tests/test_integration.py` — integration tests
- `tests/test_v093_security.py` — v0.9.3 security fixes
- `tests/test_v096_discovery.py` — v0.9.6 discovery + version check
- `tests/test_v098_features.py` — v0.9.8 features
- `tests/test_v099_fixes.py` — v0.9.9 fixes (23 tests)
- `tests/agents/` — agent-specific tests
- `tests/tools/` — tool-specific tests
- `tests/llm/` — LLM & memory tests
- `tests/runtime/` — sandbox tests
- `tests/interface/` — CLI tests
- `tests/telemetry/` — logging tests

### Version History (v0.9.0 → v0.9.9)

| Version | Key Changes | Tests |
|---------|------------|-------|
| v0.9.0 | Initial major release, forked from Strix | ~100 |
| v0.9.1 | Thread-safety fixes in agent graph | ~120 |
| v0.9.2 | Full re-audit, 14 bugs fixed (2C, 5H, 5M, 2L) | ~140 |
| v0.9.3 | SSRF, path traversal, proxy, container security fixes | ~160 |
| v0.9.4 | Additional hardening | ~180 |
| v0.9.5 | Proxy resilience, mitmproxy recovery | 217 |
| v0.9.6 | Vuln discovery overhaul, iteration limits, tool output caps | 233 |
| v0.9.7 | Findings ledger, memory compression rewrite, subagent context | 260 |
| v0.9.8 | DuckDuckGo fallback, dynamic memory, EnhancedAgentState, CI/CD, TUI | 292 |
| v0.9.9 | Endpoint dedup, state wiring, auth scanning, persistence | 315 |

### Audit History

Two full audits documented:
1. **AUDIT_REPORT.md** (v0.9.0) — 67 findings: 6 CRITICAL, 14 HIGH, 21 MEDIUM, 12 LOW, etc. All fixed by v0.9.5.
2. **AUDIT_REPORT_v0.9.2.md** (v0.9.2) — 14 bugs: 2 CRITICAL (thread-safety), 5 HIGH, 5 MEDIUM, 2 LOW. All fixed.

### Real Scan Results (v0.9.9 validated against OWASP Juice Shop)

Scan ran against `http://host.docker.internal:3000` (Juice Shop) using DeepSeek v3.2 via OpenRouter. Results:

| # | Vuln | Severity | CVSS | Endpoint |
|---|------|----------|------|----------|
| 1 | SQL Injection Auth Bypass | CRITICAL | 10.0 | POST /rest/user/login |
| 2 | Mass Assignment (role escalation) | CRITICAL | 10.0 | POST /api/Users |
| 3 | IDOR (user enum) | HIGH | 7.1 | GET /api/Users/{id} |
| 4 | Default Creds + Weak Password Policy | CRITICAL | 9.4 | POST /rest/user/login, /api/Users |

Scan stats: 9 agents, 234 tool calls, 4.1M input tokens, $0.74 cost. Scan ended due to API credit exhaustion (APIError), so `finish_scan` and `enhanced_state.json` export were NOT reached. Vulnerability reports were saved individually during the scan (working correctly).

Output: `phantom_runs/host-docker-internal-3000_fa26/` (4 vuln-*.md files, vulnerabilities.csv, audit.jsonl with 231 entries)

### Known Issues & Gaps (Prioritized)

#### HIGH Priority
1. **Graceful Credit Exhaustion Handling**: When LLM API credits run out (APIError), the scan crashes without calling `finish_scan`. Should catch APIError, save state, generate partial report.
2. **Docker Sandbox Image Stale**: The `phantom-sandbox:latest` image has NOT been rebuilt since v0.9.5. Any new tool code changes require a rebuild. Run: `docker build -t ghcr.io/usta0x001/phantom-sandbox:latest .`
3. **`katana_crawl` Sandbox Timeout**: Katana tool frequently fails in sandbox with execution timeout errors. Needs investigation — may need longer timeout or async execution.
4. **`record_finding` Parameter Hallucination**: LLM sometimes passes wrong parameter names to `record_finding` tool. Consider stricter parameter validation or adding aliases.

#### MEDIUM Priority
5. **Unused `ScanStatus` Import**: `enhanced_state.py` has unused import (minor cleanup).
6. **LiteLLM Info Messages Noise**: `LiteLLM.Info: If you need to debug this error...` messages clutter scan output. Should be suppressed or redirected to log file.
7. **No Partial Report on Crash**: If scan crashes mid-way, only individual vuln reports survive. No summary report is generated. `finish_scan` should have a crash-recovery mode.
8. **Input Token Cost**: At ~4.1M tokens for a standard scan, cost can be significant. Could optimize by reducing tool output verbosity further or implementing smarter memory compression.

#### LOW Priority
9. **Scan Resume**: No ability to resume a crashed/interrupted scan from where it left off.
10. **Enhanced Report Format**: Current vuln reports are markdown. Could add HTML, PDF, or interactive report formats.
11. **Notification System**: Slack/webhook notifications exist in config but may not be fully wired.

### What to Do Next (Roadmap to v1.0)

1. **Crash-resilient scanning** — Catch APIError and other LLM failures, call `finish_scan` with partial results
2. **Rebuild Docker sandbox** — Include all v0.9.5+ tool changes in the sandbox image
3. **v0.9.10 or v1.0-rc1** — Fix HIGH priority issues above, comprehensive integration test with a real scan that runs to completion
4. **Documentation** — Update README with full feature list, add user guide, complete API docs
5. **Performance** — Optimize token usage, add streaming support, improve memory compression efficiency
6. **Plugin System** — Finalize and document the tool plugin system for custom security tools
7. **Differential Scanning** — Wire up knowledge persistence for comparing scans of the same target over time

### Commands Reference

```bash
# Run tests
cd c:\Users\Gadouri\Desktop\New folder (2)\phantom
python -m pytest tests/ -q --tb=short

# Run a scan (non-interactive / headless)
phantom scan -t http://TARGET:PORT -m standard -n

# Run a scan (with TUI)
phantom scan -t http://TARGET:PORT -m standard

# Authenticated scanning
phantom scan -t https://app.com -m standard -H "Authorization: Bearer TOKEN" -H "Cookie: session=abc"

# Check version
phantom --version

# Juice Shop target (already running)
docker ps | findstr juice  # Container: juiceshop on port 3000
```

### Other Projects in Workspace

The workspace also contains related security tool projects for reference:
- **strix/** — The upstream fork that Phantom is based on
- **guardian-cli/** — CLI security scanner with Gemini AI
- **shannon/** — TypeScript security scanner
- **redamon/** — Reconnaissance and monitoring platform
- **pentagi/** — PentAGI platform with frontend/backend

---

**When I say "continue", start by reading the CHANGELOG.md and running the test suite to verify you understand the current state. Then ask me what I want to work on, or propose the highest-impact improvement based on the known issues above.**
