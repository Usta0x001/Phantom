# Phantom Scanner — Comprehensive Codebase Audit

**Date:** February 25, 2026  
**Scope:** Full audit of `phantom/` codebase — capabilities, gaps, and improvement opportunities

---

## 1. SCAN MODES

### 1.1 Available Modes

Three scan mode markdown files exist at `phantom/skills/scan_modes/`:
| Mode | File | Description |
|------|------|-------------|
| **Quick** | `quick.md` | Time-boxed rapid assessment (<10 min). High-impact vulns only. |
| **Standard** | `standard.md` | Balanced assessment with systematic methodology (~30 min). |
| **Deep** | `deep.md` | Exhaustive assessment with maximum coverage and vuln chaining. |

### 1.2 How Modes Actually Work

**Modes are implemented at TWO levels:**

1. **Prompt-level (active & wired):** The scan mode name is passed via `LLMConfig.scan_mode` → `LLM._load_system_prompt()` loads the corresponding `.md` file as a Jinja skill and injects it into the system prompt. This IS wired at runtime — the agent receives different instructions per mode.

2. **Code-level via `scan_profiles.py` (EXISTS but NOT wired):** `phantom/core/scan_profiles.py` defines a rich `ScanProfile` dataclass with:
   - `max_iterations` (quick=20, standard=40, deep=80)
   - `sandbox_timeout_s` (quick=60, standard=120, deep=180)
   - `reasoning_effort` (quick=low, standard=medium, deep=high)
   - `priority_tools` / `skip_tools` lists
   - `max_concurrent_tools`, `enable_browser`, `nuclei_severity`
   - Two additional profiles: `stealth` and `api_only`

   **However**, `scan_profiles.py` is **never imported by the runtime**. The `cli.py` and `tui.py` both hardcode `max_iterations=300` regardless of mode. The profile's `skip_tools`, `priority_tools`, and `enable_browser` settings are completely unused. Only the prompt text varies.

### 1.3 Verdict
The scan mode system is **50% implemented**. The prompt differentiation works well, but the `ScanProfile` parameters (iteration caps, tool restrictions, severity filters) are dead code. This is a significant missed optimization — quick scans waste iterations because they get the same 300-iteration budget as deep scans.

---

## 2. TOOL INVENTORY

### 2.1 Complete Tool List

| Category | Tool Function | Description | Sandbox? |
|----------|--------------|-------------|----------|
| **Terminal** | `terminal_execute` | Execute shell commands in sandbox container | Client-side |
| **Python** | `python_action` | Execute Python code (new_session, execute, close, list_sessions) | Client-side |
| **Browser** | `browser_action` | Full browser automation (27 actions: navigate, click, type, JS exec, screenshot, etc.) | Client-side |
| **Proxy** | `list_requests` | List captured HTTP requests with HTTPQL filter | Client-side |
| | `view_request` | View request/response details | Client-side |
| | `send_request` | Send custom HTTP request | Client-side |
| | `repeat_request` | Replay/modify captured request | Client-side |
| | `scope_rules` | Manage proxy scope rules | Client-side |
| | `list_sitemap` | View discovered sitemap | Client-side |
| **Security** | `nmap_scan` | Port scanning (quick/standard/comprehensive/stealth/udp) | Sandbox |
| | `nmap_vuln_scan` | NSE vulnerability scripts | Sandbox |
| | `nuclei_scan` | Template-based vuln scanning | Sandbox |
| | `nuclei_scan_cves` | CVE-specific nuclei templates | Sandbox |
| | `nuclei_scan_misconfigs` | Misconfiguration detection | Sandbox |
| | `httpx_probe` | HTTP/HTTPS service probing | Sandbox |
| | `httpx_screenshot` | Web page screenshots | Sandbox |
| | `httpx_full_analysis` | Complete HTTP analysis | Sandbox |
| | `ffuf_directory_scan` | Directory/file fuzzing | Sandbox |
| | `ffuf_parameter_fuzz` | Hidden parameter discovery | Sandbox |
| | `sqlmap_test` | SQL injection testing | Sandbox |
| | `sqlmap_dump_database` | Database exfiltration post-SQLi | Sandbox |
| | `sqlmap_forms` | Automatic form-based SQLi | Sandbox |
| | `subfinder_enumerate` | Subdomain enumeration | Sandbox |
| | `subfinder_with_sources` | Subdomain enum with source attribution | Sandbox |
| **Reporting** | `create_vulnerability_report` | Create structured vuln report with CVSS | No sandbox |
| **Agent Graph** | `create_agent` | Spawn sub-agent with task & skills | No sandbox |
| | `view_agent_graph` | View agent hierarchy and status | No sandbox |
| | `send_message_to_agent` | Inter-agent messaging | No sandbox |
| | `wait_for_message` | Wait for messages from other agents | No sandbox |
| | `agent_finish` | Sub-agent completion signal | No sandbox |
| **Finish** | `finish_scan` | Root agent scan completion | No sandbox |
| **Thinking** | `think` | Internal reasoning scratchpad | No sandbox |
| **Notes** | Notes tools | Persistent notes across iterations | No sandbox |
| **TODO** | TODO tools | Task tracking | No sandbox |
| **File Edit** | File editing tools | Edit files in workspace | No sandbox |
| **Web Search** | `web_search` | Perplexity AI-powered search (requires API key) | No sandbox |

**Total: ~35+ distinct tool functions**

### 2.2 Security Tools Available in Sandbox (not Phantom tools, but accessible via terminal)

The Docker sandbox is Kali Linux-based with:
- **Recon:** nmap, subfinder, naabu, httpx, gospider, katana, arjun
- **Scanning:** nuclei, sqlmap, trivy, zaproxy, wapiti, vulnx/cvemap
- **Fuzzing:** ffuf, dirsearch
- **Code Analysis:** semgrep, bandit, trufflehog, retire, eslint
- **Specialized:** jwt_tool, wafw00f, interactsh-client
- **Proxy:** Caido CLI (running in sandbox)
- **Languages:** Python 3, Go, Node.js

### 2.3 Tools the Agent CAN'T Use (but would be useful)

| Missing Tool | Use Case | Impact |
|-------------|----------|--------|
| **nikto** | Web server scanner | Medium — nuclei covers most of this |
| **burpsuite** | Advanced proxying | Low — Caido CLI already present |
| **amass** | Advanced subdomain enum | Medium — subfinder covers basic cases |
| **masscan** | Ultra-fast port scanning | Low — nmap with -T4 is adequate |
| **testssl.sh** | TLS/SSL analysis | Medium — no dedicated TLS testing tool |
| **wfuzz** | Advanced fuzzing | Low — ffuf covers this |
| **dalfox** | Dedicated XSS scanner | High — no specialized XSS confirmation tool |
| **commix** | Command injection | Medium — no dedicated RCE tool |
| **ssrfmap** | SSRF automation | Medium — would help with blind SSRF |
| **OWASP ZAP API** | Programmatic scanning | Medium — ZAP is in sandbox but no typed wrapper |

---

## 3. REPORTING SYSTEM

### 3.1 `create_vulnerability_report` Tool

This is the primary reporting mechanism, located at `phantom/tools/reporting/reporting_actions.py`. It:
- Accepts 18+ parameters (title, description, impact, target, technical_analysis, poc_description, poc_script_code, remediation_steps, + 8 CVSS components)
- Validates all required fields and CVSS parameter values
- Computes CVSS 3.1 score using the `cvss` library
- Runs LLM-based deduplication against existing reports before accepting
- Stores reports via the global `Tracer` object
- Returns success/failure with report ID and severity

### 3.2 Output Formats

Supported via `phantom report export --format`:
| Format | Status | Implementation |
|--------|--------|---------------|
| **JSON** | ✅ Working | Direct copy of tracer JSON data |
| **SARIF** | ✅ Working | `phantom/interface/formatters/sarif_formatter.py` |
| **Markdown** | ✅ Working | `_render_markdown_report()` in `cli_app.py` |
| **HTML** | ✅ Working | `_render_html_report()` in `cli_app.py` — self-contained dark-theme HTML |

### 3.3 Final Summary Report

The `finish_scan` tool requires the root agent to provide:
- `executive_summary`
- `methodology`
- `technical_analysis`
- `recommendations`

Additionally, `phantom/core/report_generator.py` (566 lines) contains a comprehensive `ReportGenerator` class with JSON/HTML/Markdown export. **However**, this is NOT wired into the runtime — it's standalone library code. Reports are generated from the Tracer's stored data instead.

### 3.4 Verdict
The reporting system is **functional and solid** for the core workflow. The `ReportGenerator` class in `core/` is dead code. SARIF support is good for CI/CD integration. The deduplication system (LLM-based) is a notable strength.

---

## 4. PROMPT ENGINEERING

### 4.1 System Prompt Location

`phantom/agents/PhantomAgent/system_prompt.jinja` — 408 lines of Jinja2 template.

### 4.2 Prompt Quality Assessment

**Strengths:**
- **Extremely pentest-focused** — written from a bug bounty hunter's perspective
- **Comprehensive tool usage instructions** — exact XML-based function call format documented
- **Multi-agent strategy** well-defined — clear rules for when to spawn sub-agents
- **Vulnerability priority list** — 10 high-impact targets prioritized (IDOR, SQLi, SSRF, XSS, etc.)
- **Black-box vs White-box differentiation** — separate workflows for each
- **Validation requirements** — "full exploitation required, no assumptions"
- **De-duplication awareness** — prompt tells agent to respect duplicate rejections
- **Efficiency tactics** — spray via scripts, batch operations, use established fuzzers
- **Environment description** — complete list of available tools in sandbox
- **Skill injection system** — Jinja2 template dynamically loads vulnerability-specific knowledge

**Weaknesses:**
- **Extremely aggressive language** ("GO SUPER HARD", "PUSH TO THE ABSOLUTE LIMIT", "2000+ steps MINIMUM") — this wastes tokens and can cause the agent to loop instead of reporting
- **Contradictory for quick mode** — the aggressive mandate conflicts with time-boxed quick scan instructions
- **No explicit token budget awareness** — agent doesn't know how much budget remains
- **Missing: post-scan cleanup instructions** — no guidance on cleaning up artifacts
- **Missing: rate limiting guidance** — no specific instructions about respecting target rate limits

### 4.3 Scan Mode Instructions

Each mode gets injected as `<specialized_knowledge>` alongside vulnerability-specific skills. The quick/standard/deep `.md` files are well-differentiated and contain concrete phase-by-phase instructions.

---

## 5. MEMORY & CONTEXT

### 5.1 Memory Compressor (`phantom/llm/memory_compressor.py`)

- **Token limit:** `MAX_TOTAL_TOKENS = 100,000`
- **Strategy:** Keep all system messages + last 15 regular messages intact. Summarize older messages in chunks of 10 using a separate LLM call.
- **Image handling:** Maximum 3 images retained; older images replaced with text placeholder.
- **Summary format:** Wrapped in `<context_summary>` tags with security-focused preservation instructions.
- **Token counting:** Uses `litellm.token_counter()` with fallback to `len(text) // 4`.

### 5.2 LLM Client (`phantom/llm/llm.py`)

- **Streaming:** Full streaming support with XML tool-call detection (`</function>` boundary).
- **Retry logic:** Configurable max retries (default 5), exponential backoff capped at 10s.
- **Provider support:** Any litellm-supported provider (OpenAI, Anthropic, Groq, OpenRouter, Ollama, etc.).
- **Vision support:** Auto-detected via `litellm.supports_vision()`.
- **Reasoning support:** Auto-detected, sets `reasoning_effort` param.
- **Prompt caching:** Anthropic cache control headers supported.
- **Message preparation:** System prompt → agent identity → compressed history.

### 5.3 Deduplication (`phantom/llm/dedupe.py`)

- **LLM-based:** Uses the same model as the scan to compare candidate reports against existing ones.
- **Detailed prompt:** 80+ lines of deduplication rules covering what IS and ISN'T a duplicate.
- **XML response parsing:** Extracts structured `<dedupe_result>` responses.
- **Fields compared:** title, description, impact, target, technical_analysis, poc_description, endpoint, method.

### 5.4 RAG / Knowledge Base

**No RAG system exists.** However:
- `phantom/core/knowledge_store.py` (468 lines) implements a file-based JSON knowledge store for hosts, vulnerabilities, scan history, and false positives. **It is NOT wired into the agent runtime** — it's standalone library code.
- The skill system (`phantom/skills/`) acts as a static knowledge base with 20+ vulnerability guides.

---

## 6. AGENT ARCHITECTURE

### 6.1 Base Agent (`phantom/agents/base_agent.py` — 602 lines)

**Core loop:**
1. Initialize sandbox (Docker container)
2. `while True:` loop with iteration counter
3. Check for inter-agent messages
4. Check stopping conditions (max iterations, force stop, waiting)
5. Call `LLM.generate()` for next action
6. Parse tool invocations from response
7. Execute tools via `process_tool_invocations()`
8. If tool returns "should_finish" → complete

**Iteration management:**
- Warning at `max_iterations - 10%` remaining
- Critical warning at `max_iterations - 3`
- Hard stop at `max_iterations`

### 6.2 Agent Graph System

Agents communicate via an in-memory graph (`_agent_graph` dict):
- **Nodes:** Each agent registered with ID, name, task, status, parent_id
- **Edges:** Parent→child delegation edges
- **Messages:** `_agent_messages` dict with message queues per agent
- **Sub-agents run in threads** via `threading.Thread` with their own asyncio event loops

**Signals an agent can send:**
| Signal | Mechanism |
|--------|-----------|
| Finish (root) | `finish_scan` tool |
| Finish (sub-agent) | `agent_finish` tool |
| Spawn sub-agent | `create_agent` tool |
| Send message | `send_message_to_agent` tool |
| Wait for input | `wait_for_message` tool |
| View graph | `view_agent_graph` tool |

### 6.3 Agent Specialization via Skills

Sub-agents can be created with up to 5 skills from the skill library:
- `vulnerabilities/`: sql_injection, xss, ssrf, idor, csrf, rce, xxe, etc. (20 skills)
- `reconnaissance/`: recon, tool_mastery
- `frameworks/`: fastapi, nextjs
- `protocols/`: graphql
- `technologies/`: firebase_firestore, supabase
- `cloud/`: (empty, placeholder)
- `custom/`: (empty, placeholder)
- `coordination/`: root_agent (internal)

---

## 7. PHANTOM-ONLY FEATURES (Not in Strix)

### 7.1 `phantom/core/` — Advanced Modules

| Module | Lines | Status | Description |
|--------|-------|--------|-------------|
| `scan_profiles.py` | 217 | ⚠️ UNWIRED | 5 scan profiles with tool limits, iteration caps, severity filters |
| `knowledge_store.py` | 468 | ⚠️ UNWIRED | Persistent knowledge store for cross-scan correlation |
| `verification_engine.py` | 477 | ⚠️ UNWIRED | Automated exploit verification (time-based, error-based, boolean, DOM, OOB) |
| `attack_graph.py` | 631 | ⚠️ UNWIRED | NetworkX-based attack surface modeling |
| `attack_path_analyzer.py` | 493 | ⚠️ UNWIRED | Multi-step exploit chain analysis |
| `mitre_enrichment.py` | 331 | ⚠️ UNWIRED | CWE/CAPEC mapping with 40+ CWE entries |
| `compliance_mapper.py` | 649 | ⚠️ UNWIRED | OWASP Top 10, PCI-DSS v4, NIST 800-53, ISO 27001 mapping |
| `report_generator.py` | 566 | ⚠️ UNWIRED | JSON/HTML/Markdown report generator with styled output |
| `diff_scanner.py` | 319 | ⚠️ UNWIRED | Compare two scan runs (new/fixed/persistent vulns) |
| `nuclei_templates.py` | 224 | ⚠️ UNWIRED | Auto-generate Nuclei YAML templates from findings |
| `interactsh_client.py` | 381 | ⚠️ UNWIRED | OOB callback integration for blind vuln verification |
| `audit_logger.py` | 339 | ✅ WIRED | Crash-safe JSONL audit logging (used in cli.py) |
| `scope_validator.py` | 272 | ✅ WIRED | Target scope enforcement (used in cli.py) |
| `notifier.py` | 373 | ⚠️ UNWIRED | Webhook/Slack notification hooks |
| `plugin_loader.py` | 189 | ⚠️ UNWIRED | User plugin system (`~/.phantom/plugins/`) |
| `priority_queue.py` | 349 | ⚠️ UNWIRED | Priority-based vulnerability queuing |

### 7.2 `phantom/models/`

| Model | Lines | Status |
|-------|-------|--------|
| `vulnerability.py` | 235 | ✅ Used by core modules (Pydantic models with severity, evidence, CVSS) |
| `host.py` | ~100 | ✅ Used by knowledge store |
| `scan.py` | 246 | ⚠️ Defined but not used by runtime |
| `verification.py` | 196 | ⚠️ Used by verification engine (which is unwired) |

### 7.3 `phantom/tools/security/`

All security tools are **wired and active**: nmap (2 tools), nuclei (3 tools), httpx (3 tools), ffuf (2 tools), sqlmap (3 tools), subfinder (2 tools) = **15 typed security tool wrappers**.

### 7.4 `phantom/interface/cli_app.py` — Unique Features

- **Typer-based CLI** with rich help text and emoji support
- **Report export** in JSON/SARIF/Markdown/HTML
- **Config management** subcommand (`phantom config show/set/reset`)
- **Report list** subcommand
- **Auto shell completion** installation on first run
- **Windows UTF-8 handling**
- **Non-interactive exit code:** Exit code 2 if vulnerabilities found (CI/CD friendly)

### 7.5 Dead Code Summary

**~4,500+ lines of sophisticated, unused code** in `phantom/core/` that could dramatically improve scan quality if wired in:
- Scan profiles with per-mode constraints
- Automated verification engine with 8 verification strategies
- Attack graph with path analysis
- MITRE CWE/CAPEC enrichment
- Compliance framework mapping (5 frameworks)
- Differential scanning
- Nuclei template generation from findings
- OOB callback integration
- Notification webhooks
- Plugin system

---

## 8. TEST COVERAGE

### 8.1 Test Structure

```
tests/
├── test_all_modules.py     (1009 lines — comprehensive)
├── conftest.py
├── __init__.py
├── agents/                 (empty — __init__.py only)
├── interface/              (unknown contents)
├── llm/                    (empty — __init__.py only)
├── runtime/                (unknown contents)
├── telemetry/              (unknown contents)
└── tools/
    ├── test_argument_parser.py
    └── conftest.py
```

### 8.2 What's Tested

`test_all_modules.py` covers:
- ✅ `ScopeValidator` (8 tests — URL, IP, CIDR, wildcard, deny rules)
- ✅ `AuditLogger` (event logging, tool calls, findings)
- ✅ `MITREEnricher` (CWE lookup, keyword mapping)
- ✅ `AttackGraph` (node/edge management, path finding)
- ✅ `ComplianceMapper` (framework mapping, gap analysis)
- ✅ `AttackPathAnalyzer` (path analysis, choke points)
- ✅ `ScanProfiles` (list, get, merge, register)
- ✅ `SARIFFormatter` (SARIF output validation)
- ✅ `ProviderRegistry` (LLM provider management)

### 8.3 What's NOT Tested

- ❌ Agent loop / `base_agent.py`
- ❌ Tool execution / `executor.py`
- ❌ Memory compression
- ❌ Deduplication
- ❌ Browser/proxy/terminal tool actions
- ❌ Security tool wrappers (nmap, nuclei, etc.)
- ❌ Reporting flow end-to-end
- ❌ Integration tests (scan → report)
- ❌ CLI command tests

---

## 9. CONFIGURATION

### 9.1 Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PHANTOM_LLM` | (required) | LLM model (e.g., `groq/llama-3.3-70b-versatile`) |
| `LLM_API_KEY` | None | API key for the LLM provider |
| `LLM_API_BASE` | None | Custom API base URL |
| `OPENAI_API_BASE` | None | OpenAI-compatible base URL |
| `LITELLM_BASE_URL` | None | LiteLLM proxy URL |
| `OLLAMA_API_BASE` | None | Ollama base URL |
| `PHANTOM_REASONING_EFFORT` | "high" | LLM reasoning effort (low/medium/high) |
| `PHANTOM_LLM_MAX_RETRIES` | "5" | Max LLM request retries |
| `PHANTOM_MEMORY_COMPRESSOR_TIMEOUT` | "30" | Memory compression timeout (seconds) |
| `LLM_TIMEOUT` | "300" | LLM request timeout |
| `PERPLEXITY_API_KEY` | None | Enables web search tool |
| `PHANTOM_DISABLE_BROWSER` | "false" | Disable browser tools |
| `PHANTOM_IMAGE` | `ghcr.io/usta0x001/phantom-sandbox:latest` | Docker image for sandbox |
| `PHANTOM_RUNTIME_BACKEND` | "docker" | Runtime backend |
| `PHANTOM_SANDBOX_EXECUTION_TIMEOUT` | "120" | Per-tool sandbox timeout |
| `PHANTOM_SANDBOX_CONNECT_TIMEOUT` | "10" | Sandbox connection timeout |
| `PHANTOM_SANDBOX_MODE` | "false" | Run in sandbox mode |
| `PHANTOM_ENABLE_PLUGINS` | None | Enable plugin loading (`"1"`) |

### 9.2 Config Persistence

- Stored at `~/.phantom/cli-config.json`
- Managed via `phantom config set/show/reset` commands
- LLM config changes automatically invalidate saved config
- Supports `--config` flag for custom config file override

---

## 10. FEATURE INVENTORY

### Working Features ✅
| Feature | Quality |
|---------|---------|
| LLM agent loop with streaming | Excellent |
| Multi-agent sub-agent spawning | Excellent |
| 15 typed security tool wrappers | Good |
| Browser automation (Playwright) | Good |
| Proxy integration (Caido) | Good |
| Terminal command execution | Good |
| Python code execution | Good |
| Vulnerability reporting with CVSS | Excellent |
| LLM-based deduplication | Good |
| Memory compression | Good |
| Scan mode prompt differentiation | Good |
| SARIF/JSON/MD/HTML export | Good |
| Audit logging (crash-safe JSONL) | Excellent |
| Scope validation | Good |
| CLI with Typer | Excellent |
| Non-interactive CI/CD mode | Good |
| Inter-agent messaging | Good |
| Skill/knowledge injection system | Excellent |
| 20+ vulnerability skill guides | Excellent |

### Broken/Incomplete Features ⚠️
| Feature | Issue |
|---------|-------|
| `ScanProfile` constraints | Defined but not wired — max_iterations, skip_tools, priority_tools ignored |
| Web search | Requires Perplexity API key (not free) |
| `stealth` and `api_only` scan modes | Profiles defined in code, no prompt `.md` files, mode enum in CLI doesn't include them |

### Unactivated Features (Dead Code) 🔴
| Feature | Lines | Potential Impact |
|---------|-------|-----------------|
| Knowledge Store (cross-scan learning) | 468 | HIGH — avoid re-scanning, learn from history |
| Verification Engine | 477 | HIGH — automated false positive filtering |
| Attack Graph + Path Analyzer | 1,124 | MEDIUM — visual attack surface modeling |
| MITRE CWE/CAPEC Enrichment | 331 | HIGH — standardized vuln classification |
| Compliance Mapping (5 frameworks) | 649 | HIGH — instant compliance reporting |
| Diff Scanner | 319 | MEDIUM — track vuln fixes over time |
| Nuclei Template Generator | 224 | MEDIUM — re-run targeted checks |
| Interactsh OOB Client | 381 | HIGH — verify blind vulns (SSRF, XXE, RCE) |
| Notifier (Webhook/Slack) | 373 | MEDIUM — real-time alerts |
| Plugin System | 189 | LOW — user extensibility |
| Priority Queue | 349 | MEDIUM — prioritize verification order |
| Report Generator (core) | 566 | LOW — CLI already has report export |

---

## 11. TOP 10 MOST IMPACTFUL IMPROVEMENTS

Ranked by **value / effort** ratio:

### 1. Wire `ScanProfile` Into Runtime ⚡ HIGH VALUE / LOW EFFORT
**Effort:** ~2 hours  
**Impact:** Dramatic — quick scans actually become quick (20 iterations instead of 300), tool restrictions enforced, reasoning effort optimized.  
**How:** Import `get_profile()` in `cli.py`/`tui.py`, use profile's `max_iterations`, pass `skip_tools`/`priority_tools` to tool registry filter, set `reasoning_effort` from profile.

### 2. Wire MITRE CWE/CAPEC Enrichment Into Reports ⚡ HIGH VALUE / LOW EFFORT
**Effort:** ~1 hour  
**Impact:** Every vulnerability report automatically gets CWE IDs, CAPEC attack patterns, and OWASP Top 10 mapping — massively improves report quality.  
**How:** Call `MITREEnricher.enrich()` in `create_vulnerability_report` before storing.

### 3. Wire Compliance Mapper Into Report Export ⚡ HIGH VALUE / LOW EFFORT
**Effort:** ~2 hours  
**Impact:** `phantom report export` can output compliance posture against OWASP, PCI-DSS, NIST, ISO 27001.  
**How:** Add `--compliance` flag to export command, call `ComplianceMapper` on stored vulns.

### 4. Wire Knowledge Store for Cross-Scan Learning ⚡ HIGH VALUE / MEDIUM EFFORT
**Effort:** ~4 hours  
**Impact:** Agent avoids re-scanning known endpoints, builds on past findings, tracks false positives.  
**How:** Initialize `KnowledgeStore` in `cli.py`, load previous scan data into system prompt context, save discoveries post-scan.

### 5. Wire Verification Engine ⚡ HIGH VALUE / MEDIUM EFFORT
**Effort:** ~6 hours  
**Impact:** Automated verification before reporting reduces false positives dramatically. Has 8 verification strategies already implemented (time-based, error-based, boolean, DOM reflection, OOB HTTP/DNS, known file, math eval).  
**How:** Hook into `create_vulnerability_report` as a pre-check, or create a `verify_vulnerability` tool.

### 6. Tone Down Aggressive Prompt Language 🔧 MEDIUM VALUE / LOW EFFORT
**Effort:** ~1 hour  
**Impact:** Reduces token waste from agents looping endlessly. The "2000+ steps MINIMUM" and "GO SUPER HARD" language causes agents to resist finishing. Quick mode should have explicit "FINISH QUICKLY" language instead.  
**How:** Edit `system_prompt.jinja` — make aggressiveness mode-dependent via Jinja conditionals.

### 7. Add Token Budget Awareness to Agent 🔧 MEDIUM VALUE / MEDIUM EFFORT
**Effort:** ~4 hours  
**Impact:** Agent can see remaining budget and prioritize accordingly. Prevents mid-scan exhaustion.  
**How:** Track `_total_stats` in agent state, inject remaining token/cost estimate into periodic user messages.

### 8. Wire Diff Scanner for Regression Testing 🔧 MEDIUM VALUE / LOW EFFORT
**Effort:** ~2 hours  
**Impact:** `phantom report diff <run1> <run2>` shows new/fixed/persistent vulns — essential for tracking remediation.  
**How:** Add `diff` subcommand to `report_app` Typer group, wire `DiffScanner`.

### 9. Add `stealth` and `api_only` Modes to CLI 🔧 LOW-MEDIUM VALUE / LOW EFFORT
**Effort:** ~1 hour  
**Impact:** Two additional scan profiles already defined in code. Just add to CLI enum and create `.md` prompt files.  
**How:** Add to `ScanMode` enum, create `stealth.md` and `api_only.md` in `scan_modes/`.

### 10. Integration Tests 🔧 HIGH VALUE / HIGH EFFORT
**Effort:** ~10 hours  
**Impact:** Catch regressions in the scan→agent→tool→report pipeline. Currently zero integration test coverage.  
**How:** Mock Docker runtime, create test scenarios against known-vulnerable targets, verify report output.

---

## 12. WHAT'S NEEDED FOR "PRODUCTION READY"

### Critical (Must Have)
1. **Wire `ScanProfile` constraints** — without this, quick/standard modes are meaningless from a resource perspective
2. **Integration tests** — the core pipeline (scan → agent → tools → report) has zero test coverage
3. **Token budget management** — scans can silently exhaust API budget with no feedback to the agent
4. **Error recovery** — if the sandbox crashes mid-scan, there's no graceful recovery or partial report generation
5. **Rate limiting/backoff for target** — no built-in protection against overwhelming the target

### Important (Should Have)
6. **Wire MITRE + compliance enrichment** — reports need standardized classification for enterprise use
7. **Wire verification engine** — false positive rate is too high without automated verification
8. **Wire knowledge store** — repeated scans of the same target restart from scratch
9. **Scan timeout enforcement** — the `--timeout` flag sets env var but isn't enforced as a hard deadline
10. **Structured logging** — audit logger exists but agent decisions aren't fully logged

### Nice to Have
11. **Wire notifier** — webhook/Slack alerts on critical findings
12. **Wire plugin system** — user extensibility
13. **Wire OOB client** — blind vulnerability verification
14. **Wire attack graph** — visual attack surface representation
15. **API server mode** — run Phantom as a service (not just CLI)

---

## 13. ARCHITECTURE STRENGTHS

1. **Clean separation of concerns** — tools, agents, LLM, models, skills are well-isolated
2. **Multi-model support** — any litellm-supported provider works
3. **Skill injection system** — elegant Jinja2 approach to knowledge management; 20+ vulnerability guides
4. **XML-based tool calling** — works with any LLM (not tied to OpenAI function calling format)
5. **Typed security tool wrappers** — structured output parsing for all major tools
6. **LLM-based deduplication** — intelligent duplicate detection that understands context
7. **Multi-agent architecture** — hierarchical agent spawning with inter-agent messaging
8. **Comprehensive Docker sandbox** — Kali Linux with 30+ security tools pre-installed
9. **Audit trail** — crash-safe JSONL logging of all operations
10. **Multi-format reporting** — JSON, SARIF, Markdown, HTML export

---

## 14. ARCHITECTURE WEAKNESSES

1. **Massive dead code surface** — ~4,500 lines in `core/` are implemented but never used
2. **No runtime profile enforcement** — scan modes only differ in prompt text, not behavior
3. **No persistent state between scans** — knowledge store exists but isn't connected
4. **No automated verification** — all verification is LLM-directed, no programmatic checks
5. **Aggressive one-size-fits-all prompt** — "2000+ steps" language hurts quick mode
6. **No budget tracking visible to agent** — agent can't see token usage or remaining budget
7. **Hardcoded 300 max iterations** — should come from scan profile
8. **Test coverage gaps** — comprehensive unit tests for core modules, but zero for the actual scan pipeline
