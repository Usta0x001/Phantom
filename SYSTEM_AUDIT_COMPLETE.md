# PHANTOM — COMPLETE END-TO-END SYSTEM AUDIT

**Audit Date:** 2026-04-26  
**Auditor:** OpenCode AI  
**Version Audited:** 0.9.183 (nested source) / 0.9.206 (pyproject.toml)  
**Scope:** Full codebase, architecture, features, security posture, and deployment model

---

## TABLE OF CONTENTS

1. [Executive Summary](#1-executive-summary)
2. [Project Identity & Metadata](#2-project-identity--metadata)
3. [Directory Structure & File Inventory](#3-directory-structure--file-inventory)
4. [Architecture Overview](#4-architecture-overview)
5. [Component Deep Dive](#5-component-deep-dive)
6. [Feature Matrix](#6-feature-matrix)
7. [Security Model](#7-security-model)
8. [Configuration & Secrets](#8-configuration--secrets)
9. [Runtime & Sandbox](#9-runtime--sandbox)
10. [LLM Integration Layer](#10-llm-integration-layer)
11. [Tool Ecosystem](#11-tool-ecosystem)
12. [Agent Core & ReAct Loop](#12-agent-core--react-loop)
13. [Interface Layer](#13-interface-layer)
14. [Versioning & Release Strategy](#14-versioning--release-strategy)
15. [Audit History & Reports](#15-audit-history--reports)
16. [Critical Findings](#16-critical-findings)
17. [Recommendations](#17-recommendations)

---

## 1. EXECUTIVE SUMMARY

**Phantom** is an autonomous AI-powered penetration testing agent built around a **ReAct (Reason–Act) loop**. It connects large language models (via LiteLLM) to 53+ security tools, orchestrates multi-phase scans (reconnaissance → exploitation → verification), and runs all offensive operations inside an ephemeral Docker sandbox (Kali Linux). Every reported vulnerability is verified with a working proof-of-concept (PoC) script before inclusion in reports.

### Maturity Assessment

| Category | Score | Status |
|----------|-------|--------|
| Architecture | 75/100 | Well-structured, modular |
| Security Posture | 70/100 | 7-layer defense, some gaps |
| Code Quality | 55/100 | Heavy lint warnings, complex methods |
| Test Coverage | 10/100 | Virtually no tests present |
| Documentation | 65/100 | Good README, sparse inline docs |
| Operational Maturity | 50/100 | Checkpoints exist, no CI tests |

**Overall Verdict:** Promising foundation with genuine innovations (hypothesis ledger, correlation engine, coverage tracker), but significant gaps in testing, reconnaissance depth, and post-exploitation capability prevent it from being "elite-ready."

---

## 2. PROJECT IDENTITY & METADATA

| Field | Value |
|-------|-------|
| **Name** | phantom-agent |
| **Version** | 0.9.183 (`phantom/__init__.py`) / 0.9.206 (`pyproject.toml`) |
| **Description** | Autonomous Offensive Security Intelligence — AI-powered penetration testing |
| **Author** | Usta0x001 <r_gadouri@estin.dz> |
| **License** | Apache-2.0 |
| **Repository** | https://github.com/Usta0x001/Phantom |
| **Python** | 3.12+ |
| **Package Manager** | Poetry |
| **CLI Entry** | `phantom = phantom.interface.cli_app:cli_main` |
| **Status** | Beta |

### Key Dependencies
- **LiteLLM** (~1.81.1) — LLM provider abstraction
- **Pydantic** (^2.11.3) — Data validation
- **Rich** (^13.9) / **Textual** (^4.0.0) — CLI/TUI rendering
- **Docker** (^7.1.0) — Sandbox runtime
- **NetworkX** (^3.0) / **pydot** (^3.0.0) — Attack graphs
- **Playwright** (^1.48.0, optional) — Browser automation
- **scrubadub** (^2.0.1) — PII redaction
- **traceloop-sdk** (^0.53.0) — OpenTelemetry tracing

---

## 3. DIRECTORY STRUCTURE & FILE INVENTORY

### 3.1 Root-Level Files

| File | Purpose |
|------|---------|
| `README.md` | Comprehensive project documentation (668 lines) |
| `pyproject.toml` | Poetry configuration, dependencies, tool configs (mypy, ruff, black, pytest, bandit) |
| `poetry.lock` | Locked dependency versions |
| `config.toml` | **HARDCODED API KEY** (`sk-S8L7...`) for agentrouter.org — **CRITICAL SECURITY ISSUE** |
| `implementation_summary.md` | Token optimization fixes summary (6 fixes implemented) |
| `compare_executor.py` | Standalone utility script |
| `test_scan.py` | Standalone test script |
| `auth.json` | Authentication configuration |
| `*.log` files | Runtime logs (phantom_execution.log, pytest.log, e2e logs, scan logs) |
| `nul` | Empty/null file artifact |

### 3.2 Source Code Packages

**CRITICAL STRUCTURAL ANOMALY:** The root `phantom/` directory contains **only `__pycache__` folders** with compiled `.pyc` files. The actual Python **source code** lives inside the **nested** `phantom/phantom/` directory. This means:
- Root `phantom/agents/` → only `__pycache__/`
- Root `phantom/tools/` → only `__pycache__/`
- `phantom/phantom/agents/` → contains `base_agent.py`, `phantom_agent.py`, etc.

This is a dangerous packaging artifact — the package will fail to import from source in any clean environment.

#### Active Source Tree (`phantom/phantom/`)

```
phantom/phantom/
├── __init__.py                          # version = "0.9.183"
├── agents/
│   ├── __init__.py                      # exports BaseAgent, AgentState, PhantomAgent
│   ├── base_agent.py                    # 1,480 lines — core ReAct loop
│   ├── coverage_tracker.py              # Scan coverage tracking
│   ├── hypothesis_ledger.py             # Attack hypothesis tracking
│   ├── state.py                         # AgentState persistence
│   └── PhantomAgent/
│       ├── __init__.py
│       ├── phantom_agent.py             # Main scanning agent (300 iter max)
│       └── system_prompt.jinja          # Jinja2 system prompt template
├── checkpoint/
│   ├── __init__.py                      # CheckpointManager, CheckpointData
│   ├── checkpoint.py                    # Atomic file-based checkpoints with HMAC/Fernet
│   └── models.py                        # Pydantic checkpoint models
├── config/
│   ├── __init__.py                      # Config, secrets manager
│   ├── config.py                        # Main configuration loader
│   └── secrets.py                       # SecureSecretsManager (keyring + PBKDF2)
├── core/
│   ├── __init__.py                      # AttackGraph, AttackPlan exports
│   ├── attack_graph.py                  # 772 lines — NetworkX multi-step attack paths
│   ├── diff_scanner.py                  # Differential scanning
│   ├── priority_queue.py                # Task scheduling
│   └── scan_profiles.py                 # Scan profile presets (quick/standard/deep/stealth/api_only)
├── interface/
│   ├── __init__.py                      # Lazy imports for fast startup
│   ├── cli.py                           # CLI entry points
│   ├── cli_app.py                       # Typer-based CLI application
│   ├── main.py                          # Legacy argparse entry + shared init
│   ├── streaming_parser.py              # Streaming LLM output parser
│   ├── tui.py                           # Textual TUI
│   ├── tui_components.py                # Reusable TUI widgets
│   ├── tui_design_system.py             # Design tokens
│   ├── tui_presenter.py                 # TUI view logic
│   ├── tui_tool_cards.py                # Tool card rendering
│   ├── utils.py                         # Interface helpers
│   ├── assets/
│   │   └── tui_styles.tcss              # Textual CSS
│   ├── formatters/
│   │   └── sarif_formatter.py           # SARIF output format
│   └── tool_components/                 # Per-tool output renderers
│       ├── __init__.py
│       ├── registry.py
│       ├── base_renderer.py
│       ├── _colors.py
│       ├── agents_graph_renderer.py
│       ├── agent_message_renderer.py
│       ├── browser_renderer.py
│       ├── file_edit_renderer.py
│       ├── finish_renderer.py
│       ├── notes_renderer.py
│       ├── proxy_renderer.py
│       ├── python_renderer.py
│       ├── reporting_renderer.py
│       ├── scan_info_renderer.py
│       ├── terminal_renderer.py
│       ├── thinking_renderer.py
│       ├── todo_renderer.py
│       ├── user_message_renderer.py
│       └── web_search_renderer.py
├── llm/
│   ├── __init__.py                      # LLM, LLMConfig, custom model registries
│   ├── llm.py                           # 1,749 lines — main LLM client, cost tracking
│   ├── config.py                        # LLM configuration dataclass
│   ├── dedupe.py                        # LLM response deduplication
│   ├── memory_compressor.py             # Context-window compression
│   ├── tracked_completion.py            # Async completion with telemetry
│   ├── utils.py                         # Content cleaning, parsing helpers
│   └── pentager/                        # Reflection & summarization submodule
│       ├── __init__.py
│       ├── chain_summarizer.py          # ChainAST + threshold-based summarization
│       └── reflector.py                 # Lightweight re-prompt for empty responses
├── logging/
│   ├── __init__.py                      # AuditLogger
│   └── audit.py                         # Audit logger with file rotation
├── models/
│   ├── __init__.py                      # ScanPhase, ScanStatus, Vulnerability, Host
│   ├── host.py                          # Host target model
│   ├── scan.py                          # Scan result/status models
│   └── vulnerability.py                 # Vulnerability model with severity/status enums
├── runtime/
│   ├── __init__.py                      # Runtime factory (Docker only)
│   ├── runtime.py                       # AbstractRuntime ABC
│   ├── docker_runtime.py                # Docker sandbox implementation (717 lines)
│   └── tool_server.py                   # In-sandbox FastAPI tool server
├── skills/
│   └── __init__.py                      # Markdown skill loader with XSS sanitization
├── telemetry/
│   ├── __init__.py                      # Tracer exports
│   ├── tracer.py                        # OpenTelemetry tracer
│   ├── flags.py                         # Telemetry feature flags
│   └── utils.py                         # Sanitizer, OTEL bootstrap
├── tools/
│   ├── __init__.py                      # Tool module imports, feature flags
│   ├── registry.py                      # Central tool registration with XML schema introspection
│   ├── executor.py                      # 1,829 lines — async execution engine
│   ├── argument_parser.py               # LLM arg → Python type conversion
│   ├── context.py                       # Execution context management
│   ├── dynamic_tools.py                 # Dynamic tool loading at runtime
│   ├── agents_graph/                    # Agent coordination graph
│   ├── api_schema/                      # API schema discovery
│   ├── browser/                         # Playwright-based browser automation
│   ├── detection/                       # Vulnerability detection engine
│   ├── file_edit/                       # File editing/patch tools
│   ├── finish/                          # Agent graceful termination
│   ├── fuzzer/                          # Web fuzzing engine
│   ├── hypothesis/                      # Hypothesis tracking tools
│   ├── notes/                           # Agent note-taking
│   ├── oast/                            # Out-of-band security testing
│   ├── osint/                           # Open-source intelligence
│   ├── payload_gen/                     # Smart payload generation
│   ├── proxy/                           # HTTP proxy (Caido integration)
│   ├── python/                          # Sandboxed Python execution
│   ├── recon/                           # Reconnaissance (dir brute, JS analysis)
│   ├── reporting/                       # Report generation + Nuclei templates
│   ├── response_analysis/               # HTTP response analysis
│   ├── scan_registry/                   # Scan metadata registration
│   ├── scan_status/                     # Real-time scan status
│   ├── session/                         # Basic session management
│   ├── session_mgmt/                    # Advanced auth automation
│   ├── terminal/                        # Terminal/shell execution
│   ├── thinking/                        # Explicit reasoning tool
│   ├── todo/                            # Task list management
│   ├── vuln_intel/                      # CVE auto-integration
│   ├── waf/                             # WAF detection & evasion
│   └── web_search/                      # Web search (Perplexity, etc.)
└── utils/
    ├── __init__.py
    └── resource_paths.py                # Resource path resolution
```

### 3.3 Containers

| File | Purpose |
|------|---------|
| `containers/Dockerfile` | Kali Linux sandbox image (~210 lines) |
| `containers/Dockerfile.sandbox` | Sandbox-specific Dockerfile |
| `containers/docker-entrypoint.sh` | Container startup: Caido proxy, tool server, iptables egress filtering |

### 3.4 Version Snapshots

| Directory | Wheel File | Version |
|-----------|------------|---------|
| `version/v163/` | `phantom_agent-0.9.163-py3-none-any.whl` | 0.9.163 |
| `version/v164/` | `phantom_agent-0.9.164-py3-none-any.whl` | 0.9.164 |
| `version/v201/` | `phantom_agent-0.9.201-py3-none-any.whl` | 0.9.201 |

Each version directory contains a complete snapshot of the `phantom/` package source tree at that version.

### 3.5 Output & Runtime Artifacts

| Directory | Contents |
|-----------|----------|
| `phantom_runs/` | Scan output directories per target — vulnerabilities/, audit.jsonl, scan_stats.json, enhanced_state.json |
| `phantom_knowledge/` | Persistent cross-scan memory store |
| `thesis_output/` | Thesis/documentation outputs |
| `experiments/` | Experimental code |
| `dist/` | Distribution builds |

### 3.6 Cache & Temporary Directories

- `.mypy_cache/`, `.ruff_cache/`, `.pytest_cache/`, `__pycache__/`, `.hypothesis/`
- `.git/` — Git repository with multiple branches (main, release, lean-phantom, stable-0.9.38, etc.)
- `.claude/`, `.codex/` — IDE/agent configuration files

---

## 4. ARCHITECTURE OVERVIEW

Phantom follows a **layered architecture** with clear separation of concerns:

```
┌─────────────────────────────────────────────────────────────┐
│  INTERFACE LAYER                                            │
│  CLI (Typer) · TUI (Textual) · Output Parsers               │
├─────────────────────────────────────────────────────────────┤
│  ORCHESTRATION LAYER                                        │
│  Scan Profiles · Scope Guard · Cost Controller · Audit Log  │
├─────────────────────────────────────────────────────────────┤
│  AGENT CORE — ReAct Loop                                    │
│  LLM (LiteLLM) · State Machine · Memory Engine · Skills     │
├─────────────────────────────────────────────────────────────┤
│  SECURITY LAYER                                             │
│  Tool Firewall · Verifier · Output Sanitizer                │
├─────────────────────────────────────────────────────────────┤
│  DOCKER SANDBOX — Kali Linux                                │
│  Tool Server (:48081) · Caido Proxy (:48080) · 30+ Tools    │
├─────────────────────────────────────────────────────────────┤
│  OUTPUT PIPELINE                                            │
│  JSON · MD · HTML · SARIF · Attack Graph · MITRE ATT&CK     │
└─────────────────────────────────────────────────────────────┘
```

### Execution Flow

1. **User** invokes `phantom scan -t <target>`
2. **CLI** validates scope, initializes cost controller
3. **DockerRuntime** spins up ephemeral Kali container
4. **PhantomAgent** enters `agent_loop()` — up to 300 iterations
5. **Per iteration:**
   - Observe → collect tool results
   - Think → analyze context
   - Plan → choose next tool
   - Act → build arguments
   - Firewall → validate tool call
   - Execute → Docker sandbox
   - Verify → re-test findings
6. **Enrichment** → MITRE mapping, compliance tagging, attack graph
7. **Report** → JSON + HTML + Markdown + SARIF
8. **Cleanup** → destroy container

---

## 5. COMPONENT DEEP DIVE

### 5.1 Agent Core (`phantom/phantom/agents/`)

**`BaseAgent`** (1,480 lines)
- Metaclass `AgentMeta` auto-configures Jinja2 `FileSystemLoader` per subclass
- `agent_loop(task)` — main ReAct loop (max 300 iterations)
- Hypothesis context building — scopes conversation to active attack surface
- Auto-status injection every N iterations
- Rate-limit backoff, no-action streak detection
- Deduplication via action batch signatures
- Checkpoint save/restore
- Sub-agent restoration from checkpoints

**`PhantomAgent`** (extends BaseAgent)
- `max_iterations = 300`
- `default_skills = ["root_agent"]` for root agents
- `execute_scan(scan_config)` — builds task from repos, local code, web apps, IPs
- Appends sanitized user instructions with highest priority

**`AgentState`** (`state.py`)
- Persistent agent context
- Tracks iteration count, findings, coverage
- Supports serialization for checkpoints

**`HypothesisLedger`** (`hypothesis_ledger.py`)
- Structured external memory surviving context compression
- Prevents redundant payload testing
- Tracks tested hypotheses and theories

**`CoverageTracker`** (`coverage_tracker.py`)
- Prevents testing the same surface twice
- URL/parameter/path coverage tracking

### 5.2 LLM Layer (`phantom/phantom/llm/`)

**`LLM`** (`llm.py` — 1,749 lines)
- Built on **LiteLLM** — supports 100+ providers
- Custom model registries: Kimi-K2.5, DeepSeek-V3.2
- Token budgeting and cost tracking (global + per-model stats)
- Retry logic with tenacity
- Memory compression via `MemoryCompressor`
- Deduplication via `dedupe.py`
- Global rate-limit handling

**`LLMConfig`** (`config.py`)
- Model selection, skills, parameters
- Scan mode defaults (quick=4000 tokens, stealth=6000, default=8000)

**Pentager Subsystem** (`pentager/`)
- **`ChainSummarizer`** — threshold-based message summarization (avoids LLM calls for decisions)
- **`Reflector`** — lightweight re-prompt for empty responses (uses cheaper model, gpt-4o-mini)
- **`ChainAST`** — parses messages into structured sections

### 5.3 Tool Ecosystem (`phantom/phantom/tools/`)

**`registry.py`** (345 lines)
- Central `@register_tool` decorator
- XML schema introspection for tool descriptions
- Dynamic content injection (`{{DYNAMIC_SKILLS_DESCRIPTION}}`)
- Parameter schema parsing from XML

**`executor.py`** (1,829 lines)
- Async tool execution engine
- Prompt injection detection (16 regex patterns)
- Sandbox integration
- Screenshot extraction
- Auto-summarization for outputs >16KB
- Command injection detection

**Tool Categories (27 sub-packages):**

| Category | Tools | Purpose |
|----------|-------|---------|
| `agents_graph` | Agent coordination | Sub-agent spawning and graph management |
| `api_schema` | Schema discovery | OpenAPI/GraphQL introspection |
| `browser` | Playwright automation | Chromium-based web interaction |
| `detection` | Vuln detection | Adaptive wordlists, IDOR tester |
| `file_edit` | File patches | In-sandbox file modifications |
| `finish` | Termination | Graceful scan completion |
| `fuzzer` | Web fuzzing | ffuf-based fuzzing with manager |
| `hypothesis` | Hypothesis mgmt | Ledger integration tools |
| `notes` | Note-taking | Agent scratchpad |
| `oast` | Out-of-band testing | Interactsh integration |
| `osint` | Intelligence | crt.sh, Shodan, WHOIS, GitHub dorking, subdomain brute |
| `payload_gen` | Payload generation | Smart/adaptive payloads |
| `proxy` | HTTP proxy | Caido proxy management |
| `python` | Code execution | Sandboxed Python/IPython |
| `recon` | Reconnaissance | Directory brute, JS analysis |
| `reporting` | Report generation | Elite reports, Nuclei YAML templates |
| `response_analysis` | Response analysis | Anomaly detection |
| `scan_registry` | Scan metadata | Scan registration tools |
| `scan_status` | Status tracking | Real-time progress |
| `session` | Basic sessions | Cookie/session handling |
| `session_mgmt` | Auth automation | Advanced authentication flows |
| `terminal` | Shell execution | Bash command execution with tmux |
| `thinking` | Reasoning | Explicit "think" tool for LLM |
| `todo` | Task management | Agent task lists |
| `vuln_intel` | Threat intel | CVE auto-integration |
| `waf` | WAF evasion | 20+ WAF signatures with strategies |
| `web_search` | Web search | Perplexity integration |

### 5.4 Runtime & Sandbox (`phantom/phantom/runtime/`)

**`AbstractRuntime`** (`runtime.py`)
- ABC defining: `create()`, `destroy()`, `get_url()`, `execute()`

**`DockerRuntime`** (`docker_runtime.py` — 717 lines)
- Auto-start Docker Desktop on Windows
- Port discovery with jittered exponential backoff
- Container lifecycle management
- Tool server port forwarding (:48081)
- Caido proxy port forwarding (:48080)
- HMAC token generation for tool server auth
- Container name validation (prevents injection)

**`tool_server.py`**
- FastAPI-based in-sandbox tool server
- Health check endpoint
- Authenticated tool execution API

### 5.5 Core Models (`phantom/phantom/core/` & `models/`)

**Domain Models:**
- `Vulnerability` — id, title, severity (CRITICAL/HIGH/MEDIUM/LOW/INFO), status (SUSPECTED/CONFIRMED/FALSE_POSITIVE/MITIGATED), evidence, remediation
- `ScanResult` — scan_id, target, status, phase, timing, metadata
- `Host` — ip, hostname, ports, services, os_info

**Attack Graph** (`attack_graph.py` — 772 lines)
- NetworkX directed graph
- Node types: VULNERABILITY, ASSET, OBJECTIVE, TECHNIQUE
- Edge types: ENABLES, AFFECTS, ACHIEVES, USES
- Path planning with priority scoring
- Betweenness centrality for critical vuln identification
- Multi-step vulnerability chains (bounded depth 5)
- Exports: JSON, GraphML, DOT

**Scan Profiles** (`scan_profiles.py`)
- `quick`: 15 iters, 300s timeout, low reasoning, 3 agents
- `standard`: 150 iters, 600s, medium, 8 agents
- `deep`: 300 iters, 1200s, high, 15 agents
- `stealth`: 200 iters, 900s, medium, no browser
- `api_only`: 100 iters, 600s, medium, API-focused

### 5.6 Configuration & Secrets (`phantom/phantom/config/`)

**`Config`** (`config.py`)
- Main configuration loader
- Lazy-loading to avoid circular imports
- Environment variable integration
- Secure secrets integration

**`SecureSecretsManager`** (`secrets.py` — 447 lines)
- OS-native keyring (Windows Credential Manager, macOS Keychain, Linux Secret Service)
- PBKDF2 fallback with machine-derived salt
- Automatic plaintext migration
- Sensitive keys: LLM_API_KEY, PERPLEXITY_API_KEY, SHODAN, GITHUB, VULNERS, WHOISXML, API_NINJAS, NVD, CHECKPOINT, TRACELOOP

### 5.7 Interface (`phantom/phantom/interface/`)

**CLI** (`cli_app.py` — Typer)
- `scan` — main penetration test command
- `resume` / `resumes-delete` — checkpoint management
- `report list/export/delete` — report handling (JSON, SARIF, MD, HTML)
- `config show/set/reset` — configuration
- `audit` — system audit reports
- `version` / `profiles` — meta commands

**TUI** (`tui.py` + components)
- Full Textual terminal UI
- Tool cards, streaming output, design system
- Per-tool renderers (17 renderer types)

**Formatters**
- `sarif_formatter.py` — SARIF (Static Analysis Results Interchange Format)

### 5.8 Telemetry & Logging (`phantom/phantom/telemetry/`, `logging/`)

**`AuditLogger`** (`logging/audit.py`)
- Comprehensive security event logging
- File rotation
- Sensitive data redaction
- **WARNING:** Audit mode writes full un-redacted LLM prompts to disk

**OpenTelemetry Tracer** (`telemetry/tracer.py`)
- Span tracking
- Graceful fallback if OTel absent
- Feature flags in `flags.py`

---

## 6. FEATURE MATRIX

| Feature | Status | Notes |
|---------|--------|-------|
| Autonomous ReAct Loop | ✅ | Up to 300 iterations |
| 53 Security Tools | ✅ | Registered via XML schemas |
| Docker Sandbox | ✅ | Kali Linux, ephemeral |
| Multi-Agent Parallelism | ✅ | Sub-agent spawning |
| 7-Layer Defense Model | ✅ | See Section 7 |
| Verified Findings (PoC) | ✅ | Re-exploit with clean script |
| MITRE ATT&CK Enrichment | ✅ | CWE, CAPEC, CVSS 3.1 |
| Compliance Mapping | ✅ | OWASP Top 10, PCI DSS v4, NIST 800-53 |
| Knowledge Persistence | ✅ | Cross-scan memory |
| Cost Control | ✅ | Per-request + per-scan caps |
| Checkpoint/Resume | ✅ | Atomic, HMAC-signed, encrypted |
| SSRF Protection | ✅ | DNS pinning, scope guard |
| Prompt Injection Detection | ✅ | 16 regex patterns in executor |
| WAF Detection | ✅ | 20+ signatures |
| Browser Automation | ✅ | Playwright + Chromium |
| Caido Proxy Integration | ✅ | Interception + logging |
| Attack Graph | ✅ | NetworkX-based |
| Coverage Tracker | ✅ | Prevents redundant testing |
| Hypothesis Ledger | ✅ | Structured memory |
| Vuln Correlation Engine | ✅ | Attack chain recognition |
| ASN Enumeration | ❌ | Not implemented |
| Subdomain Bruteforcing | ❌ | Passive only (crt.sh) |
| Post-Exploitation | ❌ | None |
| Active Directory Attacks | ❌ | None |
| Proxy Chain / Tor | ❌ | Only Caido for interception |
| Cloud IAM Analysis | ❌ | None |
| Container/K8s Escape | ❌ | None |
| Business Logic Testing | ❌ | None |
| Custom Exploit Development | ❌ | None |
| Memory Corruption | ❌ | None |

---

## 7. SECURITY MODEL

### 7.1 7-Layer Defense Model

| Layer | Component | Implementation |
|-------|-----------|----------------|
| L1 | Scope Validator | Target allowlist, SSRF protection, DNS pinning |
| L2 | Tool Firewall | Argument sanitization, injection block, registry validation |
| L3 | Docker Sandbox | Ephemeral Kali, restricted Linux caps, network isolation |
| L4 | Cost Controller | Per-request ceiling (`PHANTOM_PER_REQUEST_CEILING`), budget cap (`PHANTOM_MAX_COST`) |
| L5 | Time Limiter | Per-tool timeout, global scan expiry |
| L6 | HMAC Audit Trail | Tamper-evident append-only log (`audit.jsonl`) |
| L7 | Output Sanitizer | PII redaction (`scrubadub`), credential scrubbing |

### 7.2 Egress Filtering (Docker)

In `docker-entrypoint.sh`:
- iptables rules restrict outbound traffic
- Allowed: loopback, established connections, DNS (UDP/TCP 53), host gateway, Docker bridge (172.16.0.0/12)
- Blocked traffic is LOGged and DROPped

### 7.3 Secrets Management

- OS keyring primary storage
- PBKDF2-encrypted file fallback
- Machine-derived salt (Windows MachineGuid, Linux /etc/machine-id)
- Automatic plaintext migration on first access

### 7.4 Prompt Injection Protection

In `tools/executor.py` (lines 70-100):
- 16 regex patterns detecting:
  - System prompt manipulation (`</system>`, `[SYSTEM]`, `<<SYS>>`)
  - Instruction override (`ignore previous instructions`, `forget previous`)
  - Role manipulation (`you are now malicious`, `become DAN`)
  - Function/tool injection (`</function>`, `<function=...>`, `[INST]`)
  - Dangerous actions (`rm -rf`, `reveal secrets`)

### 7.5 Container Security

- Non-root user (`pentester`)
- Limited sudo: only `nmap`, `ncat`, `arp`, `ip`
- `cap_net_raw` only for nmap (no `cap_net_admin` or `cap_net_bind_service`)
- CA certificates generated per-container
- Tool server token stored in tmpfs file, not environment variable (PHT-018 fix)

---

## 8. CONFIGURATION & SECRETS

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PHANTOM_LLM` | LLM model (LiteLLM format) | `openai/gpt-4o` |
| `LLM_API_KEY` | API key (comma-separated for rotation) | — |
| `PHANTOM_REASONING_EFFORT` | low/medium/high | `medium` |
| `PHANTOM_SCAN_MODE` | Default profile | `standard` |
| `PHANTOM_IMAGE` | Sandbox Docker image | `ghcr.io/usta0x001/phantom-sandbox:latest` |
| `PHANTOM_MAX_COST` | Hard cost stop (USD) | — |
| `PHANTOM_PER_REQUEST_CEILING` | Per-request cost cap | — |
| `LLM_MAX_TOKENS` | Override max tokens | — |
| `PHANTOM_WEBHOOK_URL` | Critical alert webhook | — |
| `PHANTOM_DISABLE_BROWSER` | Disable Playwright | `false` |
| `PHANTOM_TELEMETRY` | Anonymous telemetry | `false` |

### Configuration Files

- `~/.phantom/config.yaml` — User configuration
- `~/.phantom/secrets.enc` — Encrypted secrets (PBKDF2)
- `~/.phantom/.salt` — Machine salt
- `config.toml` (project root) — **Contains hardcoded API key** ⚠️

---

## 9. RUNTIME & SANDBOX

### Docker Sandbox Image

- **Base:** `kalilinux/kali-rolling:latest` (not pinned — supply chain risk)
- **Size:** ~13 GB (one-time pull)
- **User:** `pentester` (non-root)
- **Tools installed:** nmap, sqlmap, nuclei, subfinder, naabu, ffuf, httpx, katana, cvemap, gospider, interactsh-client, arjun, dirsearch, wafw00f, retire, eslint, js-beautify, JS-Snooper, jsniper, jwt_tool, trufflehog, zaproxy, trivy, wapiti, semgrep, bandit, jshint, caido-cli
- **Runtime:** Python 3.12, Playwright Chromium, Go, Node.js, tmux

### Container Startup (`docker-entrypoint.sh`)

1. Validate CA certificate
2. Start Caido proxy (port 48080)
3. Obtain guest API token via GraphQL
4. Create temporary Caido project
5. Configure system-wide proxy settings
6. Add CA to browser trust store
7. Start tool server (port 48081) with token from tmpfs file
8. Configure iptables egress filtering

### Tool Server

- FastAPI application inside container
- Authenticated via HMAC token
- Health check endpoint
- Executes tools in sandboxed environment

---

## 10. LLM INTEGRATION LAYER

### Provider Support (via LiteLLM)

| Provider | Example Model |
|----------|--------------|
| OpenAI | `openai/gpt-4o` |
| Anthropic | `anthropic/claude-opus-4-5` |
| Google | `gemini/gemini-2.5-pro` |
| Groq | `groq/llama-3.3-70b-versatile` |
| DeepSeek | `deepseek/deepseek-chat` |
| OpenRouter | `openrouter/deepseek/deepseek-v3.2` |
| Ollama | `ollama/llama3.1` (local) |
| Azure OpenAI | `azure/gpt-4o` |

### Cost Tracking

- Global stats: input/output tokens, cached tokens, cost, request count
- Per-model stats dictionary
- Thread-safe with `threading.Lock()`
- Token drift event logging

### Memory Management

- `MemoryCompressor` — LLM-based context compression
- `ChainSummarizer` — threshold-based summarization (cheaper, no LLM calls for decisions)
- `VectorMemory` (`phantom/memory/vector_store.py`) — SQLite-backed persistent storage with semantic search

---

## 11. TOOL ECOSYSTEM

### Tool Registration Pattern

```python
@register_tool(sandbox_execution=True/False)
async def my_tool(param: str) -> dict:
    ...
```

Tools are defined via Python functions with XML schema descriptions. The registry introspects signatures and generates LLM-compatible schemas.

### Dynamic Tool Loading

`dynamic_tools.py` supports:
- Compact tool prompts (subset loading)
- Category-based filtering
- Context-aware tool selection
- Task-based tool subsets

### Execution Flow

1. LLM returns tool invocation
2. `executor.py` resolves canonical tool name
3. Prompt injection scan (16 patterns)
4. Argument conversion (`argument_parser.py`)
5. Sandbox decision (`should_execute_in_sandbox`)
6. If sandbox: HTTP call to tool server in Docker
7. If local: direct function call
8. Output sanitization and screenshot extraction
9. Auto-summarize if output >16KB

---

## 12. AGENT CORE & REACT LOOP

### Iteration Cycle

```
INIT → OBSERVE → THINK → PLAN → ACT → FIREWALL → EXECUTE → OBSERVE → ...
                                      ↓ (block)
                                    THINK
```

### Key Behaviors

- **Max iterations:** 300 (deep mode)
- **Status injection:** Compact `[AUTO-STATUS]` packet every N iterations
- **No-action streak:** Detects and warns when agent takes no action
- **Deduplication:** Blocks exact repeat of previously successful action batch
- **Error handling:** Dedicated paths for sandbox errors, LLM errors, generic errors
- **Sub-agents:** Background thread restoration from checkpoints

### System Prompt

Jinja2 template at `phantom/phantom/agents/PhantomAgent/system_prompt.jinja`
- Configurable via `PHANTOM_USE_CONDENSED_PROMPT` (~100 lines vs 477 lines)
- Dynamic tool loading guidance
- Delegation hierarchy (tools first, terminal batch, sub-agents only)

---

## 13. INTERFACE LAYER

### CLI Commands

```bash
phantom scan -t <target> [options]
phantom resume
phantom report list/export/delete
phantom config show/set/reset
phantom audit
phantom version
phantom profiles
```

### TUI Features

- Real-time streaming output
- Tool cards with rich formatting
- Color-coded severity indicators
- Progress tracking
- 17 specialized renderers for different tool output types

### Output Formats

- **Markdown** (`.md`) — Human-readable findings with PoC
- **JSON** (`.json`) — Machine-parseable
- **HTML** (`.html`) — Styled report
- **SARIF** (`.sarif`) — Static Analysis Results Interchange Format
- **CSV** (`.csv`) — Summary index
- **Attack Graph** — DOT/GraphML/PNG

---

## 14. VERSIONING & RELEASE STRATEGY

### Version Snapshots

The project maintains **complete source snapshots** for key versions:

| Version | Date | Key Changes |
|---------|------|-------------|
| v0.9.163 | ~Apr 20 | Baseline |
| v0.9.164 | ~Apr 21 | Token optimization fixes |
| v0.9.183 | ~Apr 23 | Current (nested source) |
| v0.9.201 | ~Apr 24 | Latest snapshot |
| v0.9.206 | Apr 26 | pyproject.toml version |

### Distribution

- **PyPI:** `phantom-agent` package
- **Docker:** `ghcr.io/usta0x001/phantom:latest`
- **Wheel files:** Stored in `version/` directory

### Git Branches

- `main` — primary development
- `release` — release branch
- `lean-phantom` — stripped-down variant
- `stable-0.9.38` — stable maintenance
- `v0.9.39-preserved` — version preservation
- `release-0.9.8`, `release-0.9.11` — patch releases

---

## 15. AUDIT HISTORY & REPORTS

### Audit Reports Present in Repository

| Report | Focus |
|--------|-------|
| `AUDIT_1_EXECUTIVE_SUMMARY.md` | Overall assessment (Score: 37/100) |
| `AUDIT_2_CRITICAL_ISSUES.md` | 8 critical gaps (recon, exploit, evasion) |
| `AUDIT_3_HIGH_ISSUES.md` | High severity findings |
| `AUDIT_4_MEDIUM_LOW_ISSUES.md` | 23 medium/low findings |
| `AUDIT_5_WIRING_VERIFICATION.md` | Component integration analysis |
| `AUDIT_6_ENHANCEMENT_ROADMAP.md` | Phased improvement plan |
| `AUDIT_7_NORTH_STAR_VISION.md` | Long-term elite capability vision |
| `FULL_AUDIT_REPORT.md` | OpenCode audit (PASS verdict) |
| `COMPREHENSIVE_SECURITY_AUDIT.md` | Security-focused audit |
| `SECURITY_AUDIT_1_EXECUTIVE_SUMMARY.md` | Security executive summary |
| `EFFICIENCY_AUDIT_1_EXECUTIVE_SUMMARY.md` | Token/cost efficiency |
| `EFFICIENCY_AUDIT_2-7.md` | Efficiency breakdowns |
| `COST_OPTIMIZATION.md` | Cost optimization strategies |
| `FINAL_VERIFICATION_REPORT.md` | Final verification |
| `VERSION_COMPARISON_REPORT.md` | Version diff analysis |
| `ARCHITECTURE_AUDIT_REPORT.md` | Architecture audit |
| `REPORT_1.md` through `REPORT_7.md` | Additional report segments |

### Previous Audit Findings Summary

**From AUDIT_1_EXECUTIVE_SUMMARY.md (Claude Opus 4.5):**
- Maturity Score: 37/100 ("scanner, not a pentester")
- Critical gaps: ASN enumeration, subdomain brute, post-exploitation, AD attacks, proxy chains, cloud IAM, container escapes, test coverage
- Genuine strengths: Hypothesis ledger, correlation engine, coverage tracker, WAF detection, checkpoint system

**From FULL_AUDIT_REPORT.md (OpenCode):**
- Verdict: PASS
- Security: HIGH confidence
- Stability: HIGH
- Code Quality: ACCEPTABLE
- Previous issues (HIGH-001, MEDIUM-002) fixed
- MEDIUM-001 (dead code) persists

---

## 16. CRITICAL FINDINGS

### 🔴 CRITICAL-001: Hardcoded API Key in `config.toml`

**File:** `config.toml`  
**Line 8:** `env_key = "sk-S8L7IAmQuSqDquIX43izp2XEUUSWDG423fexmg9hQgQOJTIc"`  
**Impact:** API key is committed to repository, exposed to anyone with access.  
**Fix:** Remove from repo, rotate key, use environment variables or secrets manager.

### 🔴 CRITICAL-002: Source Code Packaging Anomaly

**Issue:** Root `phantom/agents/`, `phantom/tools/`, etc. contain **only `__pycache__`** with `.pyc` files. Actual `.py` source is in **nested** `phantom/phantom/` directory.  
**Impact:** Package will fail to import from source in clean environments. Poetry `packages` directive includes `{ include = "phantom", format = ["sdist", "wheel"] }` which may pick up wrong directory.  
**Fix:** Restructure so source lives at `phantom/` root, or update `pyproject.toml` packages config to point to `phantom/phantom/`.

### 🔴 CRITICAL-003: Docker Base Image Not Pinned

**File:** `containers/Dockerfile` line 4  
**Issue:** `FROM kalilinux/kali-rolling:latest` — no date tag or digest.  
**Impact:** Supply chain attack vector — upstream image changes can compromise sandbox.  
**Fix:** Pin to specific digest or date-tag.

### 🟠 HIGH-001: Virtually No Test Coverage

**Issue:** `tests/` directory contains only `__pycache__` with 73 compiled `.pyc` files. No `.py` test sources present.  
**Impact:** Zero confidence in correctness, dangerous to refactor, regressions go unnoticed.  
**Fix:** Restore test source files, implement minimum 80% coverage target.

### 🟠 HIGH-002: Version Mismatch

**Issue:** `phantom/__init__.py` says `0.9.183`, `pyproject.toml` says `0.9.206`.  
**Impact:** Confusion about actual version, potential packaging issues.  
**Fix:** Synchronize versions across all files.

### 🟠 HIGH-003: Extensive Lint Warnings

**Issue:** Ruff reports 100+ PLC0415 (lazy imports), 30+ BLE001 (bare except), 25+ E501 (line too long), 15+ S110 (try-except-pass).  
**Impact:** Maintainability issues, masked errors.  
**Fix:** Systematic cleanup — extract methods, use specific exceptions, run formatter.

### 🟡 MEDIUM-001: No AGENTS.md

**Issue:** No `AGENTS.md` file exists anywhere in the project.  
**Impact:** Missing agent-focused development guidelines.  
**Fix:** Create `AGENTS.md` with build steps, test commands, coding conventions.

### 🟡 MEDIUM-002: Audit Log Warning

**Issue:** `logging/__init__.py` warns that audit mode writes full un-redacted LLM prompts to disk.  
**Impact:** Potential PII/secrets exposure in logs.  
**Fix:** Ensure redaction is applied even in audit mode, or document this as expected behavior with access controls.

### 🟡 MEDIUM-003: Token Optimization Not Default

**Issue:** All 6 token optimization fixes require environment variables (`PHANTOM_USE_CONDENSED_PROMPT`, etc.) to enable.  
**Impact:** Users don't get optimizations by default.  
**Fix:** Enable safe optimizations by default, gate risky ones behind flags.

---

## 17. RECOMMENDATIONS

### Immediate (This Week)

1. **Remove hardcoded API key** from `config.toml` and rotate the key
2. **Fix source code structure** — either move `phantom/phantom/` contents to root `phantom/` or update package config
3. **Synchronize versions** across `__init__.py`, `pyproject.toml`, and any other version references
4. **Pin Docker base image** to specific digest

### Short-Term (This Month)

5. **Restore test files** — the `.pyc` cache suggests tests existed; recover from git history or recreate
6. **Enable token optimizations by default** for safe fixes
7. **Run linting pass** — `ruff check --fix` and `ruff format` across codebase
8. **Create `AGENTS.md`** with development guidelines

### Medium-Term (3 Months)

9. **Add ASN enumeration** — integrate RIPE/ARIN/BGPView APIs
10. **Add active subdomain bruteforcing** — integrate `subfinder`, `amass`, smart wordlists
11. **Add proxy chain support** — SOCKS5, Tor integration
12. **Build real test suite** — unit, integration, e2e against DVWA/Juice Shop/WebGoat

### Long-Term (6-12 Months)

13. **Post-exploitation capabilities** — privesc enumeration, credential harvesting (paths only), lateral movement simulation
14. **Active Directory support** — LDAP enum, Kerberoasting, BloodHound
15. **Cloud security testing** — AWS/Azure/GCP IAM enumeration, S3 bucket testing
16. **Container/K8s testing** — Docker socket detection, K8s API enumeration
17. **Business logic testing** — workflow abuse, race condition detection

---

*End of Complete System Audit*
