# Phantom — System Architecture v1.0

**Author**: Usta0x001  
**Version**: 0.9.20  
**Date**: March 2026

---

## 1. Overview

Phantom is an **autonomous adversary simulation platform** — an AI-powered penetration testing agent that discovers and verifies real vulnerabilities in web applications, APIs, and network services without human intervention.

The system consists of an **LLM-driven reasoning loop** that controls a **sandboxed Docker execution environment** with pre-installed security tools (nmap, sqlmap, nuclei, ffuf, nikto, Playwright browser). A **multi-layer security architecture** ensures the agent operates within authorized scope and cannot harm the host system.

```
┌─────────────────────────────────────────────────────────────┐
│                        USER / CLI                           │
│   phantom --target https://target.com --mode deep           │
├─────────────────────────────────────────────────────────────┤
│                    ORCHESTRATION LAYER                       │
│  ┌─────────┐ ┌──────────┐ ┌──────────┐ ┌───────────────┐   │
│  │ Profile │ │  Scope   │ │   Cost   │ │ Audit Logger  │   │
│  │ Manager │ │Validator │ │Controller│ │ (HMAC chain)  │   │
│  └─────────┘ └──────────┘ └──────────┘ └───────────────┘   │
├─────────────────────────────────────────────────────────────┤
│                      AGENT CORE                             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │               BaseAgent (ReAct Loop)                │    │
│  │  ┌──────────┐ ┌───────────┐ ┌──────────────────┐   │    │
│  │  │  State   │ │   LLM     │ │ Memory Compressor│   │    │
│  │  │ Machine  │ │  Client   │ │ (Context Window) │   │    │
│  │  └──────────┘ └───────────┘ └──────────────────┘   │    │
│  └─────────────────────────────────────────────────────┘    │
├─────────────────────────────────────────────────────────────┤
│                    SECURITY LAYER                            │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────────┐    │
│  │Tool Firewall │ │ Verification │ │  Scope Enforcer  │    │
│  │(Arg Sanitize)│ │   Engine     │ │  (DNS Pinning)   │    │
│  └──────────────┘ └──────────────┘ └──────────────────┘    │
├─────────────────────────────────────────────────────────────┤
│                    EXECUTION LAYER                           │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              Docker Sandbox Container                 │   │
│  │  ┌──────┐┌───────┐┌──────┐┌────┐┌─────┐┌─────────┐  │   │
│  │  │ nmap ││sqlmap ││nuclei││ffuf││nikto││Playwright│  │   │
│  │  └──────┘└───────┘└──────┘└────┘└─────┘└─────────┘  │   │
│  │  ┌──────────────────────────────────┐                │   │
│  │  │    Tool Server (HTTP API)        │                │   │
│  │  └──────────────────────────────────┘                │   │
│  └──────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────┤
│                      OUTPUT LAYER                            │
│  ┌──────────┐ ┌──────────┐ ┌───────────┐ ┌─────────────┐   │
│  │  JSON    │ │  HTML    │ │ Markdown  │ │Attack Graph │   │
│  │ Report   │ │ Report   │ │  Report   │ │  (NetworkX) │   │
│  └──────────┘ └──────────┘ └───────────┘ └─────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. Module Architecture

### 2.1 Package Structure

```
phantom/
├── agents/                    # Agent Core
│   ├── base_agent.py          # ReAct loop, iteration control, error handling
│   ├── state.py               # AgentState — Pydantic model, message management
│   ├── enhanced_state.py      # EnhancedAgentState — vuln/host/scan tracking
│   ├── protocol.py            # Agent protocol interfaces
│   └── PhantomAgent/          # Main agent persona with prompts
│
├── core/                      # Security & Domain Logic
│   ├── scope_validator.py     # Target authorization with DNS pinning
│   ├── verification_engine.py # Vulnerability confirmation (SQLi, XSS, RCE, OOB)
│   ├── audit_logger.py        # Crash-safe HMAC-chained JSONL audit trail
│   ├── cost_controller.py     # LLM spend limits and tracking
│   ├── report_generator.py    # JSON/HTML/Markdown structured reports
│   ├── attack_graph.py        # NetworkX-based attack surface modeling
│   ├── attack_path_analyzer.py# Attack chain analysis
│   ├── knowledge_store.py     # Cross-scan learning (encrypted at rest)
│   ├── scan_profiles.py       # Configurable scan modes (quick/deep/stealth)
│   ├── compliance_mapper.py   # OWASP/CWE/NIST mapping
│   ├── mitre_enrichment.py    # MITRE ATT&CK technique tagging
│   ├── interactsh_client.py   # Out-of-band callback verification
│   ├── priority_queue.py      # CVSS-based vulnerability triage
│   ├── nuclei_templates.py    # Dynamic Nuclei template generation
│   ├── diff_scanner.py        # Differential scanning
│   ├── notifier.py            # Alert dispatch
│   └── plugin_loader.py       # Plugin discovery
│
├── tools/                     # Tool Implementations
│   ├── executor.py            # Tool dispatch, firewall integration, truncation
│   ├── registry.py            # XML schema-driven tool registration
│   ├── terminal/              # Sandbox shell execution
│   ├── browser/               # Playwright-based browser automation
│   ├── agents_graph/          # Multi-agent delegation
│   ├── finish/                # Post-scan enrichment pipeline
│   ├── security/              # Verification actions
│   ├── findings/              # Finding recording
│   ├── web_search/            # OSINT / web search
│   ├── proxy/                 # HTTP proxy integration
│   ├── python/                # In-sandbox Python execution
│   ├── file_edit/             # File manipulation in sandbox
│   ├── reporting/             # Interim reporting tools
│   ├── thinking/              # Chain-of-thought tools
│   ├── todo/                  # Agent task planning
│   └── notes/                 # Agent scratchpad
│
├── llm/                       # LLM Integration
│   ├── llm.py                 # LiteLLM client, streaming, cost tracking
│   ├── config.py              # LLMConfig dataclass
│   ├── memory_compressor.py   # Context window management via summarization
│   ├── provider_registry.py   # Multi-provider support
│   ├── dedupe.py              # Response deduplication
│   └── utils.py               # XML parsing, tool call extraction
│
├── runtime/                   # Sandbox Infrastructure
│   ├── runtime.py             # AbstractRuntime interface
│   ├── docker_runtime.py      # Docker container lifecycle
│   └── tool_server.py         # HTTP API bridge to sandbox tools
│
├── models/                    # Domain Models (Pydantic)
│   ├── vulnerability.py       # Vulnerability with CVSS, severity, evidence
│   ├── host.py                # Host, Port, Technology models
│   ├── scan.py                # ScanResult, ScanPhase, ScanStatus
│   └── verification.py        # VerificationResult, ExploitAttempt
│
├── skills/                    # Knowledge Base
│   ├── reconnaissance/        # Recon technique playbooks
│   ├── vulnerabilities/       # Vulnerability-specific attack skills
│   ├── frameworks/            # Framework-specific testing guides
│   ├── technologies/          # Technology-specific enumeration
│   ├── protocols/             # Protocol attack techniques
│   ├── cloud/                 # Cloud-specific testing
│   ├── scan_modes/            # Mode-specific strategy guidance
│   ├── coordination/          # Multi-agent coordination
│   └── custom/                # User-defined skills
│
├── interface/                 # User Interface
│   ├── cli.py                 # Rich CLI with live dashboard
│   ├── tui.py                 # Terminal UI components
│   ├── streaming_parser.py    # Real-time LLM output parsing
│   └── formatters/            # Output formatting
│
├── telemetry/                 # Observability
│   └── tracer.py              # Run tracking, vulnerability index, stats
│
├── config/                    # Configuration
│   └── config.py              # Env-based config with keyring support
│
└── utils/                     # Utilities
    └── resource_paths.py      # Cross-platform resource resolution
```

---

## 3. Core Data Flow

### 3.1 Scan Lifecycle

```
1. CLI parses target + profile → ScopeValidator + ScanProfile
2. DockerRuntime creates isolated sandbox container
3. AuditLogger + Tracer initialized (HMAC chain started)
4. BaseAgent.run() enters ReAct loop:
   
   ┌──────────────────────────────────────────┐
   │            ITERATION LOOP                 │
   │                                           │
   │  a. LLM receives:                        │
   │     - System prompt (persona + tools)     │
   │     - Conversation history (bounded)      │
   │     - Findings ledger (permanent)         │
   │     - Current phase + priority queue      │
   │                                           │
   │  b. LLM responds with tool invocations    │
   │                                           │
   │  c. ToolFirewall validates each call      │
   │     - Injection pattern detection         │
   │     - Scope validation (DNS pinning)      │
   │     - Arg length + count limits           │
   │     - Extra-args whitelist enforcement    │
   │                                           │
   │  d. Executor dispatches to Tool Server    │
   │     - Local tools: run in-process         │
   │     - Sandbox tools: HTTP to container    │
   │     - Result truncated to 8KB             │
   │                                           │
   │  e. Auto-record findings to ledger        │
   │                                           │
   │  f. Memory compression if > threshold     │
   │                                           │
   │  g. Cost controller checks budget         │
   │                                           │
   │  h. Loop detector checks for repetition   │
   │                                           │
   │  STOP CONDITIONS:                         │
   │  - max_iterations reached (200)           │
   │  - wall-clock time exceeded (4h)          │
   │  - cost limit exceeded ($25)              │
   │  - agent calls finish_scan()              │
   │  - user requests stop                     │
   └──────────────────────────────────────────┘

5. finish_scan() triggers enrichment pipeline:
   - Vulnerability verification (VerificationEngine)
   - MITRE ATT&CK enrichment
   - Compliance mapping (OWASP Top 10, CWE, NIST)
   - Attack graph generation (NetworkX)
   - Nuclei template generation
   - Knowledge store update (encrypted)
   - Report generation (JSON + HTML + Markdown)
   - Credential scrubbing
   
6. Sandbox destroyed, audit trail finalized
```

### 3.2 Tool Execution Path

```
LLM Response → parse_tool_invocations()
                    │
                    ▼
            ToolFirewall.validate()
              │             │
              │ BLOCKED     │ ALLOWED
              ▼             ▼
         Log violation   Executor.dispatch()
         Return error      │
                          ┌┴──────────────────┐
                          │                    │
                    Local Tool           Sandbox Tool
                    (in-process)         (HTTP → container)
                          │                    │
                          ▼                    ▼
                    Direct call        httpx.post(tool_server)
                          │                    │
                          └────────┬───────────┘
                                   │
                                   ▼
                          _format_tool_result()
                          (truncate, XML wrap)
                                   │
                                   ▼
                          _auto_record_findings()
                          (extract vulns to ledger)
                                   │
                                   ▼
                          AuditLogger.log_tool_call()
```

---

## 4. Security Architecture

### 4.1 Defense in Depth

| Layer | Component | Protection |
|-------|-----------|------------|
| **L1: Authorization** | `ScopeValidator` | Whitelist-based target auth, CIDR/domain/regex rules, DNS pinning to prevent rebinding |
| **L2: Sandbox Isolation** | `DockerRuntime` | Ephemeral container, no host network, no privileged mode, restricted capabilities, port reservation with minimal TOCTOU window |
| **L3: Cost Control** | `CostController` | Hard budget limit ($25 default), per-request tracking, warning at 80% threshold |
| **L4: Iteration Control** | `AgentState` | Iteration cap (300), approaching-max threshold at 85% |
| **L5: Audit Trail** | `AuditLogger` | Append-only JSONL, HMAC-SHA256 chain for tamper detection, verified on resume, file rotation |
| **L6: Output Sanitization** | `ReportGenerator` | CSV formula injection prevention, credential scrubbing, Jinja2 autoescape |

### 4.2 Threat Model

| Threat | Mitigation |
|--------|------------|
| LLM prompt injection via target | Tool firewall blocks shell metacharacters, scope validator prevents SSRF |
| Sandbox escape | Docker isolation, no host mounts, no privileged mode |
| Cost runaway | Hard budget limits, per-request tracking, model-aware pricing |
| Scope creep | DNS-pinned scope validation on every tool call |
| Audit tampering | HMAC chain verified on resume, append-only writes |
| Data exfiltration | Credential scrubbing in reports, token exclusion from serialization |

---

## 5. LLM Integration

### 5.1 Provider Support

Via LiteLLM, Phantom supports **any OpenAI-compatible API**:
- **OpenRouter** (recommended): DeepSeek, Claude, GPT-4, Llama
- **OpenAI**: GPT-4o, GPT-4-turbo
- **Anthropic**: Claude 3.5 Sonnet, Claude 3 Opus
- **Local**: Ollama, vLLM, LM Studio

### 5.2 Memory Management

```
Token Budget: 80,000 tokens (configurable)

When context exceeds budget:
1. Keep system prompt (always)
2. Keep last 12 messages (always)
3. Summarize older messages via separate LLM call
4. Preserve all URLs, payloads, findings verbatim
5. Findings ledger is NEVER compressed (permanent)
```

### 5.3 Skills System

Phantom loads domain-specific **skill files** to augment the system prompt:
- Reconnaissance playbooks (subdomain enum, port scan strategies)
- Vulnerability-specific attack guides (SQLi, XSS, RCE, SSRF, IDOR)
- Framework-specific testing (Express, Django, Spring, WordPress)
- Protocol analysis (HTTP/2, WebSocket, GraphQL)

---

## 6. Data Models

### 6.1 Vulnerability

```python
class Vulnerability(BaseModel):
    id: str                    # Unique identifier
    name: str                  # Human-readable name
    vulnerability_class: str   # sqli, xss, rce, ssrf, idor, etc.
    severity: VulnerabilitySeverity  # critical, high, medium, low, info
    cvss_score: float          # 0.0 - 10.0
    target: str                # Affected URL/endpoint
    description: str           # Technical description
    detected_by: str           # Tool or technique that found it
    evidence: list[str]        # Raw evidence strings
    status: VulnerabilityStatus     # detected, verified, false_positive
    verified_at: datetime | None
    exploit_steps: list[str]   # Reproduction steps
    remediation: str           # Fix recommendation
    cwe_ids: list[str]         # CWE mappings
    mitre: dict | None         # MITRE ATT&CK enrichment
```

### 6.2 AgentState

```python
class AgentState(BaseModel):
    agent_id: str
    iteration: int             # Current iteration (max 200)
    messages: list[dict]       # Conversation history (max 500)
    findings_ledger: list[str] # Permanent, never compressed
    actions_taken: list[dict]  # Tool call history (bounded)
    errors: list[str]          # Error log (bounded)
    max_scan_duration_seconds: int = 14400  # 4 hours
    _cumulative_elapsed_seconds: float = 0.0  # Resume-aware
```

### 6.3 EnhancedAgentState (extends AgentState)

```python
class EnhancedAgentState(AgentState):
    scan_result: ScanResult           # Structured scan tracking
    current_phase: ScanPhase          # recon → enumeration → exploitation → reporting
    hosts: dict[str, Host]            # Discovered hosts with ports/technologies
    vulnerabilities: dict[str, Vulnerability]  # All findings
    tested_endpoints: dict[str, list] # Deduplication map
    vuln_stats: dict[str, int]        # Severity breakdown
```

---

## 7. Report Pipeline

### 7.1 Post-Scan Enrichment

```
finish_scan() triggers sequential pipeline:

1. Verification     → Re-test HIGH/CRITICAL vulns with VerificationEngine
2. MITRE Enrichment → Tag each vuln with ATT&CK technique IDs
3. Compliance Map   → Generate OWASP Top 10 / CWE / NIST mappings
4. Attack Graph     → Build NetworkX directed graph of attack surface
5. Attack Paths     → Analyze entry→target chains, calculate risk
6. Nuclei Templates → Generate .yaml templates for reproducibility
7. Knowledge Update → Store hosts/vulns/history for future scans (encrypted)
8. Report Gen       → JSON + HTML + Markdown (credential-scrubbed)
9. Credential Scrub → Final pass to remove any leaked secrets
```

### 7.2 Report Formats

| Format | Purpose | Features |
|--------|---------|----------|
| **JSON** | Machine-readable | Full vulnerability data, CVSS, evidence, MITRE tags |
| **HTML** | Executive/team | Styled with CSS, sortable tables, severity badges |
| **Markdown** | Documentation | GitHub-compatible, CSV-injection safe tables |

---

## 8. Configuration

### 8.1 Scan Profiles

| Profile | Max Iterations | Timeout | Browser | Description |
|---------|---------------|---------|---------|-------------|
| `quick` | 30 | 60s | No | Fast surface scan |
| `standard` | 60 | 120s | Yes | Balanced assessment |
| `deep` | 200 | 180s | Yes | Thorough testing |
| `stealth` | 100 | 120s | No | Low noise, slow |
| `api_only` | 80 | 90s | No | REST/GraphQL focus |

### 8.2 Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `OPENROUTER_API_KEY` | LLM API key | Required |
| `PHANTOM_MODEL` | LLM model name | `openrouter/deepseek/deepseek-chat` |
| `PHANTOM_MAX_COST_USD` | Budget limit | `25.0` |
| `PHANTOM_KNOWLEDGE_KEY` | Encryption key for knowledge store | None (disabled) |
| `PHANTOM_SANDBOX_IMAGE` | Docker image | `ghcr.io/usta0x001/phantom-sandbox:latest` |

---

## 9. Test Architecture

| Suite | Tests | Scope |
|-------|-------|-------|
| `test_e2e_system.py` | 184 | Full system integration |
| `test_v0920_audit_fixes.py` | 39 | Security fix verification |
| `test_all_modules.py` | ~200 | Module-level unit tests |
| `test_v0918_features.py` | ~100 | Feature regression tests |
| `test_v0910_coverage.py` | ~80 | Coverage gap tests |
| `test_security_fixes.py` | ~50 | Security-specific tests |
| **Total** | **808** | **0 failures, 21 skipped** |

---

## 10. Deployment

```bash
# Quick start
pip install phantom-agent
phantom --target https://target.com --mode deep

# Docker
docker build -t phantom .
docker run phantom --target https://target.com

# Development
git clone https://github.com/Usta0x001/Phantom
cd Phantom
pip install -e ".[dev]"
python -m pytest tests/
```

---

*Document generated for Phantom v0.9.20 — Autonomous Adversary Simulation Platform*  
*Author: Usta0x001 | License: Apache-2.0*
