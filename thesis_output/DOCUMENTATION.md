# Phantom Documentation — v1.0

**Author**: Usta0x001  
**Repository**: [github.com/Usta0x001/Phantom](https://github.com/Usta0x001/Phantom)  
**License**: Apache-2.0

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Installation](#2-installation)
3. [Quick Start](#3-quick-start)
4. [Configuration](#4-configuration)
5. [Scan Modes & Profiles](#5-scan-modes--profiles)
6. [Tool Reference](#6-tool-reference)
7. [Agent Behavior](#7-agent-behavior)
8. [Security Model](#8-security-model)
9. [Reports & Output](#9-reports--output)
10. [Skills System](#10-skills-system)
11. [Knowledge Persistence](#11-knowledge-persistence)
12. [Multi-Agent Delegation](#12-multi-agent-delegation)
13. [Troubleshooting](#13-troubleshooting)
14. [API Reference](#14-api-reference)
15. [Contributing](#15-contributing)

---

## 1. Introduction

Phantom is an **autonomous AI-powered penetration testing agent**. It uses large language models (LLMs) to plan, execute, and report on security assessments — discovering real vulnerabilities in real targets through intelligent tool orchestration.

### What Phantom Does

- **Reconnaissance**: Subdomain enumeration, port scanning, technology fingerprinting
- **Vulnerability Discovery**: SQL injection, XSS, RCE, SSRF, IDOR, authentication bypasses
- **Verification**: Re-exploits findings to confirm they're real (not false positives)
- **Reporting**: Generates structured JSON, HTML, and Markdown reports with MITRE ATT&CK and OWASP Top 10 mappings

### What Makes Phantom Different

| Feature | Phantom | Traditional Scanners |
|---------|---------|---------------------|
| Reasoning | LLM-driven adaptive testing | Static rules/signatures |
| Chaining | Chains vulnerabilities automatically | Tests in isolation |
| Context | Remembers what worked/failed | Stateless per test |
| Verification | Re-exploits to confirm | Reports unverified |
| Reporting | MITRE + OWASP + attack graphs | Flat CVE lists |

---

## 2. Installation

### Prerequisites

- **Python 3.12+** (tested on 3.12–3.14)
- **Docker Desktop** (for sandbox container)
- An **LLM API key** (OpenRouter recommended)

### Install from PyPI

```bash
pip install phantom-agent
```

### Install from Source

```bash
git clone https://github.com/Usta0x001/Phantom.git
cd Phantom
pip install -e ".[dev]"
```

### Docker Image

```bash
docker pull ghcr.io/usta0x001/phantom-sandbox:latest
```

---

## 3. Quick Start

### Basic Scan

```bash
export OPENROUTER_API_KEY="sk-or-v1-your-key-here"
phantom --target https://target.com
```

### With Options

```bash
phantom --target https://target.com \
  --mode deep \
  --model openrouter/deepseek/deepseek-chat \
  --max-cost 10.0 \
  --output-dir ./my-reports
```

### Multi-Target

```bash
phantom --target https://app1.com --target https://app2.com --mode standard
```

### Non-Interactive

```bash
phantom --target https://target.com --non-interactive --mode quick
```

---

## 4. Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OPENROUTER_API_KEY` | OpenRouter API key | **Required** |
| `OPENAI_API_KEY` | OpenAI API key (alternative) | — |
| `ANTHROPIC_API_KEY` | Anthropic API key (alternative) | — |
| `PHANTOM_MODEL` | LLM model identifier | `openrouter/deepseek/deepseek-chat` |
| `PHANTOM_MAX_COST_USD` | Maximum LLM spend per scan | `25.0` |
| `PHANTOM_SANDBOX_IMAGE` | Docker sandbox image | `ghcr.io/usta0x001/phantom-sandbox:latest` |
| `PHANTOM_SANDBOX_EXECUTION_TIMEOUT` | Per-tool timeout (seconds) | `600` |
| `PHANTOM_KNOWLEDGE_KEY` | Fernet key for encrypted knowledge store | — (disabled) |
| `PHANTOM_LOG_LEVEL` | Logging verbosity | `INFO` |

### LLM Provider Configuration

Phantom uses [LiteLLM](https://docs.litellm.ai/) under the hood, supporting 100+ providers:

```bash
# OpenRouter (recommended — access to all models)
export OPENROUTER_API_KEY="sk-or-v1-..."
phantom --model openrouter/deepseek/deepseek-chat --target ...

# OpenAI
export OPENAI_API_KEY="sk-..."
phantom --model gpt-4o --target ...

# Anthropic
export ANTHROPIC_API_KEY="sk-ant-..."
phantom --model claude-3-5-sonnet-20241022 --target ...

# Local (Ollama)
phantom --model ollama/llama3.1 --target ...
```

---

## 5. Scan Modes & Profiles

### Built-in Profiles

| Profile | Iterations | Timeout | Browser | Best For |
|---------|-----------|---------|---------|----------|
| **quick** | 30 | 60s | No | Fast recon, surface-level scan |
| **standard** | 60 | 120s | Yes | Balanced day-to-day testing |
| **deep** | 200 | 180s | Yes | Thorough assessment, all tools |
| **stealth** | 100 | 120s | No | Low-noise, evasive scanning |
| **api_only** | 80 | 90s | No | REST/GraphQL API testing |

### Usage

```bash
phantom --target https://target.com --mode deep
phantom --target https://api.target.com --mode api_only
```

### What Each Profile Controls

- **Max iterations**: How many tool-call cycles the agent performs
- **Sandbox timeout**: Per-tool execution limit
- **Browser**: Whether Playwright-based browser tools are available
- **Priority tools**: Which tools the agent should prefer
- **Skip tools**: Which tools are excluded
- **Nuclei severity**: Scanner sensitivity level

---

## 6. Tool Reference

### Sandbox Execution

| Tool | Description |
|------|-------------|
| `terminal_execute` | Execute any CLI command in the Docker sandbox (nmap, sqlmap, ffuf, nuclei, katana, httpx, subfinder, etc.) |
| `python_action` | Run Python scripts in the sandbox |

### HTTP Proxy & Traffic

| Tool | Description |
|------|-------------|
| `send_request` | Send crafted HTTP requests |
| `repeat_request` | Replay and modify intercepted requests |
| `list_requests` | List all intercepted HTTP requests |
| `view_request` | Inspect a specific request/response |
| `list_sitemap` | Browse discovered URL sitemap |
| `view_sitemap_entry` | Inspect a sitemap entry |
| `scope_rules` | View/set target scope rules |

### Browser Automation

| Tool | Description |
|------|-------------|
| `browser_action` | Navigate, click, input, screenshot, execute JS |

### Agent Orchestration

| Tool | Description |
|------|-------------|
| `view_agent_graph` | View multi-agent task graph |
| `create_agent` | Spawn a specialized sub-agent |
| `send_message_to_agent` | Send a task to a sub-agent |
| `agent_finish` | Mark an agent task complete |
| `wait_for_message` | Block until an agent responds |

### Reporting & Findings

| Tool | Description |
|------|-------------|
| `create_vulnerability_report` | Record a confirmed vulnerability |
| `finish_scan` | Finalize scan and generate report |

### Notes & Task Management

| Tool | Description |
|------|-------------|
| `create_note` | Create a note in the agent scratchpad |
| `list_notes` | List all notes |
| `update_note` | Edit an existing note |
| `delete_note` | Remove a note |
| `create_todo` | Add a task to the agent's TODO list |
| `list_todos` | List current TODO items |
| `update_todo` | Edit a TODO item |
| `mark_todo_done` | Mark a task completed |
| `mark_todo_pending` | Reset a task to pending |
| `delete_todo` | Remove a TODO item |

### Reasoning & Search

| Tool | Description |
|------|-------------|
| `think` | Internal reasoning step (no external action) |
| `web_search` | Search the web via Perplexity (requires API key) |

### File Operations

| Tool | Description |
|------|-------------|
| `str_replace_editor` | Edit files in the sandbox |
| `list_files` | List files in a directory |
| `search_files` | Search file contents |

---

## 7. Agent Behavior

### The ReAct Loop

Phantom follows a **Reason + Act** cycle on every iteration:

1. **Observe**: Review current state, findings, conversation history
2. **Think**: Reason about what to test next (chain-of-thought)
3. **Act**: Invoke one or more tools via XML-structured calls
4. **Record**: Auto-capture findings to persistent ledger

### Scan Phases

The agent progresses through structured phases:

```
RECON → ENUMERATION → EXPLOITATION → POST_EXPLOITATION → REPORTING
```

- **RECON**: Port scanning, subdomain enumeration, tech fingerprinting
- **ENUMERATION**: Directory brute-forcing, parameter discovery, API mapping
- **EXPLOITATION**: Vulnerability testing (SQLi, XSS, RCE, etc.)
- **POST_EXPLOITATION**: Privilege escalation, lateral movement analysis
- **REPORTING**: Verification, enrichment, report generation

### Memory Management

The agent's conversation history is bounded to prevent token overflow:

- **Max 500 messages** in conversation (older messages trimmed, system prompt preserved)
- **80,000 token threshold** triggers automatic memory compression
- **Findings ledger** is **never compressed** — all discoveries survive memory management
- Last 12 messages are always preserved verbatim

### Stop Conditions

The agent stops when any condition is met:
- Iteration limit reached (200 for deep scans)
- Wall-clock time exceeded (4 hours, cumulative across resumes)
- Cost budget exceeded ($25 default)
- Agent explicitly calls `finish_scan()`
- User requests stop (Ctrl+C in interactive mode)

---

## 8. Security Model

### Sandbox Isolation

All offensive tools execute inside a **Docker container**:
- No host filesystem access
- No host network (except target)
- Ephemeral — destroyed after scan
- Rate-limited tool execution

### Tool Firewall

Every tool invocation passes through `ToolInvocationFirewall`:

- **8 injection patterns** detected (semicolons, pipes, backticks, `$()`, etc.)
- **Per-tool whitelist** for extra arguments (nmap, sqlmap, ffuf)
- **Argument length limit**: 4,096 characters
- **Dangerous sandbox commands blocked**: fork bombs, `rm -rf /`, `curl | sh`

### Scope Enforcement

`ScopeValidator` enforces target authorization:

- **Whitelist-based**: Only explicitly authorized targets are tested
- **DNS pinning**: Prevents DNS rebinding attacks
- **Private IP blocking**: Prevents SSRF to internal networks
- **Validated on every tool call**: Not just at scan start

### Audit Trail

`AuditLogger` provides tamper-evident logging:

- **JSONL format**: One JSON object per line
- **HMAC-SHA256 chain**: Each entry references the previous entry's hash
- **Verified on resume**: Detects tampering between scan sessions
- **Crash-safe**: `fsync` after every write

---

## 9. Reports & Output

### Output Directory Structure

```
phantom_runs/
└── target-name_a1b2/
    ├── scan_stats.json          # Timing, costs, tool usage
    ├── vulnerabilities.csv      # Quick reference vulnerability index
    ├── report.json              # Full structured report
    ├── report.html              # Styled HTML report
    ├── report.md                # Markdown report
    ├── attack_graph.json        # NetworkX graph data
    ├── compliance_report.json   # OWASP/CWE/NIST mappings
    ├── nuclei_templates/        # Generated .yaml templates
    ├── audit.jsonl              # HMAC-chained audit trail
    ├── enhanced_state.json      # Full agent state snapshot
    └── screenshots/             # Browser screenshots
```

### Vulnerability Report Fields

Each vulnerability includes:
- **Identification**: ID, name, class, severity, CVSS score
- **Location**: Target URL, affected parameter, HTTP method
- **Evidence**: Raw request/response data, payloads used
- **Verification**: Confirmed/unconfirmed status, verification method
- **Enrichment**: CWE IDs, MITRE ATT&CK techniques, OWASP category
- **Remediation**: Specific fix recommendations

---

## 10. Skills System

Skills are **Markdown knowledge files** loaded into the agent's system prompt to provide domain expertise:

### Skill Categories

```
skills/
├── reconnaissance/     # Port scanning strategies, subdomain techniques
├── vulnerabilities/    # SQLi, XSS, RCE, SSRF, IDOR attack guides
├── frameworks/         # Express, Django, Spring, WordPress testing
├── technologies/       # Node.js, PHP, .NET specific techniques
├── protocols/          # HTTP/2, WebSocket, GraphQL testing
├── cloud/              # AWS, Azure, GCP security testing
├── scan_modes/         # Strategy guides per scan profile
├── coordination/       # Multi-agent task delegation patterns
└── custom/             # User-defined skill files
```

### Adding Custom Skills

Create a Markdown file in `phantom_knowledge/custom/`:

```markdown
# My Custom Skill

## When to Use
When testing applications using [specific technology].

## Techniques
1. Check for [specific vulnerability pattern]
2. Test endpoint `/api/v1/secret` with payload `...`
```

---

## 11. Knowledge Persistence

Phantom learns from past scans via `KnowledgeStore`:

- **Host database**: Previously discovered hosts, ports, technologies
- **Vulnerability database**: Known vulnerabilities per target
- **False positive signatures**: Findings confirmed as false positives
- **Scan history**: When targets were last scanned, what was found

### Encryption at Rest

Set `PHANTOM_KNOWLEDGE_KEY` (Fernet key) to encrypt all stored data:

```bash
# Generate a key
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# Enable encryption
export PHANTOM_KNOWLEDGE_KEY="your-generated-key"
```

---

## 12. Multi-Agent Delegation

Phantom can spawn **sub-agents** for specialized tasks:

```
Main Agent (PhantomAgent)
├── Sub-Agent: "Focus on SQL injection in /api/users"
├── Sub-Agent: "Enumerate all subdomains of target.com"
└── Sub-Agent: "Test authentication bypass on /admin"
```

Each sub-agent:
- Gets its own sandbox context
- Has a focused task scope
- Reports findings back to the parent
- Is cleaned up automatically on completion

---

## 13. Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| "Docker is not available" | Start Docker Desktop, verify `docker ps` works |
| "API key not found" | Set `OPENROUTER_API_KEY` environment variable |
| Scan hangs | Check Docker container health: `docker ps` |
| "Out of scope" errors | Verify target matches scope rules |
| High costs | Use `--mode quick` or `--max-cost 5.0` |
| Memory errors | Reduce `--max-iterations` or use smaller model |

### Debug Mode

```bash
PHANTOM_LOG_LEVEL=DEBUG phantom --target https://target.com
```

### Viewing Audit Trail

```bash
# Pretty-print audit log
python -c "
import json
for line in open('phantom_runs/target_xxxx/audit.jsonl'):
    print(json.dumps(json.loads(line), indent=2))
"
```

---

## 14. API Reference

### Core Classes

```python
# Start a scan programmatically
from phantom.agents.PhantomAgent import PhantomAgent
from phantom.llm.config import LLMConfig

config = {
    "llm_config": LLMConfig(model="openrouter/deepseek/deepseek-chat"),
    "non_interactive": True,
    "targets_info": [{"original": "https://target.com"}],
}
agent = PhantomAgent(config)
await agent.run()
```

### Key Modules

| Module | Class | Purpose |
|--------|-------|---------|
| `phantom.agents.base_agent` | `BaseAgent` | ReAct loop engine |
| `phantom.agents.state` | `AgentState` | State machine |
| `phantom.agents.enhanced_state` | `EnhancedAgentState` | Vuln/host tracking |
| `phantom.core.scope_validator` | `ScopeValidator` | Target authorization |
| `phantom.core.audit_logger` | `AuditLogger` | Tamper-evident logging |
| `phantom.core.cost_controller` | `CostController` | Budget management |
| `phantom.core.verification_engine` | `VerificationEngine` | Vuln confirmation |
| `phantom.core.report_generator` | `ReportGenerator` | Report output |
| `phantom.runtime.docker_runtime` | `DockerRuntime` | Container lifecycle |
| `phantom.tools.executor` | `process_tool_invocations` | Tool dispatch |
| `phantom.llm.llm` | `LLM` | LLM client |

---

## 15. Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.

### Development Setup

```bash
git clone https://github.com/Usta0x001/Phantom.git
cd Phantom
pip install -e ".[dev]"
python -m pytest tests/  # 808 tests, 0 failures
```

### Test Structure

```
tests/
├── test_e2e_system.py        # 184 end-to-end integration tests
├── test_v0920_audit_fixes.py # 39 security fix verification tests
├── test_all_modules.py       # Module-level unit tests
├── test_v0918_features.py    # Feature regression tests
├── test_v0910_coverage.py    # Coverage gap tests
└── test_security_fixes.py    # Security-specific tests
```

---

*Phantom v1.0 Documentation — Author: Usta0x001*  
*Last updated: March 2026*
