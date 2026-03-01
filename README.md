<div align="center">

# ☠ PHANTOM

### Autonomous Offensive Security Intelligence

*" Why So Serious ?! "*

<br>

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.12%2B-yellow.svg)](https://python.org)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg)](https://hub.docker.com/r/redwan07/phantom)
[![PyPI](https://img.shields.io/pypi/v/phantom-agent.svg)](https://pypi.org/project/phantom-agent/)
[![Version](https://img.shields.io/badge/Version-0.9.19-purple.svg)](https://github.com/Usta0x001/Phantom/releases)

**AI-powered multi-agent penetration testing that thinks like a hacker.**

[Quick Start](#-quick-start) · [Features](#-features) · [Architecture](#-architecture) · [Documentation](#-documentation) · [Contributing](#-contributing)

> **585 tests passing** · **152-point security audit** · **E2E validated** · **$0.22/scan average cost**

</div>

---

## 📖 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Architecture](#-architecture)
- [Quick Start](#-quick-start)
- [Usage](#-usage)
- [Configuration](#-configuration)
- [CI/CD Integration](#-cicd-integration)
- [Development](#-development)
- [Documentation](#-documentation)
- [Contributing](#-contributing)
- [License](#-license)

## 🎯 Overview

Phantom deploys **autonomous AI agents** that act like expert penetration testers — they probe your systems dynamically, discover vulnerabilities, chain attack paths, and validate findings through real proof-of-concepts.

Unlike static scanners that just pattern-match, Phantom **thinks**: it reads responses, adapts strategy, exploits chained vulnerabilities, and proves every finding with working PoCs. No false positives. No manual triage.

> **Built for** security teams, bug bounty hunters, and developers who need fast, accurate offensive testing without the overhead of manual pentesting.

### Why Phantom?

| Traditional Scanners | **Phantom** |
|---|---|
| Pattern matching / signatures | AI reasoning + adaptive strategy |
| High false positive rate | Every finding validated with PoC |
| Single-pass scanning | Multi-agent collaboration & chaining |
| Generic reports | MITRE ATT&CK mapped + compliance ready |
| Manual triage needed | Actionable findings, remediation steps |

## 🆕 What's New in v0.9.19

- **9 critical bug fixes** — Loop detector was dead code, tool firewall could be silently bypassed, report generation could crash on unknown severities, zombie agents could resurrect
- **Scan resume** — Checkpoint-based system lets you `--resume` interrupted scans without losing progress
- **Cost tracking** — `scan_stats.json` with per-scan cost breakdown, per-request cost ceiling
- **SSRF bypass testing** — Built-in SSRF allowlist for testing internal services safely
- **152-point security audit** — Full-spectrum adversarial audit across 5 domains
- **585 tests passing** — Comprehensive regression suite covering all audit fixes

## ✨ Features

- 🤖 **Fully Autonomous** — AI agents that think, adapt, and act like real pentesters
- 🔬 **20+ Security Tools** — nmap, nuclei, sqlmap, ffuf, semgrep, katana, and more in a sandboxed Docker environment
- 🛡️ **Secure Sandbox** — All operations inside isolated Docker containers. Zero risk to your host
- 👥 **Multi-Agent System** — Specialized agent trees: discovery → exploitation → validation → reporting
- 🎯 **Real PoCs** — Every vulnerability comes with working proof-of-concept code
- 📊 **MITRE ATT&CK Mapping** — Findings automatically mapped to TTPs and techniques
- 📋 **Compliance Reports** — OWASP Top 10, PCI DSS, SOC 2 mapping out of the box
- 📦 **SARIF Output** — Native GitHub Security tab integration
- 🔄 **Differential Scanning** — Track new/fixed vulnerabilities across scan runs
- 🧠 **Knowledge Persistence** — Learns from past scans, avoids redundant work
- 🔔 **Notifications** — Webhook & Slack alerts on critical findings
- 🔌 **Plugin System** — Extend with custom tools and workflows
- ⚡ **Multiple LLM Providers** — OpenAI, Anthropic, Google, Groq, DeepSeek, Ollama, and more via LiteLLM
- 💰 **Cost Tracking** — Per-request cost ceiling, scan_stats.json with full cost breakdown
- ⏸️ **Scan Resume** — Checkpoint-based resume after interruptions — never lose progress
- 🔒 **Security Hardened** — 152-point security audit, tool firewall, scope validator, HMAC audit trail

## 🏗️ Architecture

### System Overview

```mermaid
flowchart TB
    classDef person fill:#08427B,stroke:#073B6F,color:#fff
    classDef system fill:#9b59b6,stroke:#8e44ad,color:#fff
    classDef external fill:#555555,stroke:#333333,color:#fff

    user["👤 Security Engineer"]

    phantom["☠ PHANTOM<br/>Autonomous Pentest Agent"]

    target["🎯 Target System<br/>(Web App / API / Network)"]
    llm["🧠 LLM Provider<br/>(OpenAI / Anthropic / Groq / Ollama)"]
    sandbox["🐳 Docker Sandbox<br/>(Kali Tools Environment)"]

    user --> |"Configure & Launch"| phantom
    phantom --> |"Tests"| target
    phantom --> |"Reasons & Plans"| llm
    phantom --> |"Executes Tools"| sandbox
    phantom --> |"Reports"| user

    class user person
    class phantom system
    class target,llm,sandbox external
```

### Agent Architecture

```mermaid
flowchart TD
    subgraph Orchestrator["☠ Root Agent (Orchestrator)"]
        direction TB
        A[Analyze Target] --> B[Create Strategy]
        B --> C[Spawn Specialist Agents]
    end

    subgraph Discovery["🔍 Discovery Agents"]
        D1[Port Scanner]
        D2[Web Crawler]
        D3[Tech Fingerprint]
    end

    subgraph Attack["⚔️ Attack Agents"]
        E1[SQLi Specialist]
        E2[XSS Specialist]
        E3[SSRF / IDOR]
        E4[Auth Bypass]
    end

    subgraph Validation["✅ Validation Agents"]
        F1[PoC Builder]
        F2[Impact Assessor]
        F3[Report Generator]
    end

    C --> Discovery
    C --> Attack
    Discovery --> |Findings| Attack
    Attack --> |Vulns| Validation

    style Orchestrator fill:#9b59b6,stroke:#8e44ad,color:#fff
    style Discovery fill:#3498db,stroke:#2980b9,color:#fff
    style Attack fill:#e74c3c,stroke:#c0392b,color:#fff
    style Validation fill:#2ecc71,stroke:#27ae60,color:#fff
```

<details>
<summary><b>🔄 Scan Execution Flow</b> (click to expand)</summary>

```mermaid
sequenceDiagram
    participant U as User
    participant P as Phantom CLI
    participant O as Orchestrator Agent
    participant S as Sandbox (Docker)
    participant L as LLM Provider
    participant T as Target

    U->>P: phantom --target https://app.com
    P->>S: Launch sandbox container
    P->>O: Initialize with system prompt + tools

    Note over O,L: Reconnaissance Phase
    O->>L: Plan reconnaissance strategy
    L-->>O: Use nmap, nuclei, httpx
    O->>S: Execute: nmap -sV target
    S->>T: TCP/UDP probes
    T-->>S: Open ports & services
    S-->>O: Port scan results

    O->>S: Execute: nuclei -u target
    S->>T: Template-based checks
    T-->>S: Vulnerability matches
    S-->>O: Initial findings

    Note over O,L: Attack Phase
    O->>L: Analyze findings, plan attacks
    L-->>O: Spawn SQLi + XSS agents
    O->>S: Execute: sqlmap --url target/api
    S->>T: SQL injection payloads
    T-->>S: Database extracted
    S-->>O: Confirmed SQLi

    Note over O,L: Validation Phase
    O->>L: Build PoC for SQLi
    L-->>O: Working exploit script
    O->>S: Verify PoC execution
    S->>T: Reproduce attack
    T-->>S: Attack confirmed
    S-->>O: PoC validated

    O->>P: create_vulnerability_report()
    P->>U: 📋 Report with PoCs
```

</details>

<details>
<summary><b>🐳 Sandbox Architecture</b> (click to expand)</summary>

```mermaid
graph TB
    subgraph Host["🖥️ Host Machine"]
        CLI[Phantom CLI]
        Docker[Docker Engine]
    end

    subgraph Sandbox["🐳 Phantom Sandbox Container"]
        ToolServer[Tool Server API]

        subgraph Tools["Security Tools"]
            nmap[nmap]
            nuclei[nuclei]
            sqlmap[sqlmap]
            ffuf[ffuf]
            httpx[httpx]
            katana[katana]
            semgrep[semgrep]
            arjun[arjun]
            zap[ZAP Proxy]
            more[+ 10 more...]
        end

        subgraph Runtime["Execution Environment"]
            Shell[Bash Shell]
            Python[Python Runtime]
            Browser[Playwright Browser]
        end
    end

    CLI --> |HTTP API| ToolServer
    ToolServer --> Tools
    ToolServer --> Runtime
    Sandbox -.-> |"Isolated Network"| Target["🎯 Target"]

    style Host fill:#2c3e50,stroke:#1a252f,color:#fff
    style Sandbox fill:#9b59b6,stroke:#8e44ad,color:#fff
    style Tools fill:#3498db,stroke:#2980b9,color:#fff
    style Runtime fill:#e74c3c,stroke:#c0392b,color:#fff
```

</details>

<details>
<summary><b>🧠 Knowledge & Memory System</b> (click to expand)</summary>

```mermaid
graph TB
    subgraph "Persistent Knowledge"
        KS[(Knowledge Store<br/>JSON Persistence)]
        FP[False Positive<br/>Tracking]
        History[Scan History<br/>& Statistics]
    end

    subgraph "Working Memory"
        State[Agent State<br/>Messages & Context]
        Tracer[Telemetry Tracer<br/>Run Data]
        Graph[Attack Graph<br/>NetworkX DAG]
    end

    subgraph "Intelligence"
        MITRE[MITRE ATT&CK<br/>Enrichment]
        Compliance[Compliance<br/>Mapper]
        Priority[Priority Queue<br/>Severity-Ranked]
    end

    State --> |Findings| KS
    KS --> |Past Scans| State
    State --> |Vulns| Graph
    Graph --> |Attack Paths| MITRE
    MITRE --> |TTPs| Compliance
    KS --> |Known FPs| FP
    Tracer --> |Reports| History

    classDef persist fill:#f39c12,stroke:#e67e22,color:#000
    classDef working fill:#3498db,stroke:#2980b9,color:#fff
    classDef intel fill:#2ecc71,stroke:#27ae60,color:#fff

    class KS,FP,History persist
    class State,Tracer,Graph working
    class MITRE,Compliance,Priority intel
```

</details>

<details>
<summary><b>📊 Vulnerability Lifecycle</b> (click to expand)</summary>

```mermaid
stateDiagram-v2
    [*] --> Detected: Tool finds potential vuln
    Detected --> Verified: PoC confirms exploitability
    Detected --> FalsePositive: Validation fails

    Verified --> Reported: create_vulnerability_report()
    Verified --> Exploited: Successful exploitation

    Exploited --> Reported: Impact documented

    Reported --> [*]: Scan complete

    FalsePositive --> [*]: Filtered out

    note right of Detected
        Nuclei, sqlmap, or
        manual testing finds
        a potential issue
    end note

    note right of Verified
        Agent builds PoC
        and confirms the
        vulnerability works
    end note

    note right of Reported
        CVSS scored, MITRE mapped,
        compliance tagged,
        remediation added
    end note
```

</details>

## 🚀 Quick Start

### Prerequisites

- **Docker** (running) — [Install Docker](https://docs.docker.com/get-docker/)
- **Python 3.12+** — [Install Python](https://python.org)
- **An LLM API key** — [OpenAI](https://platform.openai.com/api-keys), [Anthropic](https://console.anthropic.com/), [Groq](https://console.groq.com/) (free), or any [LiteLLM provider](https://docs.litellm.ai/docs/providers)

### Install & Run

```bash
# Install via pip
pip install phantom-agent

# Or via pipx (recommended for CLI tools)
pipx install phantom-agent

# Configure your LLM provider
export PHANTOM_LLM="openai/gpt-4o"        # or groq/llama-3.3-70b-versatile (free!)
export LLM_API_KEY="your-api-key"

# Launch your first scan
phantom scan --target https://your-app.com
```

### Docker Quick Start

```bash
# Pull and run directly
docker run --rm -it \
  -e PHANTOM_LLM="openai/gpt-4o" \
  -e LLM_API_KEY="your-key" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  ghcr.io/usta0x001/phantom:latest \
  scan --target https://your-app.com
```

> [!NOTE]
> First run automatically pulls the sandbox image (`ghcr.io/usta0x001/phantom-sandbox:latest`, ~14GB, Kali-based with 20+ security tools). Scan results save to `phantom_runs/`.

## 📦 Usage

### Basic Scans

```bash
# Web application black-box scan
phantom scan --target https://your-app.com

# Quick scan (faster, less thorough)
phantom scan --target https://your-app.com --scan-mode quick

# Deep scan (comprehensive, slower)
phantom scan --target https://your-app.com --scan-mode deep

# Non-interactive / headless mode (for scripts & CI)
phantom scan --target https://your-app.com --non-interactive
```

### Advanced Testing

```bash
# Authenticated testing
phantom scan --target https://your-app.com \
  --instruction "Login with admin:password123 and test admin endpoints for IDOR"

# Focused vulnerability hunting
phantom scan --target https://api.your-app.com \
  --instruction "Focus on SQL injection and auth bypass in /api/v2 endpoints"

# Interactive TUI mode (rich terminal interface)
phantom --target https://your-app.com

# Resume an interrupted scan
phantom scan --target https://your-app.com --resume
```

### Scan Modes & Profiles

```bash
# View all scan profiles
phantom profiles
```

| Mode | Iterations | Speed | Coverage | Best For |
|------|:----------:|-------|----------|----------|
| `quick` | 20 | ~10-20 min | Surface-level, common vulns | CI/CD gates, quick checks |
| `standard` | 40 | ~30-60 min | Balanced depth | Regular security testing |
| `deep` | 80 | ~1-3 hours | Full attack surface | Thorough pentests, audits |
| `stealth` | 30 | ~20-40 min | Quiet probing, no noisy tools | Production systems, stealth recon |
| `api_only` | 40 | ~30-60 min | API-focused, no browser | REST/GraphQL API testing |

Each profile controls: iteration limit, tool allowlist/blocklist, browser permissions, reasoning effort, and sandbox timeout.

### Post-Scan Enrichment

Every scan automatically runs a 7-stage enrichment pipeline after completion:

1. **MITRE ATT&CK** — CWE/CAPEC/OWASP mapping for every finding
2. **Compliance** — OWASP Top 10, PCI DSS, NIST mapping → `compliance_report.md`
3. **Attack Graph** — NetworkX-based attack path analysis → `attack_graph.json` + `attack_paths.md`
4. **Nuclei Templates** — Auto-generated YAML templates per vulnerability
5. **Knowledge Store** — Persistent cross-scan memory (learns from past scans)
6. **Notifications** — Webhook/Slack alerts for critical/high findings
7. **Reports** — Structured JSON, HTML, and Markdown reports

### Diff Scanning

```bash
# Compare two scan runs to see what changed
phantom diff <run1> <run2>
```

## ⚙️ Configuration

### Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `PHANTOM_LLM` | LLM provider/model | `openai/gpt-4o` |
| `LLM_API_KEY` | API key(s), comma-separated for rotation | `sk-...` |
| `PHANTOM_REASONING_EFFORT` | Thinking depth: `low`, `medium`, `high` | `high` |
| `PHANTOM_SCAN_MODE` | Default scan mode | `standard` |
| `PERPLEXITY_API_KEY` | Enable web search OSINT | `pplx-...` |
| `PHANTOM_IMAGE` | Custom sandbox Docker image | `ghcr.io/usta0x001/phantom-sandbox:latest` |
| `PHANTOM_WEBHOOK_URL` | Webhook for critical findings | `https://hooks.slack.com/...` |
| `PHANTOM_DISABLE_BROWSER` | Disable Playwright browser | `false` |
| `PHANTOM_MAX_COST` | Maximum cost per scan (USD) | `10.0` |
| `PHANTOM_PER_REQUEST_CEILING` | Max cost per LLM request (USD) | `5.0` |

### Supported LLM Providers

| Provider | Model Example | Notes |
|----------|--------------|-------|
| **OpenAI** | `openai/gpt-4o` | Best overall |
| **Anthropic** | `anthropic/claude-sonnet-4-20250514` | Excellent reasoning |
| **Google** | `gemini/gemini-2.5-pro` | Large context |
| **Groq** | `groq/llama-3.3-70b-versatile` | **Free tier** |
| **Ollama** | `ollama/llama3.1` | Local, no API key |
| **DeepSeek** | `deepseek/deepseek-chat` | Cost-effective |
| **OpenRouter** | `openrouter/deepseek/deepseek-v3.2` | Multi-provider gateway |
| **Azure** | `azure/gpt-4o` | Enterprise |
| **AWS Bedrock** | `bedrock/anthropic.claude-v2` | Enterprise |

> Phantom uses [LiteLLM](https://github.com/BerriAI/litellm) — any [supported provider](https://docs.litellm.ai/docs/providers) works out of the box.

### Persistent Configuration

```bash
# Save config so you don't re-enter it every time
phantom config set PHANTOM_LLM openai/gpt-4o
phantom config set LLM_API_KEY sk-your-key

# View current config
phantom config show
```

## 🔄 CI/CD Integration

### GitHub Actions

```yaml
name: Phantom Security Scan

on:
  pull_request:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Phantom
        run: pip install phantom-agent

      - name: Run Security Scan
        env:
          PHANTOM_LLM: ${{ secrets.PHANTOM_LLM }}
          LLM_API_KEY: ${{ secrets.LLM_API_KEY }}
        run: phantom scan --target ./ --non-interactive --scan-mode quick

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: phantom_runs/latest/results.sarif
```

## 🔧 Development

```bash
# Clone the repository
git clone https://github.com/Usta0x001/Phantom.git
cd Phantom

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# .venv\Scripts\activate   # Windows

# Install dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Lint
ruff check phantom/
```

### Project Structure

```
phantom/
├── phantom/                 # Core package
│   ├── agents/              # AI agent system
│   │   ├── PhantomAgent/    # Main agent + system prompt
│   │   ├── base_agent.py    # Agent base class
│   │   ├── state.py         # Thread-safe agent state
│   │   └── enhanced_state.py
│   ├── llm/                 # LLM integration
│   │   ├── llm.py           # Core LLM client
│   │   ├── provider_registry.py
│   │   └── memory_compressor.py
│   ├── core/                # Core modules (16 active engines)
│   │   ├── scan_profiles.py     # quick/standard/deep/stealth/api_only
│   │   ├── scope_validator.py   # Target authorization
│   │   ├── knowledge_store.py   # Cross-scan persistence
│   │   ├── mitre_enrichment.py  # CWE/CAPEC/OWASP mapping
│   │   ├── attack_graph.py      # NetworkX attack DAG
│   │   ├── attack_path_analyzer.py
│   │   ├── compliance_mapper.py # OWASP/PCI/NIST mapping
│   │   ├── report_generator.py  # JSON/HTML/MD reports
│   │   ├── nuclei_templates.py  # Auto template generation
│   │   ├── diff_scanner.py      # Cross-run comparison
│   │   ├── notifier.py          # Webhook/Slack alerts
│   │   ├── audit_logger.py      # JSONL audit trail
│   │   ├── verification_engine.py
│   │   └── priority_queue.py
│   ├── tools/               # Security tool wrappers
│   ├── interface/           # CLI, TUI, reporting
│   ├── runtime/             # Docker sandbox management
│   ├── telemetry/           # Local-only run tracking
│   └── config/              # Configuration management
├── tests/                   # Test suite (585+ tests)
├── containers/              # Dockerfile for sandbox
├── scripts/                 # Install & build scripts
└── docs/                    # Documentation
```

## 📚 Documentation

| Topic | Description |
|-------|-------------|
| [Quick Start](#-quick-start) | Get scanning in 2 minutes |
| [Configuration](#-configuration) | All settings and providers |
| [Architecture](#-architecture) | How the agent system works |
| [CI/CD](#-cicd-integration) | GitHub Actions integration |
| [Contributing](#-contributing) | How to contribute |

## 🤝 Contributing

We welcome contributions! See our [Contributing Guide](CONTRIBUTING.md) for details.

- 🐛 **Bug Reports** — [Open an issue](https://github.com/Usta0x001/Phantom/issues)
- 💡 **Feature Requests** — [Start a discussion](https://github.com/Usta0x001/Phantom/discussions)
- 🔧 **Pull Requests** — Fork, branch, and submit a PR

## ⭐ Support

**Love Phantom?** Give us a ⭐ on [GitHub](https://github.com/Usta0x001/Phantom)!

## 📄 License

Apache License 2.0 — see [LICENSE](LICENSE) for details.

## 🙏 Acknowledgements

Phantom builds on incredible open-source projects:
[LiteLLM](https://github.com/BerriAI/litellm) · [Nuclei](https://github.com/projectdiscovery/nuclei) · [Playwright](https://github.com/microsoft/playwright) · [Textual](https://github.com/Textualize/textual) · [Rich](https://github.com/Textualize/rich) · [NetworkX](https://github.com/networkx/networkx)

---

<div align="center">

**☠ PHANTOM** · *" Why So Serious ?! "* · Autonomous Offensive Security Intelligence

Made with 🖤 by [Usta0x001](https://github.com/Usta0x001)

</div>

> [!WARNING]
> **Only test systems you own or have explicit authorization to test.** You are fully responsible for using Phantom ethically and legally. Unauthorized access to computer systems is illegal.
