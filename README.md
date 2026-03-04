<div align="center">

# PHANTOM

**Autonomous Adversary Simulation Platform**

> *"Why so Serious!"* — Phantom doesn't ask. It finds.

<br>

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=flat-square)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.12%2B-3776AB.svg?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Docker](https://img.shields.io/badge/Docker-Required-2496ED.svg?style=flat-square&logo=docker&logoColor=white)](https://github.com/Usta0x001/Phantom/pkgs/container/phantom-sandbox)
[![PyPI](https://img.shields.io/pypi/v/phantom-agent.svg?style=flat-square&logo=pypi&logoColor=white)](https://pypi.org/project/phantom-agent/)
[![Tests](https://img.shields.io/badge/Tests-731%20passing-2ecc71.svg?style=flat-square&logo=pytest&logoColor=white)](#testing)
[![Audit](https://img.shields.io/badge/Audit-83%20Resolved-e74c3c.svg?style=flat-square&logo=hackthebox&logoColor=white)](#security-audit)

<br>

AI-driven penetration testing that reasons, adapts, and verifies — like a human red-teamer.

[Quick Start](#quick-start) · [Architecture](#architecture) · [Usage](#usage) · [Contributing](#contributing)

</div>

---

## Overview

Phantom is an autonomous AI penetration testing agent. It uses large language models to discover and verify real vulnerabilities in web applications, APIs, and network services — with zero human intervention.

Unlike signature-based scanners, Phantom **reasons** about targets: it reads responses, identifies attack surfaces, chains multi-step exploits, and produces working proof-of-concept code for every confirmed finding.

| | Traditional Scanners | Phantom |
|---|---|---|
| **Approach** | Signature matching | LLM-guided reasoning |
| **False Positives** | 40–70% typical | Every finding verified with working PoC |
| **Depth** | Single-pass | Multi-phase with chained exploits |
| **Reports** | Generic dumps | MITRE ATT&CK mapped, compliance-ready |
| **Triage** | Manual review | Actionable findings + remediation |

---

## Core Capabilities

**Autonomous Operation** — AI agents that plan, execute, and adapt penetration tests through a ReAct (Reasoning + Acting) loop. No hand-holding required.

**30+ Security Tools** — nmap, nuclei, sqlmap, ffuf, httpx, katana, semgrep, nikto, gobuster, arjun, Playwright browser, and more — all running inside an isolated Docker sandbox.

**Sandboxed Execution** — All offensive tools run in ephemeral Docker containers. No host filesystem access, restricted capabilities, automatic cleanup.

**Multi-Agent System** — Specialized sub-agents for parallel recon, exploitation, and validation. The root agent coordinates; sub-agents specialize.

**7-Layer Security** — Scope validator, tool firewall, Docker sandbox, cost controller, time limits, HMAC audit trail, output sanitizer.

**Verified Findings** — Every vulnerability includes a working PoC exploit, raw evidence, and reproducible steps. No guessing.

**MITRE ATT&CK Enrichment** — Automatic CWE, CAPEC, and technique-level tagging with CVSS 3.1 scoring.

**Compliance Mapping** — OWASP Top 10 (2021), PCI DSS v4.0, NIST 800-53 — mapped automatically per finding.

**Knowledge Persistence** — Cross-scan memory stores hosts, vulnerabilities, and false positive signatures. The agent learns from past scans.

**Cost Tracking** — Per-request and per-scan budget limits. Every token counted, every dollar tracked.

---

## Architecture

<details open>
<summary><strong>High-Level Architecture</strong></summary>

```mermaid
%%{init: {'theme': 'dark'}}%%
flowchart TB
    subgraph Interface["Interface Layer"]
        CLI["CLI / TUI"]
        Stream["Streaming Parser"]
    end

    subgraph Orchestration["Orchestration"]
        Profile["Scan Profiles"]
        Scope["Scope Validator"]
        Cost["Cost Controller"]
        Audit["Audit Logger"]
    end

    subgraph Agent["Agent Core"]
        ReAct["BaseAgent · ReAct Loop"]
        State["State Machine"]
        LLM["LLM Client · LiteLLM"]
        Memory["Memory Compressor"]
        Skills["Skills Engine"]
    end

    subgraph Security["Security Layer"]
        Firewall["Tool Firewall"]
        Verifier["Verification Engine"]
    end

    subgraph Execution["Docker Sandbox"]
        ToolServer["Tool Server · HTTP API"]
        Tools["30+ Security Tools"]
        Browser["Playwright · Chromium"]
    end

    subgraph Output["Output"]
        Reports["JSON / HTML / MD"]
        Graph["Attack Graph"]
        MITRE["MITRE ATT&CK"]
        Compliance["Compliance"]
    end

    Interface --> Agent
    Orchestration -.-> Agent
    Agent --> Security
    Security --> Execution
    Agent --> Output

    style Interface fill:#6c5ce7,stroke:#a29bfe,color:#fff
    style Orchestration fill:#00b894,stroke:#55efc4,color:#fff
    style Agent fill:#e17055,stroke:#fab1a0,color:#fff
    style Security fill:#d63031,stroke:#ff7675,color:#fff
    style Execution fill:#0984e3,stroke:#74b9ff,color:#fff
    style Output fill:#fdcb6e,stroke:#ffeaa7,color:#2d3436
```

</details>

<details>
<summary><strong>Scan Execution Flow</strong></summary>

```mermaid
%%{init: {'theme': 'dark'}}%%
sequenceDiagram
    participant User
    participant CLI as Phantom CLI
    participant Agent as Agent (ReAct)
    participant Firewall as Tool Firewall
    participant Sandbox as Docker Sandbox
    participant LLM as LLM Provider
    participant Target

    User->>CLI: phantom scan --target app.com
    CLI->>Sandbox: Create ephemeral container
    CLI->>Agent: Initialize with scope + profile

    rect rgba(108, 92, 231, 0.15)
        Note over Agent,LLM: Reconnaissance
        Agent->>LLM: Analyze target, plan strategy
        LLM-->>Agent: Use nmap, httpx, nuclei
        Agent->>Firewall: Validate tool call
        Firewall-->>Agent: Approved
        Agent->>Sandbox: Execute nmap -sV target
        Sandbox->>Target: Probes
        Target-->>Sandbox: Open ports & services
        Sandbox-->>Agent: Results
    end

    rect rgba(214, 48, 49, 0.15)
        Note over Agent,LLM: Exploitation
        Agent->>LLM: Plan attacks from findings
        LLM-->>Agent: SQLi on /api, XSS on /search
        Agent->>Sandbox: Execute sqlmap
        Sandbox->>Target: Injection payloads
        Target-->>Sandbox: Vulnerability confirmed
        Sandbox-->>Agent: Finding + evidence
    end

    rect rgba(0, 184, 148, 0.15)
        Note over Agent,LLM: Verification
        Agent->>Sandbox: Re-exploit with clean PoC
        Sandbox->>Target: Reproduce attack
        Target-->>Sandbox: Confirmed
    end

    Agent->>CLI: Reports (JSON/HTML/MD)
    CLI->>User: Findings + PoCs + compliance
    CLI->>Sandbox: Destroy container
```

</details>

<details>
<summary><strong>Agent Decision Loop (ReAct)</strong></summary>

```mermaid
%%{init: {'theme': 'dark'}}%%
stateDiagram-v2
    [*] --> Observe: Scan initialized
    Observe --> Reason: Tool results received
    Reason --> Plan: LLM analyzes context
    Plan --> Act: Select tool + arguments
    Act --> Validate: Tool Firewall check

    Validate --> Execute: Approved
    Validate --> Reason: Blocked — re-plan

    Execute --> Record: Results returned
    Record --> CheckStop: Update state

    CheckStop --> Observe: Continue
    CheckStop --> Finalize: Stop condition met

    Finalize --> Verify: Re-test critical findings
    Verify --> Enrich: MITRE + compliance
    Enrich --> Report: Generate reports
    Report --> [*]: Scan complete
```

</details>

<details>
<summary><strong>Sandbox Architecture</strong></summary>

```mermaid
%%{init: {'theme': 'dark'}}%%
graph TB
    subgraph Host["Host Machine"]
        CLI["Phantom CLI"]
        Docker["Docker Engine"]
    end

    subgraph Container["Ephemeral Sandbox · Kali-based · ~13GB"]
        ToolServer["Tool Server API :48081"]

        subgraph Toolkit["Offensive Tools"]
            nmap & nuclei & sqlmap & ffuf
            httpx & katana & semgrep & nikto
            gobuster & arjun & more["20+ more"]
        end

        subgraph Runtime["Runtime"]
            Python["Python 3.12"]
            PW["Playwright + Chromium"]
            Caido["Caido Proxy"]
        end
    end

    CLI -->|"Authenticated HTTP"| ToolServer
    ToolServer --> Toolkit
    ToolServer --> Runtime
    Container -.->|"Network"| Target["Target System"]

    style Host fill:#2d3436,stroke:#636e72,color:#dfe6e9
    style Container fill:#0984e3,stroke:#74b9ff,color:#fff
    style Toolkit fill:#d63031,stroke:#ff7675,color:#fff
    style Runtime fill:#6c5ce7,stroke:#a29bfe,color:#fff
```

</details>

<details>
<summary><strong>7-Layer Security Model</strong></summary>

```
Layer 1  Scope Validator       Target allowlist, SSRF protection, DNS pinning
Layer 2  Tool Firewall         Argument validation, shell injection blocking
Layer 3  Docker Sandbox        Ephemeral container, restricted capabilities
Layer 4  Cost Controller       Per-request ceiling ($5), scan budget ($25)
Layer 5  Time Limits           Per-tool timeout, global scan timeout
Layer 6  HMAC Audit Trail      Tamper-evident, append-only event log
Layer 7  Output Sanitizer      PII stripping, credential redaction
```

</details>

---

## Quick Start

**Requirements:** Docker (running) · Python 3.12+ · An LLM API key

```bash
# Install
pip install phantom-agent
# or: pipx install phantom-agent

# Configure
export PHANTOM_LLM="openai/gpt-4o"
export LLM_API_KEY="your-api-key"

# Run your first scan
phantom scan --target https://your-app.com
```

First run pulls the sandbox image (~13GB). Results saved to `phantom_runs/`.

### Docker

```bash
docker run --rm -it \
  -e PHANTOM_LLM="openai/gpt-4o" \
  -e LLM_API_KEY="your-key" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  ghcr.io/usta0x001/phantom:latest \
  scan --target https://your-app.com
```

---

## Usage

```bash
# Quick scan (~15 min)
phantom scan --target https://app.com --scan-mode quick

# Standard scan (~45 min)
phantom scan --target https://app.com

# Deep scan (1–3 hours, exhaustive)
phantom scan --target https://app.com --scan-mode deep

# Stealth (low-noise, IDS/WAF evasion)
phantom scan --target https://app.com --scan-mode stealth

# API-only (no browser)
phantom scan --target https://api.app.com --scan-mode api_only

# With custom instructions
phantom scan --target https://app.com \
  --instruction "Focus on SQL injection in /api/v2 endpoints"

# Resume interrupted scan
phantom scan --target https://app.com --resume

# Interactive TUI
phantom --target https://app.com

# Non-interactive (CI/CD)
phantom scan --target https://app.com --non-interactive
```

### Scan Profiles

| Profile | Iterations | Duration | Best For |
|---------|:----------:|:--------:|----------|
| `quick` | 60 | ~15 min | CI/CD, rapid checks |
| `standard` | 120 | ~45 min | Regular testing |
| `deep` | 300 | 1–3 hours | Comprehensive audit |
| `stealth` | 60 | ~30 min | Production, IDS evasion |
| `api_only` | 100 | ~45 min | REST/GraphQL APIs |

### Post-Scan Pipeline

Every scan runs a 7-stage enrichment pipeline automatically:

```
1. MITRE ATT&CK     CWE, CAPEC, OWASP mapping
2. Compliance        OWASP Top 10, PCI DSS v4, NIST 800-53
3. Attack Graph      NetworkX path analysis
4. Nuclei Templates  Auto-generated YAML for regression
5. Knowledge Store   Persistent memory updated
6. Notifications     Webhook/Slack for critical findings
7. Reports           JSON, HTML, Markdown output
```

---

## Configuration

<details>
<summary><strong>Environment Variables</strong></summary>

| Variable | Description | Default |
|----------|-------------|---------|
| `PHANTOM_LLM` | LLM model identifier | `openai/gpt-4o` |
| `LLM_API_KEY` | API key (comma-separated for rotation) | — |
| `PHANTOM_REASONING_EFFORT` | `low` / `medium` / `high` | `high` |
| `PHANTOM_SCAN_MODE` | Default scan profile | `standard` |
| `PHANTOM_IMAGE` | Sandbox Docker image | `ghcr.io/usta0x001/phantom-sandbox:latest` |
| `PHANTOM_MAX_COST` | Max cost per scan (USD) | `25.0` |
| `PHANTOM_PER_REQUEST_CEILING` | Max cost per LLM request | `5.0` |
| `PHANTOM_WEBHOOK_URL` | Webhook for critical findings | — |
| `PHANTOM_DISABLE_BROWSER` | Disable Playwright | `false` |

</details>

<details>
<summary><strong>Supported LLM Providers</strong></summary>

Phantom uses [LiteLLM](https://github.com/BerriAI/litellm) — any of 100+ providers work:

| Provider | Model Example | Notes |
|----------|--------------|-------|
| OpenAI | `openai/gpt-4o` | Best overall |
| Anthropic | `anthropic/claude-sonnet-4-20250514` | Strong reasoning |
| Google | `gemini/gemini-2.5-pro` | Large context |
| Groq | `groq/llama-3.3-70b-versatile` | Free tier |
| DeepSeek | `deepseek/deepseek-chat` | Cost-effective |
| OpenRouter | `openrouter/deepseek/deepseek-v3.2` | Multi-provider |
| Ollama | `ollama/llama3.1` | Local, no API key |
| Azure | `azure/gpt-4o` | Enterprise |

</details>

---

## CI/CD Integration

<details>
<summary><strong>GitHub Actions</strong></summary>

```yaml
name: Security Scan
on:
  pull_request:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install phantom-agent
      - run: phantom scan --target ./ --non-interactive --scan-mode quick
        env:
          PHANTOM_LLM: ${{ secrets.PHANTOM_LLM }}
          LLM_API_KEY: ${{ secrets.LLM_API_KEY }}
```

</details>

---

## Development

```bash
git clone https://github.com/Usta0x001/Phantom.git
cd Phantom
python -m venv .venv && source .venv/bin/activate  # .venv\Scripts\activate on Windows
pip install -e ".[dev]"
pytest tests/ -v
```

<details>
<summary><strong>Project Structure</strong></summary>

```
phantom/
├── phantom/                  # Core package
│   ├── agents/               #   Agent system (ReAct loop, state, delegation)
│   ├── core/                 #   Security, reporting, knowledge (20+ modules)
│   ├── tools/                #   30+ security tool wrappers
│   ├── llm/                  #   LLM client, memory compression
│   ├── runtime/              #   Docker sandbox management
│   ├── interface/            #   CLI, TUI, streaming
│   ├── models/               #   Pydantic domain models
│   ├── skills/               #   Domain knowledge files
│   └── telemetry/            #   Run tracing
├── tests/                    # 731+ tests
├── containers/               # Sandbox Dockerfile
├── scripts/                  # Build scripts
└── docs/                     # Documentation
```

</details>

---

## Testing

731+ tests, 0 failures:

| Suite | Tests | Scope |
|-------|:-----:|-------|
| Integration | 153 | Full system E2E |
| Audit fixes | 39 | Security fix verification |
| Unit tests | ~200 | Module-level |
| Feature tests | ~100 | Regression |
| Coverage tests | ~80 | Gap coverage |
| Security tests | ~50 | Security-specific |

---

## Security Audit

Two deep offensive audits on the codebase — all findings resolved:

| Severity | Found | Fixed |
|----------|:-----:|:-----:|
| Critical | 8 | 8 |
| High | 19 | 19 |
| Medium | 34 | 34 |
| Low | 22 | 22 |
| **Total** | **83** | **83** |

---

## Documentation

- [Architecture](docs/ARCHITECTURE.md) — System design
- [Documentation](docs/DOCUMENTATION.md) — Full reference
- [Quick Start](QUICKSTART.md) — Get scanning in 2 minutes
- [Contributing](CONTRIBUTING.md) — Development guidelines

---

## Contributing

Contributions welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

- **Bugs** — [Open an issue](https://github.com/Usta0x001/Phantom/issues)
- **Features** — [Start a discussion](https://github.com/Usta0x001/Phantom/discussions)
- **PRs** — Fork, branch, test, submit

---

## License

Apache License 2.0 — see [LICENSE](LICENSE).

---

## Acknowledgements

Built on: [LiteLLM](https://github.com/BerriAI/litellm) · [Nuclei](https://github.com/projectdiscovery/nuclei) · [Playwright](https://github.com/microsoft/playwright) · [Textual](https://github.com/Textualize/textual) · [Rich](https://github.com/Textualize/rich) · [NetworkX](https://github.com/networkx/networkx) · [SQLMap](https://github.com/sqlmapproject/sqlmap)

---

<div align="center">

**PHANTOM** — *"Why so Serious!"*

Made by [Usta0x001](https://github.com/Usta0x001)

</div>

> **WARNING:** Only test systems you own or have explicit written authorization to test. Unauthorized access to computer systems is illegal.
