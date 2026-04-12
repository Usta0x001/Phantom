# PHANTOM - Deep System Analysis

## Executive Summary

Phantom is an autonomous AI-driven penetration testing tool that leverages large language models (LLMs) to conduct security assessments. The system orchestrates multiple specialized agents, memory management systems, and tool execution pipelines to perform comprehensive security testing with minimal human intervention.

---

## 1. Repository Structure

```
phantom/
├── agents/                    # Agent implementations
│   ├── base_agent.py         # Core agent loop & execution
│   ├── PhantomAgent/
│   │   └── phantom_agent.py  # Main pentesting agent
│   ├── hypothesis_ledger.py # Hypothesis tracking
│   ├── coverage_tracker.py   # Attack surface coverage
│   ├── correlation_engine.py # Vulnerability chain detection
│   ├── state.py              # Agent state management
│   └── enhanced_state.py     # Extended state features
├── llm/                      # LLM integration
│   ├── llm.py                # Main LLM handler
│   ├── config.py            # LLM configuration
│   ├── memory_compressor.py # Context compression
│   ├── dedupe.py             # Response deduplication
│   ├── utils.py             # LLM utilities
│   └── pentager/            # Pentager-specific components
│       ├── reflector.py     # Reflection mechanism
│       └── chain_summarizer.py
├── tools/                    # Security tools
│   ├── registry.py          # Tool registration
│   ├── executor.py          # Tool execution engine
│   ├── cache.py             # Tool result caching
│   ├── terminal/            # Terminal commands (nmap, sqlmap, etc.)
│   ├── browser/             # Browser automation
│   ├── proxy/               # Proxy management
│   ├── recon/               # Reconnaissance tools
│   ├── fuzzer/              # Fuzzing tools
│   ├── vuln_intel/          # CVE/vulnerability intel
│   ├── osint/               # OSINT tools
│   └── ... (80+ tool modules)
├── core/                     # Core functionality
│   ├── attack_graph.py      # NetworkX attack visualization
│   ├── scan_profiles.py    # Scan profiles
│   └── priority_queue.py   # Task prioritization
├── config/                   # Configuration
│   ├── config.py           # Main config manager
│   └── secrets.py          # Secrets management
├── runtime/                  # Sandbox runtime
│   ├── runtime.py          # Main runtime
│   ├── docker_runtime.py   # Docker sandbox
│   └── tool_server.py      # Tool execution server
├── interface/               # User interfaces
│   ├── main.py             # Entry point
│   ├── cli.py              # CLI mode
│   ├── tui.py              # TUI mode
│   └── formatters/         # Output formatters
├── checkpoint/              # State persistence
│   ├── checkpoint.py       # Checkpoint manager
│   └── models.py           # Data models
├── logging/                 # Logging
│   └── audit.py            # Audit logging
├── telemetry/               # Telemetry
│   ├── tracer.py           # Execution tracer
│   ├── flags.py            # Feature flags
│   └── utils.py            # Utilities
└── skills/                  # Agent skills/prompts
```

---

## 2. Entry Points

### 2.1 Main Entry: `phantom/interface/main.py`

```python
# Entry flow:
1. parse_arguments()     - Parse CLI args (--target, --scan-mode, etc.)
2. check_docker_installed() - Verify Docker availability
3. pull_docker_image()   - Pull sandbox image if needed
4. validate_environment() - Check env vars (PHANTOM_LLM, etc.)
5. asyncio.run(warm_up_llm()) - Test LLM connectivity
6. generate_run_name()  - Create unique run identifier
7. clone_repository()    - Clone target repos if needed
8. run_cli() or run_tui() - Launch agent in appropriate mode
```

**Key Arguments:**
- `--target`: Target URL, repo, domain, IP (multiple allowed)
- `--instruction`: Custom pentest instructions
- `--scan-mode`: quick|standard|deep|stealth|api_only
- `--non-interactive`: Batch mode (no TUI)

---

## 3. Core Components

### 3.1 BaseAgent (`phantom/agents/base_agent.py`)

The BaseAgent is the fundamental agent class that orchestrates the entire pentesting workflow.

**Key Attributes:**
```python
self.llm                  # LLM handler
self.state               # AgentState (messages, iteration, etc.)
self.hypothesis_ledger   # HypothesisLedger instance
self.coverage_tracker    # CoverageTracker instance
self.correlation_engine  # CorrelationEngine instance
self.attack_graph        # AttackGraph (NetworkX)
self.max_iterations      # 300 (configurable)
```

**Agent Loop (`agent_loop()`):**
```
1. _initialize_sandbox_and_state() - Create Docker sandbox
2. while True:
   a. Check for new messages from other agents
   b. If waiting for input → wait
   c. If should_stop → enter waiting state or return
   d. Increment iteration
   e. Inject periodic status (every 10 iterations):
      - Scan status summary
      - Hypothesis ledger (every 10)
      - Coverage tracker (every 15)
      - Correlation engine (every 20)
   f. _process_iteration() - Get LLM response
   g. Execute tool invocations
   h. _maybe_save_checkpoint() - Persist state
   i. If should_finish → return results
```

**Key Methods:**
- `execute_scan()` - Execute a complete pentest
- `_process_iteration()` - Single iteration (LLM call + tools)
- `_execute_actions()` - Execute tool invocations
- `_check_agent_messages()` - Inter-agent messaging
- `agent_loop()` - Main execution loop

### 3.2 PhantomAgent (`phantom/agents/PhantomAgent/phantom_agent.py`)

Extends BaseAgent with pentesting-specific logic.

**Key Method: `execute_scan(scan_config)`**
```python
# Parses targets into categories:
- repositories: GitHub/GitLab repos (cloned to workspace)
- local_code: Local directories
- urls: Web applications (registered for SSRF)
- ip_addresses: Direct IP targets

# Constructs task description with:
- Target information
- User instructions (highest priority)
- Calls agent_loop(task)
```

---

## 4. LLM Integration (`phantom/llm/llm.py`)

### 4.1 LLM Class Architecture

```python
class LLM:
    def __init__(self, config: LLMConfig, agent_name: str):
        self.config = config
        self.memory_compressor = MemoryCompressor(model_name)
        self.system_prompt = self._load_system_prompt(agent_name)
        self._reasoning_effort = "high"  # or from config
        
    async def generate(self, conversation_history):
        # Main LLM interaction method
```

### 4.2 Key Features

**1. Memory Compression**
- Automatically compresses conversation history when token limit exceeded
- Uses `_extract_anchors_from_chunk()` to preserve high-signal findings
- Injects "finding_anchors" every iteration after first

**2. Retry Logic**
- Rate-limit errors (429): Up to 10 retries with exponential backoff
- Context too large: Force compress and retry
- Unknown errors: 2 retries max
- Fallback model support if primary fails

**3. Circuit Breaker**
```python
# Prevents cascading failures after repeated LLM errors
- CLOSED: Normal operation
- OPEN: Blocking requests (after 5 consecutive failures)
- HALF_OPEN: Testing recovery after 60s cooldown
```

**4. Budget Management**
- 80% warning: Log warning, continue
- 90% warning: Reduce reasoning effort, downgrade scan mode
- 100%: Abort or continue (configurable)

**5. Adaptive Scan Mode**
```python
# Auto-downgrade scan mode based on budget
deep → standard → quick
```

---

## 5. Memory Compressor (`phantom/llm/memory_compressor.py`)

### 5.1 Compression Strategy

```python
def compress_history(messages, agent_state):
    1. Handle image limits (max 3 images, 300KB total)
    2. Keep all system messages
    3. Keep last 10 messages intact
    4. Summarize older messages in chunks
    
    # Chunk-based summarization (parallel or sequential)
    # Chunk size: 10 messages (configurable)
```

### 5.2 Anchor Extraction

The compressor identifies high-signal keywords to create "anchors" that survive compression:

```python
_ANCHOR_KEYWORDS = (
    "vulnerability", "exploit", "sqli", "xss", "rce",
    "injection", "bypass", "authentication", "cve-",
    "payload", "proof of concept", "credential", "token",
    "session", "cookie", "internal", "localhost", "shell",
    # ... 100+ keywords
)
```

These anchors are stored in `agent_state.finding_anchors` and re-injected every iteration to ensure critical findings aren't lost.

---

## 6. Hypothesis Ledger (`phantom/agents/hypothesis_ledger.py`)

### 6.1 Purpose
Structured external memory that survives memory compression and prevents redundant payload testing.

### 6.2 Data Model

```python
@dataclass
class Hypothesis:
    id: str              # "H-0001"
    surface: str         # "/api/login::username"
    vuln_class: str      # "sqli"
    status: str          # "open|testing|confirmed|rejected"
    payloads_tested: list[str]
    iterations_spent: int
    evidence_for: list[str]
    evidence_against: list[str]
    successful_payloads: list[str]  # P3.2: Track successful payloads
    details: dict        # Exploitation details
```

### 6.3 Key Methods

```python
# Add new hypothesis
add(surface, vuln_class) → hyp_id

# Record testing
record_payload(hyp_id, payload)
record_result(hyp_id, outcome, evidence, successful_payload)

# Queries
has_tested(surface, vuln_class, payload) → bool
get_open_hypotheses() → list[Hypothesis]
get_stale_hypotheses(threshold=20) → list[Hypothesis]
get_scored_hypotheses() → list[dict]  # Priority scores

# LLM injection
to_prompt_summary(top_n=10, status_filter=["open","testing"])
```

### 6.4 Priority Scoring

```python
# Scoring factors:
- evidence_balance: 0-30 pts (evidence_for / total)
- freshness: 0-20 pts (recently updated)
- investment: 0-25 pts (3-10 iterations = optimal)
- status: 0-15 pts (testing > open)
- payload_variety: 0-10 pts (1-5 payloads = optimal)
```

---

## 7. Coverage Tracker (`phantom/agents/coverage_tracker.py`)

### 7.1 Purpose
Tracks which attack surfaces have been tested for which vulnerability classes.

### 7.2 Data Models

```python
@dataclass
class TestedItem:
    id: str              # "S-A1B2C3D4"
    surface: str         # "/api/login"
    surface_type: str    # "endpoint", "parameter", "form_field"
    vuln_classes_tested: list[str]
    test_count: int
    failure_reasons: list[str]  # "WAF_BLOCKED", "403_FORBIDDEN"
    
@dataclass
class DiscoveredSurface:
    surface: str
    surface_type: str
    source: str          # "crawl", "js_analysis"
    priority_hints: list[str]
```

### 7.3 Key Methods

```python
discover_surface(surface, surface_type, source, hints)
record_test(surface, surface_type, vuln_class, note)
record_failure(surface, surface_type, reason, vuln_class)
get_blocked_surfaces() → surfaces with WAF/rate-limit failures
get_coverage_matrix() → surfaces × vuln_classes
get_coverage_gaps() → untested combinations
to_prompt_summary(max_items=15)
```

---

## 8. Correlation Engine (`phantom/agents/correlation_engine.py`)

### 8.1 Purpose
Identifies potential vulnerability chains (e.g., SSRF + cloud metadata = credential theft).

### 8.2 Chain Patterns

```python
CHAIN_PATTERNS = [
    {"id": "ssrf_to_cloud_metadata", "required_findings": ["ssrf"], ...},
    {"id": "sqli_to_rce", "required_findings": ["sqli"], ...},
    {"id": "lfi_to_rce", "required_findings": ["lfi", "path_traversal"], ...},
    {"id": "xss_to_session_hijack", "required_findings": ["xss"], ...},
    # ... 10 predefined patterns
]
```

### 8.3 Key Methods

```python
add_finding(vuln_class, surface, severity, details)
update_chain_status(suggestion_id, status, note)
get_active_suggestions() → chain opportunities
analyze_combinations() → multi-vulnerability patterns
to_prompt_summary(max_items=10)
```

---

## 9. Attack Graph (`phantom/core/attack_graph.py`)

### 9.1 Purpose
Visualizes vulnerability relationships using NetworkX for multi-step attack chain analysis.

### 9.2 Node Types

```python
class AttackNodeType(str, Enum):
    VULNERABILITY = "vulnerability"
    ASSET = "asset"
    OBJECTIVE = "objective"
    TECHNIQUE = "technique"
```

### 9.3 Edge Types

```python
class AttackEdgeType(str, Enum):
    ENABLES = "enables"    # Vuln A enables exploiting Vuln B
    AFFECTS = "affects"    # Vuln affects an asset
    ACHIEVES = "achieves"  # Attack chain achieves objective
    USES = "uses"          # Objective uses technique
```

### 9.4 Analysis Methods

```python
find_paths(source, target, cutoff) → list[list[str]]
get_critical_vulnerabilities(top_n) → betweenness centrality
get_attack_surface() → metrics (nodes, edges, density)
get_vulnerability_chains(min_length=2) → multi-step paths
to_json() / to_graphml() / to_dot() → export formats
```

---

## 10. Tool System (`phantom/tools/`)

### 10.1 Tool Registry (`registry.py`)

Tools are registered via decorator and loaded from XML schemas:

```python
@register_tool(sandbox_execution=True)
async def some_tool(agent_state=None, **kwargs):
    # Tool implementation
    return result
```

**Registry Functions:**
- `get_tool_by_name(name)` → Callable
- `get_tool_names()` → list[str]
- `get_tools_prompt()` → XML string for system prompt
- `should_execute_in_sandbox(tool_name)` → bool

### 10.2 Tool Execution (`executor.py`)

```python
async def execute_tool(tool_name, agent_state, **kwargs):
    # 1. Apply stealth rate limiting (if enabled)
    # 2. Check RBAC permissions
    # 3. Check tool cache for idempotent results
    # 4. Execute in sandbox or locally
    # 5. Cache successful results
    # 6. Format output with truncation
    # 7. Extract vulnerability signals
```

**Key Features:**
- **Stealth Mode**: 2s delay between HTTP requests
- **Caching**: 21% reduction in redundant calls
- **Output Truncation**: Smart extraction for nmap, nuclei, sqlmap, ffuf
- **Vulnerability Signals**: Extract confirmed findings from tool output

### 10.3 Tool Categories

| Category | Tools |
|----------|-------|
| **Terminal** | terminal_execute, exec_terminal (nmap, sqlmap, nuclei, ffuf, curl, etc.) |
| **Browser** | browser_navigate, browser_action, crawl_website |
| **Web Testing** | send_request, http_request, analyze_response |
| **Recon** | js_analysis, directory_bruteforce |
| **Fuzzer** | fuzzer, run_fuzzer |
| **Vuln Intel** | cve_search, shodan_search, exploit_search |
| **OSINT** | subdomain_enum, whois_lookup, github_dork |
| **Reporting** | create_vulnerability_report, create_issue |
| **Proxy** | start_proxy, scope_rules |
| **Session** | session_mgmt, auth_automation |

---

## 11. Execution Pipeline

### 11.1 End-to-End Flow

```
┌─────────────────────────────────────────────────────────────────┐
│ main.py: main()                                                 │
│   1. parse_arguments()                                         │
│   2. check_docker_installed()                                   │
│   3. pull_docker_image() → ghcr.io/usta0x001/phantom-sandbox   │
│   4. validate_environment()                                     │
│   5. warm_up_llm()                                              │
│   6. run_cli() or run_tui()                                     │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ cli.py / tui.py                                                 │
│   Creates PhantomAgent with config                              │
│   Calls agent.execute_scan(scan_config)                        │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ phantom_agent.py: execute_scan()                               │
│   1. Parse targets (repos, local_code, urls, ip_addresses)      │
│   2. Register SSRF hosts                                        │
│   3. Construct task description                                │
│   4. Call agent_loop(task)                                      │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ base_agent.py: agent_loop()                                    │
│   while True:                                                  │
│     1. _initialize_sandbox_and_state(task)                     │
│     2. Check for inter-agent messages                           │
│     3. _process_iteration()                                    │
│       a. Inject periodic status (10/15/20 iter)                 │
│       b. llm.generate(conversation_history)                    │
│       c. _execute_actions(tool_invocations)                    │
│     4. _maybe_save_checkpoint()                                 │
│     5. If should_finish: return results                        │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ llm.py: generate()                                             │
│   1. _prepare_messages()                                       │
│      - Compress history via memory_compressor                  │
│      - Inject finding_anchors                                   │
│   2. _enforce_request_size_limits()                            │
│   3. _stream() → litellm.acompletion                           │
│   4. Parse tool_invocations from response                      │
│   5. Return LLMResponse                                        │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ executor.py: execute_tool()                                    │
│   1. Check cache for idempotent results                        │
│   2. Execute in sandbox or locally                             │
│   3. Cache successful results                                  │
│   4. Truncate output (smart extraction)                        │
│   5. Extract vulnerability signals                             │
│   6. Return formatted result                                   │
└─────────────────────────────────────────────────────────────────┘
```

---

## 12. Configuration System

### 12.1 Config Class (`phantom/config/config.py`)

Central configuration manager with 100+ settings:

**LLM Settings:**
- `phantom_llm`: Model name (e.g., "openai/gpt-5")
- `llm_api_key`, `llm_api_base`
- `phantom_reasoning_effort`: none|minimal|low|medium|high|xhigh
- `phantom_max_cost`: Budget limit in USD

**Memory & Compression:**
- `phantom_compressor_llm`: Cheaper model for summarization
- `phantom_compressor_chunk_size`: 10 (msgs per call)
- `phantom_max_context_ceiling`: 80000 tokens

**Performance:**
- `phantom_tool_cache_enabled`: true
- `phantom_compressor_parallel`: true
- `phantom_adaptive_scan`: true

**Security:**
- `phantom_scope_enforcement`: true (network isolation)
- `phantom_rbac_enabled`: false (tool-level permissions)
- `phantom_circuit_breaker_enabled`: true

**External APIs (optional):**
- `phantom_shodan_api_key`
- `phantom_github_token`
- `phantom_nvd_api_key`

---

## 13. Checkpoint System

### 13.1 CheckpointManager (`phantom/checkpoint/checkpoint.py`)

Persists agent state for resumption:

```python
# Saved data:
- agent state (messages, iteration, etc.)
- hypothesis ledger
- coverage tracker
- correlation engine
- attack graph
- scan config
```

**Key Methods:**
```python
build(state, tracer, hypothesis_ledger, coverage_tracker, ...)
save(checkpoint)
load(run_name)
should_save(iteration) → bool (every 5 iterations)
```

---

## 14. Telemetry & Audit

### 14.1 Tracer (`phantom/telemetry/tracer.py`)

Global execution tracer:

```python
# Tracks:
- Agent creation/completion
- Tool executions
- LLM requests/responses
- Scan progress
- Vulnerability reports
- Total cost tracking

# Methods:
log_agent_creation(agent_id, name, task, parent_id)
log_tool_execution_start(agent_id, tool_name, args)
update_streaming_content(agent_id, content)
get_total_llm_stats() → cost, tokens, requests
```

### 14.2 Audit Logger (`phantom/logging/audit.py`)

Detailed audit logging:

```python
# Events:
log_agent_created()
log_agent_iteration()
log_agent_completed()
log_agent_failed()
log_llm_request()
log_llm_response()
log_tool_start()
log_tool_result()
log_compression()
log_security_event()
```

---

## 15. Key Features Summary

| Feature | Component | Description |
|---------|-----------|-------------|
| **Memory Compression** | `memory_compressor.py` | Summarizes old messages, preserves anchors |
| **Anchor Injection** | `llm.py` | Re-injects findings every iteration |
| **Hypothesis Tracking** | `hypothesis_ledger.py` | Prevents redundant payload testing |
| **Coverage Tracking** | `coverage_tracker.py` | Tracks tested surfaces |
| **Chain Detection** | `correlation_engine.py` | Identifies vulnerability chains |
| **Attack Graph** | `attack_graph.py` | NetworkX visualization |
| **Checkpointing** | `checkpoint.py` | State persistence & resumption |
| **Tool Caching** | `cache.py` | 21% reduction in redundant calls |
| **Circuit Breaker** | `llm.py` | Prevents cascading LLM failures |
| **Budget Management** | `llm.py` | Graceful degradation at 80/90/100% |
| **Stealth Mode** | `executor.py` | 2s rate limiting |
| **Smart Truncation** | `executor.py` | Signal extraction for scanners |
| **RBAC** | `rbac.py` | Tool-level permissions (optional) |
| **Scope Enforcement** | `docker_runtime.py` | Network isolation |

---

## 16. Dependencies

**Core:**
- `litellm`: LLM abstraction layer
- `httpx`: HTTP client
- `docker`: Docker API
- `jinja2`: Template rendering
- `rich`: Terminal UI

**Optional:**
- `networkx`: Attack graph visualization
- `PIL`: Screenshot processing
- `defusedxml`: Safe XML parsing

---

## 17. Summary

Phantom is a sophisticated autonomous penetration testing system that combines:

1. **LLM-driven decision making** with structured memory management
2. **Multiple specialized components** for hypothesis tracking, coverage, and correlation
3. **Robust execution pipeline** with caching, checkpointing, and error handling
4. **80+ security tools** integrated via a flexible registry system
5. **Comprehensive telemetry** for audit and debugging

The system is designed for fully autonomous operation while maintaining safety through scope enforcement, circuit breakers, and budget management.