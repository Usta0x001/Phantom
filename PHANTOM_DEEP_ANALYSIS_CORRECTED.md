# PHANTOM - Corrected & Verified System Architecture

> **Note**: This analysis corrects assumptions and inconsistencies from the initial review, verified against actual code execution paths.

---

## 1. Verified Entry Points

### 1.1 Main Flow (Verified)

```
main.py:main()
    ↓
parse_arguments() ──→ validates --target, --scan-mode, --instruction-file
    ↓
check_docker_installed() ──→ exits if docker CLI not found
    ↓
pull_docker_image() ──→ pulls ghcr.io/usta0x001/phantom-sandbox:latest (if not exists)
    ↓
validate_environment() ──→ checks PHANTOM_LLM (required), LLM_API_KEY (optional)
    ↓
asyncio.run(warm_up_llm()) ──→ tests LLM connectivity with "OK" prompt
    ↓
generate_run_name() ──→ creates unique ID like "estin-dz_1aa6"
    ↓
clone_repository() ──→ clones target repos to /workspace/
    ↓
run_cli() OR run_tui() ──→ creates PhantomAgent and executes scan
    ↓
display_completion_message() ──→ shows results panel
```

**Key Verification**:
- `run_cli()` is used in non-interactive mode (`--non-interactive`)
- `run_tui()` is used in interactive mode (default)
- Both ultimately call `PhantomAgent(agent_config).execute_scan(scan_config)`

### 1.2 CLI Entry (`cli.py:run_cli`)

```python
async def run_cli(args):
    1. Check for --resume_run flag → load checkpoint if present
    2. Create LLMConfig with scan_mode
    3. Build agent_config dict:
       - llm_config, max_iterations, non_interactive
       - local_sources, hypothesis_ledger, coverage_tracker
       - correlation_engine, attack_graph (restored from checkpoint)
       - _checkpoint_manager
    4. Create Tracer(args.run_name)
    5. Create PhantomAgent(agent_config)
    6. agent.execute_scan(scan_config)
    7. On completion: checkpoint_mgr.mark_completed()
```

---

## 2. Corrected Core Agent Architecture

### 2.1 Agent Hierarchy (Verified)

```
PhantomAgent (extends BaseAgent)
    ├── max_iterations = 300
    └── execute_scan(scan_config) → parses targets → agent_loop(task)

BaseAgent (metaclass=AgentMeta)
    ├── Loads system prompt from: resources/agents/{agent_name}/
    ├── Loads skills from: skills/ (vulnerabilities/, frameworks/, etc.)
    └── agent_loop(task) → main execution loop
```

**Correction**: The agent doesn't directly extend BaseAgent — PhantomAgent extends BaseAgent. The AgentMeta metaclass dynamically loads Jinja2 prompts from `resources/agents/{agent_name}/`.

### 2.2 Verified Agent Loop (`base_agent.py:agent_loop`)

```python
async def agent_loop(self, task):
    # STEP 1: Initialize sandbox (unless PHANTOM_SANDBOX_MODE=true)
    await _initialize_sandbox_and_state(task)
        → Creates Docker container via runtime.create_sandbox()
        → Stores sandbox_id, sandbox_token, sandbox_info
    
    # STEP 2: Main loop
    while True:
        # Check for inter-agent messages
        _check_agent_messages(state)
        
        # Handle waiting states
        if state.is_waiting_for_input():
            await _wait_for_input()
            continue
            
        # Check stop conditions
        if state.should_stop():
            if non_interactive: return final_result
            await _enter_waiting_state(tracer)
            continue
            
        # Increment iteration
        state.increment_iteration()
        
        # Inject periodic status (lines 620-688)
        if iteration > 0:
            # Every 10 iterations: scan_status, hypothesis_ledger (every 10)
            # Every 15 iterations: coverage_tracker
            # Every 20 iterations: correlation_engine
            # At 85% max_iterations: final warning to call finish tool
        
        # Get LLM response
        final_response = await llm.generate(conversation_history)
        
        # Execute actions
        if final_response.tool_invocations:
            await _execute_actions(actions, tracer)
        
        # Checkpoint
        _maybe_save_checkpoint(tracer)
        
        # Exit if finished
        if should_finish:
            return final_result
```

---

## 3. Verified LLM Integration

### 3.1 LLM.generate() Flow (`llm.py:333`)

```python
async def generate(self, conversation_history):
    # STEP 1: Rate limit check
    if now < _GLOBAL_RATE_LIMIT_UNTIL: sleep(wait_time)
    
    # STEP 2: Circuit breaker check
    if not _CIRCUIT_BREAKER.allow_request(): raise LLMRequestFailedError
    
    # STEP 3: Budget check (80/90/100% thresholds)
    _check_budget()
    
    # STEP 4: Prepare messages
    messages = await _prepare_messages(conversation_history)
        → Add system prompt
        → Add agent_identity (<agent_name>, <agent_id>)
        → Run memory_compressor.compress_history()
        → Inject finding_anchors (if any)
        → Add <meta>Continue</meta> if last was assistant
    
    # STEP 5: Enforce request size limits
    messages = await _enforce_request_size_limits(messages)
        → Drop old images → Force compress → Trim history
    
    # STEP 6: Model routing (if enabled)
    if routing_enabled: model = _pick_routing_model(messages)
    
    # STEP 7: Stream response
    async for response in _stream(messages):
        yield response
    
    # STEP 8: Update usage stats
    _update_usage_stats(response)
```

### 3.2 Memory Compressor (`memory_compressor.py:598`)

```python
def compress_history(self, messages, agent_state):
    # 1. Handle images: max 3 images, 300KB total
    # 2. Split messages:
    #    - system_msgs: kept intact
    #    - recent_msgs: last 10 messages kept intact
    #    - old_msgs: to be summarized
    
    # 3. Check if compression needed
    #    - if total_tokens <= threshold * 0.9: return unchanged
    
    # 4. If needed:
    #    - Extract anchors from old_msgs (100+ keywords)
    #    - Add anchors to agent_state.finding_anchors
    #    - Summarize old_msgs in chunks (parallel if enabled)
    #    - Return: system_msgs + compressed + recent_msgs
```

**Key Anchor Keywords** (verified in lines 59-116):
- Vulnerability indicators: `vulnerability`, `exploit`, `sqli`, `xss`, `rce`, `cve-`, `payload`
- Credentials: `password`, `credential`, `token`, `session`, `cookie`
- Network: `localhost`, `127.0.0.1`, `169.254.169.254` (AWS metadata)
- Execution: `shell`, `command`, `exec`, `admin`, `root`

### 3.3 Finding Anchors Injection (`llm.py:618-648`)

```python
# In _prepare_messages():
if _has_anchors:
    # Only inject if not already in last 5 messages
    if not _already_injected:
        # Format: - <text> (600 chars each, max 15)
        # Wrapped in <finding_anchors> tags
        messages.append({"role": "user", "content": anchor_reminder})
```

**Verification**: This runs EVERY iteration starting from iteration 2 (not just at 75% as initially stated). This ensures confirmed findings are always in context.

---

## 4. Verified Tool System

### 4.1 Tool Registration (`registry.py:152`)

```python
@register_tool(sandbox_execution=True)
def some_tool(agent_state=None, **kwargs):
    return result
```

**Verified Tool Count**: 149 `@register_tool` decorators found across the codebase (not 80+ as initially stated).

### 4.2 Tool Categories (`tools/__init__.py:31-81`)

```python
# Non-sandbox mode imports:
- agents_graph
- browser (unless disabled)
- file_edit
- finish
- fuzzer
- notes
- oast
- proxy
- python
- reporting
- scan_registry
- session
- terminal
- thinking
- todo
- web_search (if PERPLEXITY_API_KEY set)
- osint
- vuln_intel
- waf
- payload_gen
- response_analysis
- session_mgmt
- hypothesis
- detection
- scan_status
```

### 4.3 Tool Execution (`executor.py:364`)

```python
async def execute_tool(tool_name, agent_state, **kwargs):
    # 1. Stealth rate limiting (if scan_mode="stealth")
    _apply_stealth_rate_limit(tool_name)
        → 2s delay between HTTP tools
    
    # 2. RBAC check (if enabled)
    check_tool_permission(tool_name)
    
    # 3. Cache check (if tool is idempotent)
    cached = cache.get(tool_name, kwargs)
    if cached: return cached
    
    # 4. Execute in sandbox or locally
    if execute_in_sandbox and not sandbox_mode:
        result = await _execute_tool_in_sandbox(...)
    else:
        result = await _execute_tool_locally(...)
    
    # 5. Cache result
    cache.put(tool_name, kwargs, result)
    
    # 6. Format output (truncation, signal extraction)
    return _format_tool_result_with_meta(result)
```

### 4.4 Smart Output Extraction (`executor.py:1214-1227`)

```python
# For specific tools, extract signal instead of dumb truncation:
- ffuf: Extract non-404 status lines
- nmap/naabu: Extract open port lines
- nuclei: Extract severity-tagged lines
- sqlmap: Extract injection confirmations, database info
- terminal_execute: Auto-detect scanner in output
```

---

## 5. Verified External Memory Systems

### 5.1 Hypothesis Ledger (`hypothesis_ledger.py`)

**Verified Data Model**:
```python
@dataclass
class Hypothesis:
    id: str           # "H-0001"
    surface: str     # "/api/login::username"
    vuln_class: str  # "sqli"
    status: str      # "open|testing|confirmed|rejected"
    payloads_tested: list[str]
    iterations_spent: int
    evidence_for: list[str]
    evidence_against: list[str]
    successful_payloads: list[str]  # P3.2: confirmed payloads
    details: dict     # exploitation details
```

**Verified Methods**:
- `add(surface, vuln_class)` → creates or returns existing
- `record_payload(hyp_id, payload)` → tracks tested payloads
- `record_result(hyp_id, outcome, evidence)` → updates status
- `has_tested(surface, vuln_class, payload)` → prevents redundancy
- `get_scored_hypotheses()` → returns priority-scored list
- `to_prompt_summary(top_n, status_filter)` → LLM injection

### 5.2 Coverage Tracker (`coverage_tracker.py`)

**Verified Data Models**:
```python
@dataclass
class TestedItem:
    id: str                    # "S-A1B2C3D4"
    surface: str               # "/api/login"
    surface_type: str          # "endpoint", "parameter"
    vuln_classes_tested: list[str]
    test_count: int
    failure_reasons: list[str] # "WAF_BLOCKED", "403_FORBIDDEN"

@dataclass
class DiscoveredSurface:
    surface: str
    surface_type: str
    source: str               # "crawl", "js_analysis"
    priority_hints: list[str]
```

### 5.3 Correlation Engine (`correlation_engine.py`)

**Verified Chain Patterns** (10 predefined):
```python
CHAIN_PATTERNS = [
    {"id": "ssrf_to_cloud_metadata", "required_findings": ["ssrf"]},
    {"id": "sqli_to_rce", "required_findings": ["sqli"]},
    {"id": "lfi_to_rce", "required_findings": ["lfi", "path_traversal"]},
    {"id": "xxe_to_ssrf", "required_findings": ["xxe"]},
    {"id": "idor_to_priv_esc", "required_findings": ["idor"]},
    {"id": "xss_to_session_hijack", "required_findings": ["xss"]},
    {"id": "auth_bypass_to_admin", "required_findings": ["auth_bypass"]},
    {"id": "open_redirect_to_phishing", "required_findings": ["open_redirect"]},
    {"id": "ssti_to_rce", "required_findings": ["ssti"]},
    {"id": "info_disclosure_to_exploit", "required_findings": ["info_disclosure"]},
]
```

### 5.4 Attack Graph (`attack_graph.py`)

**Verified Node/Edge Types**:
```python
class AttackNodeType(Enum):
    VULNERABILITY = "vulnerability"
    ASSET = "asset"
    OBJECTIVE = "objective"
    TECHNIQUE = "technique"

class AttackEdgeType(Enum):
    ENABLES = "enables"    # Vuln A enables Vuln B
    AFFECTS = "affects"    # Vuln affects asset
    ACHIEVES = "achieves"  # Chain achieves objective
    USES = "uses"          # Objective uses technique
```

---

## 6. Verified Skill System

### 6.1 Skill Loading (`skills/__init__.py:134`)

```python
def load_skills(skill_names: list[str]) -> dict[str, str]:
    # 1. For each skill_name:
    #    - If contains "/": look in that category
    #    - Else: search all categories
    # 2. Read .md file
    # 3. Strip frontmatter (--- ... ---)
    # 4. Sanitize for prompt injection
    # 5. Return {skill_name: content}
```

### 6.2 Skill Categories (Verified)

```
skills/
├── vulnerabilities/      # 15+ files: xss, sqli, ssrf, rce, idor, etc.
├── frameworks/          # nextjs, fastapi, nestjs
├── technologies/        # supabase, firebase_firestore
├── protocols/           # graphql
├── scan_modes/          # quick, standard, deep, stealth, api_only
├── coordination/        # root_agent
├── reconnaissance/      # recon, tool_mastery
├── targets/            # owasp_juice_shop
├── cloud/              # (placeholder)
└── custom/             # (placeholder)
```

**Skill Injection** (`llm.py:270-274`):
```python
skills_to_load = [
    *config.skills,           # e.g., ["root_agent"]
    f"scan_modes/{scan_mode}" # e.g., "scan_modes/deep"
]
skill_content = load_skills(skills_to_load)
```

---

## 7. Verified Runtime System

### 7.1 Docker Runtime (`docker_runtime.py`)

```python
class DockerRuntime(AbstractRuntime):
    async def create_sandbox(agent_id, token, local_sources):
        # 1. Find available ports (tool_server, caido)
        # 2. Pull/verify image
        # 3. Create container with:
        #    - Network mode: bridge
        #    - Port bindings: tool_server, caido
        #    - Environment: TOOL_SERVER_TOKEN
        #    - Volumes: local_sources → /workspace/
        # 4. Wait for tool server health check
        # 5. Return SandboxInfo
```

### 7.2 Tool Server (`runtime/tool_server.py`)

- Runs in Docker container
- Exposes `/execute` endpoint for tool execution
- Authenticates via Bearer token
- Default port: 48081

---

## 8. Verified Checkpoint System

### 8.1 CheckpointManager (`checkpoint/checkpoint.py`)

```python
def build(run_name, state, tracer, scan_config, ...):
    # Saves:
    - run_name, status, iteration
    - root_agent_state (messages, iteration, etc.)
    - hypothesis_ledger_state
    - coverage_tracker_state
    - correlation_engine_state
    - attack_graph_state
    - sub_agent_states
    - vulnerability_reports
    - scan_config
    - llm_stats_at_checkpoint
```

**Verified Interval**: Every 5 iterations (configurable via `phantom_checkpoint_interval`)

### 8.2 Resume Flow (`cli.py:62-175`)

```python
if resume_run:
    # 1. Load checkpoint
    cp = checkpoint_mgr.load()
    
    # 2. Restore agent state
    restored_state = AgentState.model_validate(cp.root_agent_state)
    restored_state.clear_sandbox()  # Fresh container
    
    # 3. Restore external memory
    restored_hypothesis_ledger = HypothesisLedger.from_dict(...)
    restored_coverage_tracker = CoverageTracker.from_dict(...)
    restored_correlation_engine = CorrelationEngine.from_dict(...)
    restored_attack_graph = AttackGraph.from_dict(...)
    
    # 4. Extend iterations: used + fresh budget, max 5x original
    extended = restored_state.iteration + base_max_iter
    restored_state.max_iterations = min(extended, _abs_iter_cap)
    
    # 5. Inject resume message
    restored_state.add_message("user", f"[SCAN RESUMED] ... {len(cp.vulnerability_reports)} vulns found")
```

---

## 9. Verified Telemetry & Audit

### 9.1 Tracer (`telemetry/tracer.py`)

```python
class Tracer:
    # Tracks:
    - scan_config: {"scan_id", "targets", "user_instructions", "scan_mode"}
    - run_name
    - vulnerability_reports: list of finding dicts
    - chat_messages: conversation history
    - tool_executions: {"tool_name", "args", "status", "duration_ms", "result"}
    - agent_statuses: {agent_id: "running"|"completed"|"failed"|...}
    - streaming_content: current LLM response
    - caido_url: for live proxy viewing
    
    # Methods:
    log_agent_creation(agent_id, name, task, parent_id)
    log_tool_execution_start(agent_id, tool_name, args)
    update_tool_execution(execution_id, status, result)
    log_chat_message(content, role, agent_id)
    update_streaming_content(agent_id, content)
    get_total_llm_stats() → {"total": {cost, requests, input_tokens, ...}, "per_model": {...}}
```

### 9.2 Audit Logger (`logging/audit.py`)

```python
# Events logged:
- agent_created, agent_iteration, agent_completed, agent_failed
- llm_request, llm_response, llm_error, rate_limit_hit, rate_limit_abort
- tool_start, tool_result, tool_error
- compression, image_eviction
- checkpoint
- security_event (injection_blocked, budget_warning_80/90)
```

---

## 10. Corrected Configuration System

### 10.1 Config Class (`config/config.py`)

**Verified Key Settings**:

| Setting | Default | Purpose |
|---------|---------|---------|
| `phantom_llm` | None | **Required** - Model name |
| `llm_api_key` | None | Optional |
| `llm_api_base` | None | For local models |
| `phantom_reasoning_effort` | None | none/minimal/low/medium/high/xhigh |
| `phantom_max_cost` | None | Budget limit (USD) |
| `phantom_checkpoint_interval` | "5" | Save every N iterations |
| `phantom_tool_cache_enabled` | "true" | Cache tool results |
| `phantom_compressor_parallel` | "true" | Parallel compression |
| `phantom_circuit_breaker_enabled` | "true" | Prevent cascade failures |
| `phantom_scope_enforcement` | "true" | Network isolation |
| `phantom_adaptive_scan` | "true" | Auto-downgrade mode |

---

## 11. End-to-End Execution Path (Verified)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ main.py:main()                                                              │
│   argparse → validate → warm_up_llm → run_cli/tui                            │
└─────────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│ cli.py:run_cli()                                                            │
│   - Parse args                                                              │
│   - Create LLMConfig(scan_mode)                                             │
│   - Create agent_config (hypothesis_ledger, coverage_tracker, etc.)        │
│   - Create Tracer                                                           │
│   - Create PhantomAgent                                                     │
│   - agent.execute_scan(scan_config)                                         │
└─────────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│ phantom_agent.py:execute_scan()                                            │
│   - Parse targets (repos, local_code, urls, ip_addresses)                   │
│   - Register SSRF hosts                                                      │
│   - Construct task description                                             │
│   - agent_loop(task)                                                        │
└─────────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│ base_agent.py:agent_loop()                                                  │
│   Loop (max 300 iterations):                                                │
│     1. Initialize sandbox (first iteration)                                  │
│     2. Check inter-agent messages                                           │
│     3. Handle waiting states                                                │
│     4. Increment iteration                                                   │
│     5. Inject periodic status (10/15/20 iter)                               │
│     6. llm.generate(conversation_history)                                  │
│        a. memory_compressor.compress_history()                            │
│        b. Inject finding_anchors                                             │
│        c. litellm.acompletion()                                            │
│        d. Parse tool_invocations                                           │
│     7. _execute_actions(tools)                                              │
│        a. executor.execute_tool()                                           │
│        b. Cache check → execute → cache result                             │
│        c. Format output (truncation, signal extraction)                    │
│     8. _maybe_save_checkpoint()                                            │
│     9. If should_finish: return                                            │
└─────────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│ llm.py:generate() → _stream()                                              │
│   - Prepare messages (compress + anchors)                                   │
│   - Enforce size limits                                                     │
│   - Route model if enabled                                                  │
│   - Call litellm.acompletion()                                              │
│   - Update stats (tokens, cost)                                             │
│   - Record success/failure (circuit breaker)                                │
│   - Parse tool calls from response                                          │
└─────────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│ executor.py:execute_tool()                                                 │
│   - Stealth rate limiting                                                  │
│   - RBAC check                                                              │
│   - Cache lookup                                                            │
│   - Execute (sandbox or local)                                              │
│   - Cache result                                                            │
│   - Format output                                                           │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 12. Summary of Corrections

| Item | Initial | Corrected |
|------|---------|-----------|
| Tool count | 80+ | 149 `@register_tool` decorators |
| Anchor injection | At 75% iterations | Every iteration from #2 |
| Memory compression threshold | Fixed 25% | Model-aware (65% for 128K, 50% for 32K, 40% for small) |
| Hypothesis scoring | Not detailed | Evidence (30pts) + freshness (20pts) + investment (25pts) + status (15pts) + payload (10pts) |
| Scan modes | 5 mentioned | 5: quick, standard, deep, stealth, api_only |
| Checkpoint interval | Not specified | 5 iterations (configurable) |
| Stealth rate limit | Not specified | 2 seconds between HTTP tools |
| Circuit breaker threshold | Not specified | 5 consecutive failures → open |

---

## 13. Key Insights from Code Review

1. **Memory Management is Critical**: The system has multiple layers of memory management (compression, anchors, hypothesis ledger, coverage tracker, correlation engine) to handle long-running pentests without losing context.

2. **Tool Selection is Dynamic**: `tools/dynamic_tools.py` allows loading only relevant tools based on task context, reducing token usage from ~25K to ~5K per call.

3. **Checkpoint Resume is Comprehensive**: Not just agent state, but ALL external memory systems (hypothesis ledger, coverage tracker, correlation engine, attack graph) are restored on resume.

4. **Security is Layered**: Multiple security features (scope enforcement, circuit breaker, RBAC, prompt injection sanitization, message deduplication) protect both the system and the target.

5. **Audit Trail is Complete**: Every significant action (LLM calls, tool executions, compressions, agent lifecycle) is logged for compliance and debugging.