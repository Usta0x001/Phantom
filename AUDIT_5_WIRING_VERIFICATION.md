# PHANTOM AUDIT REPORT - WIRING VERIFICATION

**Purpose**: Verify that all components are properly integrated and that data flows correctly through the system.

---

## ARCHITECTURE OVERVIEW

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              PHANTOM AGENT                                   │
│                        (phantom_agent.py:1-600)                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐       │
│  │  HypothesisLedger │    │  CoverageTracker │    │ CorrelationEngine│       │
│  │  (hypothesis_     │    │  (coverage_      │    │ (correlation_    │       │
│  │   ledger.py)      │    │   tracker.py)    │    │  engine.py)      │       │
│  └────────┬─────────┘    └────────┬─────────┘    └────────┬─────────┘       │
│           │                       │                       │                  │
│           └───────────────────────┼───────────────────────┘                  │
│                                   │                                          │
│                                   ▼                                          │
│                        ┌──────────────────┐                                  │
│                        │    BaseAgent     │                                  │
│                        │  (base_agent.py) │                                  │
│                        └────────┬─────────┘                                  │
│                                 │                                            │
│                                 ▼                                            │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                         TOOL EXECUTOR                                 │   │
│  │                       (executor.py:1-400)                             │   │
│  ├──────────────────────────────────────────────────────────────────────┤   │
│  │                                                                       │   │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐         │   │
│  │  │  OSINT  │ │VulnIntel│ │   WAF   │ │ Payload │ │ Fuzzer  │         │   │
│  │  │  Tools  │ │  Tools  │ │  Tools  │ │   Gen   │ │  Tools  │         │   │
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘         │   │
│  │                                                                       │   │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐         │   │
│  │  │  OAST   │ │ Browser │ │ Session │ │Response │ │   API   │         │   │
│  │  │  Tools  │ │  Tools  │ │  Mgmt   │ │Analysis │ │ Schema  │         │   │
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘         │   │
│  │                                                                       │   │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐                                 │   │
│  │  │Terminal │ │Reporting│ │ Finish  │                                 │   │
│  │  │  Tools  │ │  Tools  │ │  Tools  │                                 │   │
│  │  └─────────┘ └─────────┘ └─────────┘                                 │   │
│  │                                                                       │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                            EXTERNAL SERVICES                                  │
├──────────────────────────────────────────────────────────────────────────────┤
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐    │
│  │   LLM   │ │  Caido  │ │ Shodan  │ │  crt.sh │ │ Sandbox │ │  OAST   │    │
│  │ (litellm)│ │  Proxy  │ │   API   │ │         │ │  (E2B)  │ │ Server  │    │
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘    │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## WIRING VERIFICATION RESULTS

### 1. AGENT → TOOL EXECUTOR

**Location**: `base_agent.py:680-750`

**Verification**:
```python
# base_agent.py:680
async def _execute_tool(self, tool_name: str, tool_args: dict) -> ToolResult:
    result = await self.executor.execute(
        tool_name=tool_name,
        arguments=tool_args,
        agent_state=self.state,
    )
```

**Status**: ✅ PROPERLY WIRED

**Data Flow**:
1. LLM returns tool_calls in response
2. `_process_response()` extracts tool calls
3. `_execute_tool()` passes to executor
4. Executor returns `ToolResult`
5. Result injected into conversation

**Issues Found**: None

---

### 2. HYPOTHESIS LEDGER INTEGRATION

**Location**: `base_agent.py:127-135`, `phantom_agent.py`

**Verification**:
```python
# base_agent.py:127-135
try:
    from phantom.tools.hypothesis.hypothesis_actions import set_ledger
    set_ledger(hypothesis_ledger)
except ImportError:
    logger.warning("Hypothesis actions not available")
```

**Status**: ⚠️ WEAK WIRING - IMPORT ERROR PRESENT

**LSP Error**:
```
ERROR [131:18] Import "phantom.tools.hypothesis.hypothesis_actions" could not be resolved
```

**Issue**: The hypothesis_actions module path may not exist or is incorrectly referenced. The ledger is created but may not be accessible to tools.

**Impact**: Medium - Hypothesis tracking may not persist across tool calls.

**Fix Required**:
1. Verify `phantom/tools/hypothesis/` directory exists
2. Create `hypothesis_actions.py` with `set_ledger()` function
3. Or refactor to pass ledger through executor context

---

### 3. COVERAGE TRACKER INTEGRATION

**Location**: `phantom_agent.py`, tools access via state

**Verification**: Coverage tracker is instantiated in PhantomAgent but:
- Not passed to executor explicitly
- Tools access via `agent_state` parameter

**Status**: ✅ PROPERLY WIRED (via state)

**Data Flow**:
1. PhantomAgent creates CoverageTracker
2. Stored in agent state
3. Tools receive state, can access tracker
4. `_should_test()` queries tracker before testing

---

### 4. CORRELATION ENGINE INTEGRATION

**Location**: `correlation_engine.py`, `phantom_agent.py`

**Verification**:
```python
# phantom_agent.py (implied)
# Correlation engine checks after each vulnerability finding
```

**Status**: ⚠️ PARTIALLY WIRED

**Issue**: The correlation engine exists and has good chain definitions, but:
- Not automatically triggered after vulnerability discovery
- Requires explicit tool call to `check_vulnerability_chains()`
- No automatic escalation path execution

**Impact**: High - Attack chains not automatically exploited

**Fix Required**:
1. Add post-vulnerability hook in executor
2. Auto-trigger correlation check after any vuln finding
3. Queue chain stage actions automatically

---

### 5. TOOL REGISTRY → EXECUTOR

**Location**: `registry.py`, `executor.py`

**Verification**:
```python
# registry.py - Tools register with @register_tool decorator
# executor.py - Looks up tools from registry

class ToolExecutor:
    def __init__(self, registry: ToolRegistry = None):
        self.registry = registry or get_global_registry()
    
    async def execute(self, tool_name: str, ...) -> ToolResult:
        tool_func = self.registry.get(tool_name)
```

**Status**: ✅ PROPERLY WIRED

---

### 6. PROXY MANAGER INTEGRATION

**Location**: `proxy_manager.py`, `fuzzer_actions.py`, `osint_actions.py`

**Verification**:
```python
# proxy_manager.py provides Caido integration
# But tools don't consistently use it
```

**Status**: ⚠️ INCONSISTENT WIRING

**Issues**:
1. `fuzzer_actions.py` uses httpx directly without proxy
2. `osint_actions.py` uses httpx directly without proxy
3. Only explicit proxy tool calls route through Caido

**Impact**: Medium - Traffic not intercepted, SSRF protection bypassed

**Fix Required**:
```python
# Add to all HTTP-making tools:
from phantom.tools.proxy.proxy_manager import get_proxied_client

async def some_tool(...):
    async with get_proxied_client() as client:
        response = await client.get(url)
```

---

### 7. CHECKPOINT SYSTEM INTEGRATION

**Location**: `checkpoint.py`, `base_agent.py:850-900`

**Verification**:
```python
# base_agent.py:850-870
if self.checkpoint_manager.should_save(self.state.iteration):
    checkpoint_data = CheckpointManager.build(
        run_name=self._run_name,
        state=self.state,
        tracer=self.tracer,
        scan_config=self.scan_config,
    )
    self.checkpoint_manager.save(checkpoint_data)
```

**Status**: ⚠️ PARTIALLY WIRED

**Issues**:
1. `hypothesis_ledger` not included in checkpoint (see C-08)
2. `coverage_tracker` not included in checkpoint
3. `run_name` can be None (LSP error)

**Fix Required**:
```python
# checkpoint.py CheckpointData needs:
hypothesis_ledger: dict[str, Any] = {}
coverage_tracker: dict[str, Any] = {}
```

---

### 8. AUDIT LOGGING INTEGRATION

**Location**: `audit.py`, various tool files

**Verification**:
```python
# audit.py provides comprehensive logging
# Integrated via get_audit_logger() singleton
```

**Status**: ✅ PROPERLY WIRED

**Evidence**:
- `executor.py` logs tool start/result/error
- `llm.py` logs LLM requests/responses
- `base_agent.py` logs agent lifecycle

---

### 9. LLM CLIENT INTEGRATION

**Location**: `llm.py`, `base_agent.py`

**Verification**:
```python
# base_agent.py
self.llm_client = LLMClient(
    model=model,
    config=llm_config,
    tracer=self.tracer,
)

# Main loop uses:
response = await self.llm_client.chat(messages)
```

**Status**: ✅ PROPERLY WIRED

**Features Verified**:
- Circuit breaker active
- Rate limiting active
- Memory compression integrated
- Token counting accurate

---

### 10. BROWSER → TAB MANAGER INTEGRATION

**Location**: `browser_actions.py`, `tab_manager.py`, `browser_instance.py`

**Verification**:
```python
# browser_actions.py:245
from .tab_manager import get_browser_tab_manager
manager = get_browser_tab_manager()
```

**Status**: ✅ PROPERLY WIRED

---

## END-TO-END FLOW TRACE

### Scenario: Scan URL for SQL Injection

```
1. USER INPUT: "Scan https://target.com for vulnerabilities"
   │
   ▼
2. PHANTOM AGENT: Parse task, build system prompt
   Location: phantom_agent.py:_build_system_prompt()
   │
   ▼
3. LLM CLIENT: Send prompt to model
   Location: llm.py:chat()
   │
   ▼
4. LLM RESPONSE: Tool call - dns_enum("target.com")
   │
   ▼
5. EXECUTOR: Execute dns_enum
   Location: executor.py:execute()
   │
   ├── RBAC Check: Verify tool allowed
   ├── Sandbox Check: Run locally (sandbox_execution=False)
   ├── SSRF Check: Validate target domain
   └── Execute: osint_actions.dns_enum()
   │
   ▼
6. TOOL RESULT: DNS records returned
   │
   ▼
7. HYPOTHESIS LEDGER: No hypothesis yet
   │
   ▼
8. LLM RESPONSE: Tool call - crtsh_search("target.com")
   │
   ▼
9. EXECUTOR: Execute crtsh_search
   │
   ▼
10. LLM RESPONSE: Tool call - detect_waf("https://target.com")
    │
    ▼
11. EXECUTOR: Execute detect_waf
    │
    ▼
12. WAF RESULT: "Cloudflare detected"
    │
    ▼
13. LLM RESPONSE: Tool call - get_waf_evasion_strategies("cloudflare")
    │
    ▼
14. LLM RESPONSE: Tool call - generate_sqli_payloads(context="cloudflare")
    │
    ▼
15. COVERAGE TRACKER: Check if /api/users tested for sqli
    Location: coverage_tracker.py:is_tested()
    Result: False (not tested)
    │
    ▼
16. HYPOTHESIS LEDGER: Create hypothesis "sqli_in_users_endpoint"
    Location: hypothesis_ledger.py:create_hypothesis()
    │
    ▼
17. LLM RESPONSE: Tool call - execute_fuzz_batch(...)
    │
    ▼
18. EXECUTOR: Execute fuzzer with payloads
    │
    ├── Stealth Mode: Add delays
    ├── Parallel Execution: 5 concurrent
    └── Response Analysis: Check each result
    │
    ▼
19. VULNERABILITY FOUND: SQLi confirmed
    │
    ▼
20. HYPOTHESIS LEDGER: Confirm hypothesis, record payload
    Location: hypothesis_ledger.py:confirm_hypothesis()
    │
    ▼
21. COVERAGE TRACKER: Mark /api/users:sqli as tested
    Location: coverage_tracker.py:mark_tested()
    │
    ▼
22. CORRELATION ENGINE: Check for chains
    Location: correlation_engine.py:check_vulnerability_chains()
    Result: "sqli_to_rce" chain possible
    │
    ▼
23. LLM RESPONSE: Continue exploitation per chain...
    │
    ▼
24. REPORTING: Create vulnerability report
    Location: reporting_actions.py:create_vulnerability_report()
    │
    ▼
25. CHECKPOINT: Save state
    Location: checkpoint.py:save()
    │
    ▼
26. CONTINUE OR FINISH: Based on coverage/iteration limit
```

---

## WIRING ISSUES SUMMARY

| Component | Status | Issue | Severity |
|-----------|--------|-------|----------|
| Agent → Executor | ✅ OK | - | - |
| Hypothesis Ledger | ⚠️ WEAK | Import error, may not persist | Medium |
| Coverage Tracker | ✅ OK | - | - |
| Correlation Engine | ⚠️ PARTIAL | Not auto-triggered | High |
| Tool Registry | ✅ OK | - | - |
| Proxy Manager | ⚠️ INCONSISTENT | Tools bypass proxy | Medium |
| Checkpoint | ⚠️ PARTIAL | Missing ledger/tracker | High |
| Audit Logging | ✅ OK | - | - |
| LLM Client | ✅ OK | - | - |
| Browser Manager | ✅ OK | - | - |

---

## CRITICAL WIRING FIXES NEEDED

### Fix 1: Hypothesis Import Error
```python
# Verify path exists:
phantom/tools/hypothesis/__init__.py
phantom/tools/hypothesis/hypothesis_actions.py

# Or change import in base_agent.py to correct path
```

### Fix 2: Correlation Engine Auto-Trigger
```python
# Add to executor.py after successful vuln finding:
async def _post_vulnerability_hook(self, result: ToolResult):
    if result.indicates_vulnerability:
        chains = await self.correlation_engine.check_chains(result)
        if chains:
            await self._queue_chain_exploitation(chains)
```

### Fix 3: Consistent Proxy Usage
```python
# Create phantom/tools/http/client.py:
async def get_http_client() -> httpx.AsyncClient:
    """Get HTTP client with proxy if configured."""
    proxy_config = get_proxy_config()
    return httpx.AsyncClient(proxies=proxy_config)

# Update all tools to use this instead of raw httpx
```

### Fix 4: Checkpoint State Completeness
```python
# Add to CheckpointData:
hypothesis_ledger: dict = Field(default_factory=dict)
coverage_tracker: dict = Field(default_factory=dict)

# Add to CheckpointManager.build():
hypothesis_ledger=state.hypothesis_ledger.to_dict() if state.hypothesis_ledger else {},
coverage_tracker=state.coverage_tracker.to_dict() if state.coverage_tracker else {},
```

---

*"A system is only as strong as its weakest connection. These wiring issues mean Phantom occasionally 'forgets' what it learned."*
