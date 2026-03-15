# REPORT 6 — Enhancement Plan

Prioritized list of concrete improvements. Each item includes: what to change,
where in the code to change it, expected impact on cost and/or finding quality,
and implementation difficulty.

Priority tiers:
- **P0** — Fix now. High impact, low effort, no architectural change needed.
- **P1** — Fix soon. High impact, moderate effort.
- **P2** — Fix when time allows. Moderate impact, higher effort.
- **P3** — Future work. High impact but requires architectural change.

---

## P0 — Immediate Wins (Low Effort, High Impact)

### P0.1 — Remove / Replace the "2000+ steps minimum" Instruction

**File**: `phantom/agents/PhantomAgent/system_prompt.jinja`
**What to do**: Find and remove or replace the instruction stating that real
vulnerability discovery needs 2000+ steps minimum. Replace with:

```
Work efficiently. Use the minimum steps necessary to confirm or rule out each
hypothesis. A well-executed targeted scan is better than an exhaustive
unfocused one.
```

**Why**: This single instruction tells the LLM to burn iterations. It directly
counteracts every cost-saving mechanism in the system. Removing it will reduce
average iteration count and token usage.

**Expected impact**: 15–25% reduction in iteration count. Rough cost saving:
$15–$40 per scan.

**Effort**: 5 minutes.

---

### P0.2 — Enable Adaptive Scan Mode by Default

**File**: `phantom/config/config.py`
**What to change**:
```python
# Before:
phantom_adaptive_scan = "false"

# After:
phantom_adaptive_scan = "true"
```

Also set sensible budget thresholds if not already set:
```python
phantom_adaptive_scan_threshold_1 = "30"   # % of budget → downgrade deep→standard
phantom_adaptive_scan_threshold_2 = "60"   # % of budget → downgrade standard→quick
```

**Why**: The feature is fully implemented and tested. It exists specifically for
cost control. There is no reason it should be off by default.

**Expected impact**: On scans that run long, automatic downgrade to quick scan
mode can cut the final 30–40% of scan cost in half.

**Effort**: 2 minutes (config change) + verify threshold values are reasonable.

---

### P0.3 — Enable Model Routing by Default

**File**: `phantom/config/config.py`
**What to change**:
```python
# Before:
phantom_routing_enabled = "false"

# After:
phantom_routing_enabled = "true"
```

Verify that the routing logic in `phantom/llm/llm.py` correctly identifies
tool-execution turns (turns where the LLM output is just a tool call with no
reasoning) and routes them to a cheaper model (e.g. haiku or gpt-4o-mini).

**Why**: Tool-execution turns (e.g. "run nmap on this IP") do not need the
full capability of claude-3-7-sonnet. A cheaper model works fine. These turns
make up roughly 40–60% of all iterations.

**Expected impact**: 25–35% reduction in LLM cost (tool-execution turns at
~10% the cost of full reasoning turns).

**Effort**: 2 minutes (config change) + spot-check routing logic is working.

---

### P0.4 — Fix PoC Replay Success Detection

**File**: `phantom/tools/reporting/reporting_actions.py`
**Problem**: Checking for "error" / "exception" / "fail" in output to determine
if a PoC failed produces wrong results for most real exploits (which output
these words as part of a successful demonstration).

**What to do**: Replace word-presence check with exit-code-based detection plus
a whitelist of known "success patterns" per vulnerability type:

```python
# Instead of:
failed = any(word in output.lower() for word in ["error", "exception", "fail"])

# Use:
failed = (exit_code != 0) and not any(
    pattern in output.lower()
    for pattern in SUCCESS_PATTERNS.get(vuln_type, [])
)

SUCCESS_PATTERNS = {
    "sqli": ["extracted", "dumped", "found", "rows", "injection confirmed"],
    "xss": ["executed", "alert", "confirmed", "payload reflected"],
    "rce": ["uid=", "root", "command executed", "output:"],
    "idor": ["unauthorized", "forbidden", "leaked", "other user"],
    # ... etc
}
```

If exit code is 0, mark as passed regardless of output content.
If exit code is non-zero AND no success pattern found, mark as failed.

**Why**: Currently findings with working PoCs are being marked as unconfirmed.
This artificially deflates reported finding counts and confidence scores.

**Effort**: 2–3 hours (write SUCCESS_PATTERNS dict, update detection logic,
test against known good PoC outputs).

---

### P0.5 — Disable Context Inheritance for ALL Sub-Agents by Default

**File**: `phantom/tools/agents_graph/agents_graph_actions.py`
**Problem**: When `inherit_context=True` (which is often the default), child
agents start with the full parent history. For a parent at iteration 150 with
80k tokens of history, each child starts 80k tokens heavier.

**What to do**: Change the default for `inherit_context` to `False`. Instead,
pass a concise task brief explicitly:

```python
# In create_agent, add a parameter:
def create_agent(name, goal, inherit_context=False, context_summary=None):
    if context_summary:
        # Inject only the summary, not full history
        initial_history = [{"role": "user", "content": context_summary}]
    else:
        initial_history = []
```

The parent agent should generate a brief context summary (1–3 paragraphs: what
was found, what the child should do, what to report back) and pass that instead
of the full history.

**Why**: This is the single largest cost driver after raw iteration count.
Eliminating full history inheritance and replacing with targeted summaries can
reduce child agent initial token load by 85–95%.

**Expected impact**: For a scan with 5 child agents: save ~5 × 80k × 50 iters
= 20M tokens = ~$60 per scan.

**Effort**: 4–6 hours (change default, update callers to pass context_summary,
update system prompt to instruct root agent to write summaries when spawning).

---

## P1 — High-Impact Improvements (Moderate Effort)

### P1.1 — Fix Tool Truncation: Middle-Preserving Strategy for ffuf and nmap

**File**: `phantom/tools/executor.py`, function `_format_tool_result_with_meta`
**Problem**: Head+tail truncation discards the middle of tool output. For ffuf
(directory fuzzing), the interesting findings are distributed throughout the
output, not just at start and end. The current strategy silently drops them.

**What to do**: For `ffuf` and `nmap`, switch to a "finding-first" extraction
strategy:

```python
def _extract_ffuf_findings(output: str, limit: int) -> str:
    """Extract lines that look like findings, up to limit chars."""
    lines = output.splitlines()
    finding_lines = [
        line for line in lines
        if any(code in line for code in ["200", "201", "301", "302", "403", "500"])
        or any(kw in line.lower() for kw in ["found", "status", "size", "words"])
    ]
    result = "\n".join(finding_lines)
    if len(result) > limit:
        return result[:limit] + f"\n...[{len(result)-limit} chars truncated]"
    return result
```

For `nmap`, extract only open port lines and service lines (lines starting with
port numbers or containing "open").

**Why**: The agent makes decisions based on tool output. If tool output silently
drops important findings, the agent misses them entirely. This directly affects
finding quality.

**Effort**: 3–4 hours (implement per-tool extractors, test against real tool
output samples).

---

### P1.2 — Implement a Shared Finding Registry

**Problem**: Multiple agents scan the same endpoints independently. No
deduplication of scanning effort happens in real-time.

**What to do**: Add a process-level shared registry (can be a simple dict
protected by asyncio.Lock) that tracks:
- Which endpoints have been scanned by which tools
- What findings have been reported (by endpoint + vuln type)

Before an agent runs a tool, check the registry:
```python
async def should_scan(endpoint: str, tool: str, scan_registry: ScanRegistry) -> bool:
    if await scan_registry.was_scanned(endpoint, tool):
        return False  # Skip — already done
    await scan_registry.mark_scanning(endpoint, tool)
    return True
```

Agents consult the registry before executing tools. This eliminates duplicate
scans across agents.

**Why**: In a multi-agent deep scan, duplicate tool executions are common. Each
wasted tool execution also generates tool output that gets stored in history,
compounding cost.

**Effort**: 6–8 hours (design registry schema, integrate with tool execution
pipeline, handle partial/failed scans, test with concurrent agents).

---

### P1.3 — Structured Finding Extraction vs Compression

**Problem**: Memory compression summarizes everything including tool output
containing vulnerability evidence. The LLM summary loses exact parameter names,
response bodies, and payloads needed for PoC generation.

**What to do**: Before compression, extract structured "finding anchors" from
messages that contain vulnerability indicators. Store these anchors in the
agent state (not in conversation history) and inject them back when the
reporting phase begins.

```python
@dataclass
class FindingAnchor:
    iteration: int
    tool: str
    endpoint: str
    parameter: str
    payload: str
    response_snippet: str
    vuln_type: str

# In compression pipeline:
anchors = extract_anchors(messages_being_compressed)
agent_state.finding_anchors.extend(anchors)

# In reporting phase setup:
history.append({"role": "user", "content": format_anchors(agent_state.finding_anchors)})
```

**Why**: PoC quality depends on the agent having exact values (the specific
payload, the exact endpoint, the exact parameter). Compression discards these.
Anchors preserve them at low cost (anchors are small structured objects, not
full messages).

**Effort**: 8–12 hours (anchor extraction heuristics, state schema change,
injection logic, testing).

---

### P1.4 — Add Basic Session/Cookie Management

**Problem**: No authentication support means 60–80% of real application attack
surfaces are unreachable.

**What to do**: Add a pre-scan phase where the agent can be given (or can
discover) credentials, performs a login, and stores the resulting cookies/tokens
for injection into all subsequent tool calls:

```python
# New tool: session_login
async def session_login(url: str, username: str, password: str) -> SessionInfo:
    """Attempt login and capture session cookies/tokens."""
    ...

# Modify terminal_execute to support cookie injection:
async def terminal_execute(command: str, session_id: str = None) -> str:
    if session_id:
        cookies = session_store.get(session_id)
        command = inject_cookies(command, cookies)
    ...
```

Also add a `session_refresh` tool the agent can call when it detects a 401/403
response that may indicate session expiry.

**Why**: This is the single largest coverage gap. Without it, Phantom cannot
test authenticated endpoints at all.

**Effort**: 12–20 hours (login tool, session store, cookie injection for curl/
ffuf/nuclei/sqlmap, session refresh detection).

---

## P2 — Moderate-Impact, Higher-Effort Improvements

### P2.1 — Extend History Caching Beyond System Prompt

**File**: `phantom/llm/llm.py`, function `_add_cache_control()`
**What to do**: Apply Anthropic's prompt caching to the first N messages of
conversation history (the stable prefix that doesn't change between calls).
The first ~50 messages of a 200-iteration scan are the same across calls 51–200.

```python
def _add_cache_control(messages: list) -> list:
    # Apply cache to system message (already done)
    # Also apply to messages that are older than CACHE_STABLE_AGE iterations
    CACHE_STABLE_AGE = 20  # messages older than this are stable
    stable_cutoff = len(messages) - CACHE_STABLE_AGE
    for i, msg in enumerate(messages):
        if i < stable_cutoff and i > 0:  # skip system msg (already cached)
            msg = dict(msg)
            msg["cache_control"] = {"type": "ephemeral"}
            messages[i] = msg
    return messages
```

**Expected impact**: On long scans, caching the stable history prefix can save
40–60% of input token cost for mid-to-late iterations. Anthropic charges 10%
of normal price for cache hits.

**Effort**: 4–6 hours (implement and verify cache control placement, test that
cache hit rate is actually high).

---

### P2.2 — Replace LLM-based CVSS Scoring with Formula-Based Scoring

**File**: `phantom/tools/reporting/reporting_actions.py`
**What to do**: Have the LLM provide the CVSS vector components as structured
output (AV, AC, PR, UI, S, C, I, A) and compute the score mathematically using
the standard CVSS 3.1 formula. This eliminates LLM numeric hallucination.

```python
def compute_cvss31(av, ac, pr, ui, s, c, i, a) -> float:
    """Standard CVSS 3.1 formula — not LLM-generated."""
    # ISC, ESC, Impact, Exploitability sub-score calculations
    ...
```

**Why**: LLM-generated scores are biased high and inconsistent. Formula-based
scores are reproducible and auditable.

**Effort**: 3–4 hours (implement formula, update LLM prompt to produce
structured vector components, validate against known CVSS scores).

---

### P2.3 — Smarter Stall Detection: Semantic Stall

**File**: `phantom/agents/base_agent.py`, function `_detect_stall()`
**Problem**: Current stall detection only catches exact tool repetition, not
semantic stalls where the agent keeps calling different tools but makes no
progress.

**What to do**: Track a "progress score" based on:
- New unique endpoints discovered per N iterations
- New finding types confirmed per N iterations
- Phase transitions per N iterations

If progress score is 0 for 10+ iterations, inject a stronger prompt:
```
You have made no new discoveries in the last 10 iterations. Consider:
1. Moving to a different vulnerability class
2. Targeting a different endpoint
3. Escalating to deeper enumeration
4. Concluding this phase if thoroughly covered
```

**Effort**: 6–8 hours (define progress metrics, track them in agent state,
implement detection, write intervention prompts).

---

### P2.4 — Per-Agent Cost Budget

**Problem**: The global cost budget (`phantom_max_cost`) stops the entire scan
when hit. There is no per-agent budget, so one runaway agent can exhaust the
budget that was meant for all agents.

**What to do**: Add per-agent cost tracking and budget enforcement:

```python
# In AgentState:
agent_cost_budget: float = field(default=0.0)  # 0 = no limit
agent_cost_spent: float = field(default=0.0)

# In LLM.generate():
if agent_state.agent_cost_budget > 0:
    if agent_state.agent_cost_spent >= agent_state.agent_cost_budget:
        raise AgentBudgetExhausted(agent_id)
```

Root agent gets the largest budget. Sub-agents get proportionally smaller
budgets. This prevents one child from consuming resources intended for others.

**Effort**: 6–8 hours (state change, enforcement in LLM layer, budget
allocation logic in create_agent, handling of budget exhaustion).

---

## P3 — Architectural Changes (Future Work)

### P3.1 — Dynamic Payload Generation

Replace static skill-file payloads with a payload generator that adapts to
observed application behavior:
- If application uses a specific framework, use framework-specific payloads
- If previous payloads were filtered, generate bypass variants
- If application shows WAF signatures, use WAF-bypass techniques

**Estimated effort**: 40–80 hours (new component, LLM-assisted payload mutation,
feedback loop from tool results).

### P3.2 — Response Diffing Engine

Add a comparison tool that takes two HTTP responses and highlights behavioral
differences:
- Status code changes
- Response body differences (length, content, timing)
- Header differences

This enables detection of blind injection vulnerabilities that currently
require the LLM to notice subtle patterns in raw text.

**Estimated effort**: 20–30 hours (diff engine, integration with terminal tool,
prompt updates to use diff results).

### P3.3 — Persistent Cross-Scan Knowledge Base

Store findings, endpoint maps, and technology fingerprints from past scans.
When scanning a target again or a similar target, load relevant prior knowledge
to skip the recon phase.

**Estimated effort**: 30–50 hours (knowledge store, similarity matching,
retrieval integration, privacy/isolation considerations).

---

## Summary: Expected Impact by Priority

| Priority | Items | Cost Reduction | Finding Quality |
|---|---|---|---|
| P0 (all 5) | 5 quick fixes | **40–55% cost reduction** | **+25% quality** |
| P1 (all 4) | 4 medium items | **+15–20% additional** | **+40% quality** |
| P2 (all 4) | 4 larger items | **+10–15% additional** | **+20% quality** |
| **P0+P1 combined** | 9 items | **~55–75% total cost reduction** | **~65% quality gain** |

After P0+P1 implementation:
- Expected scan cost: $30–$60 (down from $100–$160)
- Expected finding coverage on unauthenticated apps: comparable to a
  junior penetration tester
- Expected finding coverage on authenticated apps: improved but still limited
  until P1.4 (session management) is complete

After P1.4 (session management):
- Unlocks 60–80% of real application attack surfaces
- Expected capability: mid-tier automated scanner with LLM-enhanced logic flaw
  detection

---

## Recommended Execution Order

1. **Week 1**: P0.1, P0.2, P0.3 (config + prompt changes — 1 hour total)
2. **Week 1**: P0.4 (fix PoC replay — 3 hours)
3. **Week 2**: P0.5 (context inheritance default — 6 hours)
4. **Week 2**: P1.1 (fix ffuf/nmap truncation — 4 hours)
5. **Week 3**: P1.2 (shared finding registry — 8 hours)
6. **Week 4**: P1.3 (finding anchors — 12 hours)
7. **Month 2**: P1.4 (session management — 20 hours)
8. **Month 2**: P2.1, P2.2, P2.3, P2.4 as time allows
