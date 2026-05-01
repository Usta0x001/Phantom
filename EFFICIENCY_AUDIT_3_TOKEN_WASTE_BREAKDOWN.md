# PHANTOM AI EFFICIENCY AUDIT - TOKEN WASTE BREAKDOWN

**Document 3 of 7:** Detailed Token Usage Analysis

---

## TOKEN CONSUMPTION MAP

### Per-Request Token Distribution (Average)

```
┌─────────────────────────────────────────────────────────────┐
│ PHANTOM LLM REQUEST ANATOMY (36,800 tokens avg)            │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│ ████████████████████ System Prompt: 15,000 tokens (41%)     │
│ │  ├─ Base Instructions: 3,500 tokens                       │
│ │  ├─ Tool Schemas (40 tools): 5,000 tokens ← WASTE        │
│ │  ├─ Reporting Mandate + Examples: 2,500 tokens           │
│ │  ├─ Multi-Agent Guidelines: 1,500 tokens                 │
│ │  ├─ Scan Mode Skills: 1,500 tokens                       │
│ │  └─ Environment Info: 1,000 tokens                       │
│                                                              │
│ ██████████████ Conversation History: 12,800 tokens (35%)    │
│ │  ├─ Recent Messages (last 20): 8,000 tokens              │
│ │  ├─ Compressed Summaries: 3,000 tokens                   │
│ │  └─ Tool Results (last 5): 1,800 tokens                  │
│                                                              │
│ ████ Finding Anchors: 1,600 tokens (4%)                     │
│ │  └─ High-signal findings preserved from compression       │
│                                                              │
│ █████ Hypothesis Ledger: 2,000 tokens (5%)                  │
│ │  └─ Top 10 hypotheses injected every 10 iterations        │
│                                                              │
│ ████ Coverage Tracker: 1,600 tokens (4%)                    │
│ │  └─ Attack surface coverage summary (every 15 iters)      │
│                                                              │
│ ███ Correlation Engine: 1,200 tokens (3%)                   │
│ │  └─ Vulnerability chain suggestions (every 20 iters)      │
│                                                              │
│ ██ Agent Identity: 400 tokens (1%)                          │
│ │  └─ Agent ID + name metadata block                        │
│                                                              │
│ █████ Dynamic Injections: 2,200 tokens (6%)                 │
│ │  ├─ Iteration warnings (approaching limit): 400 tokens    │
│ │  ├─ Phase-gate reminders: 300 tokens                     │
│ │  ├─ No-action streak corrections: 200 tokens             │
│ │  └─ Rate-limit backoff messages: 300 tokens              │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## WASTE ANALYSIS

### Category 1: STATIC OVERHEAD (Re-sent Every Call)

**Total: 20,400 tokens/call (55% of request)**

#### 1.1 System Prompt Bloat
**Current:** 15,000 tokens  
**Optimized:** 6,000 tokens  
**Savings:** 9,000 tokens/call (-60%)

Breakdown:
```
CURRENT (15,000 tokens):
├─ Base Instructions: 3,500 tokens
├─ Tool Schemas (ALL 40 tools): 5,000 tokens ← REMOVE 90%
├─ Reporting Examples (SSRF, SQLi): 2,500 tokens ← COMPRESS 70%
├─ Multi-Agent Rules: 1,500 tokens
├─ Scan Mode Skill: 1,500 tokens
└─ Environment Info: 1,000 tokens

OPTIMIZED (6,000 tokens):
├─ Base Instructions: 2,000 tokens (compressed)
├─ Tool Schemas (5-8 relevant tools): 500 tokens ← DYNAMIC FILTER
├─ Reporting Template (no examples): 800 tokens ← REMOVE BLOAT
├─ Multi-Agent Rules (condensed): 800 tokens
├─ Scan Mode Skill: 1,000 tokens
└─ Environment Info: 900 tokens
```

**Why Tool Schemas Are Waste:**
- System includes schemas for ALL 40 tools on EVERY call
- Agent only uses 5-8 tools per iteration on average
- Sub-agents inherit parent's full toolset (never need `finish_scan`)
- Browser tools included even when target has no web UI

**Measurement Gap:**
- ❌ No per-tool usage tracking
- ❌ No schema size metrics
- ❌ No tool selection heatmap

#### 1.2 Agent Identity Block
**Current:** 400 tokens  
**Optimized:** 50 tokens  
**Savings:** 350 tokens/call (-88%)

```xml
<!-- CURRENT (400 tokens): -->
<agent_identity>
<meta>Internal metadata: do not echo or reference.</meta>
<agent_name>SQL Injection Specialist Agent for /api/login endpoint</agent_name>
<agent_id>agent_abc12345</agent_id>
</agent_identity>

<!-- OPTIMIZED (50 tokens): -->
<meta>Agent: agent_abc12345</meta>
```

**Why This Is Waste:**
- LLM never references agent ID in responses
- Name is verbose and redundant (already in system prompt)
- XML wrapper adds 30% overhead

---

### Category 2: DYNAMIC WASTE (Injected Periodically)

**Total: 6,800 tokens over 100 iterations**

#### 2.1 Hypothesis Ledger Injection
**Frequency:** Every 10 iterations  
**Size:** 2,000 tokens/injection  
**Total (100 iters):** 20,000 tokens  
**Waste:** 40% (8,000 tokens)

```
CURRENT INJECTION (2,000 tokens):
[HYPOTHESIS LEDGER — current scan state]
  H-0001 | TESTING    | sqli           | /api/login::username | payloads=5 ev+=2 ev-=1 iters=12
  H-0002 | OPEN       | xss            | /search?q= | payloads=0 ev+=0 ev-=0 iters=0
  H-0003 | CONFIRMED  | idor           | /user/{id} | payloads=3 ev+=5 ev-=0 iters=8
  ...
  Total: 10 | open=5 testing=3 confirmed=1 rejected=1
[END LEDGER]

PROBLEM:
- Includes CONFIRMED/REJECTED hypotheses (already reported) ← 40% waste
- Re-injects same data every 10 iterations even when unchanged
- No delta-only updates

OPTIMIZED (1,200 tokens):
[HYPOTHESIS UPDATES (only changed since last injection)]
  H-0001: TESTING → CONFIRMED (2 new evidence)
  H-0007: NEW | xss | /profile?bio= (just discovered)
[SUMMARY] 10 total | 3 active | 2 confirmed
```

**Estimated Savings:** 800 tokens/injection × 10 injections = 8,000 tokens/scan

#### 2.2 Coverage Tracker Injection
**Frequency:** Every 15 iterations  
**Size:** 1,600 tokens/injection  
**Total (100 iters):** ~10,000 tokens  
**Waste:** 30% (3,000 tokens)

```
CURRENT (1,600 tokens):
[COVERAGE TRACKER]
Surface: /api/login | Tested: sqli, xss, auth_bypass | Not Tested: csrf, idor, xxe
Surface: /api/register | Tested: sqli | Not Tested: xss, csrf, idor, auth_bypass, xxe
Surface: /api/profile | Tested: idor | Not Tested: sqli, xss, csrf, auth_bypass, xxe
...
[END COVERAGE]

PROBLEM:
- Lists EVERY vulnerability class for EVERY surface
- Repeats "Not Tested" 50+ times ← verbosity waste
- No prioritization signal

OPTIMIZED (1,100 tokens):
[COVERAGE GAPS — prioritized]
High-value untested:
  - /api/admin/* (0% coverage, admin surface)
  - /upload (only tested xss, missing: xxe, path_traversal, rce)
[PROGRESS] 12/45 surfaces tested (27%)
```

**Estimated Savings:** 500 tokens/injection × 7 injections = 3,500 tokens/scan

#### 2.3 Finding Anchors Re-Injection
**Frequency:** Every LLM call (when present)  
**Size:** 1,600 tokens average  
**Total (100 iters):** 160,000 tokens  
**Waste:** 70% (112,000 tokens)

```
CURRENT (anchors re-sent EVERY call after first compression):
<finding_anchors>
Confirmed signals from earlier in this scan — report any NOT yet reported:
- SQL injection confirmed at /api/login username param using payload ' OR '1'='1-- response showed user list dump with 50+ rows
- IDOR vulnerability allows accessing ANY user profile by changing id param from /user/1 to /user/2 confirmed with payload showing other user's email
- XSS reflected at /search?q= using payload <script>alert(1)</script> executed in browser
...
</finding_anchors>

PROBLEM:
- Same anchors re-sent on EVERY call after compression (100+ calls)
- No tracking of which findings already reported
- Anchors never pruned after create_vulnerability_report called

OPTIMIZED (inject ONCE at iteration 75, 85, 95 for final sweep):
<unreported_findings>
Check if these need reporting:
- [anchor_id_abc] SQL injection /api/login (if not reported, call create_vulnerability_report NOW)
</unreported_findings>
```

**Estimated Savings:** 1,200 tokens × 90 unnecessary injections = 108,000 tokens/scan

---

### Category 3: CONVERSATION HISTORY INEFFICIENCY

**Average History Size:** 12,800 tokens  
**Waste Component:** 30% (3,840 tokens)

#### 3.1 Tool Result Verbosity
```
TYPICAL TOOL RESULT (current):
<tool_result>
<tool_name>terminal_execute</tool_name>
<result>
$ nuclei -u https://target.com -t cves/
[INF] Using Nuclei Engine 3.0.0 (latest)
[INF] Using Nuclei Templates 9.5.0 (latest)
[INF] Loading templates...
[INF] Loading 1234 templates
[INF] Starting scan...
[INF] Templates loaded for: 45 CVEs
[WRN] Template cves/2023/CVE-2023-12345.yaml skipped (target not vulnerable)
[WRN] Template cves/2023/CVE-2023-12346.yaml skipped (target not vulnerable)
... (500 lines of noise)
[CRITICAL] CVE-2023-99999 detected on https://target.com/admin
[INF] Scan complete. 1 finding.
</result>
</tool_result>

TOKEN COUNT: ~2,500 tokens
SIGNAL: 1 line (50 tokens)
WASTE: 98%

OPTIMIZED (smart extraction applied):
<tool_result>
<tool_name>terminal_execute</tool_name>
<result>
[PHANTOM_SIGNAL_DETECTED]
  >> SCANNER_CRITICAL: 1 critical finding detected
[/PHANTOM_SIGNAL_DETECTED]
[nuclei findings: 1 results]
[CRITICAL] CVE-2023-99999 detected on https://target.com/admin
[END nuclei scan - 1234 templates tested, 1 match]
</result>
</tool_result>

TOKEN COUNT: ~200 tokens
SIGNAL: Preserved
WASTE: Eliminated
```

**Current Mitigation:**
- Smart extraction implemented for: ffuf, nuclei, sqlmap, nmap
- Reduces 10,000-token outputs to 500-2,000 tokens
- **Gap:** Not applied to generic `terminal_execute` output

**Estimated Savings:** 2,000 tokens × 5 tool results in history = 10,000 tokens

#### 3.2 Duplicate Messages
```
CURRENT (message deduplication happens but inefficient):
# state.py:74-93
def add_message(self, role: str, content: Any, ...):
    # Hash-based dedup (NEW - good)
    content_hash = hashlib.sha256(content.encode()).hexdigest()
    if content_hash in self._message_hashes:
        return
    
    # Window-based dedup (OLD - redundant)
    _window = self.messages[-5:]
    for m in reversed(_window):
        if m.get("role") == role and m.get("content") == content:
            return  # DEAD CODE - already caught by hash check above

WASTE: Double dedup check on every message (5-10ms overhead)
```

**Optimization:** Remove window-based check (already covered by hash).

---

## TOKEN EFFICIENCY OPPORTUNITIES

### Opportunity 1: Anthropic Prompt Caching

**Current State:** NOT ENABLED by default  
**Potential Savings:** 90% reduction on system prompt tokens

```python
# llm/llm.py:529-531
if self._is_anthropic() and self.config.enable_prompt_caching:
    messages = self._add_cache_control(messages)

# config.py — missing:
enable_prompt_caching: bool = True  # Should default to True!
```

**Impact if enabled:**
```
WITHOUT CACHING (current):
├─ Call 1: 15,000 system prompt tokens @ $3/M = $0.045
├─ Call 2: 15,000 tokens @ $3/M = $0.045
├─ Call 100: 15,000 tokens @ $3/M = $0.045
└─ Total: 1,500,000 tokens = $4.50

WITH CACHING (enabled):
├─ Call 1: 15,000 tokens @ $3/M = $0.045 (cache write)
├─ Call 2: 15,000 cached @ $0.30/M = $0.0045 (90% off)
├─ Call 100: 15,000 cached @ $0.30/M = $0.0045
└─ Total: 15,000 + (99 × 15,000 @ 90% off) = $0.49

SAVINGS: $4.01 per 100-iteration scan (89% reduction on system prompt)
```

**Why Not Enabled:**
- Config defaults to `enable_prompt_caching = False`
- Requires Anthropic model (claude-3/3.5)
- Not tested on other providers

### Opportunity 2: Dynamic Tool Schema Filtering

**Current:** ALL tools included in EVERY request  
**Proposed:** Include only relevant tools based on:
- Agent role (sub-agents don't need `finish_scan`)
- Scan phase (recon phase doesn't need `create_vulnerability_report`)
- Hypothesis state (if no web target, exclude browser tools)

```python
# Proposed implementation:
def _get_relevant_tools(agent_state, hypothesis_ledger) -> list[str]:
    tools = ["thinking", "terminal_execute"]  # Always include
    
    # Add based on role
    if agent_state.parent_id is None:
        tools.append("finish_scan")
    else:
        tools.append("agent_finish")
    
    # Add based on scan phase (iteration-based heuristic)
    if agent_state.iteration < 30:
        # Recon phase
        tools.extend(["send_request", "browser_action", "proxy_tools"])
    else:
        # Exploitation phase
        tools.extend(["send_request", "create_vulnerability_report"])
    
    # Add based on hypotheses
    if hypothesis_ledger.has_hypotheses_for("web"):
        tools.extend(["browser_action", "send_request"])
    if hypothesis_ledger.has_hypotheses_for("api"):
        tools.extend(["send_request"])
    
    return tools

# Estimated savings:
# - Full toolset: 40 tools × 125 tokens/schema = 5,000 tokens
# - Filtered toolset: 8 tools × 125 tokens/schema = 1,000 tokens
# - Savings: 4,000 tokens/call × 100 calls = 400,000 tokens/scan
```

### Opportunity 3: Compressed System Prompt Template

**Current:** Verbose natural-language instructions  
**Proposed:** Dense, structured format

```
CURRENT (3,500 tokens):
<reporting_mandate>
CRITICAL — THIS IS YOUR #1 PRIORITY:
- ANY vulnerability you discover MUST be reported via create_vulnerability_report immediately.
- A scan without reported findings is a COMPLETE FAILURE.
- You MUST find and report vulnerabilities — this is the sole measure of success.

VERIFICATION REQUIREMENT - BEFORE REPORTING:
- You must PROVE the vulnerability, not just detect signals
- For EVERY vulnerability, demonstrate with YOUR crafted payload:
  1. Payload that exploits the vulnerability
  2. Response proving exploitation worked (data exfil, auth bypass, command output)
...
</reporting_mandate>

COMPRESSED (1,200 tokens):
<mandate>
FIND+REPORT vulns via create_vulnerability_report. NO report = FAILURE.
PROOF required: working payload + exploitation evidence (not just signals).
Report confidence: LIKELY (proven) | SUSPECTED (partial evidence).
</mandate>
```

**Estimated Savings:** 2,300 tokens × 100 calls = 230,000 tokens/scan

---

## COST ANALYSIS: TOKEN WASTE → DOLLARS WASTE

### Baseline Scan (100 iterations, GPT-4o pricing)

```
┌────────────────────────────────────────────────────┐
│ CURRENT TOKEN ECONOMICS                            │
├────────────────────────────────────────────────────┤
│ Input tokens:  3,680,000 @ $5/M    = $18.40      │
│ Output tokens:   400,000 @ $15/M   = $6.00       │
│ TOTAL COST:                         $24.40       │
└────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────┐
│ WASTE BREAKDOWN (by category)                      │
├────────────────────────────────────────────────────┤
│ Static prompt overhead:   1,500,000 @ $5/M = $7.50 │
│ Redundant tool schemas:     500,000 @ $5/M = $2.50 │
│ Finding anchors flood:      100,000 @ $5/M = $0.50 │
│ Tool result verbosity:      200,000 @ $5/M = $1.00 │
│ Hypothesis re-injection:     80,000 @ $5/M = $0.40 │
│ Coverage re-injection:       50,000 @ $5/M = $0.25 │
│ TOTAL WASTE:                                 $12.15 │
└────────────────────────────────────────────────────┘

WASTE PERCENTAGE: 49.8% of total cost
```

### Optimized Scan (with all mitigations)

```
┌────────────────────────────────────────────────────┐
│ OPTIMIZED TOKEN ECONOMICS                          │
├────────────────────────────────────────────────────┤
│ Input tokens:  1,500,000 @ $5/M    = $7.50       │
│   ├─ System prompt (cached):   14,000 @ $0.30/M  │
│   ├─ Tool schemas (filtered):  100,000 @ $5/M    │
│   ├─ Conversation:           1,200,000 @ $5/M    │
│   └─ Dynamic injections:       186,000 @ $5/M    │
│ Output tokens:   400,000 @ $15/M   = $6.00       │
│ TOTAL COST:                         $13.50       │
└────────────────────────────────────────────────────┘

SAVINGS: $10.90 per scan (45% reduction)
```

---

**Next Document:** EFFICIENCY_AUDIT_4_MEMORY_AND_COMPRESSION.md
