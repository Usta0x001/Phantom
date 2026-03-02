# PHANTOM Deep System Audit — v0.9.22

**Date:** March 2, 2026  
**Scan Reference:** `host-docker-internal-3000_e109`  
**Scan Result:** 3 vulnerabilities found (SQLi, IDOR, LFI) — 29 tool calls in ~20 minutes  
**Target:** 50+ vulnerabilities in OWASP Juice Shop  

---

## EXECUTIVE SUMMARY

The agent is **choosing to call `finish_scan` after just 29 iterations** out of an allowed 150. This is not a crash, not a context limit, not an iteration cap — the LLM simply *decides* it's done. The root causes are:

1. **The `finish_scan` minimum-work gate is absurdly permissive** (5 iterations, 3 tool calls)
2. **No subagents are being spawned** — the root agent tries to do everything alone
3. **Context is ballooning at ~58K tokens/request**, leaving no room for continued exploration
4. **Vuln-class rotation tracker never receives findings** — `record_finding()` is never called
5. **No mandatory minimum vuln-class coverage** before `finish_scan` is allowed

Getting to 50+ vulns requires fixes across **8 critical areas**.

---

## DETAILED BUG LIST

### BUG #1: `finish_scan` Minimum-Work Gate FAR Too Permissive
**Severity:** CRITICAL  
**File:** `phantom/tools/finish/finish_actions.py` lines 656-657  
**What's wrong:** `MIN_ITERATIONS = 5` and `MIN_TOOL_CALLS = 3`. The agent passes this gate trivially at iteration ~6. With 150 iterations allowed, the gate should enforce at least 30-40% utilization.  
**Evidence:** In the e109 scan, the agent called `finish_scan` at iteration ~29 with no resistance.

**Fix:**
```python
# Replace:
MIN_ITERATIONS = 5
MIN_TOOL_CALLS = 3

# With iteration-aware gating:
# Use at least 25% of the profile budget before allowing finish
if agent_state is not None:
    max_iter = getattr(agent_state, "max_iterations", 150)
    MIN_ITERATIONS = max(15, int(max_iter * 0.25))  # At least 25% of budget
    MIN_TOOL_CALLS = max(10, int(max_iter * 0.15))  # At least 15% tool activity
```

Additionally, add a **vuln-class diversity gate** — require at least N distinct vuln classes tested:
```python
# After existing iteration/tool checks, add:
if hasattr(agent_state, "findings_ledger"):
    ledger = agent_state.findings_ledger
    # Count distinct vuln class categories tested
    vuln_categories_tested = set()
    vuln_keywords = {
        "sqli": "sqli", "sql": "sqli", "xss": "xss", "idor": "idor",
        "auth": "auth", "jwt": "auth", "path": "lfi", "lfi": "lfi",
        "ssrf": "ssrf", "upload": "upload", "csrf": "csrf", "xxe": "xxe",
        "info": "info", "business": "business",
    }
    for entry in ledger:
        lower = entry.lower()
        for keyword, category in vuln_keywords.items():
            if keyword in lower:
                vuln_categories_tested.add(category)
    MIN_CLASSES = 4  # Must test at least 4 different vuln classes
    if len(vuln_categories_tested) < MIN_CLASSES:
        return {
            "success": False,
            "message": f"Cannot finish: only {len(vuln_categories_tested)}/{MIN_CLASSES} "
                       f"vulnerability classes tested. Test more diverse attack vectors.",
            "blocked_by": "diversity_gate",
            "classes_tested": list(vuln_categories_tested),
        }
```

---

### BUG #2: `VulnClassTracker.record_finding()` Is Never Called
**Severity:** CRITICAL  
**File:** `phantom/core/vuln_class_rotation.py` line 129  
**What's wrong:** The `record_finding()` method exists on `VulnClassTracker` but is **never invoked** from anywhere in the codebase. This means the tracker's `class_findings` dict is always empty, so:
- The tracker can't correlate findings to classes
- Progress summaries always show "0 findings" per class
- The tracker can't make intelligent decisions about when to rotate

**Evidence:** `grep -r "vuln_rotation.record_finding" phantom/` returns 0 results.

**Fix:** Wire `record_finding()` into `create_vulnerability_report` and the `_auto_record_findings` path:

In `phantom/tools/reporting/reporting_actions.py`, after a successful report creation:
```python
# After report_id = tracer.add_vulnerability_report(...)
# Wire vuln_rotation tracker
try:
    from phantom.tools.agents_graph import agents_graph_actions
    root_id = agents_graph_actions._root_agent_id
    if root_id:
        root_agent = agents_graph_actions._agent_instances.get(root_id)
        if root_agent and hasattr(root_agent, "_vuln_rotation") and root_agent._vuln_rotation:
            # Map vulnerability title to class ID
            vuln_class = _guess_vuln_class_for_rotation(title, description)
            root_agent._vuln_rotation.record_finding(vuln_class)
except Exception:
    pass
```

---

### BUG #3: No Subagents Are Being Spawned
**Severity:** CRITICAL  
**File:** Architectural issue — system prompt + LLM behavior  
**What's wrong:** In the e109 scan, **zero subagents were created**. The root agent did all 29 tool calls itself. The system prompt instructs the agent to "create targeted sub-agents" but the LLM simply ignores this because:
1. The system prompt is already ~15-20K tokens, plus skill files
2. By the time the agent has done recon (katana, nuclei, ffuf), the context is already massive
3. The LLM takes the path of least tokens: test a few things → report → finish

**Impact:** Without subagents, the agent can only test one vuln class at a time sequentially. With subagents, it could test 4-6 classes in parallel.

**Fix:** Force subagent creation after the recon phase. In the `agent_loop` after the recon phase transition (around line 207 in `base_agent.py`):

```python
# After RECON → EXPLOIT phase transition:
if current == ScanPhase.RECON and (pct >= 0.25 or findings_count >= 3):
    self.state.set_phase(ScanPhase.EXPLOIT)
    # AUTO-SPAWN: If root agent and no subagents exist, inject a directive
    if self.state.parent_id is None:
        self.state.add_message("user",
            "⚠️ MANDATORY: You MUST now create specialized subagents for each "
            "vulnerability class. Create at least 3 subagents:\n"
            "1. 'SQLi & Auth Agent' (skills: sql_injection, authentication_jwt)\n"
            "2. 'XSS & CSRF Agent' (skills: xss, csrf)\n"
            "3. 'Access Control Agent' (skills: idor, path_traversal, ssrf)\n"
            "Share the endpoint list and discovered API routes with each subagent."
        )
```

---

### BUG #4: Context Bloat — 58K Tokens Average Per Request
**Severity:** HIGH  
**File:** `phantom/llm/memory_compressor.py`, `phantom/llm/llm.py`  
**What's wrong:** 1.7M input tokens across 29 requests = ~58K average. The context grows rapidly because:
1. Tool responses (nuclei, katana, ffuf) return massive outputs (up to 3000 chars of raw nmap output, up to 80 katana URLs, etc.)
2. Memory compression only fires when total tokens exceed `max_total_tokens * 0.9` = 72K
3. By the time compression fires, the LLM has already seen 58K+ of context for several requests
4. The system prompt itself is ~15-20K tokens (Jinja template + skills + tool schema)

**Key metric:** DeepSeek V3 has 163K context window, compression threshold = `163840 * 0.75 = 122,880`. But at 58K+ per request by request ~15, the context is nearing 100K. By request 29 the input for that single request was likely 120K+ tokens — approaching the compression threshold.

**Fix:**
1. **Reduce tool output caps aggressively:**
   - `nuclei_tool.py`: Change `_MAX_FINDINGS = 30` → `_MAX_FINDINGS = 15`
   - `katana_tool.py`: Change `_MAX_URLS = 80` → `_MAX_URLS = 40`  
   - `nuclei_tool.py`: Reduce `raw_output_tail` from 2000 → 500 chars

2. **Compress more aggressively — trigger at 60% not 90%:**
   In `memory_compressor.py`:
   ```python
   # Replace:
   if total_tokens <= self.max_total_tokens * 0.9:
   # With:
   if total_tokens <= self.max_total_tokens * 0.60:
   ```

3. **Reduce system prompt size** — the system prompt is enormous. Move the `<multi_agent_system>` section and the `<execution_guidelines>` detailed instructions into a loadable skill file instead of the base prompt.

---

### BUG #5: `katana_crawl` with `headless=True` FAILED During the Scan
**Severity:** HIGH  
**File:** `phantom/tools/security/katana_tool.py` and `phantom/tools/security/security_tools_schema.xml`  
**What's wrong:** In the e109 audit log, entry [4] shows `katana_crawl` with `headless=true` FAILED. The `headless` parameter is present in both the Python function signature and the XML schema — so this failure is likely a **sandbox/Docker issue** (headless Chrome not available, or XML schema parse issue that rejected the parameter during earlier scans).

Since Juice Shop is an Angular SPA, headless crawling is **essential** for discovering dynamic routes. Without it, katana found only 3 URLs.

**Impact:** The agent found only 3 URLs from non-headless katana, severely limiting attack surface discovery.

**Fix:** 
1. Ensure the sandbox Docker image has Chrome/Chromium installed for headless crawling
2. Add a fallback: if headless katana fails, automatically run `browser_action` to navigate the SPA and extract API calls
3. In `katana_tool.py`, catch headless failures gracefully:
```python
if headless and not result.get("success"):
    # Retry without headless as fallback
    cmd_parts_retry = [p for p in cmd_parts if p not in ("-headless", "-no-sandbox")]
    fallback_result = terminal_execute(command=" ".join(cmd_parts_retry), timeout=float(max_duration) + 30)
    # ... parse fallback result
```

---

### BUG #6: Output Token Budget Too Small (~160 tokens/response)
**Severity:** HIGH  
**File:** `phantom/llm/provider_registry.py` line 120  
**What's wrong:** The provider registry for `openrouter/deepseek/deepseek-chat-v3-0324` sets `max_tokens=16_384`, but the agent only averages 160 output tokens per response. With 4643 output tokens across 29 requests, the LLM is generating extremely terse responses — just enough for a single tool call XML block.

This isn't a bug per se — it's a symptom. The LLM generates just the minimum to make a tool call because the tool call XML format is compact. But it means:
- The LLM doesn't think deeply before acting
- It doesn't plan multi-step strategies
- It doesn't analyze tool results thoroughly

**Fix:** The root issue is that the system prompt says "EVERY message you output MUST be a single tool call. Do not send plain text-only responses." This is too restrictive. The agent should be allowed to think-then-act:

In the system prompt, relax the rule:
```
# Replace:
"While active in the agent loop, EVERY message you output MUST be a single tool call"
# With:
"Each message should contain exactly one tool call. Before the tool call,
you may include a brief analysis (2-3 sentences) of what you learned from
the previous tool result and your reasoning for the next action."
```

---

### BUG #7: `enhanced_state.json` Is Empty / `to_report_data()` Returns Empty Dict
**Severity:** HIGH  
**File:** `phantom/agents/enhanced_state.py`  
**What's wrong:** The enhanced_state.json from the e109 scan is an empty JSON object `{}`. The `to_report_data()` method is being called but returning nothing. This means:
1. No endpoint tracking data survives
2. No host data survives
3. No tool usage stats survive
4. The vulnerability tracking in EnhancedAgentState isn't populating

**Root cause:** Need to check `to_report_data()` implementation — the `endpoints`, `hosts`, `tools_used` dicts are likely empty because the agent's tool calls don't populate them (the auto-tracking hooks aren't firing).

**Fix:** Read and fix `to_report_data()` to at least include `findings_ledger` and `iteration` data even when other fields are empty.

---

### BUG #8: Checkpoint Missing `max_iterations` Field
**Severity:** MEDIUM  
**File:** `phantom/agents/enhanced_state.py` (checkpoint serialization)  
**What's wrong:** Checkpoint file shows `max_iterations: None`. This breaks resume functionality because on resume, the `remaining = profile.max_iterations - resumed_state.iteration` calculation will fail or produce wrong results when max_iterations is None.

**Fix:** Ensure `max_iterations` is always serialized in the checkpoint:
```python
def save_checkpoint(self, run_dir):
    data = {
        "iteration": self.iteration,
        "max_iterations": self.max_iterations,  # Ensure not None
        ...
    }
```

---

### BUG #9: No Minimum Security Scanner Enforcement
**Severity:** HIGH  
**File:** `phantom/tools/finish/finish_actions.py`  
**What's wrong:** The `finish_scan` gate checks iteration count and tool count, but doesn't verify that **any security scanning tools** were actually used. The agent could theoretically call `think` 5 times and `finish_scan`.

**Fix:** Add security scanner check:
```python
REQUIRED_TOOL_TYPES = {"nuclei_scan", "sqlmap_test", "ffuf_directory_scan", "send_request", "katana_crawl"}
tools_used = set()
for action in getattr(agent_state, "actions_taken", []):
    tool = action.get("action", {}).get("tool_name", "") or action.get("action", {}).get("name", "")
    tools_used.add(tool)

scanner_tools_used = tools_used & REQUIRED_TOOL_TYPES
if len(scanner_tools_used) < 3:
    return {
        "success": False,
        "message": f"Cannot finish: only used {len(scanner_tools_used)} security tools "
                   f"({scanner_tools_used}). Must use at least 3 different scanner types.",
    }
```

---

### BUG #10: Vuln-Class Rotation Tick Doesn't Correlate with Actual Testing
**Severity:** MEDIUM  
**File:** `phantom/core/vuln_class_rotation.py`  
**What's wrong:** The `tick()` method increments `current_class_iters` every iteration regardless of what the agent is actually doing. If the agent spends 15 iterations on recon (katana, ffuf, nmap), the tracker thinks those were spent on "SQLi" (class index 0), and fires a rotation to XSS — even though the agent hasn't tested SQLi yet.

**Fix:** Don't count recon-phase iterations against the vuln class budget:
```python
def tick(self, is_recon: bool = False) -> str | None:
    self.total_iterations += 1
    if is_recon:
        return None  # Don't count recon iterations against class budget
    # ... rest of existing logic
```

In `base_agent.py`, pass the phase status:
```python
is_recon = getattr(self.state, "current_phase", None) == ScanPhase.RECON
rotation_msg = self._vuln_rotation.tick(is_recon=is_recon)
```

---

### BUG #11: `nuclei_scan` Timeout May Be Too Short For Full Template Suite
**Severity:** MEDIUM  
**File:** `phantom/tools/security/nuclei_tool.py` line 89  
**What's wrong:** `timeout=600.0` (10 minutes) for nuclei with 9000+ templates. For Juice Shop, nuclei should find ~10-15 findings, but if the scan times out, results are truncated.

**Evidence:** In the e109 scan, `nuclei_scan` ran once with `severity=all`. We can't tell from the audit log whether it completed successfully or timed out.

**Fix:** Increase default timeout to 900 seconds (15 minutes) for full template scans. Also log the number of findings found on completion.

---

### BUG #12: `nmap_scan` Was Never Run
**Severity:** MEDIUM  
**File:** System prompt / agent behavior  
**What's wrong:** Despite `nmap_scan` being listed as a mandatory first step and a priority tool, the agent never ran it in the e109 scan. Port/service discovery is critical for identifying non-HTTP services.

**Fix:** This is a prompt/LLM behavior issue. The system prompt already instructs the agent to run nmap, but the LLM skips it. Making `nmap_scan` part of an automatic recon pipeline (run before the agent loop starts) would guarantee it:

```python
# In phantom_agent.py execute_scan(), before calling agent_loop():
# Auto-run mandatory recon tools
auto_recon_results = await self._run_mandatory_recon(targets)
task_description += f"\n\nAUTO-RECON RESULTS (already completed):\n{auto_recon_results}"
```

---

### BUG #13: System Prompt Is Too Long (~15-20K Tokens)
**Severity:** MEDIUM  
**File:** `phantom/agents/PhantomAgent/system_prompt.jinja`  
**What's wrong:** The system prompt is 459 lines. When combined with the Juice Shop skill (130 lines), the security tools schema (392 lines), the quick scan mode skill, and other injected content, the total system prompt easily exceeds 15K tokens. This leaves less room for actual scan data in the context window.

**Fix:**
1. Move the `<multi_agent_system>` section (lines 200-459) into a separate skill file
2. Move the `<execution_guidelines>` section into a skill file
3. Keep the core system prompt under 100 lines
4. Load guidelines as skills only when needed

---

### BUG #14: Coverage-Based Stopping Advisory Is Too Generous
**Severity:** MEDIUM  
**File:** `phantom/agents/base_agent.py` lines 270-290  
**What's wrong:** The coverage advisory says "Coverage is HIGH. If no new attack vectors remain, consider finishing with finish_scan" when coverage reaches 80%. This **encourages** the agent to stop early. For Juice Shop with 100+ vulns, finishing at 80% endpoint coverage with only 3 vulns is a terrible outcome.

**Fix:** Change the advisory to encourage continued testing:
```python
if coverage_pct >= 80:
    self.state.add_advisory(
        f"📊 COVERAGE UPDATE: {tested}/{discovered} endpoints tested "
        f"({coverage_pct:.0f}% coverage), {vuln_count} vulnerabilities found.\n"
        f"{'GOOD' if vuln_count >= 20 else 'LOW'} vuln count. "
        f"{'Consider wrapping up.' if vuln_count >= 30 else 'Keep testing — switch to untested vuln classes.'}",
        ttl=3,
    )
```

---

### BUG #15: Stagnation Detector Uses Wrong Finding Count
**Severity:** MEDIUM  
**File:** `phantom/agents/base_agent.py` lines 333-340  
**What's wrong:** The stagnation detector reads `findings_ledger` count and `vulnerabilities` dict count, taking the max. But `vulnerabilities` dict on EnhancedAgentState is always empty (BUG #7), so it only uses `findings_ledger`. The `findings_ledger` includes non-vuln entries (recon findings, dead-ends), so the count grows even when no new vulns are found, making the stagnation detector ineffective.

**Fix:** Count only vulnerability-tagged ledger entries:
```python
vuln_count = sum(1 for f in getattr(self.state, "findings_ledger", [])
                 if "[vuln" in f.lower() or "vulnerability" in f.lower())
```

---

### BUG #16: `sqlmap_test` Was Never Run
**Severity:** HIGH  
**File:** Agent behavior / prompt issue  
**What's wrong:** Despite being a priority tool and the Juice Shop skill specifically mentioning SQLi endpoints, `sqlmap_test` was never called. The agent used `send_request` to manually test SQLi instead. Manual SQLi testing finds 1-2 vulns; sqlmap would find 5+.

**Fix:** In the system prompt, add stronger enforcement:
```
MANDATORY: After discovering endpoints, you MUST run sqlmap_test on at least 3 different
endpoints before finishing. sqlmap is 100x more thorough than manual SQL injection testing.
```

Also add sqlmap to the auto-recon pipeline (see BUG #12).

---

### BUG #17: `jwt_tool` Was Never Run
**Severity:** MEDIUM  
**File:** Agent behavior  
**What's wrong:** Juice Shop uses JWT auth with known vulnerabilities (none algorithm, weak secret). The agent logged in and got a JWT but never ran `jwt_tool` to test it. The Juice Shop skill mentions JWT testing multiple times.

---

### BUG #18: No XSS Vulnerability Was Reported
**Severity:** HIGH  
**File:** Agent behavior  
**What's wrong:** The agent tested XSS at entries [13-18] — it sent `<script>alert(1)</script>` to multiple endpoints. But it never called `create_vulnerability_report` for any XSS finding. The Juice Shop is **known** to have multiple XSS vulnerabilities. The agent likely saw the XSS reflected but moved on to IDOR testing without reporting it.

**Fix:** The issue is that the LLM doesn't validate and report each finding before moving on. This is a prompt compliance issue. The `finish_scan` diversity gate (BUG #1 fix) would catch this.

---

### BUG #19: No `wapiti` or `arjun` Tool Available
**Severity:** LOW  
**File:** `phantom/tools/security/security_tools_schema.xml`  
**What's wrong:** The system prompt mentions `wapiti` and `arjun` as preferred tools, but they are not in the tools schema XML. The agent can only use tools defined in the schema.

**Fix:** Either add wapiti/arjun tool wrappers or remove mentions from the system prompt to avoid confusion.

---

### BUG #20: `LLMConfig` Defaults `scan_mode` to `"deep"` for Unknown Modes
**Severity:** LOW  
**File:** `phantom/llm/config.py` line 18  
**What's wrong:** `self.scan_mode = scan_mode if scan_mode in ["quick", "standard", "deep"] else "deep"`. This means typos like "quik" silently default to "deep" mode with no warning.

**Fix:** Log a warning when falling back to default mode.

---

## ROOT CAUSE ANALYSIS: WHY THE AGENT STOPS AT 29 ITERATIONS

### The Chain of Events:

1. **Iterations 1-6 (Recon):** nuclei, katana, katana-headless(FAIL), ffuf×2, api-docs → Context already ~100K tokens
2. **Iterations 7-12 (SQLi testing):** send_request×5 to login, users API, then `create_vulnerability_report` for SQLi → First big context spike
3. **Iterations 13-18 (XSS testing):** send_request×6 testing XSS on feedbacks, search, track-order, main.js → Context grows more, NO vuln reported
4. **Iterations 19-23 (IDOR testing):** send_request for user IDs, then `create_vulnerability_report` for IDOR 
5. **Iterations 24-27 (LFI testing):** send_request to /ftp paths, `create_vulnerability_report` for LFI
6. **Iterations 28-29 (SSRF test + finish):** One SSRF test, then `finish_scan`

### Why It Stopped:

1. **The LLM "feels done"** — it found 3 vulns, tested 4-5 vuln classes, and the system prompt says "Quality over quantity: one verified exploit is worth more than 50 unverified detections" and "Use finish_scan when: (a) coverage is satisfactory, (b) findings are verified, (c) remaining attack surface is low-value"
2. **Context is enormous** (~58K avg, likely 120K+ at request 29). The LLM may be hitting soft context degradation where it loses track of instructions deep in the prompt
3. **No subagents** — working solo means the agent bears the full context burden
4. **The `finish_scan` gate doesn't block it** — 5 iterations + 3 tool calls is trivially satisfied
5. **No "you're only 19% through your budget" reminders** — the approaching-max warning only fires at 85% (iteration 128). At iteration 29, there's no budget utilization feedback
6. **The system prompt contradicts itself** — it says "WORK RELENTLESSLY" but also "If coverage is HIGH... consider finishing"

---

## RECOMMENDATIONS FOR REACHING 50+ VULNERABILITIES

### Priority 1 — Critical Fixes (implement ALL):

| # | Fix | Expected Impact |
|---|-----|-----------------|
| 1 | **Raise `finish_scan` minimum gate to 25% of budget** (37+ iterations for quick) | Prevents premature termination |
| 2 | **Add vuln-class diversity gate** — require 4+ classes tested before finish | Forces broader testing |
| 3 | **Add security scanner gate** — require 3+ different scanner tools used | Forces tool diversity |
| 4 | **Wire `VulnClassTracker.record_finding()` into report creation** | Enables intelligent rotation |
| 5 | **Add periodic budget utilization advisory** every 10 iterations | Keeps agent aware of remaining budget |

### Priority 2 — High-Impact Fixes:

| # | Fix | Expected Impact |
|---|-----|-----------------|
| 6 | **Force subagent creation** after recon phase | 3-4x parallelism = more vulns |
| 7 | **Reduce tool output caps by 50%** | Slower context growth = more iterations |
| 8 | **Trigger memory compression at 60% instead of 90%** | More headroom |
| 9 | **Auto-run mandatory recon** before agent loop (nmap, nuclei, katana) | Guarantees baseline coverage |
| 10 | **Fix headless katana** or add browser fallback for SPA discovery | More endpoints found |

### Priority 3 — Medium-Impact Fixes:

| # | Fix | Expected Impact |
|---|-----|-----------------|
| 11 | **Reduce system prompt to <100 lines** — move detailed guidelines to skills | 5-10K token savings |
| 12 | **Change coverage advisory** to encourage continued testing below 30 vulns | Prevents premature finish |
| 13 | **Fix enhanced_state.json export** to include actual scan data | Better scan analytics |
| 14 | **Fix checkpoint max_iterations serialization** | Enables reliable resume |

### Expected Outcome After Fixes:

With these fixes applied:
- Agent would run **60-80 iterations minimum** (vs. 29 now)
- Subagents would test **6-8 vuln classes in parallel** (vs. 4 sequential now)
- Memory compression at 60% threshold = **~40% more iterations before context fills**
- Vuln-class diversity gate ensures **minimum 4 different vuln types tested**
- Juice Shop specific: SQLi (5+), XSS (5+), IDOR (5+), Auth/JWT (3+), LFI (3+), Info Disclosure (5+), Business Logic (3+), SSRF (2+), Upload (2+), Misc (5+) = **~38-50 vulns realistic**

---

## APPENDIX: FILE-BY-FILE FINDINGS

| File | Issues Found |
|------|-------------|
| `phantom/tools/finish/finish_actions.py` | #1 (CRITICAL), #9 (HIGH) |
| `phantom/core/vuln_class_rotation.py` | #2 (CRITICAL), #10 (MEDIUM) |
| `phantom/agents/base_agent.py` | #3 (CRITICAL), #14 (MEDIUM), #15 (MEDIUM) |
| `phantom/llm/memory_compressor.py` | #4 (HIGH) |
| `phantom/tools/security/katana_tool.py` | #5 (HIGH) |
| `phantom/llm/provider_registry.py` | #6 (HIGH) |
| `phantom/agents/enhanced_state.py` | #7 (HIGH), #8 (MEDIUM) |
| `phantom/tools/security/nuclei_tool.py` | #11 (MEDIUM) |
| `phantom/agents/PhantomAgent/system_prompt.jinja` | #13 (MEDIUM) |
| `phantom/agents/PhantomAgent/phantom_agent.py` | #12 (MEDIUM) |
| `phantom/tools/security/security_tools_schema.xml` | #19 (LOW) |
| `phantom/llm/config.py` | #20 (LOW) |
| Agent behavior (not a code bug) | #16 (HIGH), #17 (MEDIUM), #18 (HIGH) |
