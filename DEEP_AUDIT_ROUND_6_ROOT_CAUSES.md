# Phantom Deep Audit — Round 6: Root Cause Analysis

**Date**: 2026-03-03  
**Target**: OWASP Juice Shop via `http://host.docker.internal:3000`  
**Scan Mode**: `quick` (150 iterations)  
**Result**: ~10 vulnerabilities found. Juice Shop has 100+.  
**Observed Symptoms**: Scanners ran iterations 1-5 only. Agent fell back to `send_request` for 60% of actions. `finish_scan` called 7 times.

---

## EXECUTIVE SUMMARY

The 50-vulnerability gap is caused by a combination of **code bugs (≈35%)** and **architectural limitations (≈65%)**. The code bugs are fixable. The architectural limitations require design changes.

**Breakdown of the gap:**
- **Code bugs causing missed vulns**: ~35% (17-18 vulns)  
  - Truncation destroying scanner results: 8-10 vulns
  - `finish_scan` gate thrashing wasting iterations: 3-5 vulns
  - Loop detector blocking valid repeated calls: 2-3 vulns
  - Quick mode missing tools: 2-3 vulns
- **Architectural limitations**: ~65% (32-33 vulns)  
  - LLM can't reliably chain multi-step exploits (business logic, race conditions)
  - Single-query nuclei finds ~10-15 CVEs; Juice Shop's remaining 85 vulns need manual interactive testing
  - Context window exhaustion forces compression, losing attack state
  - LLM ignores instructions ("mandatory" scanner orders bypassed ~40% of the time)

---

## BUG LIST

### BUG #1 — CRITICAL: `send_request` body truncation at 3K chars destroys vuln evidence

**File**: [proxy_manager.py](phantom/phantom/tools/proxy/proxy_manager.py#L443-L445)  
**Lines**: 443-445

```python
body_limit = 3000 if "text/html" in content_type else 5000
if len(body_content) > body_limit:
    body_content = body_content[:body_limit] + "\n... [truncated]"
```

**Severity**: CRITICAL  
**Impact**: 8-10 missed vulnerabilities

**Why this causes missed vulns**: Juice Shop's HTML pages (login, search, product detail) are 10-40KB. The body is truncated to 3KB, cutting off:
- Reflected XSS payloads that appear in the lower half of the HTML
- SQL error messages that appear inside nested `<div>` tags
- Sensitive data (user details, credit cards) returned in APIs with large response bodies
- JavaScript source that leaks API routes and secrets

When the LLM sees `... [truncated]`, it cannot determine whether its payload was reflected. It assumes the test was negative and moves on.

**Fix**: 
- Increase HTML body limit to 8KB for security-testing responses
- Better: Return a structured "interesting sections" extract: search for payload reflection, error keywords, and sensitive data patterns in the full body, and present only those excerpts to the LLM

---

### BUG #2 — CRITICAL: Tool result truncation at 12K chars drops multi-finding scanner output

**File**: [executor.py](phantom/phantom/tools/executor.py#L393-L417)  
**Lines**: 393-417

```python
_trunc_limit = 12000 if tool_name in _scanner_tools else 6000
_start_chars = _trunc_limit // 2
_end_chars = _trunc_limit // 2
if len(final_result_str) > _trunc_limit:
    start_part = final_result_str[:_start_chars]
    end_part = final_result_str[-_end_chars:]
    ...
    final_result_str = (
        start_part
        + f"\n\n... [{omitted} characters truncated] ...\n\n"
        + end_part
    )
```

**Severity**: CRITICAL  
**Impact**: 5-8 missed vulnerabilities

**Why this causes missed vulns**: Nuclei output against Juice Shop can be 30-60KB (it finds 15-25 template matches). At the 12K truncation limit, the middle ~50% of findings are dropped. The LLM sees the first 6K and last 6K — it never sees findings #8-#17 (roughly). Those are the MEDIUM severity findings (misconfigs, info disclosures, header issues) that would count as valid vulnerabilities.

The nuclei tool itself caps at 40 findings and sorts by severity, so by the time the 40-finding JSON reaches `_format_tool_result`, it's already well-structured — but `_format_tool_result` truncates the serialized JSON string at a character boundary, potentially breaking JSON structure and making findings unparseable.

**Fix**:
- Increase scanner truncation limit to 24K
- Better: Truncate at the *structured data level* (cut findings list, not character string). Return a summary object with top findings + "and N more findings omitted"

---

### BUG #3 — HIGH: `finish_scan` minimum-work gate creates a 7-rejection / wasted-iteration loop

**File**: [finish_actions.py](phantom/phantom/tools/finish/finish_actions.py#L660-L690)  
**Lines**: 660-690

```python
MIN_ITERATIONS = max(30, int(max_iter * 0.60))  # = max(30, 90) = 90 for quick mode
MIN_TOOL_CALLS = max(20, int(max_iter * 0.30))  # = max(20, 45) = 45
```

**Severity**: HIGH  
**Impact**: 3-5 missed vulnerabilities (wasted iterations)

**Why this causes missed vulns**: The 60% gate means the agent CANNOT finish before iteration 90 (out of 150). But the system also says "finish at 75% budget" via phase transitions (line 252 of base_agent.py: `elif current == ScanPhase.EXPLOIT and pct >= 0.75` triggers REPORT phase). 

The phase transition at iteration 112 (`0.75 * 150`) tells the agent "Call finish_scan NOW". But the diversity gate (AUTO-002) then rejects it because not enough vuln classes were tested. The agent keeps trying `finish_scan`, getting rejected each time, wasting 1-2 iterations per attempt. With 7 rejections, that's 7-14 wasted iterations — 5-9% of the total budget.

Additionally, the `is_approaching_max_iterations` threshold at 93% (line 209, state.py) sends an URGENT warning at iteration 139, and a CRITICAL warning at iteration 147. These warnings create pressure to finish even if the diversity gate keeps blocking.

**This is a design contradiction**: Three subsystems (phase transitions, max-iteration warnings, and finish gates) have **conflicting instructions** about when to finish. The LLM gets confused and thrashes.

**Fix**:
- Align the finish gate with the phase transition: When REPORT phase is triggered, lower the finish gate requirements (e.g., reduce MIN_VULN_CLASSES from 6 to 4, reduce MIN_ITERATIONS to 50%)
- Or: Don't inject "call finish_scan NOW" in the REPORT phase message — instead say "prepare final report data" and only allow finish_scan when gates pass

---

### BUG #4 — HIGH: Quick mode `QUICK_MODE_TOOLS` is missing critical tools

**File**: [registry.py](phantom/phantom/tools/registry.py#L22-L38)  
**Lines**: 22-38

```python
QUICK_MODE_TOOLS: set[str] = {
    "think", "finish_scan", "create_agent", "agent_finish", "send_message_to_agent",
    "record_finding", "get_findings_ledger",
    "send_request", "repeat_request", "list_requests", "list_sitemap",
    "nuclei_scan", "sqlmap_test", "ffuf_directory_scan",
    "katana_crawl", "httpx_probe", "nmap_scan",
    "python_action", "terminal_execute", "browser_action",
    "create_vulnerability_report",
    "web_search",
}
```

**Severity**: HIGH  
**Impact**: 2-3 missed vulnerabilities

**Why this causes missed vulns**: Missing tools in quick mode:
1. **`nuclei_scan_cves`** — Runs CVE-specific templates. The base `nuclei_scan` uses general templates; CVE-specific ones find different things (e.g., CVE-2021-xxxx in Express/Node)
2. **`nuclei_scan_misconfigs`** — Finds security misconfigurations (CORS, headers, directory listing). These are easy wins that count as vulns
3. **`nmap_vuln_scan`** — Nmap's vuln scripts find different things than nuclei
4. **`sqlmap_forms`** — Auto-discovers and tests forms. The agent must manually find forms without this
5. **`view_request`** — Can't inspect captured proxy traffic detail in quick mode
6. **`scope_rules`** — Can't set proxy scope

Without these tools in the system prompt, the LLM doesn't even know they exist during quick scans.

**Fix**: Add `nuclei_scan_cves`, `nuclei_scan_misconfigs`, `nmap_vuln_scan`, `sqlmap_forms`, `view_request` to `QUICK_MODE_TOOLS`.

---

### BUG #5 — HIGH: Loop detector's `DEFAULT_REPEAT_THRESHOLD = 3` blocks valid repeated scanner calls

**File**: [loop_detector.py](phantom/phantom/core/loop_detector.py#L27)  
**Line**: 27

```python
DEFAULT_REPEAT_THRESHOLD = 3    # Block after N identical calls
```

**Severity**: HIGH  
**Impact**: 2-3 missed vulnerabilities

**Why this causes missed vulns**: The agent needs to call `sqlmap_test` on multiple endpoints with the same structure:
- `sqlmap_test(url="http://target/rest/user/login", method="POST", data="email=test&password=test")`
- `sqlmap_test(url="http://target/rest/products/search?q=test")`
- `sqlmap_test(url="http://target/rest/track-order/1")`

The fingerprint function (line 139) hashes `tool_name + sorted_args`. If the agent calls `sqlmap_test` 3 times with different URLs, the **fingerprint is different** (different args) and won't trigger. BUT if it calls `nuclei_scan` with the same target URL 3 times (e.g., with different severity filters that happen to get truncated to 200 chars), the fingerprint matches and the loop detector blocks it.

The real bug is in `_tool_fingerprint`:
```python
sorted_args = sorted(
    (k, str(v)[:200]) for k, v in args.items()
    if k not in ("timeout", "timestamp")
)
```
The 200-char truncation on arg values can cause different calls to hash identically.

Additionally, `DEFAULT_STAGNATION_WINDOW = 15` means if the agent doesn't find new vulns in 15 iterations (very common during initial recon), it gets a stagnation warning that nudges it toward `finish_scan`.

**Fix**: 
- Increase `DEFAULT_REPEAT_THRESHOLD` to 5-6 for scanner tools
- Increase `DEFAULT_STAGNATION_WINDOW` to 25
- Don't truncate arg values at 200 chars for fingerprinting — use the full value hash

---

### BUG #6 — HIGH: Compression fires too aggressively despite 120K threshold

**File**: [memory_compressor.py](phantom/phantom/llm/memory_compressor.py#L293-L302)  
**Lines**: 293-302

```python
if total_tokens <= self.max_total_tokens * 0.80:
    # ...
    return messages
```

**Severity**: HIGH  
**Impact**: 2-4 missed vulnerabilities (loss of attack context)

**Why this causes missed vulns**: With `max_total_tokens = 120K` (quick profile) and a system prompt of ~15-20K tokens, compression fires at ~96K tokens. A typical Juice Shop scan reaches 96K tokens around iteration 40-50 (each iteration adds ~1.5-2K tokens from tool results + LLM response).

When compression fires, it summarizes messages in chunks of 25. The LLM-based summarizer is supposed to preserve all URLs/payloads/findings, but in practice:
1. The summarizer itself uses the SAME LLM model (DeepSeek V3), which can hallucinate or drop details
2. The critical data extraction regex (lines 319-370) catches payloads and URLs but misses **HTTP response body content** — the actual evidence of vulnerability
3. After compression, the agent loses track of which specific payloads worked on which endpoints, leading to redundant re-testing

The deeper issue: The model context window for DeepSeek is 128K, and `get_context_window` returns 128K. At 75% = 96K. But the system prompt itself is ~18K tokens, so effective working memory is only ~78K tokens. For a 150-iteration scan, that's ~520 tokens per iteration — barely enough for meaningful tool results.

**Fix**:
- The 0.80 threshold is reasonable. The real fix is reducing token waste:
  - Deduplicate the advisory/warning messages (they accumulate and eat ~5K tokens)
  - The system prompt is bloated at ~18K tokens for quick mode — trim it to 12K
  - Inject findings ledger only when it has changed, not on every compression check

---

### BUG #7 — MEDIUM: `sqlmap_test` not called because LLM defaults to `send_request`

**File**: [phantom_agent.py](phantom/phantom/agents/PhantomAgent/phantom_agent.py#L162-L183) + [base_agent.py](phantom/phantom/agents/base_agent.py#L197-L211)  
**Lines**: phantom_agent.py 162-183, base_agent.py 197-211

**Severity**: MEDIUM  
**Impact**: 3-5 missed SQLi vulnerabilities

**Why this causes missed vulns**: The task description includes a detailed Juice Shop strategy (lines 162-183 of phantom_agent.py) that says:
```
STEP 2 — TARGETED TOOL ATTACKS (iterations 11-30):
  a) sqlmap_test on /rest/user/login (POST, param=email)
  b) sqlmap_test on /rest/products/search (GET, param=q)
```

But the mandatory tool orders in `base_agent.py` only cover iterations 1-4:
```python
_scanner_orders = {
    1: "nuclei_scan",
    2: "nmap_scan", 
    3: "katana_crawl",
    4: "ffuf_directory_scan",
}
```

After iteration 4, there's NO forced scanner order. The LLM reverts to its default behavior: `send_request` (which it finds easier to construct than `sqlmap_test`). The sqlmap tool requires constructing specific arguments (`url`, `data`, `method`, `param`, `level`, `risk`, `dbms`) — the LLM often gets the argument format wrong and gives up after 1-2 failures.

The scanner enforcement alert at iterations 10/20/30 (line 231, base_agent.py) checks `scanners_used == 0`, but by iteration 10, the forced orders already ran nuclei/nmap/katana/ffuf, so `scanners_used > 0` and the alert never fires.

**Fix**: 
- Add sqlmap_test to the forced scanner orders (iteration 5 or 6)
- Make the scanner enforcement threshold `scanners_used < 5` instead of `== 0`
- The sqlmap tool description should include concrete examples: "Example: sqlmap_test(url='http://target/rest/user/login', data='email=test@test.com&password=test', method='POST', param='email')"

---

### BUG #8 — MEDIUM: Nuclei finding cap at 40 loses low-severity vulns

**File**: [nuclei_tool.py](phantom/phantom/tools/security/nuclei_tool.py#L100-L107)  
**Lines**: 100-107

```python
_MAX_FINDINGS = 40
truncated = len(findings) > _MAX_FINDINGS
if truncated:
    findings.sort(key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(
        f.get("severity", "info").lower(), 4))
    findings = findings[:_MAX_FINDINGS]
```

**Severity**: MEDIUM  
**Impact**: 1-3 missed low/info vulnerabilities

**Why this causes missed vulns**: After sorting by severity, info-level and low-level findings are dropped first. These include: missing security headers, directory listings, exposed debug endpoints, information disclosure. These are valid Juice Shop vulnerabilities.

**Fix**: Keep severity cap at 40 but ensure at least 5 findings per severity level are preserved.

---

### BUG #9 — MEDIUM: Quick profile's `nuclei_severity = "medium,high,critical"` skips low-severity findings

**File**: [scan_profiles.py](phantom/phantom/core/scan_profiles.py#L113)  
**Line**: 113

```python
nuclei_severity="medium,high,critical",
```

**Severity**: MEDIUM  
**Impact**: 2-4 missed low/info vulnerabilities

**Why this causes missed vulns**: The quick profile filters nuclei to only report medium+ severity. Juice Shop has multiple low/info findings that are valid vulnerabilities:
- HTTP security headers missing (info)
- Directory listing at /ftp (low)
- Swagger/API docs exposed (info)
- Default credentials on admin panel (info template)

These are real findings that should count toward the vuln total.

**Fix**: Change to `nuclei_severity="low,medium,high,critical"` for quick mode.

---

### BUG #10 — MEDIUM: Advisory message accumulation wastes context tokens

**File**: [base_agent.py](phantom/phantom/agents/base_agent.py#L197-L340)  
**Lines**: 197-340

**Severity**: MEDIUM  
**Impact**: Indirect — wastes 3-5K tokens, accelerates compression

**Why this causes missed vulns**: The agent loop injects messages at multiple points:
1. Mandatory tool orders (iterations 1-4): ~200 tokens each = 800 tokens
2. Scanner enforcement alerts (iterations 10, 20, 30): ~200 tokens each = 600 tokens  
3. Phase transition messages: ~300 tokens each = 600 tokens
4. Tool diversity alerts (every 10 iterations after 15): ~200 tokens each = 1000 tokens
5. Coverage updates (every 10 iterations after 20): ~200 tokens each = 1000 tokens
6. Max-iteration warnings: ~150 tokens
7. Vuln rotation messages: ~200 tokens each = 2000 tokens
8. Stagnation warnings: ~200 tokens each

**Total advisory overhead**: ~6-8K tokens over a full scan. That's 5-7% of the context window consumed by system messages, not actual scan data.

**Fix**: 
- Set TTL on all advisory messages (most already have TTL via `add_advisory`, but the `add_message("user", ...)` calls don't expire)
- Consolidate: instead of 5 different subsystems each injecting messages, have ONE advisory per iteration that summarizes all relevant warnings

---

### BUG #11 — MEDIUM: `_auto_record_findings` for `send_request` has weak vuln detection

**File**: [executor.py](phantom/phantom/tools/executor.py#L748-L768)  
**Lines**: 748-768

```python
elif tool_name in ("send_request", "repeat_request"):
    ...
    # Detect SQLi indicators in response
    if any(kw in body for kw in ("sql", "syntax error", "sqlite", "sequelize", ...)):
        agent_state.add_finding(...)
    # Detect XSS reflection
    if "<script" in body or "javascript:" in body or "onerror" in body:
        agent_state.add_finding(...)
```

**Severity**: MEDIUM  
**Impact**: 1-2 missed auto-recorded findings

**Why this causes missed vulns**: The body variable is truncated to 500 chars (`body = result.get("body", "")[:500].lower()`). But the `send_request` response body was already truncated to 3K in proxy_manager.py. So the auto-detection only sees the first 500 chars of a 3K truncated response of a potentially 40K page. XSS reflections and SQL errors deep in the page body will never be auto-detected.

**Fix**: Increase the body scan limit to at least 2000 chars for vuln-indicator detection.

---

### BUG #12 — LOW: Juice Shop skill loaded but not activated for non-port-3000 targets

**File**: [phantom_agent.py](phantom/phantom/agents/PhantomAgent/phantom_agent.py#L350-L365)  
**Lines**: 350-365

```python
juice_shop_indicators = any(
    ":3000" in url or "juice" in url
    for url in target_urls
)
```

**Severity**: LOW  
**Impact**: 0-2 missed vulnerabilities (only affects non-standard deployments)

**Why**: The detection heuristic only checks for port 3000 or "juice" in URL. If Juice Shop runs on a different port or behind a reverse proxy, the playbook skill won't load and the agent won't know the API endpoint map.

**Fix**: Add a runtime detection step: after first HTTP probe, check response for "OWASP Juice Shop" in HTML title/body.

---

### BUG #13 — LOW: `sqlmap_forms` tool has missing `extra_args` parameter

**File**: [sqlmap_tool.py](phantom/phantom/tools/security/sqlmap_tool.py#L188)  
**Line 188**: The `sqlmap_forms` function doesn't accept `extra_args` like `sqlmap_test` does.

**Severity**: LOW  
**Impact**: Auth headers can't be injected into sqlmap_forms via the auto-injection pipeline

**Fix**: Add `extra_args: str | None = None` parameter to `sqlmap_forms`.

---

### BUG #14 — LOW: Deterministic scanner orders hardcode `<TARGET_URL>` placeholder

**File**: [base_agent.py](phantom/phantom/agents/base_agent.py#L204-L211)  
**Lines**: 204-211

```python
1: ("You MUST call nuclei_scan as your FIRST tool. "
    "Run: nuclei_scan(target=<TARGET_URL>) ..."),
```

**Severity**: LOW  
**Impact**: LLM sometimes passes literal `<TARGET_URL>` as the target argument

**Fix**: Inject the actual target URL from the task description into the scanner orders.

---

## ARCHITECTURAL LIMITATIONS (Not fixable with code patches)

### ARCH-1: LLM Cannot Reliably Execute Multi-Step Exploits

Many Juice Shop vulnerabilities require multi-step chaining:
1. Login → extract JWT → modify JWT → replay with forged token → verify admin access
2. Register user → add product to basket → set negative quantity → checkout → verify free items
3. Upload XML file → trigger XXE → extract /etc/passwd

DeepSeek V3 (and most LLMs) can reason about these chains but frequently get the details wrong (wrong parameter names, wrong JSON format, missing headers). Each failure costs an iteration.

**Impact**: ~15 vulnerabilities require multi-step chains that the LLM can't reliably execute.

### ARCH-2: Single-Threaded Agent Can't Cover Enough Ground

With 150 iterations and ~10 vuln classes, the agent has ~15 iterations per class. Finding a single Juice Shop vuln in a class often requires:
- 1 iteration: reconnaissance (discover endpoint)
- 1-3 iterations: craft payload
- 1-2 iterations: send payload and check response
- 1 iteration: validate and report

That's ~5-7 iterations per vuln, meaning only 2-3 vulns per class. Juice Shop has 5-10 vulns per class.

**Impact**: Even with perfect tooling, a 150-iteration single-agent scan caps at ~25-30 unique vulns.

### ARCH-3: Subagent Spawning Doesn't Help Enough

The system supports subagents, but each subagent:
- Has 75% of parent's max_iterations (112 for quick mode)
- Creates a new sandbox (takes 10-30 seconds)
- Needs its own recon phase (wasteful duplication)
- Can't share real-time findings with siblings (only via findings ledger, which is read-only)

**Impact**: Subagents help with parallelism but each one wastes ~20-30 iterations on setup/recon.

### ARCH-4: Tool Results Are Unstructured for LLM Consumption

Scanner tools return structured JSON, but `_format_tool_result` serializes it to a string and wraps it in XML:
```xml
<tool_result>
<tool_name>nuclei_scan</tool_name>
<result><![CDATA[{"success": true, "findings": [...]}]]></result>
</tool_result>
```

The LLM has to parse JSON inside XML inside the conversation. This is error-prone and wastes tokens on formatting overhead.

---

## PRIORITY FIX ORDER

| Priority | Bug # | Severity | Est. Vuln Impact | Effort |
|----------|-------|----------|------------------|--------|
| 1 | #1 | CRITICAL | +8-10 vulns | Low |
| 2 | #2 | CRITICAL | +5-8 vulns | Medium |
| 3 | #3 | HIGH | +3-5 vulns | Medium |
| 4 | #4 | HIGH | +2-3 vulns | Low |
| 5 | #9 | MEDIUM | +2-4 vulns | Trivial |
| 6 | #5 | HIGH | +2-3 vulns | Low |
| 7 | #7 | MEDIUM | +3-5 vulns | Medium |
| 8 | #6 | HIGH | +2-4 vulns | Medium |
| 9 | #10 | MEDIUM | indirect | Medium |
| 10 | #8 | MEDIUM | +1-3 vulns | Low |

**Estimated impact of fixing all code bugs**: +17-25 additional vulnerabilities found (from ~10 to ~27-35).

**Remaining gap** (~15-25 vulns to get to 50): Requires architectural changes — more iterations, better subagent coordination, task-specific tool chains, or a fundamentally different multi-stage scanning approach.

---

## HONEST ASSESSMENT

| Category | % of 50-vuln gap | Explanation |
|----------|------------------|-------------|
| **Code bugs (fixable)** | ~35% | Truncation (#1, #2), finish thrashing (#3), missing tools (#4, #9), loop detector (#5) |
| **LLM behavior (partially fixable)** | ~25% | Agent defaults to send_request, ignores sqlmap, can't chain exploits (#7) |
| **Architecture (requires redesign)** | ~40% | 150-iteration cap, context window limits, single-agent throughput, subagent overhead |

To find 50+ vulnerabilities on Juice Shop, the system would need:
1. All code bugs fixed (+15-20 vulns)
2. `deep` mode with 300 iterations (+5-10 vulns)
3. Improved subagent parallelism with shared auth state (+5-10 vulns)
4. Pre-built Juice Shop exploit scripts that the agent can invoke directly (+10-15 vulns)
