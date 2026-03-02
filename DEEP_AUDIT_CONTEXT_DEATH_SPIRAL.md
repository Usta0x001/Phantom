# Phantom Deep Audit: Context Death Spiral Analysis

**Date**: 2026-03-02  
**Scans Analyzed**: e109 (3 vulns, 29 LLM reqs), 9311 (1 vuln, 46 LLM reqs, 8 compressions)  
**Model**: openrouter/deepseek/deepseek-chat-v3-0324 (context: 163,840 tokens, max_output: 16,384)

---

## 1. TOKEN BUDGET ANALYSIS — WHY CONTEXT FILLS UP

### Measured Token Counts

| Component | Characters | Est. Tokens | % of Context |
|-----------|-----------|-------------|--------------|
| System prompt (total, with tools embedded) | 174,404 | **~43,600** | **26.6%** |
| ↳ Base template (system_prompt.jinja) | ~28,000 | ~7,000 | 4.3% |
| ↳ Tool XML definitions (embedded via get_tools_prompt) | ~138,582 | ~34,645 | 21.1% |
| ↳ Juice Shop skill | 7,632 | ~1,908 | 1.2% |
| ↳ Quick mode skill | 5,292 | ~1,323 | 0.8% |
| ↳ Root agent skill | 2,790 | ~697 | 0.4% |
| Agent identity message | ~200 | ~50 | 0.03% |
| Task description (execute_scan) | ~12,000 | **~3,000** | 1.8% |
| Max output tokens reserved | — | **16,384** | 10% |
| **Total fixed overhead per request** | — | **~63,034** | **38.5%** |
| **Available for conversation** | — | **~100,806** | **61.5%** |

### Compression Threshold Math

The quick profile sets `memory_threshold = 80,000`. The compressor triggers at `0.82 × 80,000 = 65,600` tokens of **conversation only** (system prompt excluded from compression).

But each tool call adds to conversation:

| Tool | Avg Result Size | Est. Tokens |
|------|----------------|-------------|
| send_request | 10K body + full headers + metadata | **~3,500** |
| nuclei_scan | 20 findings × 10 fields + raw_output_tail | **~3,000** |
| katana_crawl | 40 URLs + js_files + api_endpoints + summary | **~2,500** |
| nmap_scan | Hosts + ports + raw_output | **~1,500** |
| sqlmap_test | Findings + payloads + detection | **~2,000** |
| ffuf_directory_scan | Results + discovered paths | **~2,000** |
| Agent text response | ~200-800 words | **~400** |
| Observation XML wrapper | `<tool_result>` tags | **~50** |

**Each tool call cycle = ~3,000-4,500 tokens** (tool result + assistant response).

### The Death Spiral

1. **First 15-18 tool calls** fill conversation to ~65.6K tokens → **Compression #1 fires**
2. Compression preserves `MIN_RECENT_MESSAGES = 20` messages = **~35-40K tokens** (cannot be compressed)
3. Old messages are summarized, but summaries still take ~5-10K tokens
4. **Post-compression conversation: ~45-50K tokens**
5. Only **~15-20K tokens** of free space remain
6. **Next 4-5 tool calls** fill this → **Compression #2 fires**
7. But MIN_RECENT_MESSAGES is still 20, so the floor is still ~40K
8. **Repeat: compression every 4-6 tool calls**, each time losing more context
9. After 8 compressions, the agent has essentially NO memory of early findings

**This is exactly what happened in scan #2**: 46 LLM requests, 8 compressions = compression every ~5.75 requests.

---

## 2. ALL BUGS/ISSUES FOUND

### CRITICAL (Must Fix)

#### C1. Profile `memory_threshold` overrides dynamic threshold with LOWER value
**File**: [phantom_agent.py](phantom/agents/PhantomAgent/phantom_agent.py#L38)  
**Line**: 38  
**What's wrong**: `set_memory_threshold(self.scan_profile.memory_threshold)` replaces the dynamically calculated `int(163_840 × 0.75) = 122,880` with the profile's `80,000`. This reduces available conversation space by 35%.  
**Impact**: The compression fires ~50% sooner than necessary, triggering the death spiral.  
**Fix**: Remove the profile override OR increase the quick profile threshold to match the dynamic calculation.

#### C2. `MIN_RECENT_MESSAGES = 20` creates an uncompressible 35-40K token floor
**File**: [memory_compressor.py](phantom/llm/memory_compressor.py#L7)  
**Line**: 7  
**What's wrong**: 20 recent messages are always preserved uncompressed. At ~2-3K tokens per message pair (tool result + response), this is 35-40K tokens that can NEVER be reduced. After compression, this floor eats most of the available space, causing immediate re-compression on the next few tool calls.  
**Impact**: Makes the death spiral inescapable. Even "perfect" compression can't reduce below 40K.  
**Fix**: Reduce to 8 (preserves last ~4 tool call cycles = sufficient working memory).

#### C3. `send_request` returns FULL response headers (1K+ tokens wasted per call)
**File**: [proxy_manager.py](phantom/tools/proxy/proxy_manager.py#L434)  
**Line**: 434  
**What's wrong**: `"headers": dict(response.headers)` returns ALL response headers. Most HTTP responses have 15-25 headers (Server, Date, Connection, X-Powered-By, Cache-Control, etc.). The agent only needs security-relevant headers.  
**Impact**: 21 send_request calls × ~800 wasted header tokens = **~16,800 wasted tokens** (equivalent to 4-5 extra tool calls).  
**Fix**: Filter to only security-relevant headers.

#### C4. Task description in `execute_scan` duplicates system prompt instructions (~3K tokens)
**File**: [phantom_agent.py](phantom/agents/PhantomAgent/phantom_agent.py#L131-L241)  
**Lines**: 131-241  
**What's wrong**: The task_description built in `execute_scan()` repeats instructions already present in system_prompt.jinja and quick.md skill:
- "SPA/JAVASCRIPT APP RECON STRATEGY" (~500 tokens) — duplicated from system prompt `MANDATORY INITIAL PHASES`
- "VULN-CLASS ROTATION (MANDATORY)" (~300 tokens) — duplicated from quick.md skill
- "MANDATORY FIRST STEPS" (~300 tokens) — duplicated from system prompt checklist
- "EFFICIENCY RULES" (~400 tokens) — duplicated from `EFFICIENCY TACTICS`
- "CRITICAL — DO NOT FINISH EARLY" (~400 tokens) — duplicated from quick.md
- Total duplication: ~2,000 tokens × every LLM call = massive waste  
**Impact**: These duplicate instructions are in the task (first user message) which is part of conversation history and contributes to compression triggers.  
**Fix**: Strip duplicate sections from task_description — keep only target-specific info.

#### C5. System prompt is 43,600 tokens — absurdly large
**File**: [system_prompt.jinja](phantom/agents/PhantomAgent/system_prompt.jinja)  
**Lines**: 1-459  
**What's wrong**: The system prompt contains ~7K tokens of instructions PLUS ~34.6K tokens of XML tool definitions. The tool definitions alone are 21% of the context window. Many instructions are verbose, repetitive ("NEVER", "MUST", "CRITICAL" used dozens of times), and overlap with skills.  
**Impact**: Every single LLM request carries this 43.6K token overhead; combined with max_output_tokens (16.4K), 60K tokens are consumed before any conversation.  
**Fix**: Aggressive deduplication and compression of instructions; consider moving tool definitions to a separate method that only sends relevant tools.

---

### HIGH Severity

#### H1. Tool result universal cap is 16K chars (~4K tokens) in executor.py
**File**: [executor.py](phantom/tools/executor.py#L393-L406)  
**Lines**: 393-406  
**What's wrong**: `_format_tool_result` truncates at 16,000 chars (raised from 8K). This is still too generous — security scanner output often hits this limit, putting 4K tokens into conversation per tool call.  
**Fix**: Reduce to 10K chars (still preserves critical findings, saves ~1.5K tokens per verbose result).

#### H2. `repeat_request` body cap is 15K — higher than `send_request`'s 10K
**File**: [proxy_manager.py](phantom/tools/proxy/proxy_manager.py#L596)  
**Line**: 596  
**What's wrong**: `response_body[:15000]` — inconsistent with and higher than send_request's 10K cap.  
**Impact**: Agent may use repeat_request to get larger responses, burning more tokens.  
**Fix**: Reduce to 5K (repeat_request is typically used for targeted probing).

#### H3. `nuclei_scan` includes `raw_output_tail` (500 chars) even when findings are parsed
**File**: [nuclei_tool.py](phantom/tools/security/nuclei_tool.py#L133)  
**Line**: 133  
**What's wrong**: `"raw_output_tail": raw_output[-500:]` is included even when findings are successfully parsed. This is redundant — the structured findings already contain all relevant data.  
**Fix**: Only include raw_output_tail when `total_findings == 0` (failure case).

#### H4. `nuclei_scan` findings contain verbose fields the agent doesn't need
**File**: [nuclei_tool.py](phantom/tools/security/nuclei_tool.py#L25-L39)  
**Lines**: 25-39  
**What's wrong**: Each finding includes: template_id, template_name, severity, host, matched_at, matcher_name, extracted_results, curl_command, description, reference (array), tags (array). The agent only needs: template_id, severity, matched_at, and a brief description. The curl_command alone can be 200+ chars.  
**Fix**: Slim findings to essential fields: `{template_id, severity, matched_at, description[:100]}`.

#### H5. Compression fires an LLM call per 10-message chunk
**File**: [memory_compressor.py](phantom/llm/memory_compressor.py#L313-L320)  
**Lines**: 313-320  
**What's wrong**: Old messages are split into chunks of 10 and each gets a separate LLM summarization call. With 40 old messages, that's 4 LLM calls just for compression — each taking ~30-60 seconds and costing tokens.  
**Fix**: Increase chunk_size from 10 to 30 to reduce LLM calls during compression.

#### H6. `nuclei_scan` XML schema missing `extra_args` parameter
**File**: [security_tools_schema.xml](phantom/tools/security/security_tools_schema.xml#L48-L70)  
**Lines**: 48-70  
**What's wrong**: The nuclei_scan Python function accepts `extra_args` but the XML schema doesn't expose it. The LLM can't use custom nuclei flags.  
**Fix**: Add `<parameter name="extra_args">` to the nuclei_scan schema.

#### H7. Compression discards context summaries on re-compression
**File**: [memory_compressor.py](phantom/llm/memory_compressor.py#L310-L395)  
**What's wrong**: When compression fires again, old `<context_summary>` messages are in the "old_msgs" list and get sent to the LLM for re-summarization. Summarizing a summary loses information exponentially — each layer of compression degrades facts.  
**Fix**: Detect and preserve `<context_summary>` messages as-is during re-compression instead of re-summarizing them.

#### H8. finish_scan gate rejection has no cooldown — agent retries immediately
**File**: [finish_actions.py](phantom/tools/finish/finish_actions.py#L675-L720)  
**Lines**: 675-720  
**What's wrong**: When AUTO-001/002/003 rejects finish_scan, the error message goes into conversation. The agent often retries on the very next iteration, wasting 2-3 iterations (and tokens) on repeated rejections.  
**Fix**: After rejection, inject a cooldown advisory that expires after 5 iterations, telling the agent not to retry finish_scan.

---

### MEDIUM Severity

#### M1. `send_request` body cap of 10K is still too large for most probing
**File**: [proxy_manager.py](phantom/tools/proxy/proxy_manager.py#L428-L430)  
**Lines**: 428-430  
**What's wrong**: Most send_request calls are probing API endpoints where only the first 2-3K chars of the body are informative. HTML pages are even worse — they contain boilerplate, CSS, scripts that the agent doesn't need.  
**Fix**: Cap body at 5K chars; for HTML content-type, cap at 3K.

#### M2. Katana output cap of 40 URLs may still be too many tokens
**File**: [katana_tool.py](phantom/tools/security/katana_tool.py#L126)  
**Line**: 126  
**What's wrong**: 40 URL objects × ~100 tokens each = ~4K tokens. Most are repetitive (same domain, similar paths).  
**Fix**: Reduce to 25 URLs; add dedup by path prefix (group similar paths).

#### M3. Scan profile `reasoning_effort = "high"` for quick scan wastes output tokens
**File**: [scan_profiles.py](phantom/core/scan_profiles.py#L111)  
**Line**: 111  
**What's wrong**: Quick profile uses `reasoning_effort="high"` — but in llm.py, the override logic checks `Config.get("phantom_reasoning_effort")` first, then falls back to scan_mode. The profile's value is never directly read by `LLM.__init__`.  
**Impact**: Setting is effectively ignored for LLM reasoning (it's decorative). The actual reasoning_effort is set by config or hardcoded logic.  
**Fix**: Wire the profile's `reasoning_effort` into `LLMConfig` or use "medium" for quick to save output tokens.

#### M4. Quick profile skip_tools only skips subfinder — should skip more
**File**: [scan_profiles.py](phantom/core/scan_profiles.py#L113)  
**Line**: 113  
**What's wrong**: Only `subfinder_enumerate` is skipped. For a quick scan targeting a single web app (Juice Shop), nmap port scanning, httpx_screenshot, subfinder are all low-value and waste iterations.  
**Fix**: Add to skip_tools: `subfinder_with_sources`, `httpx_screenshot`, `httpx_full_analysis`.

#### M5. Agent identity message is sent as a separate user message
**File**: [llm.py](phantom/llm/llm.py#L213-L222)  
**Lines**: 213-222  
**What's wrong**: The agent identity is injected as a separate user message in `_prepare_messages()`. This cannot be compressed because it's always re-injected. It's ~50 tokens but adds message count.  
**Fix**: Embed agent identity in the system prompt instead.

#### M6. No tool result compression for `create_vulnerability_report`
**File**: [executor.py](phantom/tools/executor.py#L663-L683)  
**What's wrong**: When `create_vulnerability_report` succeeds, the full result (including report details) is added to conversation. This can be 500+ tokens per vulnerability report.  
**Fix**: For successful vuln reports, return only `{success: true, report_id, message: "Reported: XSS at /search"}` — the details are already in the tracer.

---

### LOW Severity

#### L1. Coverage advisory messages add tokens but don't drive action
**File**: [base_agent.py](phantom/agents/base_agent.py#L267-L292)  
**Impact**: Advisory messages with HTML tables of coverage data add 200-300 tokens every 10 iterations. They expire via TTL=3, but still waste tokens in the window.

#### L2. `_sanitize_inter_agent_content` is overly aggressive — strips valid payload data
**File**: [base_agent.py](phantom/agents/base_agent.py#L698-L756)  
**Impact**: When subagents send back XSS payloads or SQL injection strings as findings, the sanitizer may strip `<script>` tags, removing evidence. Should preserve content within DATA boundaries.

#### L3. No dedup of tool XML schemas for subagents
**Impact**: Subagents get the full tool XML definitions (~34K tokens) even though they typically use only 3-4 tools. A subagent testing SQLi only needs sqlmap schemas, not all 17 security tool schemas.

---

## 3. SPECIFIC CODE CHANGES

### Fix C1: Remove profile memory_threshold override (use dynamic)

```python
# phantom/agents/PhantomAgent/phantom_agent.py line 38
# REMOVE this block:
        # Apply dynamic memory threshold from scan profile
        if self.scan_profile and hasattr(self.scan_profile, "memory_threshold"):
            self.llm.set_memory_threshold(self.scan_profile.memory_threshold)
```

**Or** keep it but set quick profile threshold much higher:
```python
# phantom/core/scan_profiles.py line 115
# Change:
        memory_threshold=80_000,
# To:
        memory_threshold=120_000,
```

### Fix C2: Reduce MIN_RECENT_MESSAGES

```python
# phantom/llm/memory_compressor.py line 7
# Change:
MIN_RECENT_MESSAGES = 20
# To:
MIN_RECENT_MESSAGES = 8
```

### Fix C3: Filter send_request response headers

```python
# phantom/tools/proxy/proxy_manager.py line 434
# Change:
                result = {
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "body": body_content,
# To:
                # Only include security-relevant headers to save context tokens
                _RELEVANT_HEADERS = {
                    "content-type", "content-length", "server", "set-cookie",
                    "location", "www-authenticate", "x-powered-by",
                    "access-control-allow-origin", "x-frame-options",
                    "content-security-policy", "strict-transport-security",
                    "x-content-type-options", "authorization",
                }
                filtered_headers = {
                    k: v for k, v in response.headers.items()
                    if k.lower() in _RELEVANT_HEADERS
                }
                result = {
                    "status_code": response.status_code,
                    "headers": filtered_headers,
                    "body": body_content,
```

### Fix C4: Strip duplicate instructions from task_description

```python
# phantom/agents/PhantomAgent/phantom_agent.py
# Remove these blocks from execute_scan() (lines ~158-241):
# 1. Remove "SPA/JAVASCRIPT APP RECON STRATEGY" block (already in system prompt)
# 2. Remove "VULN-CLASS ROTATION (MANDATORY)" block (already in quick.md skill)  
# 3. Remove "MANDATORY FIRST STEPS" block (already in system prompt)
# 4. Remove "EFFICIENCY RULES" block (already in system prompt)
# 5. Remove "CRITICAL — DO NOT FINISH EARLY" block (already in quick.md skill)
# Keep ONLY: profile name, iteration limit, skip_tools, priority_tools, enable_browser, rate_limit
```

### Fix H1: Reduce tool result universal cap

```python
# phantom/tools/executor.py line 393
# Change:
        if len(final_result_str) > 16000:
# To:
        if len(final_result_str) > 10000:
```
And adjust the split sizes:
```python
# Change:
            start_part = final_result_str[:7000]
            end_part = final_result_str[-7000:]
# To:
            start_part = final_result_str[:4500]
            end_part = final_result_str[-4500:]
```

### Fix H2: Reduce repeat_request body cap

```python
# phantom/tools/proxy/proxy_manager.py line 596
# Change:
                truncated = len(response_body) > 15000
                if truncated:
                    response_body = response_body[:15000] + "\n... [truncated]"
# To:
                truncated = len(response_body) > 5000
                if truncated:
                    response_body = response_body[:5000] + "\n... [truncated]"
```

### Fix H3: Only include raw_output_tail on zero findings

```python
# phantom/tools/security/nuclei_tool.py line 131-135
# Change:
    return {
        "success": True,
        "command": command,
        "target": target,
        "total_findings": len(findings),
        "findings_truncated": truncated,
        "findings": findings,
        "by_severity": {k: len(v) for k, v in severity_groups.items()},
        "raw_output_tail": raw_output[-500:] if len(raw_output) > 0 else "(no output)",
    }
# To:
    result = {
        "success": True,
        "command": command,
        "target": target,
        "total_findings": len(findings),
        "findings_truncated": truncated,
        "findings": findings,
        "by_severity": {k: len(v) for k, v in severity_groups.items()},
    }
    # Only include raw output when no findings were parsed (helps debug)
    if len(findings) == 0:
        result["raw_output_tail"] = raw_output[-500:] if raw_output else "(no output)"
    return result
```

### Fix H4: Slim nuclei findings to essential fields

```python
# phantom/tools/security/nuclei_tool.py lines 25-39
# Change:
            findings.append({
                "template_id": finding.get("template-id", ""),
                "template_name": finding.get("info", {}).get("name", ""),
                "severity": finding.get("info", {}).get("severity", "unknown"),
                "host": finding.get("host", ""),
                "matched_at": finding.get("matched-at", ""),
                "matcher_name": finding.get("matcher-name", ""),
                "extracted_results": finding.get("extracted-results", []),
                "curl_command": finding.get("curl-command", ""),
                "description": finding.get("info", {}).get("description", ""),
                "reference": finding.get("info", {}).get("reference", []),
                "tags": finding.get("info", {}).get("tags", []),
            })
# To:
            desc = finding.get("info", {}).get("description", "")
            findings.append({
                "template_id": finding.get("template-id", ""),
                "severity": finding.get("info", {}).get("severity", "unknown"),
                "matched_at": finding.get("matched-at", ""),
                "description": desc[:150] if desc else "",
                "matcher_name": finding.get("matcher-name", ""),
            })
```

### Fix H5: Increase compression chunk_size

```python
# phantom/llm/memory_compressor.py line 313
# Change:
        chunk_size = 10
# To:
        chunk_size = 25
```

### Fix H6: Add extra_args to nuclei_scan XML schema

```xml
<!-- phantom/tools/security/security_tools_schema.xml, inside nuclei_scan tool -->
<!-- Add after rate_limit parameter: -->
      <parameter name="extra_args" type="string" required="false">
        <description>Additional nuclei command-line arguments (e.g., "-headless" or "-t custom-templates/")</description>
      </parameter>
```

### Fix M1: Reduce send_request body cap

```python
# phantom/tools/proxy/proxy_manager.py line 428-430
# Change:
                if len(body_content) > 10000:
                    body_content = body_content[:10000] + "\n... [truncated]"
# To:
                body_limit = 3000 if "text/html" in (response.headers.get("content-type", "")) else 5000
                if len(body_content) > body_limit:
                    body_content = body_content[:body_limit] + "\n... [truncated]"
```

---

## 4. ESTIMATED IMPACT OF FIXES

### Before Fixes (Current State)
- System prompt: 43.6K tokens (fixed per request)
- Conversation ceiling before compression: 65.6K tokens (80K × 0.82)
- Min-recent floor: ~40K tokens (20 msgs)
- Breathing room after compression: ~25K tokens
- Tool calls before next compression: ~6-8
- Expected compressions in 150-iter scan: **8-12 (death spiral)**

### After All Fixes
- System prompt: ~43.6K tokens (unchanged — trimming C5 is complex)
- Conversation ceiling: **98.4K tokens** (120K × 0.82)  
- Min-recent floor: **~16K tokens** (8 msgs × ~2K avg)
- Breathing room after compression: **~82K tokens**
- Tool calls per tool: **~2K tokens** (down from ~3.5K with header/body fixes)
- Tool calls before next compression: **~35-40**
- Expected compressions in 150-iter scan: **1-2 (healthy)**

### Token Savings Per Tool Call (estimated)
| Fix | Savings |
|-----|---------|
| C3: Filter headers | ~800 tokens/send_request |
| C4: Remove task duplication | ~2,000 tokens (one-time) |
| H1: Reduce result cap 16K→10K | ~500 tokens/verbose tool |
| H3: Remove raw_output_tail | ~150 tokens/nuclei call |
| H4: Slim nuclei findings | ~200 tokens/finding × 20 = ~4,000 per nuclei call |  
| M1: Reduce body cap | ~1,500 tokens/send_request |
| **Total per send_request** | **~2,300 tokens saved** |
| **Total per nuclei_scan** | **~4,650 tokens saved** |

---

## 5. WHY THE AGENT ONLY FOUND 1 VULN IN SCAN #2

**Root cause chain:**
1. **Context fills up fast** (C1, C2, C3): With 80K threshold and huge tool results, compression fires after ~15 tool calls
2. **Compression death spiral** (C2, H5, H7): MIN_RECENT_MESSAGES=20 means compression can't actually free much space, so it fires again 5-6 calls later
3. **8 compressions destroy memory**: Each compression loses endpoint URLs, discovered paths, working payloads, and attack progress
4. **Agent loses track of what it found**: After multiple compressions, the agent doesn't remember the SQL injection it found earlier, so it can't expand from it
5. **Agent can't plan**: Without memory of what's been tested, the agent repeats the same probes or gets stuck in a loop
6. **Only 46 LLM requests in 150 iterations**: The remaining iterations were burned on compression LLM calls, waiting, or error handling

**The fix priority is: C1 + C2 + C3 first** — these three changes alone should reduce compressions from 8 to 1-2 and give the agent 3-4× more working memory.

---

## 6. STRATEGY FAILURES — WHY NOT ENOUGH VULN CLASSES

1. **The Juice Shop skill is good but arrives too late**: It's loaded into the system prompt, but the agent must still "decide" to follow it. The task description's duplicate instructions compete for attention.

2. **Subagent creation wastes iterations**: Each subagent gets its own full system prompt (43K tokens) and tool definitions. The parent agent spends iterations on agent management rather than testing.

3. **No forced tool sequence**: The agent "should" run nuclei → katana → ffuf → sqlmap in order, but there's no enforcement. The LLM may skip tools or run them on wrong endpoints.

4. **Coverage tracking is broken in practice**: `endpoints` and `tested_endpoints` on state are only populated for some tools (katana, httpx), not for manual send_request probes.

---

## 7. ADDITIONAL RECOMMENDATIONS

1. **Add a "compact mode" for tool results**: When context is above 50% utilization, automatically reduce tool result verbosity (shorter bodies, fewer fields).

2. **Pre-compress old context summaries**: Before re-compressing, detect `<context_summary>` messages and simply concatenate them instead of re-summarizing.

3. **Profile-aware tool definitions**: For quick scans, only include XML schemas for priority_tools instead of all 40+ tools. This could save ~20K tokens from the system prompt.

4. **Implement a proper tool result cache**: Instead of putting full tool results in conversation, put them in a separate store and reference them by ID. The conversation only gets a summary.
