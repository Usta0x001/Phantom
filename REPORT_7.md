# REPORT_7 — P0 + P1 Fix Implementation

**Date:** 2026-03-15  
**Scope:** All P0 and P1 issues identified in REPORT_6.md  
**Status:** All fixes implemented, verified, and wired

---

## Summary

All 9 fixes (5 P0, 4 P1) are complete. Every change was traced through the call chain to confirm correctness. No speculative changes — every line was verified by reading the actual source.

The primary theme across all fixes: **cost reduction through better signal, less noise, and avoiding redundant work.**

---

## P0 Fixes (Immediate wins)

### P0.1 — Removed "2000+ steps minimum" grinding instructions
**File:** `phantom/agents/PhantomAgent/system_prompt.jinja`

| Location | Before | After |
|----------|--------|-------|
| Line 59 | `"Real vulnerability discovery needs 2000+ steps MINIMUM - this is NORMAL"` | `"Work efficiently - exhaust high-value attack vectors before repeating low-yield ones"` |
| Line 322 | `"Real vulnerabilities take TIME - expect to need 2000+ steps minimum"` | `"Real vulnerabilities take diligence - but stop and report when you have confirmed findings rather than grinding indefinitely"` |

**Why:** The "2000+ steps" instruction was directly causing runaway costs. Agents were instructed to treat extreme step counts as normal/expected, so they never self-terminated. The replacement still preserves persistence ("exhaust every attack vector", "never give up early") without encouraging indefinite grinding.

**Verified:** Lines 59 and 322 confirmed changed in the jinja file.

---

### P0.2 — Enabled adaptive scan mode by default
**File:** `phantom/config/config.py` line 47

| Before | After |
|--------|-------|
| `phantom_adaptive_scan = "false"` | `phantom_adaptive_scan = "true"` |

**Why:** Adaptive scan auto-downgrades deep→standard→quick when budget approaches `PHANTOM_MAX_COST * PHANTOM_ADAPTIVE_SCAN_THRESHOLD (0.8)`. It was implemented but disabled. Enabling it as the default protects against cost overruns without any user configuration.

**Verified:** `llm.py` reads this at line 102 with `.lower() == "true"`, confirmed correct.

---

### P0.3 — Enabled multi-model routing by default
**File:** `phantom/config/config.py` line 50

| Before | After |
|--------|-------|
| `phantom_routing_enabled = "false"` | `phantom_routing_enabled = "true"` |

**Why:** Routing uses cheaper models for tool-heavy iterations (scan execution, file edits) and only uses reasoning models when genuinely needed. Was implemented but disabled. Enabling by default reduces cost for all runs.

**Verified:** `llm.py` reads this at line 106 with `.lower() == "true"`, confirmed correct.

---

### P0.4 — Fixed false-negative PoC replay validation
**File:** `phantom/tools/reporting/reporting_actions.py` lines 317–336

**Before:** Matched any output containing `"error"`, `"exception"`, `"traceback"`, `"fail"` → marked replay as FAILED.

**After:** Only matches execution-failure signals:
```python
_exec_failure_patterns = (
    "command not found",
    "no such file or directory",
    "permission denied",
    "syntax error",
    "traceback (most recent call last)",
    "importerror:",
    "modulenotfounderror:",
    "segmentation fault",
    "killed",
)
# Also FAILED if output is empty
if not replay_out.strip():
    _replay = "FAILED"
elif any(p in replay_out.lower() for p in _exec_failure_patterns):
    _replay = "FAILED"
```

**Why:** Real exploit output routinely contains words like "error" and "fail" (e.g., `"SQL error: you have an error in your SQL syntax"` is a successful SQLi). The old logic marked genuine PoCs as FAILED, causing agents to discard valid findings and re-attempt attacks, burning cost.

**Verified:** Logic confirmed at lines 317–336. Empty-output guard is separate and correct.

---

### P0.5 — Changed `create_agent` context inheritance default to `False`
**File:** `phantom/tools/agents_graph/agents_graph_actions.py`

**Changes:**
1. `inherit_context: bool = False` (was `True`) — all agents now start with isolated context unless caller explicitly opts in
2. Added `context_summary: str | None = None` parameter — allows passing a short parent summary instead of full history
3. Added `elif context_summary` branch: injects `<parent_context_summary>...</parent_context_summary>` as a single user message

**Why:** Inheriting full parent context is expensive (token cost) and causes validation agents to exhibit confirmation bias. The new default isolates agents. The `context_summary` parameter provides a cheap alternative: the parent can summarize its relevant findings in ~1 message rather than passing 200+ messages.

**Verified:**
- The validation-agent keyword guard (lines 298–300) still overrides `inherit_context` to `False` for names matching `_VALIDATION_AGENT_KEYWORDS` — it now just confirms the already-`False` default for those agents.
- `context_summary` block wired at lines 360–372.
- `_run_agent_in_thread` accepts the messages list as initial history — confirmed correct.

---

## P1 Fixes (Moderate effort, high impact)

### P1.1 — Smart truncation for ffuf/nmap output
**File:** `phantom/tools/executor.py`

**Added:**
- `_extract_ffuf_findings(text, limit)` (line 283): extracts non-404 status lines from ffuf output. Returns `None` if nothing found (signals fallback to head+tail).
- `_extract_nmap_findings(text, limit)` (line 323): extracts `open` port lines and Nmap summary lines. Returns `None` if no open ports found.

**Updated truncation block** (lines 588–606):
```python
if tool_name in ("ffuf",):
    extracted = _extract_ffuf_findings(final_result_str, limit)
elif tool_name in ("nmap", "naabu"):
    extracted = _extract_nmap_findings(final_result_str, limit)
if extracted is not None:
    final_result_str = extracted
    meta["smart_extracted"] = True
else:
    # fallback: head + tail
    meta["smart_extracted"] = False
```

**Why:** ffuf scans against large wordlists produce 50k+ lines where 99% are 404s. nmap `-p-` on a live host produces thousands of "filtered" lines. When truncated by head+tail, the actually-interesting findings (non-404 status codes, open ports) get cut out entirely, so the agent sees nothing useful. Smart extraction ensures signal is preserved.

**Verified:** Function signatures confirmed at lines 283 and 323. Truncation dispatch confirmed at lines 588–606 with `meta["smart_extracted"]` flag.

---

### P1.2 — Scan registry module (deduplication)
**Files created:**
- `phantom/tools/scan_registry/scan_registry_actions.py`
- `phantom/tools/scan_registry/scan_registry_actions_schema.xml`
- `phantom/tools/scan_registry/__init__.py`

**Wired:** `phantom/tools/__init__.py` line 42: `from .scan_registry import *`

**Tools exposed:**
- `check_scan_registry(target, scan_type)` → `{"registered": bool, "registered_at": ...}`
- `register_scan_target(target, scan_type)` → `{"success": bool}`

**Public Python API:** `is_registered()`, `register()`, `clear_registry()`

**Why:** Without deduplication, multiple sub-agents independently launch the same nmap/ffuf scan against the same target, multiplying cost linearly. The registry is process-wide and thread-safe, so any agent can check before launching a scan.

**Verified:** Import confirmed at `__init__.py` line 42. Module files confirmed present.

---

### P1.3 — Finding anchors (memory persistence across compression)
**Files modified:**
- `phantom/agents/state.py`
- `phantom/llm/memory_compressor.py`
- `phantom/llm/llm.py`
- `phantom/agents/base_agent.py`

**Full call chain:**

```
base_agent.py:86  → llm.set_agent_state(self.state)
                       ↓ (stores _agent_state on LLM instance)

llm.py:394–398    → asyncio.to_thread(compress_history, history, _state)
                       ↓ (passes state to compressor)

memory_compressor.py:436–438
                  → for anchor in _extract_anchors_from_chunk(chunk):
                         agent_state.add_finding_anchor(anchor)
                       ↓ (anchors saved to state.finding_anchors)

state.py:52–59    → add_finding_anchor() deduplicates by 'key' field

llm.py:408–426    → at 75% iteration threshold, if finding_anchors exist:
                       inject <finding_anchors> reminder into messages
```

**Why:** Without anchors, confirmed findings that were compressed away are lost. The agent "forgets" a SQLi was confirmed and starts re-verifying it, burning dozens of iterations. Anchors ensure the most important facts survive compression and are re-surfaced when approaching limits.

**Anchor keywords** (in `_ANCHOR_KEYWORDS`): confirmed, verified, vulnerable, exploit, bypass, rce, sqli, xss, lfi, ssrf, idor, authentication bypass, credentials found, flag found.

**Verified:**
- `state.py:50` — `finding_anchors` field present
- `state.py:52` — `add_finding_anchor` with deduplication by `key`
- `memory_compressor.py:33,42` — `_ANCHOR_KEYWORDS` and `_extract_anchors_from_chunk` present
- `memory_compressor.py:364,436–438` — `agent_state` param and anchor extraction in compression loop
- `llm.py:151–153` — `set_agent_state` method
- `llm.py:394–397` — `_state` extracted, passed to `compress_history`
- `llm.py:408–426` — anchor injection at 75% threshold
- `base_agent.py:86` — `set_agent_state` called after `set_agent_identity`

---

### P1.4 — Session management module
**Files created:**
- `phantom/tools/session/session_actions.py`
- `phantom/tools/session/session_actions_schema.xml`
- `phantom/tools/session/__init__.py`

**Wired:** `phantom/tools/__init__.py` line 43: `from .session import *`

**Tools exposed:**
- `session_login(session_id, cookies, headers, tokens, notes)` — store session after login
- `session_get(session_id)` → `{"found": bool, "session": {...}}` — retrieve stored session
- `session_refresh(session_id, ...)` — merge-update existing session (handles token rotation)

**Public Python API:** `get_session()`, `store_session()`, `clear_sessions()`

**Format:** `cookies`/`headers`/`tokens` are semicolon-separated `key=value` strings (easy for LLMs to construct from curl output)

**Why:** Without session management, every sub-agent re-authenticates independently. On targets with rate-limiting or account lockout policies, this causes failures and forces even more retry iterations. With session tools, one agent logs in and all others reuse the stored session.

**Verified:**
- `session_actions.py` — all three tools confirmed with `@register_tool(sandbox_execution=False)`
- `session/__init__.py` — exports all 6 symbols
- `tools/__init__.py:43` — `from .session import *` confirmed present

---

## Files Changed

| File | Change Type | Fix |
|------|------------|-----|
| `phantom/agents/PhantomAgent/system_prompt.jinja` | Modified | P0.1 |
| `phantom/config/config.py` | Modified | P0.2, P0.3 |
| `phantom/tools/reporting/reporting_actions.py` | Modified | P0.4 |
| `phantom/tools/agents_graph/agents_graph_actions.py` | Modified | P0.5 |
| `phantom/tools/executor.py` | Modified | P1.1 |
| `phantom/tools/__init__.py` | Modified | P1.2 wiring, P1.4 wiring |
| `phantom/agents/state.py` | Modified | P1.3 |
| `phantom/llm/memory_compressor.py` | Modified | P1.3 |
| `phantom/llm/llm.py` | Modified | P1.3 |
| `phantom/agents/base_agent.py` | Modified | P1.3 |
| `phantom/tools/scan_registry/scan_registry_actions.py` | Created | P1.2 |
| `phantom/tools/scan_registry/scan_registry_actions_schema.xml` | Created | P1.2 |
| `phantom/tools/scan_registry/__init__.py` | Created | P1.2 |
| `phantom/tools/session/session_actions.py` | Created | P1.4 |
| `phantom/tools/session/session_actions_schema.xml` | Created | P1.4 |
| `phantom/tools/session/__init__.py` | Created | P1.4 |

---

## P2/P3 Assessment

The remaining P2 and P3 items from REPORT_6 are lower-priority refinements. The P0+P1 fixes address the root causes of cost overruns:

- **Cost controls** (P0.2, P0.3) are now on by default
- **Grinding instructions** (P0.1) removed
- **Deduplication** (P1.2) prevents redundant scans
- **Session reuse** (P1.4) prevents redundant logins
- **Smart truncation** (P1.1) preserves signal in long tool outputs
- **Anchor memory** (P1.3) prevents re-verifying confirmed findings

P2/P3 items are incremental improvements and should be addressed after observing the impact of these changes on actual scan runs.
