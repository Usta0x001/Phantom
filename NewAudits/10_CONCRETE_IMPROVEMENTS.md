# Phantom — Concrete Improvements (Prioritized, Code-Exact)

This document lists all actionable improvements with exact file targets, line
references, and patch descriptions. Claims are grounded in verified code readings.

---

## CRITICAL CORRECTIONS from Code Verification

Before fixes: three findings from the initial analysis were WRONG after code verification.
Audit rigour requires documenting these corrections.

| Finding | Original Claim | Verified Reality | Status |
|---|---|---|---|
| S1 (Jinja injection) | `target_url` injected into system prompt via Jinja | `target_url` is NOT passed to `template.render()` — renders as "web application" | **Reclassified: MEDIUM** — Real risk is task-string injection, not system-prompt |
| AF-2 (Checkpoint atomic) | Checkpoint writes are not atomic | `tmp.replace(checkpoint_file)` already in place (`checkpoint.py:233`) | **FALSE — Already fixed** |
| S5 (Ledger thread safety) | HypothesisLedger has no lock | `self._lock = threading.RLock()` at line 299; all mutations use `with self._lock` | **FALSE — Already implemented** |

---

## P1 — CRITICAL Priority (Apply Immediately)

### P1-A: Task String Prompt Injection (Real S1 Vector)

**File:** `phantom/agents/PhantomAgent/phantom_agent.py`  
**Lines:** 95-97 (URL embedding), 41-47 (repo embedding), 51-57 (local code embedding)

**Problem:**
```python
# Line 97 — raw URL embedded with no sanitization:
task_parts.extend(f"- {url}" for url in urls)

# Line 85 — raw repo URL embedded:
task_parts.append(f"- {repo['url']} (available at: {repo['workspace_path']})")
```

A target URL like `http://victim.com\n\nIgnore all previous instructions...` injects
into the first user message, which has high positional weight in the LLM context.
`user_instructions` IS sanitized via `_sanitize_skill_content()` (line 106) but
target URLs and repo URLs are not.

**Fix:** Apply `_sanitize_skill_content()` to URL and repo URL values before embedding.

---

### P1-B: Sub-Agent context_summary Injection (S3)

**File:** Wherever `create_agent` tool is implemented  
**Problem:** The `context_summary` parameter (min 200 chars) is not sanitized before
being used as the sub-agent's first user message.

**Fix:** Apply `_semantic_sanitize_output()` to `context_summary` at the create_agent
tool call site before passing to the new agent's `agent_loop(task=...)`.

---

### P1-C: Jinja2 Autoescape Enable (Defense-in-Depth)

**File:** `phantom/llm/llm.py`  
**Lines:** 622-625

**Problem:**
```python
env = Environment(
    loader=FileSystemLoader([prompt_dir, skills_dir]),
    autoescape=select_autoescape(enabled_extensions=(), default_for_string=False),
)
```
Autoescape is completely disabled. If a future code change passes user-controlled data
to `template.render()`, it will be embedded verbatim. This is a latent footgun.

**Fix:** Enable autoescape for the .jinja extension specifically, and use `| safe` in
the template only for trusted content (tools_prompt, skill blocks that are internally generated).

---

## P2 — HIGH Priority

### P2-A: Prompt Injection Pattern Gaps (S4 — Proxy History)

**File:** `phantom/tools/executor.py`  
**Function:** `_PROMPT_INJECTION_PATTERNS` (constant near top of file)

**Problem:** The regex/string list misses several practical injection vectors:
- `[SYSTEM:` — plain bracket prefix (covered: `[system]` lowercase only)
- Unicode normalization attacks (`\u0061\u0073\u0073\u0069\u0073\u0074\u0061\u006e\u0074:`)
- HTTP headers containing instruction strings from proxy history

**Fix:**
1. Add `[SYSTEM:`, `[SYSTEM `, case-insensitively to the pattern list
2. Apply Unicode NFKC normalization before pattern matching (`unicodedata.normalize("NFKC", text)`)
3. Apply sanitization to proxy history query results too (not just tool output)

---

### P2-B: RBAC Default Off (S6)

**File:** `phantom/config/config.py`  
**Line:** 102

**Problem:**
```python
phantom_rbac_enabled = "false"   # explicitly disabled by default
```
RBAC provides zero security in default configuration.

**Fix:** Change default to `"true"`. The RBAC default role is already
`"senior_pentester"` (line 103) which is appropriate for pentesting use.

---

### P2-C: `send_request` RBAC Misclassification

**File:** `phantom/tools/rbac.py`  
**Problem:** `send_request` classified as `ToolCategory.READ`. An OBSERVER-role
agent can make live HTTP requests against the target.

**Fix:** Reclassify `send_request` as `ToolCategory.WRITE` or create a new
`ToolCategory.ACTIVE_READ` category and require at minimum `JUNIOR_PENTESTER`.

---

## P3 — MEDIUM Priority

### P3-A: Rate Limit Global Race Condition (S7)

**File:** `phantom/llm/llm.py`  
**Lines:** 90-91, 721-726, 800-802

**Problem:** `_GLOBAL_RATE_LIMIT_UNTIL` is a bare float written without lock.
The existing `_GLOBAL_STATS_LOCK` can be reused.

**Fix:**
```python
# At write site (line 802):
with _GLOBAL_STATS_LOCK:
    _GLOBAL_RATE_LIMIT_UNTIL = max(_GLOBAL_RATE_LIMIT_UNTIL, time.monotonic() + wait)

# At read site (line 723): add lock-free read (float reads are atomic on CPython)
# — The read is fine; only the write needs locking.
```

---

### P3-B: Circuit Breaker HALF_OPEN Race

**File:** `phantom/llm/llm.py`  
**Class:** `CircuitBreaker`

**Problem:** `allow_request()` checks `_state == HALF_OPEN` and returns True without
atomically changing to something that prevents a second thread from also seeing HALF_OPEN.

**Fix:** Add `threading.Lock` to `CircuitBreaker.__init__` and wrap the HALF_OPEN
probe transition atomically.

---

### P3-C: Budget Tracking Per-Agent Not Global

**File:** `phantom/llm/llm.py:_check_budget()`  
**Lines:** 1277-1283

**Problem:** When the global tracer is unavailable, `current_cost = self._total_stats.cost`
measures only the current agent instance cost. Each of N sub-agents could each reach
`max_cost`, causing total spend of `N × max_cost`.

**Fix:** Log a WARNING when the tracer is unavailable instead of silently falling
back to local cost. Make the global tracer non-optional for multi-agent scans.

---

### P3-D: SHA-256 Message Dedup Hash Never Expires

**File:** `phantom/agents/state.py`
**Function:** `add_message()`

**Problem:** `_message_hashes` set grows indefinitely. For a 300-iteration scan,
a repeated probe payload (same response each time) is permanently blocked from
being re-tested after any state change.

**Fix:** Replace the unbounded set with an LRU-limited set (bounded to last N=500
unique hashes). Add a `force=True` parameter to `add_message()` for explicit re-injection.

---

## P4 — LOW Priority

### P4-A: Tool Schema Stub Fallback Allows Unvalidated Calls

**File:** `phantom/tools/registry.py:196-200`

**Problem:** Tools with missing schemas get a stub with no parameter definitions.
`_validate_tool_arguments()` passes with `None` schema = no validation.

**Fix:** If schema file is missing at registration time, log ERROR and prevent
the tool from being added to the registry. Make schema a required field.

---

### P4-B: Checkpoint HMAC Key Derivation Fallback

**File:** `phantom/checkpoint/checkpoint.py:128-131`

**Problem:** When no `PHANTOM_CHECKPOINT_KEY` is set, key is derived from
`os.getuid()` (or "win" on Windows). This is predictable and provides weak
tamper protection:
```python
hashlib.sha256(
    f"phantom-checkpoint-{os.getuid() if hasattr(os, 'getuid') else 'win'}"...
)
```
All Phantom installations on the same OS user would have identical HMAC keys.

**Fix:** On first run, generate a random 32-byte key and store it in
`~/.phantom/checkpoint.key` (mode 0600). Use this as the HMAC key.
Fall back to current behavior only if the file can't be created.

---

## Remediation Priority Matrix

| ID | Severity | Fix Effort | Files Changed | Apply? |
|---|---|---|---|---|
| P1-A | Critical | 10 min | `phantom_agent.py` | ✅ Now |
| P1-B | Critical | 30 min | `create_agent` tool | ✅ Now |
| P1-C | Medium | 5 min | `llm.py` | ✅ Now |
| P2-A | High | 20 min | `executor.py` | ✅ Now |
| P2-B | High | 2 min | `config.py` | ✅ Now |
| P2-C | High | 10 min | `rbac.py` | ✅ Now |
| P3-A | Medium | 5 min | `llm.py` | ✅ Now |
| P3-B | Medium | 15 min | `llm.py` | ✅ Now |
| P3-C | Medium | 15 min | `llm.py` | Next sprint |
| P3-D | Medium | 45 min | `state.py` | Next sprint |
| P4-A | Low | 30 min | `registry.py` | Next sprint |
| P4-B | Low | 45 min | `checkpoint.py` | Next sprint |
