# REPORT 4 — Code-Verified Deep Dive & Corrections to Previous Reports

This report was produced by reading every relevant source file directly and
cross-checking every claim against the actual code. Where previous reports
(REPORT_1, REPORT_2, REPORT_3) made incorrect or incomplete statements, the
correction is documented here with file and line references.

---

## 1. Corrections to Previous Reports

### 1.1 WRONG: "No tool output truncation before history storage"

REPORT_2 and REPORT_3 both claimed there is no truncation of tool output before
it is stored in conversation history. This is **incorrect**.

**What the code actually does** (`phantom/tools/executor.py`, function
`_format_tool_result_with_meta`):

Per-tool character limits are applied **before** the result is stored:

| Tool | Normal limit | Burst limit (high-signal) |
|---|---|---|
| `terminal_execute` | 4,000 chars | 8,000 chars |
| `nuclei` | 5,000 chars | — |
| `sqlmap` | 5,000 chars | — |
| `ffuf` | 3,000 chars | — |
| `nmap` | 3,000 chars | — |
| All others | 2,000 chars | — |

"High signal" burst mode activates for `terminal_execute` when the output
contains any of: `<script`, `sql`, `jwt`, `traceback`, `error`, `exception`,
`password`, `token`, `secret`, `admin`, `injection`, `xss`, `lfi`, `rfi`,
`ssrf`, `rce`, `xxe`.

**Truncation strategy**: head + tail, middle discarded:
```
start_part + "...[middle truncated]..." + end_part
```
Each part is half the limit. This means findings that appear in the middle of
tool output (e.g. the 50th line of nmap output listing an interesting port) are
silently dropped.

**Impact**: The LLM never sees middle-of-output content. For tools like `ffuf`
that produce hundreds of lines, almost all findings are in the middle and will
be lost.

---

### 1.2 WRONG: "Adaptive scan mode reduces cost automatically"

REPORT_3 described the adaptive scan downgrade feature (deep → standard →
quick when budget thresholds are hit) as if it were active. It is **disabled by
default**.

**Code**: `phantom/config/config.py`
```python
phantom_adaptive_scan = "false"
```

The feature exists and is implemented in `phantom/llm/llm.py` but it never
activates unless the operator explicitly sets `PHANTOM_ADAPTIVE_SCAN=true`.

---

### 1.3 WRONG: "Model routing uses cheaper models for tool-heavy turns"

Same situation. The routing feature is **disabled by default**.

**Code**: `phantom/config/config.py`
```python
phantom_routing_enabled = "false"
```

Every LLM call uses the primary model (`claude-3-7-sonnet-20250219` by default)
regardless of whether the turn is a reasoning step or just a tool execution.

---

### 1.4 INCOMPLETE: "Prompt caching reduces cost for Anthropic"

REPORT_3 mentioned prompt caching. The implementation exists (`_add_cache_control()`
in `phantom/llm/llm.py`), but it only applies to the **system message**, and
only when `enable_prompt_caching=True` is set in `LLMConfig`. The conversation
history — which is the largest and most expensive part of each request — is
**not cached**. Cache hits only save the ~10k–40k token system prompt, not the
50k+ history.

---

### 1.5 INCOMPLETE: "Validation agents don't inherit parent context"

REPORT_1 described context inheritance as a general mechanism. What was not
documented: validation agents already have a partial fix baked in.

**Code**: `phantom/tools/agents_graph/agents_graph_actions.py` (~line 297):
```python
if any(kw in agent_name.lower() for kw in
       ["validation", "validator", "verify", "verifier", "check", "checker"]):
    inherit_context = False
```

If the spawned agent's **name** contains one of those keywords, `inherit_context`
is forced to `False` regardless of what the parent requested. This is an
important safeguard but it only works if agent names follow the convention.

---

## 2. Agent Loop — Verified Architecture

### 2.1 Iteration Lifecycle

Each agent runs a `while True` loop in `phantom/agents/base_agent.py`. One pass
through the loop is one "iteration". The iteration counter is incremented at the
start of each pass (`state.increment_iteration()`).

**Important exception**: when a parent agent calls `wait_for_message`, it enters
an `asyncio.sleep(0.5)` polling loop. The iteration counter is **not**
incremented during this wait. Waiting for child agents is "free" in iteration
terms. This is correct behavior but it means the iteration count understates
total elapsed time for orchestrator agents.

### 2.2 Phase Gates

Agents move through phases: `recon` → `scanning` → `exploitation` → `reporting`.
Phase transition is gated by `_check_phase_transition()` which checks:
- Minimum iterations spent in current phase
- Whether the LLM's last message contained certain trigger phrases

Phase minimums are configurable but default to low values (2–3 iterations per
phase). In practice the LLM's own judgment about when to advance phases is the
dominant factor.

### 2.3 Stall Detection

`_detect_stall()` in `base_agent.py` checks whether the last N messages
(default: 5) contain unique tool calls. If all N recent tool calls are identical
(same tool, same arguments), the agent is considered stalled and the system
injects a prompt: "You appear to be repeating the same action. Try a different
approach."

This catches infinite tool loops but does **not** catch "semantic stalls" where
the agent keeps calling different tools but makes no actual progress toward
finding vulnerabilities.

### 2.4 Checkpointing

Every `CHECKPOINT_INTERVAL` iterations (default: 10), the agent saves its full
state to disk. State includes: conversation history, hypothesis ledger, phase,
iteration count, spawned agents. This allows resuming after crash or manual stop.

Checkpoint files are stored in the scan output directory as `agent_state.json`.

---

## 3. Memory Compression — Verified Details

### 3.1 When Compression Triggers

`phantom/llm/memory_compressor.py`. Compression is triggered by
`_check_and_compress()` in `llm.py` before every LLM call. It fires when:

```
len(conversation_history) >= compression_threshold
```

Where `compression_threshold` is calculated as:
```
max(MIN_THRESHOLD, int(max_tokens * COMPRESSION_RATIO))
```

With defaults: `MIN_THRESHOLD=20`, `COMPRESSION_RATIO=0.6`. For a 200k token
context window this means compression starts when history exceeds ~120k tokens
worth of messages — or when the raw message count hits 20, whichever comes
first.

In practice the message count of 20 triggers first for typical scans. This
means compression runs very frequently (every ~10 turns after initial fill).

### 3.2 Compression Algorithm

The compressor processes messages in chunks of 10 (was 5 in older versions).
For each chunk it calls the LLM with a prompt asking for a summary. The summary
replaces the original messages. The most recent `KEEP_RECENT=8` messages are
never compressed and are always kept verbatim.

**Cost of compression itself**: Each compression call sends ~5k–15k tokens
(the chunk being compressed) and receives ~500–2000 tokens (the summary). At
claude-3-7-sonnet pricing (~$3/$15 per M tokens in/out), a compression call
costs roughly $0.02–$0.05. A typical 200-iteration scan compresses 10–15 times
per agent, adding $0.20–$0.75 per agent just for compression overhead.

### 3.3 What Compression Loses

When the LLM summarizes 10 messages into ~200 tokens, specifics are lost:
- Exact HTTP response bodies
- Specific parameter names found vulnerable
- Exact payloads that worked
- Intermediate findings that weren't flagged as "important"

The summary might say "scanned /api/users, found 3 endpoints" but lose the
exact parameter names, response codes, and error messages that would be needed
to reproduce the finding. This directly hurts the agent's ability to write
accurate PoCs later.

---

## 4. Tool Execution — Verified Details

### 4.1 Terminal Session Architecture

Each agent gets a **persistent terminal session** (`terminal_session.py`). The
session is a PTY (pseudo-terminal) subprocess running a shell. Commands are
written to the PTY's stdin and output is read until a sentinel marker is seen.

**Problem**: Output reading is time-bounded and sentinel-based. If a command
produces output slowly (e.g. a long nmap scan), the reader may timeout and
capture partial output. The remaining output is buffered in the PTY and bleeds
into the next command's output capture window.

### 4.2 Concurrent Terminal Access

`terminal_manager.py` maintains one session per agent. Agents cannot access
each other's terminals. This is correct isolation but it means agents cannot
share tool results — if two agents both run the same nmap scan, the scan runs
twice and the results are never merged.

### 4.3 Tool Result Metadata

Every tool result is wrapped with metadata by `_format_tool_result_with_meta`:
- Tool name
- Execution time (ms)
- Exit code
- Truncation indicator (if truncated)
- Character count before/after truncation

This metadata is included in the message stored to history, adding ~100–200
chars of overhead per tool call. Over 200 tool calls this is ~20k–40k chars of
pure metadata injected into history. Not a major cost driver but not zero.

---

## 5. Agent Spawning & Context Inheritance — Verified Details

### 5.1 Context Inheritance Mechanics

When `create_agent` is called with `inherit_context=True`, the **full**
conversation history of the parent agent at the moment of spawning is copied
into the child agent's initial history. This is the primary cause of token
explosion when sub-agents are spawned mid-scan.

Example: Parent agent has 80k tokens of history at iteration 150. It spawns 5
exploitation agents with `inherit_context=True`. Each child starts with 80k
tokens already in history, plus adds its own tool calls. If each child runs
50 iterations and spawns 0 sub-agents, total tokens generated:

```
Parent:   200 iters × 100k avg input = 20M tokens
Children: 5 × 50 iters × 130k avg input = 32.5M tokens
Total:    52.5M input tokens
```

At $3/M tokens: **$157.50 for one scan**.

### 5.2 Batch Completion Spike

When multiple child agents finish simultaneously, the parent's next iteration
receives all their completion reports at once. These reports contain summaries
of each child's work, typically 500–2000 tokens each. Ten children finishing
at the same time injects 5k–20k tokens into the parent's history in a single
step — a sudden spike that may itself trigger compression.

### 5.3 Agent Depth Limits

Hard limits (configurable via env vars):
- `PHANTOM_MAX_CONCURRENT_AGENTS=20`
- `PHANTOM_MAX_TOTAL_AGENTS=100`
- `PHANTOM_MAX_AGENT_DEPTH=5`

These prevent runaway spawning but 100 total agents is a very high cap. A scan
that hits the cap will have spent enormous cost to get there.

---

## 6. Reporting Pipeline — Verified Details

### 6.1 CVSS Scoring

CVSS scores are **LLM-generated**, not computed from a standard formula. The
LLM is asked to produce a CVSS vector string and a numeric score. There is a
validation step that parses the vector, but if the LLM produces a plausible-
looking but wrong vector, the validation passes anyway.

### 6.2 Deduplication

Two-stage deduplication:
1. **Hash-based**: exact duplicate tool-call results are dropped
2. **LLM-based**: `dedupe.py` sends pairs of findings to the LLM and asks if
   they describe the same vulnerability. Cost: O(N²) LLM calls for N findings.
   For 20 findings this is up to 190 comparison calls. In practice bounded to
   ~50 pairs by a similarity pre-filter, but still adds meaningful cost.

### 6.3 PoC Auto-Replay

Found in `reporting_actions.py`. When a PoC is generated, it is automatically
re-executed as a background `asyncio.create_task`. The replay output is checked
for "failure words": `error`, `exception`, `fail`, `traceback`, `not found`.

**Critical bug**: this logic is inverted for many real exploits. A SQLi PoC
that successfully extracts data will output something like:
```
[*] Error-based injection confirmed
[*] Extracting...
```
The word "error" appears → replay marked as FAILED → finding confidence
downgraded → potentially dropped from report.

The same problem applies to any tool that uses the word "error" to describe a
discovered vulnerability (which is most of them).

---

## 7. System Prompt — Active Cost Harm

The system prompt (`phantom/agents/PhantomAgent/system_prompt.jinja`) contains
this instruction:

> "Real vulnerability discovery needs 2000+ steps MINIMUM"

This is a hard-coded instruction telling the LLM it should burn at least 2000
iterations per scan. Combined with the default `max_iterations=500`, the LLM
is being told it should run 4× longer than it's allowed to. The practical
effect: the LLM treats the iteration limit as a constraint preventing it from
doing its job "properly", and tends to be verbose and exploratory rather than
efficient and targeted.

This single instruction is in direct conflict with every cost-saving mechanism
in the system.

---

## 8. Skills System — What It Actually Does

36 skill `.md` files are loaded based on target detection and scan mode. Skills
are injected into the system prompt as plain text. They provide:
- Vulnerability-specific testing methodology (what parameters to test, what
  payloads to try, what responses indicate success)
- Framework-specific attack patterns (e.g. Next.js path traversal, NestJS guard
  bypass, FastAPI dependency injection)
- Scan-mode pacing (how many iterations to spend per phase)

Skills are the most useful part of the system for directing agent behavior.
A well-written skill can compress 50 iterations of exploratory fumbling into
10 targeted ones. The current skills are comprehensive but they are generic —
they do not adapt to findings made during the scan.

---

## 9. What Is Missing / Not Implemented

The following items were **not found** in the codebase despite being mentioned
or implied in documentation:

1. **Cross-agent finding sharing**: No mechanism exists for one agent to tell
   another "I found X at endpoint Y, you should try Z there." Agents operate
   in silos. The only sharing is via completion reports (one-way, one-time).

2. **Dynamic payload generation**: Payloads are static strings in skill files
   or hardcoded in tool wrappers. No component generates payloads adapted to
   observed application behavior.

3. **Session/auth token management**: No component automatically detects that
   a login form exists, logs in, and injects the resulting session cookie into
   subsequent tool calls. Authentication-required endpoints are effectively
   invisible to the scanner.

4. **Response diffing**: No component compares two responses to detect subtle
   behavioral differences (e.g. 1ms timing difference indicating blind SQLi).
   The LLM is expected to notice these from text output, which it often misses.

5. **Scan deduplication across agents**: If 3 agents all decide to scan the
   same endpoint with the same tool, all 3 scans run. There is no "already
   being scanned" registry.

---

## 10. Summary of Critical Facts

| Item | Reality |
|---|---|
| Tool output truncation | EXISTS — head+tail, middle discarded |
| Adaptive scan mode | OFF by default |
| Model routing | OFF by default |
| Prompt caching | Partial (system msg only, not history) |
| Validation agent context isolation | Partial (name-based keyword check) |
| PoC replay success detection | Buggy (false negatives for most real exploits) |
| Cross-agent result sharing | Not implemented |
| Dynamic payload adaptation | Not implemented |
| Auth/session handling | Not implemented |
| "2000+ steps minimum" instruction | Active in system prompt, increases cost |
| Compression runs | Every ~10 turns, each call costs $0.02–$0.05 |
| Child context inheritance cost | Full parent history copied per child |
