# REPORT 3 — Cost Analysis & Token Flow

## The Core Problem

LLM cost = (input tokens per call) × (price per input token) × (number of calls).

Phantom has a compounding cost problem: all three factors grow simultaneously
during a deep scan. This section traces exactly where every token comes from.

---

## 1. What Is in Every LLM Request

Every single LLM call (every iteration, every agent) sends this message list:

```
[system message]     ← system_prompt (~10k–40k tokens, fixed per agent)
[user message]       ← agent_identity block (~30 tokens)
[user/assistant ...]  ← compressed conversation history (variable, can be 50k+)
[user message]       ← "Continue the task." sentinel if last msg was assistant
```

### 1a. System Prompt Size

The system prompt is built once and reused for every call. Its size depends on
the agent type and scan mode. Here is the breakdown:

| Component | Approx tokens |
|---|---|
| Behavioral rules (lines 1–165) | ~2,500 |
| Vulnerability priorities (lines 167–205) | ~500 |
| Multi-agent rules (lines 207–328) | ~1,200 |
| Tool call format + tool schema | ~2,000–4,000 |
| Environment description (lines 391–448) | ~600 |
| Scan mode skill (e.g. deep.md ~157 lines) | ~1,500 |
| Per-vulnerability skill (e.g. sql_injection.md) | ~3,000–6,000 each |

A root agent in deep mode with no extra skills = ~9,000–12,000 tokens.
A SQL injection sub-agent loading `sql_injection.md` + `deep.md` = ~15,000–20,000 tokens.
An agent loading 3 skill files = ~22,000–28,000 tokens.

**This system prompt is sent on every single iteration call. For 100 iterations
of one agent, you pay for the system prompt 100 times.**

At `claude-3-5-sonnet` pricing (~$3/M input tokens), a 20K-token system prompt
costs **$0.06 per iteration**. Over 100 iterations = **$6 just for the system
prompt** of one agent.

### 1b. Conversation History Growth

The conversation history is the dominant variable cost. Here is how it grows:

**Starting state**: 1 user message (the task). ~100 tokens.

**After 1 iteration**:
- +1 assistant message (LLM response with thinking + tool call): ~200–800 tokens
- +1 user message (tool result): depends on the tool

**Tool output sizes (typical)**:
| Tool | Typical output size |
|---|---|
| `nmap -sV -p 1-1000 target` | 2,000–8,000 tokens |
| `nuclei -target url` | 3,000–15,000 tokens |
| `sqlmap --level=3` | 4,000–12,000 tokens |
| `ffuf -w wordlist` | 5,000–20,000 tokens |
| `katana -u target` | 3,000–10,000 tokens |
| `subfinder -d target` | 500–3,000 tokens |
| Python script output | 200–10,000 tokens |

**After 10 iterations with common recon tools**, the history is already
20,000–80,000 tokens. The compressor fires at 76,800 tokens (60% of 128K
default). Once it fires, the history shrinks — but it grows again quickly
because new tool outputs keep being added untruncated.

### 1c. Compression Calls (The Hidden Cost)

Every time the history exceeds 76,800 tokens, `MemoryCompressor` fires during
`_prepare_messages`. It:
1. Keeps the 15 most recent messages uncompressed.
2. Sends the older messages (in 4,000-token chunks) to the LLM for
   summarization, 1,500-token output per chunk.

If the pre-compression history has 100,000 tokens and the 15 recent messages
use 20,000 tokens, there are 80,000 tokens of old messages = 20 chunks. That
is **20 extra LLM calls** just to compress the history, each costing their own
input+output tokens.

For claude-3-5-sonnet:
- 20 compression calls × 4,000 input tokens = 80,000 input tokens = **$0.24**
- 20 compression calls × 1,500 output tokens = 30,000 output tokens = **$0.45**
- **Total compression cost for one compression event: ~$0.69**

If compression fires 5 times during a deep scan (iterations 30, 60, 90, 120,
150), compression alone costs **~$3.45**.

### 1d. Sub-Agent Context Inheritance

When `create_agent(inherit_context=True)` is called (the default), the child
agent receives a `deepcopy` of the parent's full conversation history. A parent
at iteration 40 may have 40,000 tokens of history. Every child agent starts
with 40,000 input tokens already loaded before making its first LLM call.

With 15 concurrent agents each inheriting 40,000 tokens of parent context:
- 15 × 40,000 = 600,000 tokens of inherited context sent in first-iteration
  calls alone.

At $3/M input tokens = **$1.80 just for first-call inherited context**.

### 1e. Agent Completion Reports

When a sub-agent calls `agent_finish`, it sends a structured XML completion
report to the parent. The parent's `_check_agent_messages` injects this report
as a user message into the parent's conversation history. Each report adds
~500–2,000 tokens to the parent's history permanently.

With 15 sub-agents each completing and reporting: +7,500–30,000 tokens in the
parent's history.

---

## 2. Token Flow Per Iteration (Concrete Example)

**Scenario**: Root agent in deep mode, iteration 50 of 300.

| Component | Input tokens |
|---|---|
| System prompt (root agent + deep.md) | 12,000 |
| Agent identity block | 30 |
| Compressed history (50 messages after several compressions) | 35,000 |
| Phase gate message (if at 33%) | 100 |
| Ledger summary (if iteration % 10 == 0) | 300 |
| **Total input tokens** | **~47,430** |

Output: ~300–1,000 tokens (a tool call with reasoning).

At $3/M in + $15/M out (claude-3-5-sonnet):
- Input: 47,430 × $3/M = **$0.14**
- Output: 600 × $15/M = **$0.009**
- **Per iteration: ~$0.15**

Over 300 iterations: **$45 for the root agent alone**.

Add 8 sub-agents averaging 100 iterations each at $0.10/iteration:
**8 × 100 × $0.10 = $80**.

Add compression costs: ~$10.

**Estimated total for one deep scan on a medium target: $100–$200** using
claude-3-5-sonnet. Less on cheaper models, more if agents spawn additional
sub-agents.

---

## 3. The Top 5 Cost Drivers (Ranked)

### #1 — Untruncated tool outputs stored in history
**Impact: VERY HIGH**

Every `terminal_execute` and `python_execute` result is stored verbatim in
`state.messages`. A single `ffuf` run on a wordlist with 5,000 entries can
return 10,000+ tokens. This one tool call adds 10,000 tokens to every
subsequent LLM call for the rest of that agent's lifetime.

**Fix priority: HIGHEST**. Truncate tool outputs before storing them.

### #2 — System prompt sent every iteration
**Impact: HIGH**

A 20,000-token system prompt × 300 iterations = 6,000,000 input tokens just
for the system prompt. This is unavoidable with the current stateless API
design, but the system prompt can be made smaller.

**Fix priority: HIGH**. Enable prompt caching (already supported for Anthropic
models — `enable_prompt_caching=True`). Reduce skill file sizes.

### #3 — Sub-agent context inheritance by default
**Impact: HIGH**

`inherit_context=True` by default means every child starts with the full parent
history. Most child agents don't need the full parent history — they need a
summary of what the parent found, not every tool call the parent made.

**Fix priority: HIGH**. Change default to `inherit_context=False` and pass a
targeted summary instead.

### #4 — Compression using the same expensive model
**Impact: MEDIUM-HIGH**

Compression calls use `PHANTOM_COMPRESSOR_LLM` if set, but the default is the
same model as the agent. Summarization is a simple task that does not require
a frontier model.

**Fix priority: MEDIUM**. Always configure `PHANTOM_COMPRESSOR_LLM` to a cheap
fast model (e.g. `gpt-4o-mini`, `gemini-flash-1.5`).

### #5 — Too many agents running simultaneously
**Impact: MEDIUM**

Deep mode allows 15 concurrent agents. With 15 agents each making LLM calls
in parallel, cost per minute scales linearly. Most of these agents spend
significant time in recon phases that find nothing new.

**Fix priority: MEDIUM**. Reduce `max_agents` for most scans. Reserve 15-agent
capacity for very large targets.

---

## 4. The Actual Numbers From Your Runs

Looking at existing scan runs in `phantom_runs/`, the pattern of stopping
mid-run strongly suggests you hit the cost cap (or the discomfort point) around
iteration 30–60 of a deep scan — which aligns exactly with the math above.

At iteration 50, the root agent has already spent ~$7–$15 just in LLM calls,
and the sub-agents it spawned (5–10 of them) have each spent another $2–$8.
Total at iteration 50 across all agents: **$20–$50** before finding anything
deeply interesting.

---

## 5. Input Token vs Output Token Split

Across a typical scan:
- **Input tokens: ~92–95%** of all tokens
- **Output tokens: ~5–8%** of all tokens

This is important: output tokens cost 5× more per token on most models, but
the volume is low because the streaming parser stops at `</function>`. The
dominant cost is input token volume, especially the system prompt + history
paid on every single call.

---

## 6. Cost Reduction Quick-Reference

| Action | Expected savings | Effort |
|---|---|---|
| Set `PHANTOM_COMPRESSOR_LLM=gpt-4o-mini` | 30–60% of compression costs | 2 minutes |
| Enable Anthropic prompt caching | 30–50% input cost on Anthropic models | 5 minutes |
| Truncate tool outputs to 2,000 tokens before storing | 40–60% history growth reduction | 1 hour |
| Change sub-agent `inherit_context` default to `False` | 20–40% first-call input reduction | 30 minutes |
| Reduce `max_agents` to 5 for standard scans | Linear reduction in concurrent agent cost | 2 minutes |
| Use `standard` instead of `deep` profile | 50% fewer iterations cap | Immediate |
| Set `PHANTOM_MAX_REQUEST_CHARS=400000` | Fewer runaway oversized requests | 2 minutes |
