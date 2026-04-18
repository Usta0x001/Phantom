# Phantom — Memory & State Model

## 1. Memory Architecture Overview

Phantom has **four distinct memory layers** that operate at different scopes and
persistence levels:

```
┌─────────────────────────────────────────────────────────────────┐
│ LAYER 1: LLM Context Window (Ephemeral, per-call)               │
│   Contents: [system_prompt] + [anchors] + [summaries] + [recent]│
│   Scope: Single LLM API call                                     │
│   Max size: MAX_CONTEXT_CEILING = 80,000 tokens (default)        │
└─────────────────────────────────────────────────────────────────┘
         ↑ compressed from
┌─────────────────────────────────────────────────────────────────┐
│ LAYER 2: AgentState.messages (In-Process, volatile)             │
│   Contents: Full conversation history (trimmed at MAX_MSG=50)   │
│   Scope: Single agent instance lifetime                          │
│   Overflow: messages → archived_messages (max 200) + LLM summary│
└─────────────────────────────────────────────────────────────────┘
         ↑ feeds into
┌─────────────────────────────────────────────────────────────────┐
│ LAYER 3: External Structured Memory (In-Process, persistent)    │
│   HypothesisLedger: hypothesis_id → {surface, vuln_class,       │
│                     evidence_for, evidence_against, status}     │
│   CoverageTracker: (surface, vuln_class) → tested flag          │
│   CorrelationEngine: confirmed findings → chain suggestions      │
│   AttackGraph: networkx directed graph of vuln relationships     │
│   Scope: Shared across all agents in same process                │
│   Persistence: Saved in checkpoint JSON                          │
└─────────────────────────────────────────────────────────────────┘
         ↑ persisted by
┌─────────────────────────────────────────────────────────────────┐
│ LAYER 4: Checkpoint Files (On-Disk, durable)                    │
│   Contents: Full JSON snapshot of all in-process state          │
│   Scope: Run-level persistence across process restarts           │
│   Trigger: Every N iterations (configurable) + on abort          │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. Message History Lifecycle (Detailed)

### Message Addition
```python
# state.py:199
def add_message(self, role, content, thinking_blocks=None):
    # Guard 1: SHA-256 dedup (global, never expires)
    content_hash = sha256(f"{role}\x1f{content}")
    if content_hash in self._message_hashes:
        return  # silently drop duplicate
    self._message_hashes.add(content_hash)
    
    # Guard 2: Window dedup (last 5 messages, weaker)
    for m in self.messages[-5:]:
        if m["role"] == role and m["content"] == content:
            return
    
    # Append
    self.messages.append({"role": role, "content": content})
    # Note: thinking_blocks are DROPPED here
```

### Message Cleanup (periodic, called after each tool execution)
```python
# base_agent.py:1084  _cleanup_message_history()
threshold = MAX_MESSAGES_BEFORE_CLEANUP * cleanup_multiplier
# deep scan: 50 * 4 = 200 messages before cleanup
# other: 50 * 2 = 100 messages
# If len(messages) > threshold → state.cleanup_old_messages()
```

### cleanup_old_messages
```python
# state.py:89
# Takes messages[:-50] and moves to archived_messages (max 200 total)
# Keeps messages[-50:]
```

### LLM Context Preparation (every iteration)
```python
# llm.py._prepare_messages()
# → MemoryCompressor.compress_history(messages, agent_state)
#   1. Count tokens
#   2. If > _max_total_tokens (model-aware, typically ~83K for 128K model):
#      a. Extract finding_anchors from to-be-compressed messages
#      b. Chunk and parallel-summarize with secondary LLM
#      c. Prepend anchors block (<finding_anchors>...</finding_anchors>)
#      d. Append last MIN_RECENT_MESSAGES=15 verbatim
# → Prepend system_prompt as {"role": "system", "content": system_prompt}
```

---

## 3. HypothesisLedger Internal Model

The ledger is Phantom's most important memory construct. From `hypothesis_ledger.py`:

```
HypothesisLedger {
    _hypotheses: dict[hypothesis_id, Hypothesis]
    _tested_payloads: dict[(surface, vuln_class, payload_hash), TestResult]
    _correlation_engine: CorrelationEngine (weakref-like)
}

Hypothesis {
    id: str
    surface: str          # "endpoint::parameter"
    vuln_class: str       # "sqli", "xss", etc.
    status: str           # open | testing | confirmed | rejected
    priority_score: float
    evidence_for: list[str]
    evidence_against: list[str]
    successful_payloads: list[str]
    metadata: dict
}
```

**Scoring logic (inferred from get_scored_hypotheses):**
- Confirmed hypotheses score highest
- Open/testing hypotheses scored by evidence ratio and payload success rate
- Rejected hypotheses excluded from scoring

**LLM interaction:** The LLM must call specific tools (`add_hypothesis`,
`record_payload_test`, `confirm_hypothesis`, `reject_hypothesis`) to update the ledger.
The LLM's compliance with the mandated workflow is NOT enforced programmatically —
it depends entirely on prompt compliance.

---

## 4. Memory Compression: Failure Modes

### FM-M1: Anchor Keyword Over-Triggering

`_ANCHOR_KEYWORDS` in `memory_compressor.py` contains 120+ keywords covering nearly
every common web security term. Almost ANY message about security testing will match:
"endpoint", "parameter", "response", "error", "status", "config", "session", etc.

**Effect:** Compression almost never removes security-testing messages from the
anchor list. The `anchors` block grows to its limit (15 anchors) and stabilizes.
The benefit of anchoring (preservation of key findings) is diluted by noise.

### FM-M2: Summary Quality Dependency

The compressor calls a secondary LLM (configurable via `phantom_compressor_llm`,
default: same as primary). If this call fails, it falls back to a truncated
concatenation of raw messages (up to 8,000 characters).

**Effect:** On LLM failure during compression, the 8KB fallback summary is a raw
text dump with no structure. The next iteration receives this as context. The LLM
must then re-derive all facts from unstructured text, creating a risk of hallucination.

### FM-M3: SHA-256 Message Hash Never Expires

`_message_hashes` is a `set[str]` that grows indefinitely. Every message ever added
to state adds a hash. For long-running scans (300 iterations, many tool outputs):
- Each tool result can be 1-100KB of text
- Even if the content is logically different, similar content (e.g., repeated 403
  responses from the same endpoint) will be deduplicated
- **Legitimate retries with identical payloads are silently dropped**

This behavior is documented as intentional (prevent flooding) but creates an
unexpected side-effect: if an injection protection previously blocked a payload,
a later re-attempt with the exact same content is silently dropped, making it
impossible for the LLM to re-test after remediation.

### FM-M4: Parallel Compression Race

`_parallel_summarize_chunks` uses `asyncio.gather` with bounded concurrency (4).
The chunks are created from the ordered message list. If compression is triggered
while a sub-agent is simultaneously writing to shared state (hypothesis_ledger),
there is a window where the chunks being summarized are inconsistent with the
current hypothesis state.

### FM-M5: Archived Messages Not Fed to Compressor

`archived_messages` (up to 200 messages) are stored but never re-injected into
the LLM context. They are snapshot in checkpoint files but effectively inaccessible
to future iterations. This means historical evidence of early-stage findings may
be lost after the 200-message archive fills.

---

## 5. Context Token Efficiency Analysis

### System Prompt Overhead (Per-Call)

The system prompt is 827 lines of Jinja2 that renders to approximately:
- Base prompt text: ~8,000-10,000 tokens
- Tool schemas (28 tool categories, many tools each): ~4,000-8,000 tokens
- Skills content (loaded per scan mode): ~1,000-3,000 tokens

**Total fixed overhead per LLM call: ~13,000-21,000 tokens**

With a 128K model and 65% fill ratio threshold (~83K tokens), the usable
conversation space is approximately 83K - 21K = ~62,000 tokens.

For a 300-iteration scan with average tool outputs of 2KB:
- 300 iterations × 2 tool calls × 2KB each = 1.2MB raw tool output
- At 4 chars/token: 300,000 tokens of tool output vs. 62,000 available
- Compression ratio required: ~5:1

This is achievable but means a scan producing substantial output will compress
5+ times during its lifetime. Each compression adds summary latency
(LLM call) and risks information loss.

### Hypothesis Context Injection

`base_agent.py:1112 _build_hypothesis_context()` adds per-iteration:
- `<current_hypothesis>` block (top-scored hypothesis)
- `<supporting_evidence>` block (up to 5 evidence items, 300 chars each)
- Filters history to include only messages mentioning active surface/vuln class

**Side effect:** The filtering logic at line 1175-1215 uses simple string search.
A message mentioning `/api/login` is always included if the active surface is
`/api/login::username`. This creates no boundary: if the current hypothesis is
about login, ALL messages mentioning login are included verbatim, even if they
were from a completely different testing phase.

---

## 6. State Consistency Guarantees

| Property | Mechanism | Guarantee Level |
|---|---|---|
| Message ordering | `list.append()` (GIL-protected) | Strong for single-threaded agent |
| Message dedup | SHA-256 hash set | Strong (never sends duplicate if same bytes) |
| Hypothesis state | In-memory dict, no lock | Weak (concurrent sub-agent writes) |
| Coverage state | In-memory dict, no lock | Weak |
| Checkpoint atomicity | Single JSON write | Weak (no atomic rename) |
| Token budget | Global counter + lock | Strong (thread-safe) |
| RBAC state | Global singleton, no lock | Weak |
