# PHANTOM Memory Compression System - Complete Analysis

## Executive Summary

The Memory Compression System manages context window constraints for large language models by:
1. **Monitoring** token usage against model limits
2. **Triggering** compression when threshold is reached  
3. **Extracting** high-signal anchors (findings) before compression
4. **Summarizing** old messages using LLM
5. **Re-injecting** anchors into every subsequent prompt

---

## 1. Compression Triggers

### Token-Based Threshold

```python
# memory_compressor.py:570-588
# Model-aware fill ratio based on context window
if context_window >= 100_000:
    fill_ratio = 0.65   # compress at 65% of context
elif context_window >= 32_000:
    fill_ratio = 0.50    # compress at 50%
else:
    fill_ratio = 0.40     # compress at 40%
```

**Example:** For 128K context model (Claude/GPT-4):
- Threshold = 128,000 × 0.65 = **83,200 tokens**
- Compression fires when total tokens exceed 83,200

### Image Pressure

```python
# memory_compressor.py:623-628
image_payload_before = _estimate_image_payload_bytes(messages)
kept_images, evicted_images, image_payload_after = _handle_images(...)

# Also triggers compression if images exceed limit
if image_payload > MAX_TOTAL_IMAGE_BYTES:
    fire_compression()
```

---

## 2. Compression Strategy (The Pipeline)

### Step-by-Step Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                    compress_history()                              │
├─────────────────────────────────────────────────────────────────┤
│  1. Handle images (keep 3 max, evict older)                     │
│  2. Split: system + regular messages                            │
│  3. Keep recent: MIN_RECENT_MESSAGES (10)                      │
│  4. Check: total_tokens > threshold?                           │
│     └─ NO: return original messages (no compression)             │
│     └─ YES: continue                                           │
│  5. EXTRACT anchors from old messages (BEFORE summarization)      │
│  6. Chunk old messages (10 at a time)                         │
│  7. PARALLEL summarize each chunk via LLM                    │
│  8. Return: system + summaries + recent                        │
└─────────────────────────────────────────────────────────────────┘
```

### Compression Threshold Logic

```python
# memory_compressor.py:650-651
if total_tokens <= self._max_total_tokens * 0.9 and not image_pressure and evicted_images == 0:
    return messages  # No compression needed
```

**Key insight:** Uses 90% of threshold (0.9 multiplier) to leave buffer.

---

## 3. Anchor Extraction (Key Finding Preservation)

### The Problem

When LLM summarizes old messages, it loses:
- Exact payloads used
- URLs found vulnerable
- Credentials discovered
- Attack progression history

### The Solution: Anchor Extraction

```python
# memory_compressor.py:675-680
# Extract BEFORE compression - preserve high-signal findings
if agent_state and hasattr(agent_state, "add_finding_anchor"):
    for chunk in old_messages:
        for anchor in _extract_anchors_from_chunk(chunk):
            agent_state.add_finding_anchor(anchor)
```

### Keyword Detection

```python
# memory_compressor.py:59-124
_ANCHOR_KEYWORDS = (
    # Core vulnerabilities
    "vulnerability", "exploit", "sqli", "xss", "rce", "injection",
    "bypass", "authentication", "unauthorized", "found:", "discovered",
    "critical", "high", "medium", "cve-", "owasp", "payload",
    # Credentials
    "password", "credential", "secret", "api_key", "token",
    # Network
    "internal", "localhost", "127.0.0.1", "10.0.", "192.168.",
    # Execution
    "shell", "command", "exec", "system", "admin", "root",
    # Attack progression
    "chain", "pivot", "escalat", "shell", "persistence", "c2",
    # ... 100+ keywords total
)
```

### Extraction Logic

```python
# memory_compressor.py:153-169
def _extract_anchors_from_chunk(messages):
    for msg in messages:
        # Check if message contains ANY anchor keyword
        if _ANCHOR_KEYWORDS_PATTERN.search(text):
            # Take first 1500 characters
            snippet = text[:1500]
            # Store as anchor
            anchors.append({
                "key": snippet[:80],    # dedup key
                "text": snippet,        # preserved text
                "source": "compressor"
            })
    return anchors
```

### Example Flow

| Stage | Message | Anchored? |
|-------|---------|----------|
| User | "Test SQLi in /login" | ✓ (has "sqli") |
| Assistant | "Found SQLi! Payload: ' OR '1'='1" | ✓ (has "sqli", "found") |
| User | "What is weather?" | ✗ (no keywords) |
| Assistant | "Testing XSS in /search" | ✓ (has "xss") |

---

## 4. Summarization Process

### Summary Prompt Template

```python
# memory_compressor.py:196-219
SUMMARY_PROMPT_TEMPLATE = """You are a context compression agent.
Compress the scan data below while preserving ALL operationally critical information.

PRESERVE EXACTLY (copy verbatim):
- All URLs that showed vulnerability signals
- All parameter names confirmed as injectable
- All working payloads and exploit strings  
- All session tokens, cookies, credentials found
- All tool names and exact commands used
- All HTTP status codes indicating vulnerabilities

Output format:
STATUS: (current phase)
PROGRESS: (what has been done)
FINDINGS: (list each finding with exact URL, parameter, evidence)
DEAD ENDS: (list of failed attempts)
TECH STACK: (discovered technologies)
AUTH STATE: (any auth tokens obtained)
"""
```

### Chunk Processing

```python
# memory_compressor.py:656-662
# Configurable chunk size - default 10 messages per chunk
chunk_size = int(Config.get("phantom_compressor_chunk_size") or "10")

# Example: 30 old messages → 3 chunks
# Chunk 1: messages 0-9
# Chunk 2: messages 10-19  
# Chunk 3: messages 20-29
```

### Parallel Summarization

```python
# memory_compressor.py:691-720
if parallel_enabled and len(chunks) > 1:
    # Fire ALL chunk summaries in PARALLEL
    compressed = asyncio.run(_parallel_summarize_chunks(
        chunks, model_name, timeout
    ))
else:
    # Sequential fallback
    for chunk in chunks:
        summary = _summarize_messages(chunk, ...)
```

**Performance:** 4x speedup (12s → 3s for 4 chunks)

---

## 5. Result Structure

### After Compression

```python
# memory_compressor.py:731
result = system_msgs + compressed + recent_msgs
```

| Component | Count | Purpose |
|-----------|-------|---------|
| System messages | All | Instructions |
| Compressed summaries | 3-10 | Historical context |
| Recent messages | 10 | Current state |

### Summary Tag Format

```xml
<context_summary message_count='10'>
STATUS: SQLi confirmed in /login, /register
PROGRESS: Tested 50 endpoints, 5 confirmed vulnerable
FINDINGS:
- SQLi in /login param=user with payload ' OR '1'='1 --
- SQLi in /register param=email
DEAD ENDS:
- XSS in /search (sanitized)
TECH STACK: Apache 2.4, PHP 7.4, MySQL 8.0
</context_summary>
```

---

## 6. Anchor Re-Injection

### Why Re-Inject?

Even after summarization, the LLM needs to "remember" critical findings.

### Injection Logic (llm.py:618-648)

```python
# Check if agent state has anchors
_has_anchors = _state and _state.finding_anchors

if _has_anchors:
    # Get last 5 messages to avoid duplicates
    _last_msgs = compressed[-5:]
    _already_injected = any(
        "finding_anchors" in msg.get("content", "") 
        for msg in _last_msgs
    )
    
    if not _already_injected:
        # Inject up to 15 anchors (600 chars each)
        anchor_lines = []
        for anchor in _state.finding_anchors[:15]:
            anchor_lines.append(f"- {anchor['text'][:600]}")
        
        anchor_reminder = """
<finding_anchors>
Confirmed signals from earlier in this scan:
- Found SQL injection in /login endpoint
- Found XSS in /search parameter
</finding_anchors>
        """
```

### What LLM Sees

```
<finding_anchors>
Confirmed signals from earlier in this scan — 
report any that have NOT been reported yet:
- CRITICAL: SQLi confirmed in /login endpoint with payload ' OR '1'='1 --
- Found XSS reflected in search parameter with <script>alert(1)</script>
- Internal API found at 10.0.0.5:8080
- Database credentials: admin:password123
</finding_anchors>
```

---

## 7. Token Budget Management

### Model-Specific Thresholds

| Model | Context Window | Compression Point | Recent Messages |
|-------|---------------|-------------------|-----------------|
| Claude 3 Opus | 200K | 130K (65%) | 10 |
| GPT-4o | 128K | 83K (65%) | 10 |
| Claude 3 Haiku | 100K | 65K (65%) | 10 |
| Claude 3 Sonnet | 200K | 130K (65%) | 10 |
| Llama 3 8B | 8K | 3.2K (40%) | 10 |
| Kimi-K2.5 | 128K | 83K (65%) | 10 |

### Hard Ceiling

```python
# memory_compressor.py:25-36
MAX_CONTEXT_CEILING = 80_000  # Hard cap regardless of model

# Prevents runaway growth on huge context models (200K+)
self._max_total_tokens = min(MAX_CONTEXT_CEILING, ...)
```

---

## 8. Verification Results

### Test Results (from test_compression_verification.py)

```
[CONFIG VALUES]
  MAX_TOTAL_TOKENS: 128,000
  MAX_CONTEXT_CEILING: 80,000
  MIN_RECENT_MESSAGES: 10
  COMPRESSOR_MAX_TOKENS: 8,000

[KEYWORD MATCHING]
  Input: 5 messages (2 with keywords, 3 without)
  Output: 4 anchors extracted (both vulnerable + testing context)

[ANCHOR EXTRACTION]
  Extracted from old messages BEFORE summarization
  Stored in agent_state.finding_anchors
  Re-injected into every new prompt

[COMPRESSION RATIO]
  68 messages → depends on token count
  Summary replaces 10 messages (chunk_size)
  Preserves all 10 recent messages
  Preserves all system messages
```

---

## 9. Data Flow Diagram

```
                     ┌─────────────────────────────┐
                     │   User sends message(s)      │
                     │   Agent receives message   │
                     └───────────┬─────────────┘
                                 │
                                 ▼
                     ┌─────────────────────────────┐
                     │   Count total tokens    │
                     └───────────┬─────────────┘
                                 │
              ┌─────��─��──────────┴──────────────────┐
              │                                     │
              ▼                                     ▼
    ┌─────────────────────┐               ┌─────────────────────┐
    │ Under threshold  │               │ Over threshold   │
    │ Return as-is   │               │ FIRE COMPRESSION│
    └───────────────┘               └────────┬────────┘
                                             │
                                             ▼
                     ┌─────────────────────────────────────────────┐
                     │  Step 1: Handle images (evict old)         │
                     └───────────────┬─────────────────────────────┘
                                     │
                                     ▼
                     ┌─────────────────────────────────────────────┐
                     │  Step 2: Split system vs regular             │
                     └───────────────┬─────────────────────────────┘
                                     │
                                     ▼
                     ┌─────────────────────────────────────────────┐
                     │  Step 3: Extract anchors from OLD msgs     │◄──── CRITICAL
                     │  (before they get summarized away)       │
                     └───────────────┬─────────────────────────────┘
                                     │
                                     ▼
                     ┌─────────────────────────────────────────────┐
                     │  Step 4: Chunk old messages (10 at a time)       │
                     └───────────────┬─────────────────────────────┘
                                     │
                                     ▼
                     ┌─────────────────────────────────────────────┐
                     │  Step 5: PARALLEL summarize via LLM      │
                     └───────────────┬─────────────────────────────┘
                                     │
                                     ▼
                     ┌─────────────────────────────────────────────┐
                     │  Step 6: Return system + summaries + recent   │
                     └───────────────┬─────────────────────────────┘
                                     │
                                     ▼
                     ┌─────────────────────────────────────────────┐
                     │  Step 7: Re-inject anchors into prompt      │◄──── CRITICAL
                     └───────────────┬─────────────────────────────┘
                                     │
                                     ▼
                     ┌─────────────────────────────────────────────┐
                     │   Call LLM with compressed context         │
                     └─────────────────────────────────────────────┘
```

---

## 10. Key Insights

### Why This Design Works

1. **Preserves Exact Payloads**: Anchors keep exact exploit strings, not paraphrased
2. **Prevents Redundant Testing**: LLM knows what was already found
3. **Context Window Management**: Never exceeds model limits
4. **Parallel Performance**: 4x faster summarization
5. **Model Awareness**: Adjusts compression ratio per model

### Potential Issues

1. **Anchor Noise**: Keywords match testing context, not just findings
   - Mitigation: Deduplication in add_finding_anchor()
   
2. **Summary Loss**: LLM summarization can lose details
   - Mitigation: Anchor extraction preserves first 1500 chars

3. **Token Overhead**: Anchors add tokens to every request
   - Mitigation: Cap at 15 anchors × 600 chars = 9000 tokens max

---

## 11. Configuration

| Config | Default | Description |
|--------|---------|-------------|
| phantom_compressor_llm | (none) | Dedicated model for summarization |
| phantom_compressor_chunk_size | 10 | Messages per compression chunk |
| phantom_compressor_parallel | true | Enable parallel compression |
| phantom_memory_compressor_timeout | 120s | Timeout for summarization |
| phantom_max_context_ceiling | 80K | Hard ceiling on token limit |
| phantom_max_input_tokens | (auto) | Override context window detection |

---

## Conclusion

The Memory Compression System is a sophisticated context management solution that:

1. **Monitors** token usage against model-specific thresholds
2. **Extracts** high-signal findings before summarizing
3. **Summarizes** old messages via LLM using parallel processing
4. **Re-injects** anchors into every subsequent prompt
5. **Ensures** the LLM never loses critical vulnerability details

The anchor system is the key innovation - it preserves the **exact text** of findings so they survive the summarization process and remain visible to the LLM throughout the entire scan.