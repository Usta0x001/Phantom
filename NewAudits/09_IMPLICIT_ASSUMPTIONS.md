# Phantom — Implicit Assumptions & Design Debt

## What the System Assumes to Be True (But Does Not Verify)

### A1: LLM Will Follow the System Prompt Reliably

**Assumed:** The 827-line system prompt is sufficient to deterministically
control agent behavior across all scenarios.

**Reality:**  
- LLMs are probabilistic. Instructions are guidance, not hard constraints.
- At >50% context fill (e.g., iteration 200 of 300), the system prompt has lower
  relative weight than recent tool outputs.
- The system prompt itself is never reinjected after the first call — it is only in
  the system role once, at position 0 of the message list.
- "MANDATORY" and "NEVER" in natural language are suggestions, not executable rules.

**Observable symptom:** The `_no_action_streak` counter exists precisely because
the LLM predictably fails to call tools when instructed to always do so.

---

### A2: Hypothesis Ledger Is Used as Designed

**Assumed:** The LLM calls `add_hypothesis` → `has_tested_payload` → `record_payload_test`
→ `confirm/reject_hypothesis` in the specified order for every test.

**Reality:**  
- No code path enforces this sequence.
- The LLM may call `confirm_hypothesis` without a prior `add_hypothesis` (orphan
  confirmation).
- The LLM may test without recording (`record_payload_test` skipped).
- In practice, the most likely failure is: LLM calls `confirm_hypothesis` directly
  from a finding without earlier ledger registration.

**Observable symptom:** Coverage tracker and ledger may show 0 entries even after
a successful scan (agent wrote report without using the ledger).

---

### A3: Memory Compression Preserves Operationally Critical Information

**Assumed:** The LLM summarizer (memory_compressor) will retain all exploit details,
payloads, and credential strings verbatim.

**Reality:**  
- The compressor itself is an LLM call. LLMs paraphrase by nature.
- "Copy vulnerability evidence verbatim" (in the summary prompt) is a best-effort
  instruction. The summarizer model (default: same as primary model, or a cheaper one)
  may fail to identify which bytes are "evidence" vs. "analysis."
- Payload strings like `' OR '1'='1 --` may be normalized or truncated by the
  summarizer's tokenizer before output.

**Observable symptom:** After compression events, the LLM reports vulnerabilities
with generic descriptions ("SQL injection in login parameter") instead of exact
payload evidence.

---

### A4: Sub-Agents Operate as Isolated, Specialized Workers

**Assumed:** Sub-agents are created with a narrow task and limited context, and they
do exactly that task without side effects on the parent's state.

**Reality:**  
- Sub-agents share the HypothesisLedger and CoverageTracker with the parent.
- Sub-agents can call `create_agent` to spawn grandchildren (nested trees, up to
  `phantom_max_agent_depth=5` levels).
- Sub-agents can call `send_message_to_agent` to any agent_id, including the root.
- There is no task scope enforcement — a "SQLi Fuzzing Agent" can call
  `terminal_execute`, `browser_action`, or any other tool.
- The `skills` parameter in `create_agent` is purely advisory — it influences the
  system prompt only; there is no tool-level enforcement of skill boundaries.

---

### A5: The Docker Sandbox Fully Isolates Tool Execution

**Assumed:** Running tools inside a Docker container prevents breaking out and
prevents affecting the host.

**Reality:**  
- The container runs as an arbitrary user unless `--user` is set.
- The `/workspace` directory is a volume mount shared across all agents in the same
  scan — if agent A writes malware-like content to `/workspace/evil.py`, agent B can
  execute it.
- Container memory and CPU limits exist in config but must be applied at runtime by
  the Docker runtime. If the runtime call fails silently, no limits are applied.
- Network isolation (`phantom_scope_enforcement=true`) depends on iptables rules being
  correctly applied at container start time. This is not verifiable from the Python
  code layer (it depends on Docker runtime implementation).

---

### A6: Tool Results Are Factual and Trustworthy

**Assumed:** Tool outputs represent ground truth about the target.

**Reality:**  
- `nuclei`, `sqlmap`, `ffuf` all produce false positives.
- The LLM is instructed ("PROOF OR NO REPORT") to validate tool findings manually.
- In practice, for a long scan under time pressure, the LLM may accept a nuclei
  finding as confirmation without manual validation.
- This is an LLM reasoning failure, but the architecture provides no enforcement
  mechanism to require re-validation.

---

### A7: RBAC Provides Access Control

**Assumed:** RBAC limits what tools agents can execute, providing defense-in-depth.

**Reality:**  
From `config.py:102`:
```python
phantom_rbac_enabled = "false"
```
RBAC is disabled by default. Even when enabled, the implementation uses a process-
level singleton without thread locks, and `send_request` is misclassified as READ
(allowing OBSERVER-role agents to make live HTTP requests).

---

### A8: Scan Cost Budget Controls Resource Usage

**Assumed:** `phantom_max_cost` prevents runaway spending.

**Reality:**  
- Budget check fires at the START of each `generate()` call.
- A single very expensive LLM request (e.g., 200K output tokens for a complex
  reasoning step) can exceed the budget in one call with no mid-call abort.
- Sub-agents each have their own LLM instance but share the global tracer cost.
  The global cost aggregation via `tracer.get_total_llm_stats()` requires the
  tracer to be correctly wired (it is optional and lazy-initialized).
- When the tracer is unavailable: `current_cost = self._total_stats.cost` (local only).
  This means each sub-agent measures only its own costs, not the global total.
  Total cost can be `N × max_cost` without any abort.

---

### A9: The System Is "Research Mode" Safe

**Assumed:** Research mode is appropriate for all pentesting scenarios.

**Reality:**  
Research mode disables:
1. Injection argument validation (`_validate_tool_argument_injection()` returns None)
2. RBAC enforcement (all tools allowed to all agents)
3. Path traversal checks are present but the RBAC gate is the primary control

Research mode is explicitly designed to maximize offensive capability. Running
Phantom in research mode against any target means:
- Any injected instruction has full tool access
- No command injection protection for terminal/python tools
- No path traversal protection at the execution layer

**This is appropriate ONLY when the system itself is trusted.** If the target can
reach the agent (via injection), research mode becomes a critical vulnerability.

---

## Design Debt Inventory

| Debt Item | Category | Impact | Cost to Fix |
|---|---|---|---|
| Jinja2 template without escaping | Security | Critical | Low (add `\| e` filter) |
| RBAC disabled by default | Security | High | Low (change default) |
| HypothesisLedger without thread lock | Correctness | High | Low (add Lock) |
| SHA-256 dedup never expires | Correctness | Medium | Medium (LRU cache) |
| Thinking blocks not persisted | Auditability | Medium | Medium (design decision) |
| No deterministic planning layer | Architecture | High | High (requires redesign) |
| No formal proof of exploit → report binding | Correctness | High | High |
| Sub-agent task scope not enforced | Security | Medium | Medium |
| Compressor assumes LLM summarizes faithfully | Reliability | High | Medium |
| Archived messages never re-surfaced | Memory | Medium | Low |
| Checkpoint not atomically written | Reliability | High | Low (atomic rename) |
| Circuit breaker not thread-safe | Reliability | Medium | Low (add Lock) |
| Budget tracking bypassed per-agent | Cost | High | Medium |
| SSRF allowlist doesn't cover terminal/python | Security | Critical | Medium |
