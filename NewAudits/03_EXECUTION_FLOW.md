# Phantom — Execution Flow (Step-by-Step)

## Full Lifecycle of a Scan

### Phase 0: Entry Point (PhantomAgent.execute_scan)
```
scan_config = {
    "targets": [{"type": "web_application", "details": {"target_url": "..."}}],
    "user_instructions": "Focus on SQLi and auth bypass"
}

→ phantom_agent.py:23  execute_scan(scan_config)
    → Parse targets into repositories / urls / ip_addresses lists
    → Register SSRF-allowed hosts (proxy_manager.allow_ssrf_host)
    → Build task_description string (concat of target info + user_instructions)
    → Sanitize user_instructions via _sanitize_skill_content()
    → Append: "User-supplied mission constraints (highest priority):\n{safe_instructions}"
    → return await self.agent_loop(task=task_description)
```

**⚠️ FLAW:** `_sanitize_skill_content()` only strips prompt injection from
`user_instructions`. The `target_url` value is embedded directly in the SSRF allowlist
and in the task string without sanitization. A crafted URL like
`http://evil.com\nIgnore previous instructions` would inject content into the task
message sent to the LLM.

---

### Phase 1: Agent Initialization (BaseAgent.__init__)
```
→ base_agent.py:63
    → Validate llm_config (raises ValueError if None)
    → Create AgentState (or use state from config)
    → Instantiate LLM(llm_config)
    → Wire LLM ↔ AgentState (set_agent_state → refresh_tool_prompt)
    → Instantiate HypothesisLedger (fresh or shared from config)
    → Instantiate CoverageTracker (fresh or shared)
    → Instantiate CorrelationEngine (fresh or shared)
    → Try import AttackGraph (optional, fails silently to None)
    → Wire hypothesis tool (set_ledger, set_correlation_engine)
    → Wire scan_status tool (set_scan_status_context)
    → Log agent creation to Tracer + AuditLogger
    → _add_to_agents_graph()  ← adds to global graph dict
```

**⚠️ FLAW:** All tool wiring uses module-level globals (e.g. `set_ledger(...)` writes
to a module-level variable). If two concurrent root agents are created (possible in
some test scenarios), the second agent's wiring overwrites the first's. Agent IDs
are used as secondary keys in some places but not all.

---

### Phase 2: Sandbox Creation (_initialize_sandbox_and_state)
```
→ base_agent.py:673
    → If PHANTOM_SANDBOX_MODE=false and sandbox_id is None:
        → runtime.create_sandbox(agent_id, token, local_sources, scan_config)
        → Store workspace_id, auth_token, tool_server_port in state.sandbox_info
        → If caido_port present → set tracer.caido_url
    → If parent_id is None: _restore_sub_agents_from_checkpoint()
    → If messages is empty: state.add_message("user", task)
```

---

### Phase 3: Main Agent Loop (BaseAgent.agent_loop)
```
→ base_agent.py:340
LOOP:
    1. Check _force_stop → enter_waiting_state if True
    2. _check_agent_messages() → process inter-agent messages from queue
    3. Check is_waiting_for_input() → sleep(0.5) or handle timeout
    4. Check should_stop() → handle completion/waiting
    5. Check llm_failed → wait for input
    6. state.increment_iteration()
    7. Inject warning messages (approaching limit, final 3 iterations)
    8. Periodic scan_status injection (every N iterations, default 10)
    9. Inject 85% phase-gate reminder at 0.85 * max_iterations
   10. async for response in llm.generate(conversation_history):
           stream to tracer
   11. If empty response → corrective message → continue
   12. state.add_message("assistant", response.content)
   13. Extract actions (tool_invocations) from response
   14. If actions → _execute_actions(actions) → return should_finish
   15. _cleanup_message_history()
   16. _maybe_save_checkpoint()
   17. Handle rate-limit with exponential backoff (max 10 retries)
   18. Handle LLM errors, iteration errors, CancelledError
```

**Key state transitions:**
```
INITIAL → RUNNING (after sandbox created)
RUNNING → RUNNING (normal iteration)
RUNNING → WAITING (stop_requested, completed, or max_iterations)
RUNNING → FAILED (rate_limit_abort, unhandled error, sandbox failure)
WAITING → RUNNING (new message received, or timeout after 600s)
RUNNING → COMPLETED (finish tool called → should_finish=True)
```

---

### Phase 4: LLM Generation (LLM.generate)
```
→ llm.py:718
    1. Check global rate limit cooldown (sleep if _GLOBAL_RATE_LIMIT_UNTIL)
    2. Check circuit breaker (raise LLMRequestFailedError if OPEN)
    3. _check_budget() → raise if cost/token budget exceeded
    4. _prepare_messages() → system_prompt prepend + memory compression
    5. _enforce_request_size_limits() → truncate if too large
    6. Optional: model routing (reasoning model vs tool model)
    7. Retry loop (up to ratelimit_max_retries=10 for 429, max_retries=5 others):
        → _stream(messages) → yields LLMResponse chunks
        → On 429: exponential backoff (4 * 2^attempt, max 120s) + global rate limit
        → On unknown error: max 2 retries
        → On primary exhausted: try fallback model if configured
    8. On success: _check_adaptive_scan_mode()
```

**⚠️ FLAW — Message preparation order (llm.py:_prepare_messages):**  
System prompt is prepended here, AFTER context compression happens. This means
the memory compressor operates on the raw conversation (no system prompt) but the
LLM receives [system_prompt + compressed_history]. The system prompt is never
compressed or anchored — it is resent in full on every call. For an 800-line
system prompt this is ~8,000-10,000 tokens per call if the prompt is verbose.

---

### Phase 5: Tool Execution Flow
```
→ base_agent.py:847  _execute_actions(actions)
    1. Compute batch_signature (JSON of tool names + args)
    2. Check _recent_action_results for repeated successful batches
       → If 2+ identical successful batches: add corrective message, return False
    3. asyncio.create_task(process_tool_invocations(..., allowed_tools))
    4. await tool_task

→ executor.py process_tool_invocations (implied from __init__ import)
    For each action:
        → execute_tool_with_validation(tool_name, agent_state, **kwargs)
            1. Resolve canonical tool name (strip module prefix, normalize)
            2. validate_tool_availability() → check registry
            3. Check allowed_tools set → raise Exception("Tool not allowed") if missing
            4. _validate_tool_arguments() → param schema check
            5. _validate_tool_argument_injection() → only in hardened mode
            6. execute_tool() →
                a. _apply_stealth_rate_limit() (stealth mode only)
                b. RBAC check (check_tool_permission)
                c. Check tool cache (get_tool_cache)
                d. _execute_tool_in_sandbox() or _execute_tool_locally()
                e. Cache successful result
                f. Log to AuditLogger

→ _execute_tool_in_sandbox():
    → Build HTTP POST to {sandbox_url}/execute
    → Authorization: Bearer {sandbox_token}
    → Timeout: SANDBOX_EXECUTION_TIMEOUT = server_timeout + 30s

→ _execute_tool_locally():
    → get_tool_by_name() from registry
    → convert_arguments()
    → Call func(agent_state=..., **kwargs) or func(**kwargs)
    → await if coroutine
```

---

### Phase 6: Sub-Agent Creation (create_agent tool)
```
→ agents_graph_actions (create_agent call)
    1. Validate task, name, context_summary (must be 200+ chars)
    2. Create new AgentState(parent_id=current_agent_id, task=task)
    3. Create LLMConfig(skills=..., scan_mode=...)
    4. Build config dict with SHARED hypothesis_ledger, coverage_tracker,
       correlation_engine, attack_graph
    5. Instantiate PhantomAgent(config)
    6. spawn daemon thread:
         threading.Thread(target=_run_agent_in_thread, args=(agent, state, messages))
    7. _run_agent_in_thread → asyncio.run(agent.agent_loop(task))
```

**All sub-agents share the same HypothesisLedger, CoverageTracker,
CorrelationEngine, and AttackGraph instances as the root agent.
No locking is visible in hypothesis_ledger.py or coverage_tracker.py
for concurrent list/dict mutations.**

---

### Phase 7: Context Compression (_prepare_messages in LLM)
```
→ llm.py._prepare_messages(conversation_history)
    → memory_compressor.compress_history(messages, agent_state)
        1. Count tokens across all messages
        2. If total < threshold: return unchanged
        3. If total >= threshold:
            a. Extract anchors from oldest messages (_extract_anchors_from_chunk)
            b. Split history into chunks
            c. Parallel LLM summarization (_parallel_summarize_chunks, max 4 concurrent)
            d. Prepend finding_anchors block to compressed history
            e. Keep MIN_RECENT_MESSAGES (15) verbatim at the end
        4. Returns [system_prompt + anchors + summaries + recent_messages]
```

---

### Phase 8: Checkpoint Save
```
→ base_agent.py:1012 _maybe_save_checkpoint()
    → Only root agent (parent_id is None)
    → Only if checkpoint_manager configured in config
    → CheckpointManager.build():
        - Serializes: AgentState, tracer, scan_config,
                      hypothesis_ledger, coverage_tracker,
                      correlation_engine, attack_graph,
                      active sub-agent states
    → checkpoint_mgr.save(cp) → writes JSON to disk
```

---

### Phase 9: Agent Termination
```
finish_scan (root) or agent_finish (sub-agent) tool called
    → process_tool_invocations returns should_finish=True
    → _execute_actions returns True
    → agent_loop sets state.completed=True
    → Returns state.final_result
```
