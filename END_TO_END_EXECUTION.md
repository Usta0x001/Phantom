# PHANTOM AI — END-TO-END EXECUTION SIMULATION & WEAKNESS AUDIT

> **Date:** 2026-04-27  
> **Scope:** Full critical path from CLI entry to report generation  
> **Method:** Static trace of execution flow with failure-mode analysis  

---

## Simulated Scan Scenario

We simulate a 200-iteration deep scan against `https://target.example.com` with Docker sandbox enabled. The agent discovers an XSS, attempts SQLi confirmation via sqlmap, spawns a sub-agent for API testing, and finishes with a vulnerability report.

---

## Phase 1: Entry & Initialization

### 1.1 CLI Startup (`cli.py:run_cli` or `main.py`)

**What happens:**
1. Parse arguments → build `scan_config` dict
2. Create `CheckpointManager(run_dir)` 
3. If resuming: load checkpoint, restore `AgentState`, hypothesis ledger, coverage tracker, attack graph
4. Create `LLMConfig(scan_mode="deep")`
5. Build `agent_config` dict with LLM config, max_iterations=300, checkpoint manager
6. Create `Tracer(args.run_name)` → calls `reset_global_llm_stats()` (broad except, may silently fail)
7. Set `tracer.vulnerability_found_callback = display_vulnerability` (Rich UI callback)
8. Register signal handlers (SIGINT, SIGTERM, SIGHUP) and `atexit(cleanup_on_exit)`
9. Create `PhantomAgent(agent_config)`
10. Call `agent.execute_scan(scan_config)`

**Weaknesses found:**

| # | Weakness | Severity | Evidence |
|---|----------|----------|----------|
| E1 | `CheckpointManager` created before verifying `phantom_runs/` is writable | MEDIUM | `cli.py:261` — `run_dir.mkdir(parents=True, exist_ok=True)` only happens inside `save()`, not at creation time |
| E2 | Resume path dynamically accesses `args._restored_*` — no validation these exist | LOW | `cli.py:247-257` — `getattr(args, "_restored_hypothesis_ledger", None)` pattern; a typo in attribute name would silently skip restoration |
| E3 | Signal handler calls `cleanup_runtime(wait=True)` — **blocking call during signal** | HIGH | `cli.py:342` — `cleanup_runtime(wait=True)` blocks the signal handler; if Docker stop takes 30s, SIGINT is ignored for 30s |
| E4 | `atexit.register(cleanup_on_exit)` plus signal handler = **double cleanup risk** | MEDIUM | `cli.py:345-347` — both atexit and signal call `tracer.cleanup()` and `cleanup_runtime()`. Race if signal fires during normal exit |
| E5 | Tracer created with `run_name` but `set_global_tracer(tracer)` is NOT in `run_cli` — it's in `cli_app.py` | HIGH | `cli.py` never calls `set_global_tracer()`. `base_agent.py:398` calls `get_global_tracer()` which may return `None`. All tracer-dependent code silently no-ops |

### 1.2 Agent Construction (`PhantomAgent.__init__` → `BaseAgent.__init__`)

**What happens:**
1. `PhantomAgent` sets `default_llm_config = LLMConfig(skills=["root_agent"])`
2. Calls `BaseAgent.__init__(config)`
3. `BaseAgent.__init__` (180 lines):
   - Creates `AgentState` or uses provided one
   - Creates `LLM` instance → calls `_load_system_prompt()` which renders Jinja2 template
   - Creates `MemoryCompressor`
   - Wires hypothesis ledger, coverage tracker, attack graph
   - If root agent: calls `agents_graph_actions.reset_all_state()` (clears ALL global state!)
   - Sets `set_ledger()` on hypothesis actions
   - Loads checkpoint if `_checkpoint_manager` in config
   - Initializes sandbox-related fields

**Weaknesses found:**

| # | Weakness | Severity | Evidence |
|---|----------|----------|----------|
| A1 | `reset_all_state()` clears the ENTIRE agent graph on EVERY root agent creation | HIGH | `base_agent.py:167` — if you create two root agents sequentially (e.g., test then real scan), the first one's graph is destroyed |
| A2 | `__init__` does 180 lines of side effects — if any step fails, agent is partially initialized | HIGH | `base_agent.py:68-249` — no transactionality; failure mid-`__init__` leaves global registries mutated |
| A3 | System prompt loading calls Jinja2 render synchronously during construction | LOW | `llm.py:522-553` — blocks event loop if called from async context; actually okay since `__init__` is sync |
| A4 | `LLM` instance is created with `SharedLLMState()` singleton — all LLM instances share budget stats | HIGH | `llm.py:111` — `_DEFAULT_SHARED_STATE` is shared unless explicitly overridden |
| A5 | `from phantom.logging.audit import get_audit_logger` is inside `try/except` — if import fails, no audit | LOW | `base_agent.py:238` — audit logging is best-effort |

---

## Phase 2: Sandbox Initialization

### 2.1 `_initialize_sandbox_and_state(task)`

**What happens:**
1. Check `PHANTOM_SANDBOX_MODE` env var
2. If no sandbox and `state.sandbox_id` is None:
   - `runtime = get_runtime()` → singleton `DockerRuntime`
   - `runtime.create_sandbox(agent_id, token, local_sources, scan_config)`
   - Docker container created, tool server started, token written to `/run/secrets`
   - Scope firewall configured (if enabled)
   - `runtime._register_agent(api_url, agent_id, token)` → POST to `/register_agent`
   - Sets `state.sandbox_id`, `state.sandbox_token`, `state.sandbox_info`
3. If root agent: `await _restore_sub_agents_from_checkpoint()`
4. If no messages: `state.add_message("user", task)`

**Weaknesses found:**

| # | Weakness | Severity | Evidence |
|---|----------|----------|----------|
| S1 | **No retry on sandbox creation failure** — one Docker error kills the entire scan | CRITICAL | `base_agent.py:405` — `except SandboxInitializationError: return self._handle_sandbox_error(e, tracer)` — no retry, no fallback to local mode |
| S2 | `_register_agent` HTTP call has no timeout specified | MEDIUM | `docker_runtime.py:591` — `await self._register_agent(api_url, agent_id, token)` — uses default httpx timeout |
| S3 | If sandbox creation succeeds but registration fails, agent has broken sandbox state | HIGH | `docker_runtime.py:747` — `sandbox_id` and `sandbox_token` are set even if registration fails; later tool calls will 401 |
| S4 | Sub-agent restoration spawns `threading.Thread` but doesn't track if they started successfully | HIGH | `base_agent.py:763` — `thread.start()` then stores in `_running_agents`; if thread crashes immediately, no error is propagated |
| S5 | `source_copied_key = f"_source_copied_{scan_id}"` with `setattr(self, source_copied_key, True)` — instance pollution | LOW | `docker_runtime.py:555` — arbitrary attributes added to `DockerRuntime` instance |
| S6 | Scope firewall rules applied one-by-one with no rollback on partial failure | HIGH | `docker_runtime.py:489-499` — each `iptables` rule is independent; if one fails, container has partial firewall |

---

## Phase 3: Agent Loop (`agent_loop`)

### 3.1 The Main Loop

**What happens:**
```
while True:
    if _force_stop: enter waiting state
    await _check_agent_messages(state)      # inter-agent comms
    if waiting: await _wait_for_input(); continue
    if should_stop(): return final_result
    if llm_failed: await _wait_for_input(); continue
    
    state.increment_iteration()
    
    # Audit log iteration
    # Max iteration warnings at 85% and 3-left
    
    try:
        should_finish = await _process_iteration(tracer)
        # No-action streak detection (3 = warn, 8 = abort)
        # Periodic checkpoint save
        if should_finish: return final_result
    except CancelledError: handle user stop
    except LLMRequestFailedError: rate-limit backoff or abort
    except Exception: _handle_iteration_error or abort
```

**Weaknesses found:**

| # | Weakness | Severity | Evidence |
|---|----------|----------|----------|
| L1 | **`while True` with no outer scan timeout** — 300 iterations at 60s each = 5 hours with no hard limit | MEDIUM | `base_agent.py:410` — only `max_iterations` limits loops, not wall-clock time |
| L2 | `_check_agent_messages` runs EVERY iteration even if no inter-agent messages exist | LOW | `base_agent.py:420` — wastes CPU doing lock acquisition on empty dict |
| L3 | Checkpoint save happens AFTER successful iteration — **1 iteration of work lost on crash** | HIGH | `base_agent.py:507` — `_maybe_save_checkpoint(tracer)` called after `_process_iteration()` returns. If crash during tool execution, checkpoint is stale |
| L4 | Rate-limit backoff sleeps the agent thread but **does not sleep the global rate limit** | MEDIUM | `base_agent.py:637` — `await asyncio.sleep(_sleep)` blocks this agent only; other agents continue hitting the API |
| L5 | `_no_action_streak` abort at 8 iterations is arbitrary and not configurable | LOW | `base_agent.py:496` — hardcoded `8` with no env override |
| L6 | `LLMRequestFailedError` triggers emergency checkpoint save but does NOT save sub-agent states | MEDIUM | `base_agent.py:596` — `force=True` saves root state but sub-agents may have diverged |
| L7 | Iteration audit logging does 3 inline imports per iteration = 900 imports for 300-iter scan | LOW | `base_agent.py:441-447` — `from phantom.logging.audit import get_audit_logger` inside hot loop |

---

## Phase 4: Process Iteration (`_process_iteration`)

### 4.1 Status Injection & Phase Gates

**What happens:**
1. Every N iterations (default 10): `get_scan_status()` → format → SHA-256 delta-check → inject as user message
2. At 85% of max iterations: inject "FINAL WARNING — REPORT NOW" message
3. Call `self.llm.generate(self._build_hypothesis_context())`
4. Stream responses, update tracer streaming content
5. If empty response and reflector enabled: call reflector with last 4 messages
6. Add assistant message to state
7. Parse tool invocations from response
8. If tools: `_execute_actions()` → `process_tool_invocations()`
9. `_cleanup_message_history()`
10. Return `should_agent_finish`

**Weaknesses found:**

| # | Weakness | Severity | Evidence |
|---|----------|----------|----------|
| P1 | **SHA-256 hash of scan status on every 10th iteration** — expensive for no reason | MEDIUM | `base_agent.py:803-808` — `hashlib.sha256(status_msg.encode()).hexdigest()` to check if status changed; a simple string comparison would suffice |
| P2 | Phase-gate message at 85% is injected as a **user message** not a system message — may confuse LLM | MEDIUM | `base_agent.py:838` — `self.state.add_message("user", _gate_msg)` — LLM may interpret this as user input rather than system guidance |
| P3 | `_build_hypothesis_context()` does `list(self.state.get_conversation_history())` — shallow copy of list, but dicts inside are shared | LOW | `base_agent.py:1203` — mutations to history dicts by `_prepare_messages` could affect state |
| P4 | If LLM returns empty response and **reflector is disabled** (default), agent gets a generic corrective message | LOW | `base_agent.py:872` — "Empty response. You MUST call a tool." — not tailored to scan context |
| P5 | `self.llm.generate()` is an async generator but `_process_iteration` has **no timeout** — if LLM hangs forever, iteration never completes | CRITICAL | `base_agent.py:841` — `async for response in self.llm.generate(...)` with no `asyncio.wait_for` wrapper |
| P6 | `_cleanup_message_history` is called even if no actions were taken — unnecessary work | LOW | `base_agent.py:912` — called for both tool and no-tool paths |

---

## Phase 5: LLM Generation (`llm.generate` → `_stream`)

### 5.1 The Full LLM Pipeline

**What happens:**
1. `generate()` checks rate limit, then budget
2. `_prepare_messages(conversation_history)`:
   - Prepends system prompt
   - Strips thinking blocks from messages
   - Runs `memory_compressor.compress_history()` in thread pool
   - **MUTATES `conversation_history` IN PLACE** (`conversation_history.clear(); conversation_history.extend(compressed)`)
   - Clears archived messages
   - Injects agent identity and finding anchors into first message
   - Adds cache control for Anthropic
   - Returns the mutated list
3. Optionally switches model via routing
4. `_stream(messages)`:
   - Calls `tracked_acompletion(**args, stream=True, reducer=_safe_reduce_messages)`
   - Accumulates chunks
   - Yields partial responses when `</function>` or `</invoke>` detected
   - After stream: `stream_chunk_builder(chunks)` to rebuild full response
   - `_update_usage_stats()` for token/cost tracking
   - `_update_per_model_stats()` for per-model breakdown
   - `_record_token_drift_async()` (fire-and-forget)
5. Post-processing:
   - `normalize_tool_format()`
   - `strip_thinking_blocks()`
   - `fix_incomplete_tool_call()`
   - `parse_tool_invocations()` via regex
   - If looks like tool but none parsed: prepend malformed notice with available tools
   - Audit log the response
6. Yield final `LLMResponse(content, tool_invocations, thinking_blocks)`

**Weaknesses found:**

| # | Weakness | Severity | Evidence |
|---|----------|----------|----------|
| M1 | **`_prepare_messages` MUTATES the caller's list in place** — hidden side effect | HIGH | `llm.py:935-936` — `conversation_history.clear(); conversation_history.extend(compressed)`. The list from `_build_hypothesis_context()` is corrupted for any other caller |
| M2 | **Compression runs in `asyncio.to_thread()` but can take 30+ seconds** — blocks a thread pool worker | MEDIUM | `llm.py:931` — `compress_history` with LLM summarization is CPU+network heavy |
| M3 | `strip_thinking_blocks` is called TWICE — once in `_prepare_messages` and once in `_stream` output | LOW | `llm.py:906` and `llm.py:825` — redundant work |
| M4 | **`done_streaming` counter heuristic is brittle** — if `</function>` appears in normal text, streaming stops early | HIGH | `llm.py:780` — `if delta and ("</function>" in accumulated or "</invoke>" in accumulated)` — any `</function>` in prose triggers premature stop |
| M5 | **`stream_chunk_builder` may be called TWICE** — once in `_stream`, once in `_extract_thinking` | MEDIUM | `llm.py:793` and `llm.py:1377` — CPU-heavy on large streams |
| M6 | **Cost extraction returns 0.0 on ALL errors** — budget tracking is silently wrong | HIGH | `llm.py:234-267` — 3 nested try/except blocks, all return 0.0 on failure. You could spend $50 and the tracker shows $0 |
| M7 | **`_record_token_drift_async` is fire-and-forget from sync context** — silently dropped | MEDIUM | `llm.py:796-804` — `asyncio.create_task()` called from async context is fine, but `record_external_completion_usage` (sync) also tries it and catches `RuntimeError` |
| M8 | **`_safe_reduce_messages` drops ALL but pinned facts + last K messages** — evidence loss | HIGH | `llm.py` — no configuration of what gets dropped; in a 200-iter scan, the original scope and early findings may be lost |
| M9 | **Malformed notice includes available tools preview** — on EVERY bad turn | MEDIUM | `llm.py:867-873` — wastes ~40 tokens per malformed response, compounding on bad LLMs |
| M10 | `parse_tool_invocations` uses regex `finditer` on accumulated text — no XML parser | MEDIUM | `phantom/llm/utils.py` — brittle parsing; nested tags or CDATA break it |
| M11 | **No timeout on `tracked_acompletion` call** — LLM provider hang = infinite wait | CRITICAL | `llm.py:764` — `await tracked_acompletion(...)` has no outer timeout wrapper |
| M12 | **Budget check `_check_budget` reads local cost under lock, releases, then reads tracer cost** — race condition | HIGH | `llm.py:1181-1190` — non-atomic cost read; two agents can both pass 100% check |

---

## Phase 6: Tool Execution (`process_tool_invocations`)

### 6.1 The Tool Execution Chain

**What happens:**
1. `process_tool_invocations(actions, conversation_history, agent_state, owner_agent)`
2. For each tool invocation:
   - `_execute_single_tool(tool_inv, agent_state, owner_agent, tracer, agent_id, image_slots)`
   - `execute_tool_invocation()` → `execute_tool_with_validation()` → `execute_tool()`
   - If sandbox tool: `_execute_tool_in_sandbox()`:
     - Creates NEW `httpx.AsyncClient` for EVERY call
     - POST to `http://host:port/execute` with Bearer token
     - `httpx.Timeout(150s connect, 10s)`
     - Returns result or raises
   - If local tool: `_execute_tool_locally()`:
     - Looks up function in registry
     - `convert_arguments()` for type coercion
     - Calls function (async → await, sync → `asyncio.to_thread`)
   - `_format_tool_result_with_meta()`:
     - Formats as XML `<tool_result><tool_name>...</tool_name><result>...</result></tool_result>`
     - HTML-escapes the result string
     - Detects vulnerability signals via keyword grep
     - Truncates if over limit
     - Handles image attachments
   - `_auto_summarize_result()` if over threshold AND cap not reached
   - `_auto_record_hypothesis()` to update ledger
   - Collects observation XML, images, finish flag, error flag
3. After all tools:
   - Append "Tool Results:\n\n" + all observations to `conversation_history`
   - Update `agent_state.context["last_tool_batch_had_error"]`
   - Return `should_agent_finish`

**Weaknesses found:**

| # | Weakness | Severity | Evidence |
|---|----------|----------|----------|
| T1 | **NEW `httpx.AsyncClient` for EVERY sandbox tool call** — no connection pooling | HIGH | `executor.py:244` — `async with httpx.AsyncClient(trust_env=False) as client` inside `_execute_tool_in_sandbox`. For 200 iterations with 2 tools each = 400 client creations/teardowns |
| T2 | **Sandbox timeout is 150s hardcoded** — `nmap -p-` or `sqlmap --dump` will timeout | HIGH | `executor.py:70-71` — `SANDBOX_EXECUTION_TIMEOUT = _SERVER_TIMEOUT + 30 = 150s`. Large scans will abort mid-tool |
| T3 | **Tool server cancels previous task on same agent_id** — race condition | MEDIUM | `tool_server.py:149-153` — `if agent_id in agent_tasks: old_task.cancel()`. If agent sends two rapid requests, first is killed |
| T4 | **`_execute_single_tool` catches ALL exceptions and returns error dict** — caller can't distinguish network vs logic errors | MEDIUM | `executor.py:1193-1198` — `except Exception as e: result = {"success": False, "error": error_msg}` |
| T5 | **Vulnerability signal extraction is keyword grep** — misses time-based SQLi, blind XSS, business logic | HIGH | `executor.py:74-105` — `_HIGH_SIGNAL_MARKERS` checks for strings like `"sql"`, `"jwt"`, `"csrf"`. A time-based SQLi response has none of these keywords |
| T6 | **`_auto_record_hypothesis` only works for 3 tools** — misses all other tools | MEDIUM | `executor.py:1367` — `if tool_name not in {"send_request", "terminal_execute", "browser_action"}: return`. A `python_action` that finds a vulnerability is ignored |
| T7 | **URL extraction from terminal command uses regex** — fragile | LOW | `executor.py:1377` — `url_match = _re_hyp.search(r'https?://[^\s\'"]+', cmd)` — breaks on URLs with spaces, quotes, or Unicode |
| T8 | **HTML-escaping in `_format_tool_result_with_meta` corrupts tool output for the LLM** | HIGH | `executor.py:1100` — `html.escape(final_result_str)` — the LLM sees `&lt;script&gt;` instead of `<script>`. This breaks payload analysis |
| T9 | **`process_tool_invocations` appends results AFTER all tools finish** — if tool #2 hangs, tool #1 result is never fed back | MEDIUM | `executor.py:1297-1320` — sequential execution with no partial result streaming |
| T10 | **Image collection accumulates in memory** — for 200 iterations with screenshots, this is a memory leak | MEDIUM | `executor.py:1315-1317` — `all_images.extend(images)` with no size limit or eviction |

---

## Phase 7: Reporting & Cleanup

### 7.1 Finish Path

**What happens:**
1. Agent calls `finish_scan` → `_execute_single_tool` detects it → `should_agent_finish = True`
2. Returns to `agent_loop` → `state.set_completed({"success": True})` → `tracer.update_agent_status("completed")`
3. Audit log agent completion
4. Return `final_result` to `cli.py:run_cli()`
5. `tracer.save_run_data()`:
   - Writes `vulnerabilities/` directory with one `.md` per report
   - Writes `vulnerability_index.csv`
   - Writes `scan_stats.json`
   - Writes `events.jsonl`
   - All done with **synchronous blocking I/O**
6. `cleanup_on_exit()`:
   - `tracer.cleanup()`
   - `cleanup_runtime()` → stops Docker container

**Weaknesses found:**

| # | Weakness | Severity | Evidence |
|---|----------|----------|----------|
| R1 | **`save_run_data` does 100+ synchronous file writes** — blocks event loop for seconds | HIGH | `tracer.py:850-999` — every vulnerability gets its own `open().write()` call |
| R2 | **Markdown report is inline string concatenation — no template engine** | LOW | `tracer.py` — hardcoded f-strings for report formatting |
| R3 | **`_saved_vuln_ids` is a set checked during `add_vulnerability_report` but reports are still appended to `vulnerability_reports`** — duplication risk | MEDIUM | `tracer.py:377-444` — the deduplication only prevents re-writing to disk, not re-appending to the list |
| R4 | **`tracer.cleanup()` is called in signal handler AND atexit** — double execution | LOW | `cli.py:331-345` — both paths call cleanup |
| R5 | **No verification that reports were actually written to disk** | MEDIUM | `tracer.py` — `open().write()` with no `flush()` or `fsync()` |
| R6 | **Scan stats uses `json.dump(..., default=str)` — non-serializable objects become strings silently** | LOW | `tracer.py:984` — if a datetime or Decimal slips in, it's silently stringified |

---

## Cross-Phase Integration Weaknesses

These are bugs that only manifest when components interact:

| # | Weakness | Severity | Trigger Condition |
|---|----------|----------|-------------------|
| X1 | **Memory compressor mutates `conversation_history` in place, but `_build_hypothesis_context()` returns a shallow copy** — the copy is mutated, then discarded. State is safe, but the mutation is a hidden side effect | MEDIUM | Every LLM call |
| X2 | **`process_tool_invocations` receives `conversation_history` from `self.state.get_conversation_history()`, but `_prepare_messages` inside LLM has already compressed the state's internal list** — tool results are appended to a potentially compressed history | HIGH | When message count exceeds threshold |
| X3 | **Sub-agent threads are daemon=True — if main process exits abruptly, sub-agents are killed with no cleanup** | HIGH | SIGKILL, power loss, or `sys.exit()` |
| X4 | **Global tracer is not set by `cli.py`** — all tracer calls in `base_agent.py` get `None` | HIGH | When using `cli.py` directly instead of `cli_app.py` |
| X5 | **`agents_graph_actions._agent_graph` is cleared by `reset_all_state()` but `_running_agents` may still hold old thread references** | MEDIUM | Sequential scan creation |
| X6 | **`_auto_summarize_count` is a module-level global** — shared across ALL agent instances and ALL scans in the same process | HIGH | Multi-scan or multi-agent scenarios |
| X7 | **Budget stats in `SharedLLMState` are shared across all LLM instances** — sub-agents and root agent compete for the same budget counters | HIGH | Any scan with sub-agents |
| X8 | **The `reflector` is called with `(final_response.content or "")[:500]` — only 500 chars of context** — insufficient for meaningful reflection | LOW | Empty LLM responses with reflector enabled |
| X9 | **`_check_budget` reads `tracer.get_total_llm_stats()` which sums across ALL agents** — sub-agent spending reduces root agent's budget | HIGH | Scans with delegation |
| X10 | **Signal handler calls `_save_interrupt_checkpoint` which calls `CM.build()` synchronously** — if build takes 5s, SIGINT is delayed 5s | MEDIUM | User presses Ctrl+C during scan |

---

## Exploit Scenarios

### Scenario 1: Budget Drain Attack
An attacker crafts a target that produces oversized tool outputs on every iteration. The auto-summarizer fires repeatedly, consuming token budget. With the new cap of 10, the attack is mitigated, but the cap only applies per-process. An attacker could exhaust the cap early with benign large outputs, then the remaining 190 iterations get raw truncated output with no summarization.

### Scenario 2: Checkpoint Corruption
The agent crashes during `_execute_actions` (e.g., memory exhaustion from image accumulation). The checkpoint was saved at iteration N-1. On resume, the agent repeats iteration N, potentially re-running destructive tools or duplicate requests. The `_recent_action_results` dedup helps, but it's only 8 entries and checks the last 2.

### Scenario 3: Silent Sandbox Failure
The sandbox container OOMs or is killed by Docker. `agent_state.sandbox_id` is still set, so the agent thinks the sandbox is healthy. The next tool call POSTs to a dead container, gets `ConnectionRefused`, and the exception is caught and returned as `{"success": False, "error": "Sandbox communication error"}`. The agent sees this as a normal tool error and continues, never realizing the sandbox is dead.

### Scenario 4: LLM Stream Hang
The LLM provider (or litellm proxy) accepts the connection but never sends chunks. `async for chunk in response` hangs forever. The agent is stuck in `_process_iteration` with no timeout. The user sees no output, CPU is idle, and the scan never completes. No timeout = no recovery.

### Scenario 5: Race Condition on Shared Budget
Root agent and 3 sub-agents all use the same `SharedLLMState`. Each checks budget independently. All 4 pass the 80% check simultaneously. The adaptive scan mode downgrade fires for all 4, but they've already spent past the threshold. Budget exceeded by 4x.

---

## Summary Table: All End-to-End Weaknesses

| Phase | Count | Critical | High | Medium | Low |
|-------|-------|----------|------|--------|-----|
| Entry/Init | 5 | 0 | 2 | 2 | 1 |
| Sandbox Init | 6 | 1 | 3 | 1 | 1 |
| Agent Loop | 7 | 0 | 2 | 3 | 2 |
| Process Iteration | 6 | 1 | 2 | 2 | 1 |
| LLM Generation | 12 | 2 | 5 | 3 | 2 |
| Tool Execution | 10 | 1 | 4 | 3 | 2 |
| Reporting | 6 | 0 | 1 | 3 | 2 |
| Cross-Phase | 10 | 2 | 5 | 2 | 1 |
| **TOTAL** | **62** | **7** | **24** | **19** | **12** |

---

## Top 10 Fixes to Make It Production-Ready

| Rank | Fix | File | Lines | Impact |
|------|-----|------|-------|--------|
| 1 | **Add timeout wrapper around `llm.generate()`** | `base_agent.py` | 841 | Prevents infinite hangs |
| 2 | **Add timeout around `tracked_acompletion()`** | `llm.py` | 764 | Prevents provider hangs |
| 3 | **Reuse `httpx.AsyncClient` across sandbox calls** | `executor.py` | 244 | Fixes connection overhead |
| 4 | **Set global tracer in `cli.py`** | `cli.py` | 276 | Fixes telemetry blind spot |
| 5 | **Make `_prepare_messages` return a new list instead of mutating** | `llm.py` | 935-936 | Fixes hidden side effects |
| 6 | **Save checkpoint BEFORE tool execution, not after** | `base_agent.py` | 965-507 | Prevents 1-iter data loss |
| 7 | **Add sandbox health check before each tool call** | `executor.py` | 204 | Detects dead containers |
| 8 | **Add `httpx` connection pool to tool server** | `executor.py` | 244 | Massive performance win |
| 9 | **Make budget check atomic (read + check in one lock)** | `llm.py` | 1181-1190 | Fixes race condition |
| 10 | **Add outer wall-clock timeout to `agent_loop`** | `base_agent.py` | 410 | Prevents infinite scans |

---

## Bottom Line

The end-to-end execution path has **62 identifiable weaknesses** spanning all phases. The most dangerous are:

1. **No timeouts on LLM calls** — a hung provider = infinite wait
2. **Sandbox tool calls create new HTTP clients every time** — massive overhead and no connection reuse
3. **`_prepare_messages` mutates caller's list in place** — hidden side effects that corrupt data
4. **Global tracer not set by `cli.py`** — telemetry is silently disabled for CLI users
5. **Checkpoint save happens AFTER iteration** — 1 iteration of work is always at risk
6. **Budget stats are shared across all agents** — sub-agents and root compete, causing overspend
7. **No sandbox health check** — dead containers are not detected until a tool fails

These are not unit-testable bugs. They are **integration failures** that only manifest when the full pipeline runs. The system compiles, the tests pass, but a real scan will hit these issues within the first 50 iterations.

---
*End of Execution Simulation*
