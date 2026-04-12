# Phantom Memory and Context Management (Step 7)

## Scope and Evidence Basis

This report reconstructs how Phantom builds, compresses, persists, and restores context during long-running scans.

Primary anchors used:

- Context assembly and preflight limits: `phantom/llm/llm.py:588`, `phantom/llm/llm.py:702`
- Compression and anchor extraction: `phantom/llm/memory_compressor.py:657`, `phantom/llm/memory_compressor.py:734`
- Agent state lifecycle: `phantom/agents/state.py:13`
- Iteration-time state injections: `phantom/agents/base_agent.py:620`, `phantom/agents/base_agent.py:646`
- Observation feedback path: `phantom/tools/executor.py:1441`, `phantom/tools/executor.py:1480`
- Resume/checkpoint durability: `phantom/checkpoint/checkpoint.py:210`, `phantom/interface/cli.py:95`

---

## 1) How Context Is Built and Maintained

### 1.1 Request context construction

Every LLM turn is built in a fixed order inside `LLM._prepare_messages()`:

1. System prompt (`phantom/llm/llm.py:591`)
2. Agent identity block (`phantom/llm/llm.py:593`)
3. Compressed conversation history (`phantom/llm/llm.py:610`, `phantom/llm/llm.py:615`)
4. Finding anchors reinjection (`phantom/llm/llm.py:618`, `phantom/llm/llm.py:636`)
5. Continuation guard when tail role is assistant (`phantom/llm/llm.py:653`)

This means context is not append-only: history is actively rewritten by compression before each call (`phantom/llm/llm.py:615`, `phantom/llm/llm.py:616`).

### 1.2 Iteration-time context maintenance

Before model generation, `BaseAgent._process_iteration()` periodically injects compact strategic summaries:

- Scan status (`phantom/agents/base_agent.py:620`, `phantom/agents/base_agent.py:633`)
- Hypothesis ledger (`phantom/agents/base_agent.py:640`, `phantom/agents/base_agent.py:646`)
- Coverage tracker (`phantom/agents/base_agent.py:655`, `phantom/agents/base_agent.py:661`)
- Correlation/chain opportunities (`phantom/agents/base_agent.py:667`, `phantom/agents/base_agent.py:673`)

These injected summaries become normal conversation messages via `state.add_message(...)` (`phantom/agents/state.py:136`).

### 1.3 Feedback loop that maintains working context

Tool outputs are converted into observation text (and optional images) and appended as the next `user` message:

- Batch processing: `process_tool_invocations(...)` (`phantom/tools/executor.py:1441`)
- Observation append: `conversation_history.append(...)` (`phantom/tools/executor.py:1478`, `phantom/tools/executor.py:1481`)

So the model's next decision always includes prior action outcomes through conversation memory, not a separate planner store.

---

## 2) Short-Term vs Long-Term Memory

## 2.1 Short-term memory (turn-local / loop-local)

- `AgentState.messages` is the immediate working memory for model turns (`phantom/agents/state.py:42`, `phantom/agents/state.py:252`).
- Message ingestion is deduplicated by hash + recent-window checks to reduce prompt flooding (`phantom/agents/state.py:139`, `phantom/agents/state.py:149`).
- Thinking blocks are intentionally not persisted in message history to reduce hidden token bloat (`phantom/agents/state.py:155`).
- During parsing, `<thinking>...</thinking>` is stripped before tool extraction to avoid duplicate/hidden tool-call effects (`phantom/llm/llm.py:550`, `phantom/llm/utils.py:146`).

## 2.2 Long-term memory (structured and durable)

Phantom keeps strategic memory outside chat history:

- Hypotheses (`HypothesisLedger`) (`phantom/agents/base_agent.py:100`)
- Coverage facts (`CoverageTracker`) (`phantom/agents/base_agent.py:107`)
- Chain suggestions (`CorrelationEngine`) (`phantom/agents/base_agent.py:114`)
- Vulnerability graph (`AttackGraph`) (`phantom/agents/base_agent.py:123`)

These stores survive compression because they are sidecar state, then are reinjected as compact summaries (`phantom/agents/base_agent.py:646`, `phantom/agents/base_agent.py:661`, `phantom/agents/base_agent.py:673`).

Durable long-term memory for interruptions is checkpointed:

- Save/load with atomic write + HMAC integrity (`phantom/checkpoint/checkpoint.py:210`, `phantom/checkpoint/checkpoint.py:255`)
- Snapshot includes ledger/coverage/correlation/attack-graph states (`phantom/checkpoint/checkpoint.py:387`, `phantom/checkpoint/checkpoint.py:417`)
- Resume reconstructs these into runtime agent config (`phantom/interface/cli.py:108`, `phantom/interface/cli.py:145`)

---

## 3) Token Optimization Strategies

Phantom applies multiple token-control layers, not a single limiter:

1. **Prompt tool-surface reduction**
   - System prompt can include subset schemas instead of full registry (`phantom/llm/llm.py:277`, `phantom/tools/dynamic_tools.py:204`).
   - Default category presets intentionally omit low-signal tool groups for main-agent prompts (`phantom/tools/dynamic_tools.py:77`, `phantom/tools/dynamic_tools.py:80`).

2. **Model-aware history compression**
   - Compression threshold uses model context window and fill ratio (`phantom/llm/memory_compressor.py:637`, `phantom/llm/memory_compressor.py:645`).
   - Keeps recent tail and summarizes older chunks (`phantom/llm/memory_compressor.py:697`, `phantom/llm/memory_compressor.py:790`).
   - Parallel chunk summarization can reduce compression latency (`phantom/llm/memory_compressor.py:742`, `phantom/llm/memory_compressor.py:752`).

3. **Request-size preflight staircase**
   - Stage 1: drop old images (`phantom/llm/llm.py:729`)
   - Stage 2: force-compress (`phantom/llm/llm.py:747`)
   - Stage 3: trim non-system history tail (`phantom/llm/llm.py:765`, `phantom/llm/llm.py:770`)

4. **Tool-output shaping before re-entry into context**
   - Per-tool truncation budgets (`phantom/tools/executor.py:850`, `phantom/tools/executor.py:868`)
   - Smart extractor paths for noisy scanners (`phantom/tools/executor.py:1215`, `phantom/tools/executor.py:1229`)
   - Optional oversized-output summarization (`phantom/tools/executor.py:930`, `phantom/tools/executor.py:939`)

5. **Image payload control**
   - Screenshot artifacts written to disk, raw base64 removed from chat payload (`phantom/tools/executor.py:1148`, `phantom/tools/executor.py:1158`)
   - Compressor image eviction and byte caps (`phantom/llm/memory_compressor.py:683`, `phantom/llm/memory_compressor.py:809`)

6. **Sub-agent context-bomb mitigation**
   - Inherited history is intentionally sliced to a small head+tail window when large (`phantom/tools/agents_graph/agents_graph_actions.py:462`, `phantom/tools/agents_graph/agents_graph_actions.py:466`).

---

## 4) Failure Points (Context Explosion / State Loss)

## 4.1 Context explosion risks

- If all preflight reductions still fail, generation aborts with hard-cap error (`phantom/llm/llm.py:787`).
- High-volume tool output can still stress context despite truncation if limits are raised aggressively (`phantom/tools/executor.py:875`, `phantom/tools/executor.py:1208`).
- Sub-agent inheritance can amplify context if summaries are weak; system already guards with required `context_summary` and truncation, but quality remains dependent on parent brief (`phantom/tools/agents_graph/agents_graph_actions.py:295`, `phantom/tools/agents_graph/agents_graph_actions.py:462`).

## 4.2 State-loss / fidelity-loss risks

- Compression is lossy by design; fallback summaries clip content (`phantom/llm/memory_compressor.py:413`, `phantom/llm/memory_compressor.py:427`).
- Finding anchors expire after configured compression cycles, which can drop older high-signal context (`phantom/agents/state.py:61`, `phantom/agents/state.py:127`).
- Scan-status injection failures are swallowed to debug log; context quality can silently degrade (`phantom/agents/base_agent.py:627`, `phantom/agents/base_agent.py:635`).
- Auto-hypothesis behavior is split: direct signal extraction writes into `agent_state.hypothesis_ledger`, while legacy `_auto_record_hypothesis()` still references a missing `_ledger` symbol and no-ops (`phantom/tools/executor.py:1399`, `phantom/tools/executor.py:1507`, `phantom/tools/hypothesis/hypothesis_actions.py:84`).

## 4.3 Durable-state loss risks

- Checkpoints are periodic (not every iteration), so crash timing can lose recent in-memory progress (`phantom/checkpoint/checkpoint.py:33`, `phantom/checkpoint/checkpoint.py:165`).
- Oversized checkpoint payloads are skipped, which can prevent fresh state from being persisted (`phantom/checkpoint/checkpoint.py:36`, `phantom/checkpoint/checkpoint.py:217`).
- Corrupt/tampered checkpoint files are ignored on load, causing resume to fail back to non-restored state (`phantom/checkpoint/checkpoint.py:277`, `phantom/checkpoint/checkpoint.py:306`).

---

## Step 7 Reconstruction Statement

Phantom uses a hybrid memory model: short-term conversational working memory in `AgentState.messages`, long-term strategic memory in structured sidecar stores (ledger/coverage/correlation/graph), and durable recovery memory in checkpoints. Context management is aggressively optimized through schema reduction, compression, truncation, and preflight sizing, but key risks remain around lossy summarization, silent context-quality degradation paths, and checkpoint timing/size limits.
