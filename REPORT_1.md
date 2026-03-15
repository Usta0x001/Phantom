# REPORT 1 — Architecture & How the System Works

## Overview

Phantom is a multi-agent autonomous penetration testing system. It uses a ReAct
(Reason + Act) loop backed by LiteLLM to call external LLM providers, a Docker
sandbox where all tool execution happens, and a hierarchical agent tree that
spawns specialized sub-agents during a scan. Everything is written in Python.

---

## 1. Entry Point & Configuration

`phantom_agent.py` is the entry point. It reads a `ScanProfile` (quick /
standard / deep / stealth / api_only), builds an `LLMConfig`, and hands control
to `PhantomAgent`, which extends `BaseAgent`.

**Scan profiles** (`scan_profiles.py`) are named presets:

| Profile   | max_iterations | max_agents | reasoning_effort | browser |
|-----------|----------------|------------|-----------------|---------|
| quick     | 15             | 3          | low             | off     |
| standard  | 150            | 8          | medium          | on      |
| deep      | 300            | 15         | high            | on      |
| stealth   | 200            | —          | medium          | off     |
| api_only  | 100            | —          | medium          | off     |

`max_iterations` is the hard ceiling on how many LLM calls one agent can make.
Sub-agents inherit this same limit from their parent.

---

## 2. The Agent Loop (`base_agent.py`)

Every agent runs `agent_loop(task)`, a `while True` that:

1. Checks for stop/cancel/input-wait flags.
2. Calls `state.increment_iteration()`.
3. **Injects phase-gate messages** at 33%, 66%, and 90% of `max_iterations` to
   force the agent to transition from recon → exploit → report.
4. **Injects the Hypothesis Ledger summary** every 10 iterations (if non-empty),
   so the LLM always knows what has already been tested.
5. Calls `self.llm.generate(conversation_history)` → gets a streaming response.
6. Adds the response to `state.messages` as an assistant turn.
7. Parses XML tool invocations from the response.
8. Calls `_execute_actions(actions)` → runs tools → appends tool results as user
   turns in `state.messages`.
9. If a `finish_scan` / `agent_finish` tool fires, marks the agent done and
   exits.
10. Stall detection: 3 consecutive no-action iterations → corrective prompt
    injected. 8 consecutive → non-interactive run aborted.

The loop is fully asynchronous (`asyncio`). Each sub-agent runs in its own OS
thread with its own `asyncio` event loop (`asyncio.new_event_loop()`), so all
agents truly run in parallel.

---

## 3. The LLM Layer (`llm.py`)

`LLM.generate(conversation_history)` is called every iteration. Its job:

### 3a. Message Preparation (`_prepare_messages`)

1. Prepends the `system_prompt` (built once at startup — see §5).
2. Appends an `<agent_identity>` user message (agent name/ID metadata).
3. **Runs `MemoryCompressor.compress_history`** (see §4) — this may call the
   LLM a second time just to compress old messages.
4. Extends the message list with the compressed history.

### 3b. Request Size Enforcement (`_enforce_request_size_limits`)

Hard limits before any request is sent:
- `phantom_max_request_chars` = 900,000 characters (default)
- `phantom_max_request_estimated_tokens` = 220,000 tokens (default)

If exceeded, a 4-step reduction cascade fires:
1. Drop all but 1 old image from the message list.
2. Force-compress the full message list via LLM summarization.
3. Trim history to the newer half (minimum 12 messages kept).
4. Hard fail with `LLMRequestFailedError` if still over limit.

### 3c. The Actual LLM Call (`_stream`)

Uses LiteLLM's `acompletion(..., stream=True)`. Streams tokens back, stops
early when a complete `</function>` closing tag is received (so the agent
doesn't wait for the model to finish its full reasoning output).

After the stream ends, `normalize_tool_format` and `parse_tool_invocations` are
called to extract structured tool calls from the raw text.

### 3d. Retry & Fallback Logic

- Up to 10 retries on 429 (rate limit), with exponential backoff up to 120 s.
- Up to 5 retries on other errors, backoff up to 10 s.
- On 400 (context overflow): one last-chance force-compress attempt.
- If primary model exhausts all retries: falls back to `PHANTOM_FALLBACK_LLM`
  if configured.

### 3e. Adaptive Scan Mode

After each successful LLM call, `_check_adaptive_scan_mode` checks whether the
cumulative cost has exceeded `phantom_adaptive_scan_threshold` (default 0.8 =
80%) of the per-request budget. If yes, it automatically downgrades the scan
mode (deep → standard → quick), which changes how many skill files are loaded
into the next system prompt.

### 3f. Model Routing

If `phantom_routing_enabled=true`, the LLM layer inspects the message to decide
whether it is a "reasoning" turn or a "tool" turn and routes to different models
accordingly (`phantom_routing_reasoning_model` / `phantom_routing_tool_model`).

---

## 4. Memory Compressor (`memory_compressor.py`)

The compressor runs synchronously (in a thread, via `asyncio.to_thread`) on
every iteration.

**Compression threshold** = min(120,000, context_window × 0.6). For a 128K
model this is 76,800 tokens. When `sum(tokens in all history messages)` exceeds
this threshold, compression fires.

**Algorithm:**
1. Strip images above the limit (max 3 images, max 300 KB total).
2. Keep all system messages.
3. Keep the 15 most recent non-system messages intact.
4. For the older messages: divide them into chunks of ~4,000 tokens. For each
   chunk, call the LLM with a summarization prompt (max 1,500 output tokens).
   Each chunk is replaced by a single `<context_summary>` user message.

The compressor can call the LLM multiple times in one iteration (once per chunk
of old history). It uses `PHANTOM_COMPRESSOR_LLM` if set, otherwise the same
model as the agent — meaning compression calls cost money at full model rates
unless you configure a cheaper compressor model.

---

## 5. System Prompt (`system_prompt.jinja`)

The system prompt is built once when `LLM.__init__` runs. It is a Jinja2
template (458 lines) that renders with:

- Hard-coded behavioral rules (reporting mandate, communication rules, execution
  guidelines, vulnerability priorities, multi-agent rules, tool call format)
- The full tool schema for every registered tool (injected via
  `{{ get_tools_prompt() }}`)
- Skill content: for each skill name in `llm_config.skills`, the entire
  Markdown content of that skill file is injected inside `<specialized_knowledge>`
  tags

**Skills loaded per agent type:**
- Root agent always loads `scan_modes/<mode>.md` (e.g. `deep.md`)
- Sub-agents load the skill files passed in `create_agent(skills=[...])`, plus
  `scan_modes/<mode>.md`
- Example: a SQL injection sub-agent loads `sql_injection.md` (~several KB) +
  `deep.md` (~3 KB). Its system prompt may be 15,000–25,000 tokens on its own.

Because the system prompt is sent on every iteration as the first message, a
large system prompt is the single most expensive fixed cost per LLM call.

---

## 6. Tool System (`registry.py`)

Tools are Python functions decorated with `@register_tool`. The registry builds
an XML schema description of every tool's parameters, which is injected into the
system prompt via `get_tools_prompt()`.

The agent outputs a tool call as:
```
<function=tool_name>
<parameter=param_name>value</parameter>
</function>
```

The LLM streaming parser stops as soon as it sees `</function>` to minimize
latency and output token cost.

**Available tool categories:**
- `terminal_execute` — shell commands in the Docker sandbox (nmap, nuclei, sqlmap, ffuf, etc.)
- `python_execute` — Python code execution in the sandbox
- `browser_*` — browser automation (Playwright/Chromium)
- `proxy_*` — Caido proxy traffic inspection
- `create_agent`, `view_agent_graph`, `send_message_to_agent`, `wait_for_message`,
  `agent_finish` — multi-agent orchestration
- `create_vulnerability_report` — structured vulnerability reporting
- `notes_*`, `file_edit_*`, `web_search`, `think`, `todo_*` — auxiliary tools
- `finish_scan` — root agent termination

---

## 7. Multi-Agent Orchestration (`agents_graph_actions.py`)

When the LLM calls `create_agent(name, task, skills, inherit_context)`:

1. A new `AgentState` is created with `parent_id` set to the calling agent's ID.
2. A new `PhantomAgent` is constructed with its own `LLMConfig` (inheriting scan
   mode and timeout from parent).
3. If `inherit_context=True` (default), a `deepcopy` of the parent's full
   `conversation_history` is prepended to the child's initial messages. This
   gives the child background context but also significantly increases its
   starting token count.
4. A new OS `threading.Thread` is started. The thread creates its own
   `asyncio` event loop and runs `agent.agent_loop(task)` inside it.
5. The parent agent does not block — it continues its own loop immediately after
   calling `create_agent`. It later uses `wait_for_message` to pause until
   child agents report back.

**Hypothesis Ledger is shared**: the parent's `HypothesisLedger` object is
passed directly (by reference) to all child agents. This means all agents in
the tree see each other's tested payloads and surfaces without any extra
communication overhead.

**Agent completion reporting**: when `agent_finish` is called by a sub-agent,
it sends a structured `<agent_completion_report>` message to the parent via
`_agent_messages[parent_id]`. This message is picked up by the parent on its
next iteration in `_check_agent_messages` and injected as a user turn in the
parent's `conversation_history`. These reports add tokens on every agent
completion.

---

## 8. Hypothesis Ledger (`hypothesis_ledger.py`)

The Hypothesis Ledger is external structured memory that survives context
compression (the compressor never sees it — it lives on the agent object, not
in the message list).

It tracks:
- Tested surfaces (endpoint + method + parameter combinations)
- Payloads tried per surface
- Outcome (found / not_found / error)
- Timestamps

Every 10 iterations, a `to_prompt_summary(top_n=10)` digest is injected into
the conversation as a user message. This keeps the LLM aware of coverage state
without repeatedly testing the same thing.

---

## 9. Vulnerability Reporting (`reporting_actions.py`)

`create_vulnerability_report` is a full structured pipeline:

1. **Required field validation**: title, description, impact, target, technical
   analysis, PoC description, PoC code, remediation steps must all be non-empty.
2. **CVSS 3.1 calculation**: parses the `cvss_breakdown` XML the LLM provides,
   validates all 8 CVSS vector components, computes a base score and severity
   using the `cvss` library.
3. **CVE/CWE format validation**: regex-validates CVE-YYYY-NNNNN and CWE-NNN
   formats.
4. **Code location validation**: for white-box scans, validates file paths and
   line number ranges.
5. **LLM-based deduplication**: compares the new report against all existing
   reports using an LLM call to detect semantic duplicates, not just exact
   string matches.
6. **Confidence tiering**: SUSPECTED / LIKELY / VERIFIED. VERIFIED is
   auto-assigned only if the PoC script is replayed and confirmed; manual
   VERIFIED claims are rejected.
7. The final report is written to the `phantom_runs/<run_id>/` directory as JSON.

---

## 10. Diff Scanner (`diff_scanner.py`)

`diff_scanner.py` compares two scan run directories and produces a delta report:
- New vulnerabilities (in run B but not A)
- Fixed vulnerabilities (in A but not B)
- Persistent vulnerabilities (in both)

This is designed for CI/CD pipelines to detect regressions.

---

## 11. Data Flow Diagram (per iteration)

```
[Agent Loop iteration N]
         |
         v
_process_iteration()
         |
         +-- inject phase-gate message if at 33/66/90%
         +-- inject ledger summary if iteration % 10 == 0
         |
         v
llm.generate(conversation_history)
         |
         +-- _prepare_messages()
         |       +-- prepend system_prompt (fixed, ~10k-40k tokens)
         |       +-- prepend agent_identity block
         |       +-- MemoryCompressor.compress_history()  <-- may call LLM again
         |       +-- append compressed history
         |
         +-- _enforce_request_size_limits()
         |       +-- drop old images
         |       +-- force-compress if still too large
         |       +-- trim history if still too large
         |
         +-- acompletion(messages, stream=True)
         |       <-- tokens stream back from LLM provider
         |       <-- streaming stops at first </function>
         |
         +-- parse_tool_invocations(response)
         |
         v
_execute_actions(actions)
         |
         +-- run tool (terminal / python / browser / ...)
         +-- append tool result as user message in state.messages
         |
         v
[next iteration]
```

---

## 12. Persistence & Checkpointing

The agent saves checkpoints during the scan (`_maybe_save_checkpoint`). If a
scan is interrupted mid-run, it can theoretically be resumed from the last
checkpoint. All output (vulnerability reports, agent graph state, scan metadata)
is written to `phantom_runs/<run_id>/`.
