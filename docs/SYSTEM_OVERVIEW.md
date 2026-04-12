# Phantom System Overview (Code-Reconstructed)

## 0) Evidence Basis and Reconstruction Method

This overview is reconstructed from executable code paths and runtime wiring, not marketing copy.

Primary evidence examined:

- CLI and execution entrypoints: `phantom/interface/cli_app.py:131`, `phantom/interface/cli.py:46`, `phantom/interface/main.py:523`
- Agent core loop: `phantom/agents/PhantomAgent/phantom_agent.py:23`, `phantom/agents/base_agent.py:247`
- Tool execution path: `phantom/tools/executor.py:364`, `phantom/tools/executor.py:1441`
- Runtime sandbox layer: `phantom/runtime/docker_runtime.py:36`, `phantom/runtime/tool_server.py:137`
- Persistence/output systems: `phantom/telemetry/tracer.py:711`, `phantom/checkpoint/checkpoint.py:210`, `phantom/logging/audit.py:69`
- Configuration and defaults: `phantom/config/config.py:32`

---

## 1) What Phantom Actually Is

Phantom is a **Python-based autonomous security testing orchestrator** that runs an LLM-driven ReAct loop on the host and executes offensive/security tools inside a per-scan Docker sandbox.

At runtime, Phantom behaves as:

1. A CLI/TUI control plane that accepts targets/instructions.
2. A root agent (`PhantomAgent`) that converts scan context into a single evolving task.
3. A generic iterative loop (`BaseAgent.agent_loop`) that repeatedly:
   - sends conversation + tool schemas to the LLM,
   - parses tool calls,
   - executes tools (sandboxed or local),
   - feeds tool results back as next-turn observations.
4. A report writer that persists findings and final scan artifacts.

Concrete evidence:

- Scan execution starts in `run_cli()` and instantiates `PhantomAgent`: `phantom/interface/cli.py:46`, `phantom/interface/cli.py:380`
- Root execution path calls `execute_scan()` then `agent_loop()`: `phantom/agents/PhantomAgent/phantom_agent.py:23`, `phantom/agents/PhantomAgent/phantom_agent.py:111`
- ReAct loop and iteration lifecycle are implemented in `BaseAgent.agent_loop`: `phantom/agents/base_agent.py:247`
- Tool call pipeline is `process_tool_invocations()` -> `execute_tool()` -> sandbox/local dispatch: `phantom/tools/executor.py:1441`, `phantom/tools/executor.py:364`, `phantom/tools/executor.py:427`

### Practical characterization (non-marketing)

Phantom is best described as a **general agentic pentest runner** with reporting/persistence, rather than a pure scanner. It includes offensive scanning capabilities, but also generic agent tooling (file edit, python, notes, todo, agent graph), depending on mode and runtime registration.

Evidence:

- Tool registry loads many non-scanner tools: `phantom/tools/__init__.py:31`
- Dynamic tool subsets are prompt-level optimization, not hard runtime isolation: `phantom/llm/llm.py:277`, `phantom/tools/dynamic_tools.py:204`

---

## 2) System Boundaries

## 2.1 In-Boundary Components (Phantom-owned)

- **Control Plane**: CLI/TUI command handling, target parsing, profile application.
  - `phantom/interface/cli_app.py:131`, `phantom/interface/utils.py:565`
- **Agentic Reasoning Plane**: LLM orchestration, memory compression, iteration control.
  - `phantom/agents/base_agent.py:247`, `phantom/llm/llm.py:333`, `phantom/llm/memory_compressor.py`
- **Tool Orchestration Plane**: schema validation, execution routing, result shaping.
  - `phantom/tools/registry.py:152`, `phantom/tools/executor.py:579`
- **Sandbox Runtime Plane**: container lifecycle, tool server auth, port/token wiring.
  - `phantom/runtime/docker_runtime.py:521`, `phantom/runtime/tool_server.py:85`
- **State and Persistence Plane**: checkpoints, run artifacts, vulnerability files, stats.
  - `phantom/checkpoint/checkpoint.py:210`, `phantom/telemetry/tracer.py:733`
- **Audit/Telemetry Plane**: local audit/event logging.
  - `phantom/logging/audit.py:1`, `phantom/telemetry/tracer.py:167`

## 2.2 Out-of-Boundary Dependencies (External systems)

- LLM providers via LiteLLM APIs.
- Docker daemon and host networking.
- Target applications/infrastructure under test.
- Third-party tooling inside sandbox image (nmap, nuclei, sqlmap, etc.).
- Optional external APIs (Shodan, NVD, etc.) based on keys.

## 2.3 Trust Boundaries

1. **User -> Host Agent** (CLI args, instruction files, target strings).
2. **Host Agent -> LLM Provider** (sends prompts/history/tool schema).
3. **LLM Output -> Tool Executor** (high-risk boundary; model controls tool invocations).
4. **Host -> Sandbox Container** (token-authenticated HTTP to tool server).
5. **Sandbox -> Target Network** (offensive traffic generation).
6. **Runtime -> Local Artifacts** (writes reports/checkpoints/audit files).

Proof snippets:

- Bearer token validation in tool server: `phantom/runtime/tool_server.py:85`
- Host sends tool execution over HTTP with bearer token: `phantom/tools/executor.py:487`
- Checkpoint HMAC integrity verification: `phantom/checkpoint/checkpoint.py:255`

---

## 3) Inputs and Outputs

## 3.1 Inputs

### A) Operator/CLI Inputs

- Targets (repeatable `--target`) accepting URL, repository, local path, domain, or IP.
  - `phantom/interface/cli_app.py:132`, `phantom/interface/utils.py:565`
- Optional mission constraints (`--instruction`, `--instruction-file`).
  - `phantom/interface/cli_app.py:140`
- Mode/preset/control flags (`--scan-mode`, `--profile`, `--non-interactive`, `--resume`, etc.).
  - `phantom/interface/cli_app.py:180`, `phantom/interface/cli_app.py:234`

### B) Environment and Config Inputs

- LLM model/key/base and budget/timeout settings.
  - `phantom/config/config.py:35`, `phantom/config/config.py:47`, `phantom/config/config.py:165`
- Runtime image/backend and sandbox resource limits.
  - `phantom/config/config.py:163`, `phantom/config/config.py:168`

### C) Stateful Inputs

- Resume checkpoints (`checkpoint.json` + HMAC).
  - `phantom/interface/cli.py:62`, `phantom/checkpoint/checkpoint.py:246`

### D) Runtime Feedback Inputs

- Tool output observations (HTTP responses, scanner output, browser output, etc.) are fed back into LLM context every iteration.
  - `phantom/tools/executor.py:1480`, `phantom/agents/base_agent.py:691`

## 3.2 Outputs

### A) Real-time Interaction Outputs

- Live CLI/TUI streaming of progress and findings.
  - `phantom/interface/cli.py:396`, `phantom/interface/tui.py`

### B) Durable Run Artifacts

Under `phantom_runs/<run_name>/` Phantom writes:

- Vulnerability markdown files: `vulnerabilities/*.md`
- Vulnerability index CSV: `vulnerabilities.csv`
- Final narrative report: `penetration_test_report.md`
- Stats snapshot: `scan_stats.json`
- Events stream: `events.jsonl`
- Optional audit files when enabled: `audit.jsonl`, `audit.log`
- Checkpoint files: `checkpoint.json`, `checkpoint.json.hmac`

Evidence:

- Artifact path resolution and writes: `phantom/telemetry/tracer.py:308`, `phantom/telemetry/tracer.py:733`, `phantom/telemetry/tracer.py:830`, `phantom/telemetry/tracer.py:870`
- Checkpoint persistence: `phantom/checkpoint/checkpoint.py:210`
- Audit initialization paths: `phantom/logging/audit.py:5`, `phantom/logging/audit.py:107`

### C) Process-Level Outputs

- Exit code behavior in non-interactive mode indicates vulnerability presence.
  - `phantom/interface/cli_app.py:413`, `phantom/interface/cli.py:452`

---

## 4) Core Purpose vs Secondary Features

## Core Purpose (Observed)

Phantom’s core production path is:

1. Normalize targets and bootstrap run context.
2. Provision sandbox.
3. Run iterative LLM-driven reasoning + tool execution loop.
4. Create vulnerability reports from confirmed or suspected evidence.
5. Finalize scan and persist artifacts.

Core evidence chain:

- Run bootstrap: `phantom/interface/cli.py:232`
- Sandbox init in agent loop: `phantom/agents/base_agent.py:581`
- LLM iterative generation: `phantom/agents/base_agent.py:691`
- Tool execution and feedback: `phantom/tools/executor.py:1441`
- Finding creation: `phantom/tools/reporting/reporting_actions.py:544`
- Scan completion gate: `phantom/tools/finish/finish_actions.py:96`

## Secondary Features (Non-core but significant)

- Resume/checkpoint with integrity and optional encryption.
  - `phantom/checkpoint/checkpoint.py:143`, `phantom/checkpoint/checkpoint.py:187`
- Multi-agent graph orchestration and agent messaging.
  - `phantom/agents/base_agent.py:213`, `phantom/tools/agents_graph/agents_graph_actions.py`
- Cost/rate-limit/circuit-breaker protections.
  - `phantom/llm/llm.py:75`, `phantom/llm/llm.py:809`
- Audit/event telemetry and optional OTEL plumbing.
  - `phantom/telemetry/tracer.py:121`, `phantom/logging/audit.py:60`
- UI/UX and report export formats.
  - `phantom/interface/cli_app.py:851`, `phantom/interface/cli_app.py:917`

---

## 5) Reality-Check: Verified Observations vs Common Claims

This section documents verifiable behavior differences that matter architecturally.

1. **“Verified findings only” is not strictly enforced.**
   - Reports can be created with `confidence="SUSPECTED"` and without PoC script (`poc_script_code` optional for SUSPECTED).
   - PoC replay is asynchronous and may remain `PENDING`, `FAILED`, or `SKIPPED` while report is already created.
   - Evidence: `phantom/tools/reporting/reporting_actions.py:295`, `phantom/tools/reporting/reporting_actions.py:315`, `phantom/tools/reporting/reporting_actions.py:653`

2. **Command injection guard exists but is intentionally disabled in tool argument validation path.**
   - `_validate_tool_argument_injection()` returns `None` unconditionally with “disabled per user request”.
   - Evidence: `phantom/tools/executor.py:238`, `phantom/tools/executor.py:247`

3. **OTEL remote telemetry is currently hard-disabled in code path.**
   - `is_otel_enabled()` always returns `False`.
   - Evidence: `phantom/telemetry/flags.py:1`

4. **Sandbox image pinning posture is mixed across build files.**
   - `containers/Dockerfile` uses `kalilinux/kali-rolling:latest`.
   - `containers/Dockerfile.sandbox` pins by digest.
   - Evidence: `containers/Dockerfile:4`, `containers/Dockerfile.sandbox:5`

These are not value judgments; they are system-truth details needed for accurate architecture modeling.

---

## 6) High-Confidence System Boundary Statement

Phantom is a **host-side AI orchestration engine** that delegates offensive execution to a **Dockerized sandbox service** and persists a rich run record to local disk.

The hard architectural boundary is **host orchestrator <-> sandbox tool server (token-authenticated HTTP)**, while decision authority is primarily in the LLM loop with host-level policy gates (scope/rbac/budget/checkpoint/audit).

---

## 7) Proof Checklist (Requirement-to-Evidence)

- **Define what Phantom actually is** -> `phantom/interface/cli.py:380`, `phantom/agents/base_agent.py:247`, `phantom/tools/executor.py:1441`
- **Identify boundaries** -> `phantom/runtime/docker_runtime.py:521`, `phantom/runtime/tool_server.py:137`, `phantom/runtime/tool_server.py:85`
- **Identify inputs/outputs** -> `phantom/interface/cli_app.py:131`, `phantom/interface/utils.py:565`, `phantom/telemetry/tracer.py:711`
- **Core purpose vs secondary features** -> `phantom/agents/PhantomAgent/phantom_agent.py:23`, `phantom/tools/finish/finish_actions.py:96`, `phantom/checkpoint/checkpoint.py:210`

This completes Step 1 (System Overview) with code-grounded validation.
