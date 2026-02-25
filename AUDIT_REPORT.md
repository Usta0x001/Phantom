# PHANTOM SECURITY SCANNER — DEEP OFFENSIVE AUDIT REPORT

**Date:** 2025  
**Auditor:** Automated Deep Code Audit  
**Project:** Phantom v0.9.0 — Autonomous Offensive Security Intelligence  
**Scope:** Full codebase review — every Python module, configuration, test, and model  

---

## EXECUTIVE SUMMARY

Phantom is a Python-based autonomous penetration-testing agent that uses LLMs to orchestrate security scanning tools inside Docker sandboxes. The audit reviewed **45+ files** (~15,000 lines of code) across agents, core modules, tools, LLM integration, models, runtime, telemetry, config, and tests.

**Total Findings: 67**

| Severity | Count |
|:---------|:-----:|
| CRITICAL | 6 |
| HIGH | 14 |
| MEDIUM | 21 |
| LOW | 12 |
| SECURITY | 5 |
| ARCHITECTURE | 4 |
| TEST GAPS | 3 |
| DEAD CODE | 2 |

---

## 1. CRITICAL BUGS (6)

### C-01: `_prepare_messages()` DESTROYS conversation history in-place

**File:** `phantom/llm/llm.py` lines 165–184  
**Type:** Data corruption / Memory mutation  

```python
def _prepare_messages(self, conversation_history: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ...
    conversation_history.clear()      # <-- MUTATES caller's list
    conversation_history.extend(compressed)  # <-- Replaces with compressed
```

`conversation_history` is a direct reference to `agent.state.messages`. Calling `.clear()` and `.extend()` destroys the original conversation permanently and replaces it with compressed summaries **on every LLM call** that triggers compression. This means:
- Original tool call records, raw findings, and detailed messages are **irrecoverably lost**
- Sub-agents inherit already-compressed histories, losing critical detail
- Repeated compressions compound information loss (summary of summary of summary...)

**Fix:** Return a new list instead of mutating in-place, or deepcopy before mutating.

---

### C-02: Module-level mutable dicts without thread locking in agent graph

**File:** `phantom/tools/agents_graph/agents_graph_actions.py`  
**Type:** Race condition / Thread safety  

```python
_agent_graph: dict[str, Any] = {"nodes": {}, "edges": []}
_agent_messages: dict[str, list[dict[str, Any]]] = {}
_agent_instances: dict[str, Any] = {}
_agent_states: dict[str, Any] = {}
_running_agents: dict[str, Any] = {}
```

These module-level dicts are read/written from **multiple threads** (each sub-agent runs in its own thread via `_run_agent_in_thread()` → `asyncio.new_event_loop()`). Python dicts are NOT atomic for compound operations. Specifically:
- `_agent_graph["edges"]` is a list appended from multiple threads simultaneously
- `_agent_messages[agent_id].append(...)` from multiple threads
- `_running_agents.pop(agent_id, None)` concurrent with iteration

**Impact:** Data corruption, lost messages, KeyError crashes, agent desynchronization.  
**Fix:** Use a `threading.Lock` for all shared state mutations.

---

### C-03: Verification Engine marks unverified vulns as FALSE POSITIVE

**File:** `phantom/core/verification_engine.py` lines 80–84  
**Type:** Critical logic error  

```python
if result.status == VerificationStatus.IN_PROGRESS:
    result.mark_failed("All verification attempts failed")
    vuln.mark_false_positive("Automatic verification could not confirm exploitability")
```

When the verification engine cannot confirm exploitability (e.g., because OOB methods are unimplemented stubs, or the http_client is None), the vulnerability is marked as **FALSE POSITIVE**. This is logically wrong:

- **Failure to verify ≠ False positive.** The vulnerability may be real but unverifiable with available methods.
- OOB verification methods (`_verify_oob_http`, `_verify_oob_dns`) are stubs that always return `success=False`, so any SSRF/RCE/XXE vuln will always be marked false positive.
- This means **real critical vulnerabilities are being silently suppressed** from reports.

**Fix:** Mark as `UNVERIFIED` or `INCONCLUSIVE` instead of `FALSE_POSITIVE`. Only mark FP when there is positive evidence of non-exploitability.

---

### C-04: `compliance_mapper.py` pass_rate is always 0.0

**File:** `phantom/core/compliance_mapper.py` ~line 490  
**Type:** Logic error / Dead computation  

```python
passed_ids: set[str] = set()  # Never populated
# ... later:
pass_rate = len(passed_ids) / total_controls if total_controls > 0 else 0.0
```

The `passed_ids` set is initialized as empty and **never receives any elements**. The compliance report always shows 0% pass rate regardless of actual findings. This produces misleading compliance reports.

**Fix:** Populate `passed_ids` based on controls that have no violations, or remove the field.

---

### C-05: `memory_compressor.py` uses synchronous `litellm.completion()` in async context

**File:** `phantom/llm/memory_compressor.py`  
**Type:** Event loop blocking  

```python
def _summarize_messages(self, messages: list[dict]) -> str:
    response = litellm.completion(...)  # SYNCHRONOUS - blocks event loop
```

`MemoryCompressor._summarize_messages()` is called from the async agent loop path (`_prepare_messages` → `compress()`). The synchronous `litellm.completion()` call **blocks the entire asyncio event loop** for the duration of the LLM API call (potentially 10-30+ seconds). During this time:
- No other async tasks can run
- Heartbeats, timeouts, and other coroutines are starved
- The entire application appears frozen

**Fix:** Use `await litellm.acompletion()` or run in `asyncio.to_thread()`.

---

### C-06: `nuclei_templates.py` produces invalid YAML

**File:** `phantom/core/nuclei_templates.py`  
**Type:** Output corruption  

```python
def _yaml_escape(text: str) -> str:
    return text.replace(":", "\\:")  # NOT valid YAML escaping
```

YAML does not use `\:` as an escape sequence. This produces templates that Nuclei will reject with parse errors. Additionally, the template generation uses string concatenation rather than a YAML library, making it prone to injection and formatting errors.

**Fix:** Use proper YAML quoting (wrap in quotes) or use `yaml.dump()` from PyYAML/ruamel.yaml.

---

## 2. HIGH SEVERITY (14)

### H-01: ScanMode enum mismatch between CLI and LLM config

**Files:** `phantom/interface/cli_app.py` / `phantom/llm/config.py`  
**Type:** Configuration mismatch  

`cli_app.py` defines `ScanMode` with 5 values: `quick, standard, deep, stealth, api_only`.  
`llm/config.py` validates `scan_mode` against only 3: `quick, standard, deep` — defaulting to `"deep"` for unknown values.

Selecting `--scan-mode stealth` or `--scan-mode api_only` silently falls back to deep mode, defeating the purpose of stealth scanning (rate limiting, tool restrictions).

---

### H-02: Slack webhook bypasses SSRF URL validation

**File:** `phantom/core/notifier.py`  
**Type:** Security / SSRF  

`WebhookChannel.send()` calls `_validate_url()` before the POST. However, `SlackChannel` inherits from the base and calls `urllib.request.Request(self.webhook_url, ...)` **without calling `_validate_url()`**. An attacker controlling the Slack webhook URL config could target internal services.

---

### H-03: `scan_profiles.py` PROFILES dict contains mutable objects

**File:** `phantom/core/scan_profiles.py`  
**Type:** Global state corruption  

```python
PROFILES: dict[str, ScanProfile] = {
    "quick": ScanProfile(name="quick", ...),  # Mutable dataclass (frozen=False)
    ...
}
```

`ScanProfile` is not frozen. Any code that gets a profile via `get_profile("quick")` receives a direct reference to the global object. Mutating it (e.g., `profile.max_iterations = 999`) permanently corrupts the profile for all subsequent operations.

**Fix:** Make `ScanProfile` frozen, or return copies from `get_profile()`.

---

### H-04: `dedupe.py` uses synchronous `litellm.completion()` in tool path

**File:** `phantom/llm/dedupe.py`  
**Type:** Event loop blocking  

Same issue as C-05. `check_duplicate()` is sync and calls `litellm.completion()`. This is called from `reporting_actions.py` → `create_vulnerability_report()` which runs in the agent's async context.

---

### H-05: `scope_validator.py` regex compilation on every check — ReDoS risk

**File:** `phantom/core/scope_validator.py`  
**Type:** Performance / Security  

`_match_regex()` calls `re.compile()` on each invocation without caching. If users supply crafted regex patterns in scope config, this could cause catastrophic backtracking (ReDoS). For normal use, it's just wasteful.

**Fix:** Cache compiled regexes or use `re.compile()` once at configuration time.

---

### H-06: `base_agent.py` bare except that does nothing

**File:** `phantom/agents/base_agent.py` ~line 336  
**Type:** Error swallowing  

```python
except Exception as e:
    raise  # This except clause is a no-op
```

While re-raising is technically safe, the pattern suggests an incomplete error handler where logging or cleanup was intended but never implemented.

---

### H-07: `cleanup_runtime()` race condition

**File:** `phantom/runtime/__init__.py`  
**Type:** Thread safety  

```python
def cleanup_runtime() -> None:
    global _global_runtime
    if _global_runtime is not None:  # Check without lock
        _global_runtime.cleanup()
        _global_runtime = None
```

`_global_runtime` is checked and set without acquiring `_runtime_lock`, while `get_runtime()` uses the lock. Concurrent calls to `cleanup_runtime()` and `get_runtime()` can crash.

---

### H-08: `knowledge_store.py` holds lock during file I/O

**File:** `phantom/core/knowledge_store.py`  
**Type:** Performance / Contention  

`save_vulnerability()` acquires `self._lock` and calls `_save_vulns()` → `_atomic_write()` which performs file I/O while the lock is held. This blocks all other threads from reading/writing the store for the duration of disk writes.

**Fix:** Copy data under lock, release lock, then write.

---

### H-09: `interactsh_client.py` spawns new process on every poll

**File:** `phantom/core/interactsh_client.py`  
**Type:** Resource leak / Performance  

`poll_interactions()` starts a new `interactsh-client` subprocess on every call instead of maintaining a persistent session. Each poll creates and destroys a process.

---

### H-10: `llm.py` streaming parser uses fragile heuristic

**File:** `phantom/llm/llm.py`  
**Type:** Reliability  

The `_stream()` method uses a `done_streaming` counter that breaks after 5 extra chunks of empty content. This is a brittle heuristic that could:
- Break early if the LLM pauses briefly during generation
- Spin indefinitely on providers that send trailing metadata chunks

---

### H-11: `llm.py` uses private litellm API for retry decisions

**File:** `phantom/llm/llm.py`  
**Type:** Fragile dependency  

```python
litellm._should_retry(...)  # Private API — may break on any update
```

This will break silently on litellm version updates.

---

### H-12: Agent sub-agent creation inherits full conversation history

**File:** `phantom/tools/agents_graph/agents_graph_actions.py`  
**Type:** Memory explosion  

`create_agent()` passes the full parent conversation history to sub-agents. For deep agent trees (depth 3+), this means the history is copied and grows exponentially. Each sub-agent's messages include all parent messages plus their own.

---

### H-13: `notifier.py` uses synchronous `urllib.request` in potentially async context

**File:** `phantom/core/notifier.py`  
**Type:** Event loop blocking  

`WebhookChannel.send()` and `SlackChannel.send()` use synchronous `urllib.request.urlopen()`. When called from the async enrichment pipeline in `finish_actions.py`, this blocks the event loop.

---

### H-14: `warm_up_llm()` doesn't propagate failure

**File:** `phantom/interface/main.py`  
**Type:** Silent failure  

`warm_up_llm()` catches LLM connection failures, prints an error, and **returns normally** instead of raising. The scan then proceeds with a non-functional LLM, producing empty results or crashing later with confusing errors.

---

## 3. MEDIUM SEVERITY (21)

### M-01: `mitre_enrichment.py` compiles regex per keyword per finding

**File:** `phantom/core/mitre_enrichment.py`  
**Type:** Performance  

`re.search(r'\b' + re.escape(keyword) + r'\b', search_text)` is called for every keyword-finding pair — O(n×m) regex compilations. Should pre-compile all keyword patterns.

---

### M-02: `audit_logger.py` calls `os.stat()` on every write for rotation check

**File:** `phantom/core/audit_logger.py`  
**Type:** Performance  

`_rotate_if_needed()` does `self.log_path.stat()` on every `_write_entry()` call while holding the lock.

---

### M-03: `state.py` messages list grows unboundedly

**File:** `phantom/agents/state.py`  
**Type:** Memory leak  

`AgentState.messages` is a plain list with no size limit. Long-running scans accumulate thousands of messages. While compression handles this partially, the original list keeps growing before compression triggers.

---

### M-04: `attack_graph.py` BFS uses `queue.pop(0)` — O(n) on list

**File:** `phantom/core/attack_graph.py` `get_vulnerabilities_for_host()`  
**Type:** Performance  

```python
queue = [host_id]
while queue:
    current = queue.pop(0)  # O(n) — use collections.deque
```

---

### M-05: `attack_path_analyzer.py` may produce combinatorial explosion

**File:** `phantom/core/attack_path_analyzer.py`  
**Type:** Performance  

`discover_all_paths()` uses `nx.all_simple_paths` with cutoff=8. On dense graphs, this can produce millions of paths. The `max_paths` parameter provides a limit, but the underlying NetworkX call still computes paths lazily — a very dense graph could still be extremely slow.

---

### M-06: `diff_scanner.py` `_SARIF_LEVEL_MAP` re-created on every call

**File:** `phantom/core/diff_scanner.py`  
**Type:** Minor waste  

The SARIF level mapping dict is a local variable rebuilt on each invocation of `_parse_sarif`.

---

### M-07: `report_generator.py` opens files without explicit encoding error handling

**File:** `phantom/core/report_generator.py`  
**Type:** Reliability  

File writes don't specify `errors=` parameter. Non-UTF-8 characters in scan data (e.g., binary responses) could cause `UnicodeEncodeError`.

---

### M-08: `cli_app.py` report export uses first `*.json` file found

**File:** `phantom/interface/cli_app.py`  
**Type:** Fragile logic  

```python
json_files = list(run_dir.glob("*.json"))
if json_files:
    report_path = json_files[0]  # Arbitrary first match
```

Multiple JSON files in the run directory (e.g., graph.json, knowledge.json) means the wrong file could be selected for export.

---

### M-09: `cli_app.py` `_auto_install_completion()` imports non-guaranteed packages

**File:** `phantom/interface/cli_app.py`  
**Type:** Runtime error  

Imports `click` and `shellingham` which are not listed as direct dependencies in `pyproject.toml` (they're transitive via typer). May break if typer changes its dependency tree.

---

### M-10: `config.py` stores API keys in plaintext JSON

**File:** `phantom/config/config.py`  
**Type:** Security  

Config file at `~/.phantom/cli-config.json` stores `LLM_API_KEY` and `PERPLEXITY_API_KEY` in plaintext. `chmod(0o600)` is attempted but "may fail on Windows" per the inline comment.

---

### M-11: `phantom_agent.py` uses `hasattr()` to handle both dict and object profiles

**File:** `phantom/agents/PhantomAgent/phantom_agent.py`  
**Type:** Type safety  

```python
if hasattr(profile, 'skip_tools'):
    ...
```

This duck-typing approach is fragile. If the profile object changes shape, the fallback silently produces incorrect behavior.

---

### M-12: `priority_queue.py` `ScanOrchestrator.pop()` re-heaps skipped items

**File:** `phantom/core/priority_queue.py`  
**Type:** Performance  

On every `pop()`, completed items are removed and the remaining items are re-heapified. For large queues with many completed items, this is O(k log n) per pop.

---

### M-13: `memory_compressor.py` `_handle_images()` mutates dicts in-place

**File:** `phantom/llm/memory_compressor.py`  
**Type:** Side effect  

```python
item.update({"type": "text", "text": desc})
```

This changes message content items from `image_url` type to `text` type, permanently altering the original message list.

---

### M-14: `memory_compressor.py` on summarization failure returns only first message

**File:** `phantom/llm/memory_compressor.py`  
**Type:** Data loss  

If the LLM summarization call fails, the compressor returns `messages[0]` — all other messages in the chunk are lost.

---

### M-15: `register_tool()` XML schema fallback produces a stub

**File:** `phantom/tools/registry.py`  
**Type:** Missing schemas  

When a tool's XML schema file is not found, it generates:
```xml
<tool name="tool_name"><description>Schema not found for tool.</description></tool>
```

The LLM sees this as a valid tool with no parameters, potentially causing it to call tools with missing arguments.

---

### M-16: `tools/__init__.py` uses wildcard imports

**File:** `phantom/tools/__init__.py`  
**Type:** Namespace pollution  

`from .module import *` for all tool modules. This can cause name collisions and makes it impossible to track which names come from which module.

---

### M-17: `tools/__init__.py` evaluates config at import time

**File:** `phantom/tools/__init__.py`  
**Type:** Inflexibility  

`SANDBOX_MODE`, `HAS_PERPLEXITY_API`, and `DISABLE_BROWSER` are evaluated at module import time. Changing environment variables after import has no effect.

---

### M-18: `core/__init__.py` imports all 16 modules eagerly

**File:** `phantom/core/__init__.py`  
**Type:** Import performance  

Forces loading of all core modules (including `networkx`, `re`, etc.) at first `import phantom.core`. This adds significant startup latency even for simple CLI commands like `phantom --version`.

---

### M-19: `scope_validator.py` doesn't handle IPv6 bracket notation

**File:** `phantom/core/scope_validator.py`  
**Type:** Incomplete implementation  

`_extract_host()` doesn't properly handle `[::1]:8080` or `http://[::1]/path` URLs.

---

### M-20: `tracer.py` `get_total_llm_stats()` accesses `_agent_instances` without lock

**File:** `phantom/telemetry/tracer.py` lines ~480-500  

```python
from phantom.tools.agents_graph.agents_graph_actions import _agent_instances
for agent_instance in _agent_instances.values():  # No lock
```

Iterates over the module-level dict from agents_graph (which has no lock) while agents may be added/removed concurrently.

---

### M-21: `tracer.py` `finalize_streaming_as_interrupted()` acquires lock twice

**File:** `phantom/telemetry/tracer.py`  

```python
def finalize_streaming_as_interrupted(self, agent_id: str) -> str | None:
    with self._lock:
        content = self.streaming_content.pop(agent_id, None)
    if content and content.strip():
        with self._lock:  # Second lock acquire
            self.interrupted_content[agent_id] = content
```

Two separate lock acquisitions means another thread could interleave between them. Should be a single atomic operation.

---

## 4. LOW SEVERITY (12)

### L-01: `attack_path_analyzer.py` imports `math` inside loop body

**File:** `phantom/core/attack_path_analyzer.py`  
**Type:** Minor waste  

`import math` inside `prioritize_remediation()` is re-evaluated on each call.

---

### L-02: `compliance_mapper.py` loop variable leaks into module scope

**File:** `phantom/core/compliance_mapper.py`  
**Type:** Code smell  

Loop variables `_req` and `_cwe` from the `_CWE_INDEX` building comprehension leak into module scope.

---

### L-03: `knowledge_store.py` `get_all_hosts()` calls `get_host()` twice per key

**File:** `phantom/core/knowledge_store.py`  
**Type:** Unnecessary work  

```python
return [self.get_host(k) for k in self._hosts if self.get_host(k)]
# Should use: h := self.get_host(k) walrus operator
```

---

### L-04: `scan_profiles.py` `from_dict()` silently drops unknown keys

**File:** `phantom/core/scan_profiles.py`  
**Type:** Silent data loss  

If a YAML config contains misspelled keys (e.g., `max_iteratons`), they are silently ignored.

---

### L-05: `state.py` `has_waiting_timeout()` hardcodes 600s

**File:** `phantom/agents/state.py`  
**Type:** Hardcoded constant  

The 600-second waiting timeout is not configurable.

---

### L-06: `phantom_agent.py` task description joins with space when parts contain newlines

**File:** `phantom/agents/PhantomAgent/phantom_agent.py`  
**Type:** Formatting  

`" ".join(task_parts)` produces awkward formatting when parts already contain `\n`.

---

### L-07: `attack_graph.py` `from_dict()` shadows `node` and `edge` variables

**File:** `phantom/core/attack_graph.py`  
**Type:** Code smell  

```python
for node in data.get("nodes", []):
    node = dict(node)  # Shadows the loop variable
```

---

### L-08: `pyproject.toml` `asyncio_mode = "auto"` may mask missing `async` markers

**File:** `pyproject.toml`  
**Type:** Test reliability  

`pytest-asyncio` auto mode automatically treats all async test functions as asyncio, which can mask issues where `@pytest.mark.asyncio` should be explicit.

---

### L-09: `knowledge_store.py` `_load_all()` doesn't acquire lock during init

**File:** `phantom/core/knowledge_store.py`  
**Type:** Potential race  

Safe only because the constructor runs in a single thread, but if the singleton is accessed concurrently during initialization (race in double-check locking), `_load_all()` could run without the lock.

---

### L-10: `test_all_modules.py` mixes pytest and unittest styles

**File:** `tests/test_all_modules.py`  
**Type:** Inconsistency  

Some test classes use `unittest.TestCase` with `self.assertRaises()`, while others use pytest-style bare classes with `pytest.raises()`. This creates inconsistency.

---

### L-11: `tools/registry.py` `_load_xml_schema` manual XML parsing

**File:** `phantom/tools/registry.py`  
**Type:** Fragile parsing  

XML tool schemas are parsed with manual string `find()` operations instead of the already-imported `DefusedET`. The manual parsing doesn't handle XML comments, CDATA sections, or entities.

---

### L-12: `host.py` `add_port()` merge logic doesn't validate port range

**File:** `phantom/models/host.py`  
**Type:** Input validation  

Port numbers are not validated against the valid range (1-65535).

---

## 5. SECURITY ISSUES (5)

### S-01: Plaintext API key storage

**File:** `phantom/config/config.py`  
**Severity:** Medium  

API keys (`LLM_API_KEY`, `PERPLEXITY_API_KEY`) stored in `~/.phantom/cli-config.json` in plaintext. On Windows, `chmod(0o600)` fails silently, leaving the file world-readable.

**Mitigation:** Use OS keyring (via `keyring` library), encrypt at rest, or at minimum warn users.

---

### S-02: SSRF via Slack webhook URL

**File:** `phantom/core/notifier.py`  
**Severity:** Medium  

`SlackChannel` does not call `_validate_url()` before making requests. A malicious or misconfigured Slack webhook URL could target internal services (e.g., `http://169.254.169.254/` for cloud metadata).

---

### S-03: No DNS rebinding protection in URL validation

**File:** `phantom/core/notifier.py`  
**Severity:** Low  

`_validate_url()` checks scheme and blocklists, but doesn't resolve DNS to check if the target IP is internal. An attacker could use a DNS rebinding domain.

---

### S-04: Verification engine sends actual exploit payloads

**File:** `phantom/core/verification_engine.py`  
**Severity:** Informational  

The verification engine sends real SQL injection, XSS, LFI, and RCE payloads to targets. While this is expected for a pentest tool, there's no rate limiting, no WAF evasion (which could trigger blocks), and no confirmation prompt before sending exploit payloads to production systems.

---

### S-05: `bandit` skips shell injection checks

**File:** `pyproject.toml`  
**Severity:** Low  

```toml
skips = ["B101", "B601", "B404", "B603", "B607"]
```

B601 (shell injection), B603 (subprocess without shell=False), and B607 (partial path) are skipped. For a security tool that constructs commands dynamically, these checks are especially relevant.

---

## 6. ARCHITECTURE ISSUES (4)

### A-01: No dependency injection — global singletons everywhere

**Files:** Multiple  
**Affected:** `get_global_tracer()`, `get_global_audit_logger()`, `get_knowledge_store()`, `_agent_graph`, `_agent_instances`  

The codebase relies heavily on module-level global singletons and mutable module-level dicts. This creates:
- Hidden dependencies between modules
- Impossible to run concurrent scans in the same process
- Difficult to test (must monkeypatch globals)
- Thread safety burden on every global

**Recommendation:** Use dependency injection via a context object passed through the call chain.

---

### A-02: Circular import potential between tracer and agents_graph

**File:** `phantom/telemetry/tracer.py` line ~480  

```python
from phantom.tools.agents_graph.agents_graph_actions import _agent_instances
```

This import lives inside a method body, which works but creates a fragile circular dependency. `tracer.py` imports from `agents_graph_actions.py`, which imports from `tracer.py` via `get_global_tracer()`.

---

### A-03: Dual CLI entry points with divergent logic

**Files:** `phantom/interface/cli_app.py` and `phantom/interface/main.py`  

Two separate CLI systems:
- `cli_app.py` (typer-based, current entry point)
- `main.py` (argparse-based, legacy)

They have partially duplicated target-processing logic, different scan mode enums, and divergent error handling. `main.py` calls `sys.exit(1)` from `validate_environment()`, while `cli_app.py` raises exceptions.

---

### A-04: XML-based tool schemas are a maintenance liability

**Files:** `phantom/tools/registry.py`, `phantom/tools/*/` schema files  

Tools are defined as Python functions with `@register_tool` but their parameters are described in separate XML schema files. This dual-source-of-truth means:
- Parameter names in XML can drift from Python function signatures
- Adding a parameter requires editing both files
- XML is parsed with fragile string matching

**Recommendation:** Generate schemas from Python type annotations (like OpenAI function calling does).

---

## 7. TEST GAPS (3)

### T-01: No tests for the LLM module (`phantom/llm/llm.py`)

**Missing:** Tests for streaming, retry logic, memory compression integration, `_prepare_messages()` mutation behavior, token counting.

This is the most critical module in the system (the agent loop depends on it), yet it has zero direct tests. The conversation-history-destruction bug (C-01) would be caught immediately by a mutation test.

---

### T-02: No tests for `phantom/tools/agents_graph/agents_graph_actions.py`

**Missing:** Tests for `create_agent()`, `complete_agent()`, `stop_agent()`, `send_user_message_to_agent()`, `wait_for_message()`, thread safety.

The entire multi-agent orchestration system is untested.

---

### T-03: No integration or end-to-end tests

**Missing:** No tests that simulate a full scan lifecycle (create agent → run tools → generate report → finish). The existing tests are purely unit-level and use no mocks for the Docker runtime.

**Test directory structure:**
- `tests/test_all_modules.py` — 1009 lines, covers core modules well
- `tests/tools/test_argument_parser.py` — covers argument conversion
- `tests/conftest.py` — empty (1 line docstring)
- `tests/telemetry/`, `tests/runtime/`, `tests/llm/`, `tests/agents/`, `tests/interface/` — all empty `__init__.py` only

Entire subdirectory test suites are **empty stubs**.

---

## 8. DEAD CODE (2)

### D-01: `ScanOrchestrator` class in `priority_queue.py`

**File:** `phantom/core/priority_queue.py`  

`ScanOrchestrator` is defined with `ScanPriorityQueue` management but never imported or used anywhere in the codebase.

---

### D-02: `_detect_type()` in `scope_validator.py` — partial dead code

**File:** `phantom/core/scope_validator.py`  

The regex detection heuristic branch in `_detect_type()` is overly broad and may never trigger on legitimate inputs due to preceding specific checks.

---

## 9. API MISMATCHES (3)

### API-01: `ScanMode` enum values vs `LLMConfig.scan_mode` accepted values

- `cli_app.py`: `quick, standard, deep, stealth, api_only`
- `llm/config.py`: `quick, standard, deep` (anything else defaults to `deep`)

**Impact:** Stealth and API-only modes configure LLM as deep mode.

---

### API-02: `verification_engine.py` expects `vuln.parameter` but model doesn't guarantee it

- `VerificationEngine._inject_payload()` uses `vuln.parameter`
- `Vulnerability` model defines `parameter: str | None = None`
- When `parameter` is None, `_inject_payload()` falls through to inject into first query param or adds a generic `?id=payload` — potentially wrong

---

### API-03: `finish_actions.py` calls `graph.ingest_scan_findings()` with tracer report format

The enrichment pipeline converts tracer vulnerability reports to a dict format, but `AttackGraph.ingest_scan_findings()` expects specific keys (`host`, `port`, `endpoint`, `severity`, `cvss`, `title`). The tracer report format uses different keys (`target`, `url`, etc.). This mismatch could cause nodes to be labeled `"unknown"`.

---

## RECOMMENDATIONS (Priority Order)

1. **[IMMEDIATE]** Fix C-01: Stop mutating `conversation_history` in `_prepare_messages()` — return a new list
2. **[IMMEDIATE]** Fix C-03: Change verification engine to mark unverified vulns as INCONCLUSIVE, not FALSE_POSITIVE
3. **[IMMEDIATE]** Fix C-02: Add `threading.Lock` to all shared dicts in `agents_graph_actions.py`
4. **[HIGH]** Fix C-05/H-04: Replace all synchronous `litellm.completion()` with async `acompletion()`
5. **[HIGH]** Fix C-06: Use a proper YAML library for Nuclei template generation
6. **[HIGH]** Fix H-01: Sync ScanMode enum across CLI and LLM config
7. **[HIGH]** Fix H-02: Ensure SlackChannel validates URLs before requests
8. **[HIGH]** Fix H-03: Make ScanProfile frozen or return copies
9. **[MEDIUM]** Add tests for `llm.py`, `agents_graph_actions.py`, and an integration test
10. **[MEDIUM]** Replace global singletons with a dependency injection context
11. **[MEDIUM]** Remove or complete `main.py` legacy CLI — single entry point
12. **[LOW]** Pre-compile regex patterns in `mitre_enrichment.py` and `scope_validator.py`
13. **[LOW]** Populate `passed_ids` in compliance mapper or remove pass_rate

---

*End of Audit Report*
