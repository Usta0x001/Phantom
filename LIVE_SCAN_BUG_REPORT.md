# Phantom v0.9.21 — Live Scan Bug Report

**Date:** 2026-03-02  
**Scan Target:** OWASP Juice Shop (`http://host.docker.internal:3000`)  
**Model:** `deepseek/deepseek-v3.2` via OpenRouter  
**Profile:** `quick` (max 60 iterations)  
**Scan ID:** `host-docker-internal-3000_f653`  
**Duration:** ~55 minutes  
**Tool Calls:** 105 events  

---

## Executive Summary

A live scan against OWASP Juice Shop was executed to validate Phantom v0.9.21 under real conditions. The scan **found 2 formal vulnerability reports** (SQL Injection, IDOR/User Enumeration) and **5 findings ledger entries**. However, the observation revealed **15 bugs/flaws/design gaps** ranging from critical runtime crashes to dead-code state machines. Three were hot-fixed during the scan to prevent crashes; the rest are documented below with fix plans.

### Scan Results (What The Agent Found)
| # | Severity | Finding |
|---|----------|---------|
| 1 | CRITICAL | SQL Injection at `POST /rest/user/login param=email` — auth bypass + user enumeration |
| 2 | MEDIUM | IDOR — Any authenticated user can enumerate all 23 users via `GET /api/Users` |
| 3 | INFO | Swagger API publicly accessible at `/api-docs/swagger.json` |
| 4 | INFO | Open ports: 135, 445, 902, 912, 2869, 3000 |

### Agent Behavior Statistics
| Metric | Value | Assessment |
|--------|-------|------------|
| Total tool calls | 105 | OK for `quick` profile |
| `python_action` calls | 37 (35%) | **Too high** — agent writes scripts instead of using specialized tools |
| Formal vuln reports | 2 | Low — Juice Shop has 100+ challenges |
| Findings ledger entries | 5 | Low |
| Subagents spawned | 4 | Good multi-agent usage |
| Phase at end | `recon` | **BUG** — never transitions |
| Checkpoint `vuln_stats.total` | 0 | **BUG** — should be 2+ |
| Checkpoint `endpoints` count | 0 | **BUG** — should be many |
| Coverage tracker fired | Never | **BUG** — broken dependency |
| Stagnation detector fired | Never | **BUG** — sees 0 vulns |

---

## Bug Report — 15 Issues Found

### Legend
- **Fix Category:** `APPLIED` = already fixed during scan, `EASY` = <30 lines, `MODERATE` = 30-100 lines, `ARCH-V2` = requires system redesign
- **Severity:** CRITICAL > HIGH > MEDIUM > LOW

---

### BUG-01 [CRITICAL] `no-new-privileges` Broke Sandbox Container
**File:** `phantom/runtime/docker_runtime.py`  
**Category:** `APPLIED` (hot-fixed during scan)

P2-FIX10 added `security_opt=["no-new-privileges:true"]` to the container. This prevented `sudo` inside the Kali sandbox, which is required for Caido proxy setup (system-wide CA cert + proxy config).

**Symptom:** Container exit code 1: `"sudo: The "no new privileges" flag is set"`  
**Fix:** Removed `security_opt` entirely.

---

### BUG-02 [CRITICAL] `cap_drop=ALL` Too Restrictive for Security Tools
**File:** `phantom/runtime/docker_runtime.py`  
**Category:** `APPLIED` (hot-fixed during scan)

P2-FIX10 added `cap_drop=["ALL"]` with limited `cap_add`. The Kali sandbox runs complex security tools (Caido, nmap, browser) that need standard Linux capabilities (CHOWN, FOWNER, NET_BIND_SERVICE, KILL, SETUID, SETGID, etc).

**Symptom:** Container startup failed at Caido API readiness check.  
**Fix:** Removed `cap_drop=["ALL"]`, kept only `cap_add=["NET_ADMIN", "NET_RAW", "SYS_PTRACE"]`.

---

### BUG-03 [MEDIUM] `storage_opt` Incompatible with overlayfs
**File:** `phantom/runtime/docker_runtime.py`  
**Category:** `APPLIED` (hot-fixed during scan)

P2-FIX9 added `storage_opt={"size": "20g"}` which only works with `devicemapper` storage driver. Docker Desktop (Windows/Mac) uses `overlayfs` where this is silently ignored or errors.

**Fix:** Removed `storage_opt` entirely.

---

### BUG-04 [CRITICAL] Phase Transitions Never Fire — Dead State Machine
**Files:** `phantom/agents/enhanced_state.py` (L39, L292), `phantom/agents/base_agent.py`, `phantom/agents/protocol.py`  
**Category:** `MODERATE`

`current_phase` starts at `ScanPhase.RECON` and **never changes**. The `set_phase()` method exists but is never called — not from the agent loop, not from any tool, and not mentioned in the system prompt. The `protocol.py` `SCAN_PHASES` definition with dependency tracking is pure dead code.

**Observed:** Checkpoint shows `phase: "recon"` after 20+ iterations with confirmed SQL injection findings.  
**Impact:** Phase-dependent logic (`complete_phase()`, `start_phase()`, `ScanResult.phases`) is meaningless. Phase information in reports is always "recon".

**Fix Plan:** Add automatic phase transitions in `base_agent.py` based on iteration milestones and findings count.

---

### BUG-05 [CRITICAL] Subagent State Isolation — Findings Never Merge Back
**File:** `phantom/tools/agents_graph/agents_graph_actions.py` (L381)  
**Category:** `ARCH-V2`

Subagents receive a fresh `AgentState` (not `EnhancedAgentState`). When subagents call `record_finding()`, findings go to the subagent's own isolated `findings_ledger` — **never merged back** to the root agent. Context inheritance is one-way text copy of parent's last 40 findings.

When subagents call `create_vulnerability_report`, the executor tries `agent_state.add_vulnerability()` but subagent's `AgentState` doesn't have that method → `hasattr` guard silently skips it.

**Impact:** The root agent's structured vulnerability tracking (`vulnerabilities`, `vuln_stats`, `tested_endpoints`) is almost empty in multi-agent scans. Only the global tracer's flat list survives.

**Why ARCH-V2:** Proper fix requires a shared state broker or post-agent merge protocol that reconciles subagent discoveries into the root state. This touches agent lifecycle, state serialization, and the message-passing system.

---

### BUG-06 [HIGH] Findings vs Vulnerabilities — Two Parallel Tracking Systems
**Files:** `phantom/agents/state.py` (L54), `phantom/agents/enhanced_state.py` (L177), `phantom/tools/executor.py` (L558-L670)  
**Category:** `ARCH-V2`

Two independent systems track discoveries:
1. `findings_ledger` (list of strings) — populated by `record_finding` and `_auto_record_findings`
2. `vulnerabilities` dict (Vulnerability model objects) — populated only by `add_vulnerability()`

The bridge between them exists only for `create_vulnerability_report` in the executor, and it fails for subagents (BUG-05). Nuclei, SQLMap, Nmap vulns all go to `findings_ledger` as text only.

**Impact:** `vulnerabilities` dict, `vuln_stats`, `verified_vulns`, `pending_verification` are empty or near-empty. All structured vulnerability consumers return empty results.

**Why ARCH-V2:** Unifying these requires rethinking how findings flow through the system — possibly a central findings bus that auto-creates Vulnerability model objects from structured tool results.

---

### BUG-07 [HIGH] `add_endpoint()` Never Called — Endpoints Always Empty
**File:** `phantom/tools/executor.py` (L596-L609)  
**Category:** `EASY`

`EnhancedAgentState.add_endpoint()` exists but **no code calls it**. `_auto_record_findings` for katana/httpx/ffuf writes to `findings_ledger` as text (`[endpoint] API: {url}`) but never calls the structured `add_endpoint()`.

**Impact:** `self.state.endpoints` is always `[]`. Coverage tracker in `base_agent.py` uses `len(self.state.endpoints)` as the denominator → always 0 → coverage ratio is undefined → coverage advisories never fire.

**Fix Plan:** Wire `add_endpoint()` calls in `_auto_record_findings` for katana, httpx, ffuf, nmap, and katana crawl results.

---

### BUG-08 [HIGH] Coverage Tracker and Stagnation Detector Are Inert
**File:** `phantom/agents/base_agent.py` (L210-L240, L280-L300)  
**Category:** Depends on BUG-07 + BUG-05

The two primary mechanisms for intelligent scan termination are non-functional:
1. **Coverage tracker** (every 10 iterations): `discovered = len(self.state.endpoints)` = always 0 → block skipped.
2. **Stagnation detector**: `vuln_count = len(self.state.vulnerabilities)` = always 0 (BUG-05/06) → false stagnation signal.

**Impact:** Scans run until `max_iterations` (200) or wall-clock timeout (4h) with zero adaptive stopping. The intelligent stop conditions we built in P1-FIX4 and P2-FIX6 are effectively dead code.

**Fix Plan:** Fixing BUG-07 addresses coverage. For stagnation, wire it to `len(findings_ledger)` instead of (or in addition to) `len(vulnerabilities)`.

---

### BUG-09 [HIGH] `save_checkpoint` Omits `findings_ledger`
**File:** `phantom/agents/enhanced_state.py` (L373-L396)  
**Category:** `EASY`

The `save_checkpoint()` method serializes 14 fields but **does not include** `findings_ledger` or `unverified_findings`. Correspondingly, `from_checkpoint()` does not restore them.

**Impact:** On scan resume, the findings ledger (which the system prompt calls "the safest place to store critical data") is completely lost. Agent restarts with empty ledger and may re-test endpoints.

**Fix Plan:** Add `findings_ledger` to both `save_checkpoint()` and `from_checkpoint()`.

---

### BUG-10 [MEDIUM] `record_finding` Has No Severity Parameter
**File:** `phantom/tools/findings/findings_actions.py` (L14-L66)  
**Category:** `EASY`

The `record_finding` tool accepts `finding`, `category`, `description`, `title` but has **no severity parameter**. Severity is embedded in free text when present. There's no way to programmatically filter findings by severity.

**Fix Plan:** Add optional `severity` parameter that tags the finding.

---

### BUG-11 [MEDIUM] System Prompt Claims "2000+ Steps Minimum"
**File:** `phantom/agents/PhantomAgent/system_prompt.jinja` (L311)  
**Category:** `EASY`

The system prompt says: `"expect to need 2000+ steps minimum"` but `max_iterations` for profiles ranges from 60 (quick) to 300 (deep). This is impossible and gives the agent contradictory instructions.

**Fix Plan:** Change to realistic language: "expect to use most of your available iterations".

---

### BUG-12 [MEDIUM] `tested_endpoints` Tracking Fails for Subagents
**File:** `phantom/tools/executor.py` (L697-L731)  
**Category:** `ARCH-V2` (depends on BUG-05)

`_track_tested_endpoint` calls `mark_endpoint_tested()` which requires `EnhancedAgentState`. Subagents have plain `AgentState` → silently skipped. The root agent rarely executes tools directly (subagents do), so `tested_endpoints` on root is usually empty.

**Impact:** No deduplication across agents — multiple agents may test the same endpoint.

---

### BUG-13 [MEDIUM] `create_vulnerability_report` → `add_vulnerability` Bridge Is Fragile  
**File:** `phantom/tools/executor.py` (L636-L654)  
**Category:** `MODERATE`

The only path from reporting to structured tracking does a linear scan of `tracer.vulnerability_reports` to find the report by ID. It fails silently when: (a) the report isn't in the list yet, or (b) `hasattr(agent_state, "add_vulnerability")` is False for subagents.

**Fix Plan:** Move vulnerability model creation into the `create_vulnerability_report` tool itself (rather than post-hoc lookup), and pass result back to the executor explicitly.

---

### BUG-14 [LOW] `from_checkpoint` Hardcodes `max_iterations=300`
**File:** `phantom/agents/enhanced_state.py` (L457)  
**Category:** `EASY`

`max_iterations=300` is hardcoded in the resumed state constructor. Comment says "Will be overridden by caller if needed" but there's no guarantee.

**Fix Plan:** Change to `max_iterations=200` (the AgentState default) or accept it as a parameter.

---

### BUG-15 [LOW] Priority Queues Are Dead Code
**Files:** `phantom/agents/enhanced_state.py` (L89-L110), `phantom/core/priority_queue.py`  
**Category:** `ARCH-V2`

`VulnerabilityPriorityQueue` and `ScanPriorityQueue` are initialized in `initialize_scan()` but never consumed. No code calls `get_next_scan_task()` or `vuln_queue.pop()`. The agent loop doesn't consult priority queues for action selection.

**Impact:** The priority-based scanning architecture is scaffolded but entirely inert.

---

## Summary Matrix

| Bug | Severity | Category | Fix Size | Status |
|-----|----------|----------|----------|--------|
| BUG-01 | CRITICAL | Runtime | — | **APPLIED** |
| BUG-02 | CRITICAL | Runtime | — | **APPLIED** |
| BUG-03 | MEDIUM | Runtime | — | **APPLIED** |
| BUG-04 | CRITICAL | State Machine | ~30 lines | **TO FIX** |
| BUG-05 | CRITICAL | Architecture | Major | **ARCH-V2** |
| BUG-06 | HIGH | Architecture | Major | **ARCH-V2** |
| BUG-07 | HIGH | Tracking | ~20 lines | **TO FIX** |
| BUG-08 | HIGH | Stop Logic | ~10 lines | **TO FIX** |
| BUG-09 | HIGH | Checkpoint | ~15 lines | **TO FIX** |
| BUG-10 | MEDIUM | Tool API | ~10 lines | **TO FIX** |
| BUG-11 | MEDIUM | Prompt | 1 line | **TO FIX** |
| BUG-12 | MEDIUM | Architecture | Depends on BUG-05 | **ARCH-V2** |
| BUG-13 | MEDIUM | Bridge | ~25 lines | **TO FIX** |
| BUG-14 | LOW | Checkpoint | 1 line | **TO FIX** |
| BUG-15 | LOW | Dead Code | Major | **ARCH-V2** |

### Fix Plan Summary
- **Already Applied (3):** BUG-01, BUG-02, BUG-03 (docker_runtime hot-fixes)
- **Easy/Moderate Fixes (8):** BUG-04, BUG-07, BUG-08, BUG-09, BUG-10, BUG-11, BUG-13, BUG-14
- **Arch v2 Redesign (4):** BUG-05, BUG-06, BUG-12, BUG-15

### Arch v2 Items Explained
The four ARCH-V2 items all stem from one root cause: **the multi-agent architecture lacks a shared state bus**. Subagents are fire-and-forget with isolated state. A proper fix requires:
1. A central state broker that subagents write to via a shared findings API
2. Post-agent-completion merge protocol that reconciles subagent state into root
3. Unified finding/vulnerability model (merge `findings_ledger` text and `vulnerabilities` models)
4. Priority queue integration into the agent loop's action selection

This is a significant architectural change (~500-800 lines) that should be scoped as a dedicated sprint in Phantom v1.0.
