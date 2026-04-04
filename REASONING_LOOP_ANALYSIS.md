# PHANTOM REASONING LOOP ANALYSIS

## Executive Summary

After deep code analysis, I can definitively characterize Phantom's reasoning architecture. The claims made about the system are **PARTIALLY CORRECT** but several are **OVERSTATED or OUTDATED**.

---

## 1. REASONING LOOP VERIFICATION

### Claimed Loop (from audit):
```
detect → assume → justify → report (BROKEN)
```

### Required Loop (from audit):
```
signal → context → hypothesis → test → validate → proof → report (IDEAL)
```

### ACTUAL IMPLEMENTED LOOP (EVIDENCE-BASED):

```
signal → hypothesis_registration → test → record_result → report
```

**VERDICT: PARTIALLY IMPLEMENTED - The system has hypothesis tracking but WEAK validation**

---

## Evidence from Code:

### A. HypothesisLedger EXISTS and is WIRED (`hypothesis_ledger.py:56-520`)

```python
class HypothesisLedger:
    """
    Thread-safe registry of hypotheses for a single scan.
    
    Properties:
    - Survives memory compression (stored outside conversation history)
    - Prevents redundant payload testing via `has_tested()`
    - Drives coverage tracking via `get_coverage_gaps()`
    """
```

The ledger tracks:
- `surface`: Attack surface (e.g., "/api/login::username")
- `vuln_class`: Vulnerability type (e.g., "sqli")
- `status`: `open | testing | confirmed | rejected`
- `payloads_tested`: List of tested payloads
- `evidence_for` / `evidence_against`: Evidence tracking
- `successful_payloads`: Payloads that worked (P3.2 enhancement)

**PROOF: Line 97-124 in hypothesis_ledger.py shows `record_result()` method:**
```python
def record_result(
    self,
    hyp_id: str,
    outcome: str,  # 'confirmed' | 'rejected' | 'testing'
    evidence: str = "",
    successful_payload: str | None = None,
) -> None:
```

### B. CoverageTracker EXISTS (`coverage_tracker.py:81-399`)

Tracks what attack surfaces have been tested for which vulnerability classes.

```python
class CoverageTracker:
    """
    Thread-safe tracking of attack surface coverage.
    
    Key principles:
    - Returns FACTS about coverage state (not recommendations)
    - LLM decides what to test based on these facts
    """
```

### C. CorrelationEngine EXISTS (`correlation_engine.py:163-433`)

Identifies potential vulnerability chains (SSRF→cloud metadata, SQLi→RCE, etc.)

```python
# Chain patterns defined:
CHAIN_PATTERNS = [
    {"id": "ssrf_to_cloud_metadata", ...},
    {"id": "sqli_to_rce", ...},
    {"id": "lfi_to_rce", ...},
    # ... 10 patterns total
]
```

### D. Agent Loop DOES inject these into LLM context (`base_agent.py:582-620`)

```python
# Line 586-596: Hypothesis Ledger injection every N iterations
if (
    len(self.hypothesis_ledger) > 0
    and self.state.iteration > 0
    and self.state.iteration % _LEDGER_INJECT_EVERY == 0
):
    ledger_summary = self.hypothesis_ledger.to_prompt_summary(
        top_n=10,
        status_filter=["open", "testing"],
    )
```

---

## 2. WHAT'S ACTUALLY BROKEN (VALIDATED CLAIMS)

### CLAIM VERIFIED: Detection Engine is Regex/Keyword Based

**EVIDENCE: `response_analysis_actions.py:30-223`**

```python
_ERROR_PATTERNS: dict[str, list[dict[str, Any]]] = {
    "sql_error": [
        {"pattern": r"SQL syntax.*MySQL", "db": "mysql", "severity": "high"},
        {"pattern": r"Warning.*mysql_", "db": "mysql", "severity": "high"},
        # ... regex patterns only
    ],
    ...
}

_VULN_INDICATORS: list[dict[str, Any]] = [
    {"name": "Reflected Input", "pattern": r"<[^>]*(?:on\w+|javascript:|data:)[^>]*>", "vuln": "xss"},
    # ... more regex patterns
]
```

**VERDICT: CORRECT - Detection is pure regex, no AST parsing, no DOM context analysis**

### CLAIM VERIFIED: No AST/DOM Parsing

The `response_analysis_actions.py` uses only:
- `re.search()` and `re.findall()` for pattern matching
- No HTML/XML parser (like BeautifulSoup, lxml)
- No JavaScript AST parser
- No context-aware analysis

**Missing (confirmed by code search):**
- No `BeautifulSoup`, `lxml`, `html.parser` imports
- No `esprima`, `babel`, `acorn` for JS parsing
- No taint tracking system

### CLAIM PARTIALLY VERIFIED: Signal → Report Without Full Validation

**The system DOES have:**
1. HypothesisLedger for tracking hypotheses
2. `evidence_for`/`evidence_against` fields
3. `record_result()` method for outcomes

**The system LACKS:**
1. **Automatic proof verification** - The LLM decides if something is "confirmed", not code
2. **Exploit replay** - `reporting_actions.py:434-493` has PoC replay but it's:
   - Background async task (doesn't block report)
   - Weak validation (just checks for execution failures, not exploit success)
   
```python
# Line 452-466: Weak replay validation
_exec_failure_patterns = (
    "command not found",
    "no such file or directory",
    "traceback (most recent call last)",
    # ... only checks for EXECUTION failures, not EXPLOIT validation
)
if not replay_out.strip():
    _replay = "FAILED"
elif any(p in replay_out.lower() for p in _exec_failure_patterns):
    _replay = "FAILED"
else:
    _replay = "PASSED"  # <-- THIS PASSES IF COMMAND RUNS, NOT IF EXPLOIT WORKS
```

**VERDICT: PARTIALLY CORRECT - Validation layer EXISTS but is WEAK**

---

## 3. WHAT'S ACTUALLY WORKING (CLAIMS THAT ARE OVERSTATED)

### System Prompt Has PROOF Requirements (`system_prompt.jinja:1-36`)

```jinja
YOUR #1 RULE: PROOF OR NO REPORT

A vulnerability report is ONLY valid when you have CONCRETE PROOF:
- You sent a payload → You got exploitable response → You PROVED it works

WHAT IS PROOF (report immediately):
- SQLi: Your payload extracted actual data (usernames, passwords, table names) OR bypassed login
- XSS: Your payload appears in HTML source unescaped OR browser executed your script
- RCE: Your command output appeared in response (uid=1000, www-data, Linux hostname, etc.)
...

WHAT IS NOT PROOF (investigate further, DO NOT report):
- Error messages mentioning "SQL", "syntax", "undefined"
- HTTP 500, 403, 401 status codes
- Stack traces, internal IPs, version numbers
...

NEVER USE THESE WORDS IN REPORTS: potential, possible, suspected, might, could, appears to be, seems like
```

**VERDICT: The system prompt DOES require proof. The problem is ENFORCEMENT, not instruction.**

### Vulnerability Report Validation EXISTS (`reporting_actions.py:250-269`)

```python
def _validate_required_fields(**kwargs: str | None) -> list[str]:
    confidence = (kwargs.get("confidence") or "LIKELY").upper().strip()
    required_fields = {
        "title": "Title cannot be empty",
        "description": "Description cannot be empty",
        "impact": "Impact cannot be empty",
        "target": "Target cannot be empty",
        "technical_analysis": "Technical analysis cannot be empty",
    }
    if confidence != "SUSPECTED":
        required_fields["poc_script_code"] = "PoC script/code is REQUIRED for LIKELY/VERIFIED confidence"
```

**VERDICT: Reports require PoC code for non-SUSPECTED findings. This IS validation.**

---

## 4. ROOT CAUSE ANALYSIS

The reasoning loop issues stem from:

### A. LLM Autonomy vs Code Enforcement (PRIMARY ISSUE)

The system **instructs** the LLM to validate but doesn't **enforce** it:

| Layer | Instructs | Enforces | Gap |
|-------|-----------|----------|-----|
| System Prompt | YES - "PROOF OR NO REPORT" | NO - LLM can ignore | LLM discretion |
| HypothesisLedger | YES - has `evidence_for/against` | NO - LLM fills these | LLM honesty |
| ReportValidator | YES - requires `poc_script_code` | PARTIAL - accepts any string | No semantic check |
| PoC Replay | YES - runs code | WEAK - checks execution, not success | No exploit validation |

### B. Detection Layer is Pre-Semantic (SECONDARY ISSUE)

The regex-based detection in `response_analysis_actions.py`:
- Detects patterns, not vulnerabilities
- No context awareness (HTML vs JS vs JSON)
- No taint tracking from source to sink

**Example: XSS Detection**
```python
{"name": "Reflected Input", "pattern": r"<[^>]*(?:on\w+|javascript:|data:)[^>]*>", "vuln": "xss"}
```
This pattern:
- Matches `<div onclick=alert(1)>` ✓
- Also matches `<div onclick="safe_function()">` (false positive)
- Misses `<img src=x onerror=alert(1)>` (depends on exact regex)
- No distinction between reflected payload vs static content

---

## 5. CONCLUSION

| Claim | Verdict | Evidence |
|-------|---------|----------|
| Reasoning is "detect→assume→justify→report" | PARTIALLY TRUE | Loop exists but has hypothesis tracking |
| No hypothesis testing phase | FALSE | HypothesisLedger exists and is wired |
| Detection is regex/keyword only | TRUE | response_analysis_actions.py proves this |
| No AST/DOM parsing | TRUE | No parser imports found |
| No validation layer | FALSE | Validation exists but is WEAK |
| Signal→Report directly | PARTIALLY TRUE | Validation exists but doesn't ENFORCE proof |
| System prompt forces reporting | FALSE | Prompt says "PROOF OR NO REPORT" |

### Actual Architecture:

```
┌─────────────────────────────────────────────────────────────────┐
│                    CURRENT PHANTOM ARCHITECTURE                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐    │
│  │   DETECTION  │     │  HYPOTHESIS  │     │   REPORTING  │    │
│  │    LAYER     │────▶│    LEDGER    │────▶│    LAYER     │    │
│  │   (Regex)    │     │  (Tracking)  │     │ (Validation) │    │
│  └──────────────┘     └──────────────┘     └──────────────┘    │
│        │                     │                     │            │
│        │                     │                     │            │
│        ▼                     ▼                     ▼            │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐    │
│  │  Pattern     │     │  evidence_   │     │ poc_script_  │    │
│  │  Matching    │     │  for/against │     │    code      │    │
│  │  ONLY        │     │  (LLM fills) │     │ (any string) │    │
│  └──────────────┘     └──────────────┘     └──────────────┘    │
│        │                     │                     │            │
│        │                     │                     │            │
│        ▼                     ▼                     ▼            │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    LLM DECIDES                           │   │
│  │  (No code-level enforcement of proof requirements)       │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### What Needs Fixing:

1. **Detection Layer**: Add semantic parsing (HTML/JS context awareness)
2. **Validation Layer**: Code-level enforcement of proof, not just LLM instruction
3. **PoC Replay**: Validate exploit SUCCESS, not just command execution
4. **Evidence Engine**: Require extractable artifacts, not just text claims
