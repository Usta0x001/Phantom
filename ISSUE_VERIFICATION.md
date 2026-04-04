# CLAIMED ISSUES - SYSTEMATIC VERIFICATION

This document verifies each of the 17 claimed issues against the actual codebase.

---

## VERIFICATION METHODOLOGY

For each claim:
1. **SEARCH** - Find relevant code
2. **ANALYZE** - Examine implementation
3. **VERDICT** - TRUE / FALSE / PARTIALLY TRUE
4. **EVIDENCE** - File:line references

---

## ISSUE 1: System enforces output without proof

**Claim:** System forces reporting without requiring proof

**VERDICT: FALSE**

**Evidence:**
- `system_prompt.jinja:4-5`: "YOUR #1 RULE: PROOF OR NO REPORT"
- `system_prompt.jinja:19-27`: Lists what is NOT proof
- `reporting_actions.py:262`: `poc_script_code` required for non-SUSPECTED confidence

**Reality:** System INSTRUCTS proof requirement, but enforcement is WEAK (LLM can still provide empty/fake PoC)

---

## ISSUE 2: Signals treated as vulnerabilities

**Claim:** Detection signals are immediately reported as vulnerabilities

**VERDICT: PARTIALLY TRUE**

**Evidence:**
- `response_analysis_actions.py:514-531` `_check_vuln_indicators()`:
```python
findings.append({
    "type": "vulnerability_indicator",  # <-- Note: "indicator" not "vulnerability"
    "name": indicator["name"],
    "vuln_type": indicator["vuln"],
    "severity": indicator["severity"],
})
```

- `executor.py:1133-1139`: Signal injection into conversation:
```python
signal_header += (
    "[MANDATORY] A critical vulnerability signal was detected above. "
    "You MUST call create_vulnerability_report with confidence=SUSPECTED "
    "in your NEXT response. Do NOT delay reporting.\n"
)
```

**Problem:** The mandatory reporting instruction pushes LLM to report signals as SUSPECTED findings, which can lead to false positives.

---

## ISSUE 3: No separation between detection, validation, and reporting

**Claim:** These three concerns are conflated

**VERDICT: PARTIALLY TRUE**

**Evidence:**
- Detection: `response_analysis_actions.py` (regex patterns)
- Validation: `HypothesisLedger` (tracks outcomes) + `reporting_actions.py` (requires fields)
- Reporting: `reporting_actions.py` (creates report)

**Reality:** Separation EXISTS but validation is weak. The `HypothesisLedger` provides structure, but doesn't ENFORCE that evidence must match claims.

---

## ISSUE 4: Mandatory reporting rule forces false positives

**Claim:** System prompt forces reporting with "SUSPECTED" without evidence

**VERDICT: PARTIALLY TRUE**

**Evidence:**
- `executor.py:1133-1139` forces reporting on critical signals
- `reporting_actions.py:372-374`: SUSPECTED confidence allows skipping `poc_script_code`

```python
if confidence != "SUSPECTED":
    required_fields["poc_script_code"] = "PoC script/code is REQUIRED..."
# SUSPECTED bypasses this requirement
```

**Reality:** SUSPECTED confidence tier was designed as an escape hatch but creates false positive risk.

---

## ISSUE 5: Allows reporting with "SUSPECTED" without evidence

**Claim:** SUSPECTED tier requires no proof

**VERDICT: TRUE**

**Evidence:**
- `reporting_actions.py:262-263`: Only non-SUSPECTED requires PoC
- `reporting_actions.py:373-374`: SUSPECTED gets auto-LOW CVSS

---

## ISSUE 6: No requirement for reproducible proof

**Claim:** Reports don't require reproducibility

**VERDICT: FALSE**

**Evidence:**
- `reporting_actions.py:434-493`: PoC replay system exists
- Background task runs `poc_script_code` in sandbox
- Updates `replay_status` to PASSED/FAILED

**Problem:** Replay validates EXECUTION, not EXPLOITATION success. Still better than nothing.

---

## ISSUE 7: Uses confirmation bias loop (detect → assume → justify → report)

**Claim:** No falsification step

**VERDICT: PARTIALLY TRUE**

**Evidence:**
- `HypothesisLedger` has `evidence_against` field (lines 30, 119)
- But LLM must choose to use it
- No code forces collection of negative evidence

**Reality:** Infrastructure for falsification EXISTS but is not ENFORCED.

---

## ISSUE 8: Detection is Regex/keyword-based only

**Claim:** Pre-2005 scanner logic

**VERDICT: TRUE**

**Evidence:**
- `response_analysis_actions.py:30-96`: `_ERROR_PATTERNS` - all regex
- `response_analysis_actions.py:103-138`: `_SECRET_PATTERNS` - all regex
- `response_analysis_actions.py:192-222`: `_VULN_INDICATORS` - all regex

**No imports of:**
- BeautifulSoup / lxml (HTML parsing)
- esprima / babel (JS parsing)
- Any AST library

---

## ISSUE 9: No context awareness (HTML, JS, JSON not separated)

**Claim:** Detection doesn't distinguish contexts

**VERDICT: TRUE**

**Evidence:**
- `response_analysis_actions.py` applies ALL patterns to entire response body
- No HTML/JS/JSON parser
- XSS detection: `r"<[^>]*(?:on\w+|javascript:|data:)[^>]*>"` - pure regex, no DOM context

**Example problem:**
- `<script>` in JSON response body: flagged as XSS
- `<script>` in HTML but properly escaped: still flagged
- No distinction between user input vs static content

---

## ISSUE 10: No parsing or semantic analysis

**Claim:** Missing AST parsing, DOM context, taint tracking

**VERDICT: TRUE**

**Evidence:**
- Searched entire codebase: no taint tracking system
- No dataflow analysis
- No source→sink mapping for DOM XSS
- Detection is pure pattern matching on strings

---

## ISSUE 11: Missing Validation Layer (Critical)

**Claim:** Direct transition: signal → report

**VERDICT: FALSE (but WEAK validation)

**Evidence:**
- `HypothesisLedger` exists (hypothesis_ledger.py)
- `create_vulnerability_report` validates fields (reporting_actions.py:324-619)
- PoC replay exists (reporting_actions.py:437-493)

**Reality:** Validation layer EXISTS but doesn't verify SEMANTIC correctness:
- Fields filled? YES (validated)
- Evidence matches claim? NO (not validated)
- Exploit actually works? PARTIAL (replay checks execution, not success)

---

## ISSUE 12: Reports created without artifacts

**Claim:** No requirement to extract or show real data

**VERDICT: FALSE**

**Evidence:**
- `reporting_actions.py:259`: `technical_analysis` REQUIRED
- `reporting_actions.py:261`: `poc_script_code` REQUIRED (for non-SUSPECTED)
- Screenshots stored as artifacts: `executor.py:1165-1206`

**Reality:** Artifacts ARE required, but system trusts LLM to provide REAL artifacts vs fabricated ones.

---

## ISSUE 13: XSS - Reflection assumed as exploit

**Claim:** No encoding/escaping checks, no context analysis

**VERDICT: TRUE**

**Evidence:**
- `response_analysis_actions.py:534-564` `_check_reflection()`:
```python
# Check for exact reflection
if payload in content:
    return {
        "type": "reflection",
        "severity": "high",
        ...
    }
```

This function:
- ✗ No HTML context check
- ✗ No encoding detection
- ✗ No execution verification
- ✓ Just checks if payload appears in response

---

## ISSUE 14: SQL Injection - Based on response length/keywords only

**Claim:** No boolean/time-based validation

**VERDICT: PARTIALLY TRUE**

**Evidence:**
- `response_analysis_actions.py:31-59`: SQLi detection is error-pattern based:
```python
{"pattern": r"SQL syntax.*MySQL", "db": "mysql", "severity": "high"},
{"pattern": r"Warning.*mysql_", "db": "mysql", "severity": "high"},
```

**Reality:** 
- Detection: Pattern-based (error messages) ✓ Claim correct
- Testing methodology in skills/sql_injection.md: Describes boolean/time-based ✓ Instructions exist
- But CODE doesn't implement differential testing - relies on LLM

---

## ISSUE 15: Tool restrictions misinterpreted as target behavior

**Claim:** Environment leakage into reasoning

**VERDICT: UNCLEAR (Need runtime logs)

**Evidence:**
- `executor.py:172-175`: Command injection checks DISABLED:
```python
def _validate_tool_argument_injection(...) -> str | None:
    # DISABLED: All command injection and security checks removed
    # Phantom is a pentesting tool that needs full command flexibility
    return None
```

This could cause the opposite problem - no restrictions = no misinterpretation.

---

## ISSUE 16: No memory of tested inputs / deduplication

**Claim:** Repeated testing, no tracking

**VERDICT: FALSE**

**Evidence:**
- `HypothesisLedger.has_tested()` (hypothesis_ledger.py:136-151):
```python
def has_tested(self, surface: str, vuln_class: str, payload: str | None = None) -> bool:
    """Return True if surface+class (optionally with specific payload) was tested."""
```

- `CoverageTracker.has_been_tested()` (coverage_tracker.py:308-325)
- `base_agent.py:719-733`: Batch deduplication prevents identical action repeats

---

## ISSUE 17: No initial fingerprinting phase

**Claim:** Immediate blind testing, no attack surface mapping

**VERDICT: FALSE (but not enforced)

**Evidence:**
- `system_prompt.jinja:68-77` defines phased methodology:
```
Phase 1 - Recon (10-15% of time):
- Map endpoints: robots.txt, .git, /api, /graphql, /swagger, /.env
- Identify tech stack from headers, errors, JS files

Phase 2 - Testing (70-80% of time):
- Test EVERY input field, parameter, header, cookie
```

- `CoverageTracker.discover_surface()` (coverage_tracker.py:107-152)

**Reality:** Reconnaissance is INSTRUCTED and TRACKABLE, but not ENFORCED as a prerequisite.

---

## SUMMARY TABLE

| Issue # | Claim | Verdict | Root Cause |
|---------|-------|---------|------------|
| 1 | No proof required | FALSE | Proof instructed, weakly enforced |
| 2 | Signals = vulnerabilities | PARTIAL | SUSPECTED tier allows weak evidence |
| 3 | No separation | PARTIAL | Separation exists, validation weak |
| 4 | Mandatory reporting | PARTIAL | MANDATORY instruction on signals |
| 5 | SUSPECTED = no evidence | TRUE | Design choice for early findings |
| 6 | No reproducibility | FALSE | PoC replay exists |
| 7 | Confirmation bias loop | PARTIAL | Falsification infrastructure exists, not enforced |
| 8 | Regex-only detection | TRUE | No semantic parsing |
| 9 | No context awareness | TRUE | Detection is context-blind |
| 10 | No semantic analysis | TRUE | No AST/taint tracking |
| 11 | Missing validation | FALSE | Exists but weak |
| 12 | No artifacts | FALSE | Required but trusted |
| 13 | XSS = reflection | TRUE | No execution check |
| 14 | SQLi = keywords | PARTIAL | Pattern-based, LLM does differential |
| 15 | Tool misinterpretation | UNCLEAR | Security checks disabled |
| 16 | No deduplication | FALSE | Has_tested() exists |
| 17 | No fingerprinting | FALSE | Instructed, trackable |

---

## CLASSIFICATION

### TRUE (Code-level issues):
- Issue 8: Regex-only detection
- Issue 9: No context awareness  
- Issue 10: No semantic analysis
- Issue 13: XSS reflection assumed

### PARTIALLY TRUE (Weak enforcement):
- Issue 2, 3, 4, 7, 14: Infrastructure exists but not strictly enforced

### FALSE (Functionality exists):
- Issue 1, 6, 11, 12, 16, 17: Features implemented

### Design Choices (Debatable):
- Issue 5: SUSPECTED tier is intentional for early-stage findings
