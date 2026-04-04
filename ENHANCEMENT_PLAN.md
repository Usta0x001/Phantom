# PHANTOM ENHANCEMENT PLAN

## Overview

This document provides specific, implementable fixes for the verified issues in Phantom's reasoning loop architecture.

---

## PRIORITY 0: CRITICAL FIXES

### P0.1: Add Semantic HTML Parser to Detection Layer

**File:** `phantom/tools/response_analysis/response_analysis_actions.py`

**Current Problem:**
```python
# Line 534-564: XSS detection is substring match
if payload in content:
    return {"type": "reflection", "severity": "high", ...}
```

**Required Changes:**

1. **Add imports:**
```python
from html.parser import HTMLParser
from typing import NamedTuple

class ReflectionContext(NamedTuple):
    location: str  # 'attribute_value', 'tag_content', 'script', 'comment', 'style'
    tag: str       # 'div', 'script', 'img', etc.
    attribute: str | None  # 'onclick', 'src', 'href', etc.
    is_escaped: bool  # True if HTML-encoded
    is_executable: bool  # True if in dangerous context
```

2. **Create context-aware reflection checker:**
```python
class HTMLContextAnalyzer(HTMLParser):
    def __init__(self, payload: str):
        super().__init__()
        self.payload = payload
        self.contexts: list[ReflectionContext] = []
        self._current_tag = ""
        self._in_script = False
        self._in_style = False
    
    def handle_starttag(self, tag, attrs):
        self._current_tag = tag
        self._in_script = tag == "script"
        self._in_style = tag == "style"
        
        for attr_name, attr_value in attrs:
            if attr_value and self.payload in attr_value:
                is_dangerous = attr_name.startswith("on") or \
                              attr_name in ("href", "src", "action", "formaction") and \
                              ("javascript:" in attr_value.lower() or self.payload in attr_value)
                self.contexts.append(ReflectionContext(
                    location="attribute_value",
                    tag=tag,
                    attribute=attr_name,
                    is_escaped=False,  # Present in parsed attribute = not escaped
                    is_executable=is_dangerous
                ))
    
    def handle_data(self, data):
        if self.payload in data:
            self.contexts.append(ReflectionContext(
                location="script" if self._in_script else 
                         "style" if self._in_style else "tag_content",
                tag=self._current_tag,
                attribute=None,
                is_escaped=False,
                is_executable=self._in_script
            ))

def _check_reflection_with_context(payload: str, content: str) -> dict | None:
    """Enhanced reflection check with HTML context awareness."""
    
    # First check: is payload present at all?
    if payload not in content:
        return None
    
    # Check if payload is HTML-encoded (false positive indicator)
    import html
    encoded_payload = html.escape(payload)
    if encoded_payload in content and payload not in content.replace(encoded_payload, ""):
        return {
            "type": "reflection_escaped",
            "severity": "info",
            "note": "Payload reflected but HTML-encoded - NOT exploitable",
            "requires_investigation": False
        }
    
    # Parse HTML to find context
    try:
        analyzer = HTMLContextAnalyzer(payload)
        analyzer.feed(content)
        
        if not analyzer.contexts:
            return {
                "type": "reflection",
                "severity": "low",
                "note": "Payload found but context unclear",
                "requires_investigation": True
            }
        
        # Find most dangerous context
        for ctx in analyzer.contexts:
            if ctx.is_executable:
                return {
                    "type": "reflection_executable",
                    "severity": "critical",
                    "context": ctx._asdict(),
                    "note": f"Payload in executable context: {ctx.location} of <{ctx.tag}>",
                    "requires_investigation": False  # High confidence
                }
        
        # Reflected but not in dangerous context
        return {
            "type": "reflection_benign",
            "severity": "low",
            "contexts": [c._asdict() for c in analyzer.contexts],
            "note": "Payload reflected but not in executable context",
            "requires_investigation": True
        }
        
    except Exception:
        # Fallback to simple check if parsing fails
        return {
            "type": "reflection",
            "severity": "medium",
            "note": "HTML parsing failed, manual verification needed",
            "requires_investigation": True
        }
```

---

### P0.2: Enhance PoC Replay Validation

**File:** `phantom/tools/reporting/reporting_actions.py`

**Current Problem (Lines 452-466):**
```python
# Only checks execution success, not exploitation
if any(p in replay_out.lower() for p in _exec_failure_patterns):
    _replay = "FAILED"
else:
    _replay = "PASSED"  # Passes if script runs, even if exploit fails
```

**Required Changes:**

1. **Add exploit success patterns per vulnerability type:**
```python
_EXPLOIT_SUCCESS_PATTERNS: dict[str, list[str]] = {
    "sqli": [
        # Data extraction indicators
        r"information_schema",
        r"table_name",
        r"column_name", 
        r"mysql\.",
        r"pg_catalog",
        r"\d+\s+rows?\s+returned",
        # Boolean-based success
        r"true_condition_marker",
        # Time-based success (check via timing, not output)
    ],
    "xss": [
        # Browser execution indicators (for headless browser replay)
        r"alert\s*\(\s*['\"]?xss",
        r"document\.domain",
        r"XSS_CONFIRMED",
    ],
    "rce": [
        # Command execution indicators
        r"uid=\d+",
        r"www-data",
        r"root:",
        r"Linux\s+\w+\s+\d+\.\d+",
        r"Windows\s+NT",
        r"HOSTNAME=",
        r"PWD=",
    ],
    "ssrf": [
        # Internal resource access indicators
        r"169\.254\.169\.254",
        r"metadata",
        r"localhost",
        r"127\.0\.0\.1",
        r"::1",
        r"internal",
    ],
    "lfi": [
        # File content indicators
        r"root:x:0:0",
        r"\[boot\s+loader\]",
        r"<\?php",
        r"#!/bin/",
    ],
}

def _validate_exploit_success(
    vuln_type: str, 
    replay_output: str, 
    expected_marker: str | None = None
) -> tuple[str, str]:
    """
    Validate that exploit actually succeeded, not just execution.
    
    Returns:
        (status, reason): 'EXPLOIT_CONFIRMED', 'EXECUTION_ONLY', or 'FAILED'
    """
    import re
    
    output_lower = replay_output.lower()
    
    # Check for explicit marker if provided
    if expected_marker and expected_marker.lower() in output_lower:
        return ("EXPLOIT_CONFIRMED", f"Expected marker '{expected_marker}' found")
    
    # Check vuln-specific patterns
    patterns = _EXPLOIT_SUCCESS_PATTERNS.get(vuln_type, [])
    for pattern in patterns:
        if re.search(pattern, replay_output, re.IGNORECASE):
            return ("EXPLOIT_CONFIRMED", f"Exploitation indicator matched: {pattern}")
    
    # Execution succeeded but no exploit indicators
    if replay_output.strip():
        return ("EXECUTION_ONLY", "PoC ran but no exploitation indicators found")
    
    return ("FAILED", "No output from PoC execution")
```

2. **Modify replay validation call (around line 480):**
```python
# BEFORE:
if not replay_out.strip():
    _replay = "FAILED"
elif any(p in replay_out.lower() for p in _exec_failure_patterns):
    _replay = "FAILED"
else:
    _replay = "PASSED"

# AFTER:
if any(p in replay_out.lower() for p in _exec_failure_patterns):
    _replay = "FAILED"
    _replay_reason = "Execution failed"
else:
    # Get vuln_type from the report
    vuln_type = kwargs.get("vulnerability_type", "").lower()
    expected_marker = kwargs.get("expected_output_marker")
    _replay, _replay_reason = _validate_exploit_success(
        vuln_type, replay_out, expected_marker
    )
```

---

## PRIORITY 1: HIGH IMPORTANCE FIXES

### P1.1: Remove Mandatory Reporting Instruction

**File:** `phantom/tools/executor.py`

**Current Problem (Lines 1133-1139):**
```python
signal_header += (
    "[MANDATORY] A critical vulnerability signal was detected above. "
    "You MUST call create_vulnerability_report with confidence=SUSPECTED "
    "in your NEXT response. Do NOT delay reporting.\n"
)
```

**Required Change:**
```python
signal_header += (
    "[INVESTIGATION REQUIRED] A critical vulnerability signal was detected. "
    "Before reporting, you MUST:\n"
    "1. Send a CONFIRMATION payload to verify exploitation\n"
    "2. Extract CONCRETE evidence (data, output, or state change)\n"
    "3. Only then report with appropriate confidence level\n"
    "Signals alone are NOT sufficient for reporting.\n"
)
```

---

### P1.2: Add Minimum Evidence for SUSPECTED Tier

**File:** `phantom/tools/reporting/reporting_actions.py`

**Current Problem (Lines 262-263):**
```python
if confidence != "SUSPECTED":
    required_fields["poc_script_code"] = "PoC script/code is REQUIRED..."
# SUSPECTED has no requirements
```

**Required Change:**
```python
if confidence == "SUSPECTED":
    # Even SUSPECTED findings need minimum evidence
    required_fields["observed_behavior"] = (
        "SUSPECTED findings must include specific observed behavior "
        "(e.g., 'error message contained SQL syntax', 'response time was 5+ seconds')"
    )
    required_fields["next_steps"] = (
        "SUSPECTED findings must include recommended next investigation steps"
    )
else:
    required_fields["poc_script_code"] = "PoC script/code is REQUIRED for LIKELY/VERIFIED confidence"
    required_fields["extracted_evidence"] = (
        "LIKELY/VERIFIED findings must include concrete extracted evidence "
        "(data, file contents, command output, etc.)"
    )
```

---

### P1.3: Add SQLi Differential Testing Helper

**File:** `phantom/tools/response_analysis/response_analysis_actions.py`

**New Function:**
```python
def analyze_sqli_response_differential(
    baseline_response: str,
    true_condition_response: str,
    false_condition_response: str,
) -> dict:
    """
    Analyze SQLi boolean-based differential responses.
    
    Returns:
        dict with 'is_vulnerable', 'confidence', 'evidence'
    """
    baseline_len = len(baseline_response)
    true_len = len(true_condition_response)
    false_len = len(false_condition_response)
    
    # Calculate differentials
    true_diff = abs(true_len - baseline_len) / max(baseline_len, 1)
    false_diff = abs(false_len - baseline_len) / max(baseline_len, 1)
    true_false_diff = abs(true_len - false_len) / max(true_len, 1)
    
    evidence = {
        "baseline_length": baseline_len,
        "true_condition_length": true_len,
        "false_condition_length": false_len,
        "true_diff_percent": round(true_diff * 100, 2),
        "false_diff_percent": round(false_diff * 100, 2),
        "true_false_diff_percent": round(true_false_diff * 100, 2),
    }
    
    # Heuristics for SQLi detection
    # True condition should differ from false condition significantly
    if true_false_diff > 0.1:  # 10% difference between true/false
        # And true should be closer to baseline (normal behavior)
        if true_diff < false_diff:
            return {
                "is_vulnerable": True,
                "confidence": "HIGH" if true_false_diff > 0.5 else "MEDIUM",
                "evidence": evidence,
                "reasoning": "True condition response matches baseline, false condition differs significantly"
            }
    
    # Time-based indicator (caller must provide timing)
    # Content-based difference
    if "error" in false_condition_response.lower() and "error" not in true_condition_response.lower():
        return {
            "is_vulnerable": True,
            "confidence": "MEDIUM",
            "evidence": evidence,
            "reasoning": "Error in false condition response, not in true condition"
        }
    
    return {
        "is_vulnerable": False,
        "confidence": "LOW",
        "evidence": evidence,
        "reasoning": "No significant differential detected"
    }
```

---

## PRIORITY 2: MEDIUM IMPORTANCE FIXES

### P2.1: Add Evidence Validation to HypothesisLedger

**File:** `phantom/agents/hypothesis_ledger.py`

**Add to `record_result()` method (after line 97):**
```python
def record_result(
    self,
    hyp_id: str,
    outcome: str,
    evidence: str = "",
    successful_payload: str | None = None,
) -> None:
    """Record the result of a hypothesis test."""
    
    # NEW: Validate evidence is substantive
    if outcome == "confirmed" and evidence:
        if not self._validate_evidence(evidence):
            # Downgrade to "testing" if evidence is weak
            outcome = "testing"
            evidence += " [AUTO-DOWNGRADED: Evidence lacks required specificity]"
    
    # ... rest of existing code ...

def _validate_evidence(self, evidence: str) -> bool:
    """Check that evidence contains concrete artifacts, not just claims."""
    evidence_lower = evidence.lower()
    
    # Weak evidence indicators (claims without proof)
    weak_indicators = [
        "appears to be",
        "seems like",
        "might be",
        "could be",
        "potentially",
        "possibly",
        "suggests that",
        "indicates that",
    ]
    
    # Strong evidence indicators (concrete artifacts)
    strong_indicators = [
        "extracted:",
        "output:",
        "response:",
        "returned:",
        "executed:",
        "data:",
        "error message:",
        "stack trace:",
        r"\d+\s+rows?",  # SQL result count
        r"uid=\d+",  # RCE output
    ]
    
    # Must have strong indicators, must not have weak indicators
    has_weak = any(w in evidence_lower for w in weak_indicators)
    has_strong = any(re.search(s, evidence, re.IGNORECASE) for s in strong_indicators)
    
    return has_strong and not has_weak
```

---

### P2.2: Enforce Phased Methodology (Prompt Enhancement)

**File:** `phantom/agents/PhantomAgent/system_prompt.jinja`

**Add after the existing Phase definitions (around line 77):**
```jinja
## PHASE ENFORCEMENT CHECKLIST

Before transitioning from Phase 1 (Recon) to Phase 2 (Testing), verify:

□ Robots.txt and sitemap.xml checked
□ Common paths enumerated (/api, /admin, /login, /graphql, /swagger)
□ Technology stack identified (server, framework, language)
□ Input vectors catalogued (forms, APIs, headers, cookies)

YOU MUST acknowledge completing this checklist in your response before beginning vulnerability testing. Example:

"Phase 1 Complete: Identified [X] endpoints, [Y] input vectors, stack is [technology]. Proceeding to Phase 2."

If you begin testing without completing Phase 1, your findings will be UNRELIABLE.
```

---

## PRIORITY 3: LOWER IMPORTANCE FIXES

### P3.1: Add Negative Evidence Prompting

**File:** `phantom/agents/PhantomAgent/system_prompt.jinja`

**Add to the Hypothesis section:**
```jinja
## FALSIFICATION REQUIREMENT

For EVERY hypothesis you test, you MUST:

1. Record at least ONE piece of evidence FOR the vulnerability
2. Record at least ONE test that FAILED to exploit it

A hypothesis with only positive evidence is INCOMPLETE. Examples:

GOOD: "SQLi confirmed: UNION SELECT extracted usernames. Failed payloads: time-based (no delay observed), error-based (errors suppressed)."

BAD: "SQLi confirmed: error message contained 'SQL syntax'." (No failed tests, no extracted data)

Your `evidence_against` field should NEVER be empty for confirmed vulnerabilities.
```

---

## IMPLEMENTATION ORDER

```
Week 1: P0 - Critical Code Changes
├── P0.1: HTML Context Parser (2-3 days)
│   - Write HTMLContextAnalyzer class
│   - Integrate with _check_reflection()
│   - Add unit tests
│
└── P0.2: PoC Exploit Validation (1-2 days)
    - Add _EXPLOIT_SUCCESS_PATTERNS
    - Modify replay validation
    - Add unit tests

Week 2: P1 - Enforcement Changes
├── P1.1: Remove MANDATORY reporting (1 hour)
├── P1.2: SUSPECTED tier minimum evidence (2 hours)
└── P1.3: SQLi differential helper (4 hours)

Week 3: P2 - Validation & Prompt
├── P2.1: Evidence validation in HypothesisLedger (4 hours)
└── P2.2: Phased methodology enforcement (1 hour)

Week 4: P3 - Polish & Testing
├── P3.1: Negative evidence prompting (1 hour)
└── Integration testing with real targets
```

---

## TESTING STRATEGY

### Unit Tests Required

1. **HTML Context Parser:**
   - Test XSS in attribute values (`<div onclick="PAYLOAD">`)
   - Test XSS in script tags (`<script>PAYLOAD</script>`)
   - Test HTML-encoded payloads (`&lt;script&gt;`)
   - Test benign reflections (`<div>PAYLOAD</div>` where PAYLOAD has no script)

2. **PoC Exploit Validation:**
   - Test SQLi with data extraction output
   - Test RCE with command output
   - Test execution-only (no exploit indicators)
   - Test failure cases

3. **SQLi Differential Analysis:**
   - Test true/false response length differences
   - Test error-based differentials
   - Test no-difference scenarios

### Integration Tests Required

1. **Full scan against test application:**
   - Known XSS should be CONFIRMED not just SUSPECTED
   - Non-exploitable reflections should be INFO not HIGH
   - SQLi with extracted data should pass PoC validation

2. **False positive rate measurement:**
   - Track before/after ratio of SUSPECTED → CONFIRMED
   - Track false positive rate on known-safe endpoints

---

## SUCCESS METRICS

| Metric | Current (Estimated) | Target |
|--------|---------------------|--------|
| False positive rate | ~40% | <10% |
| SUSPECTED → CONFIRMED conversion | ~25% | >70% |
| PoC replay pass = actual exploit | ~50% | >90% |
| Detection context accuracy | 0% (none) | >80% |

---

## RISKS AND MITIGATIONS

| Risk | Impact | Mitigation |
|------|--------|------------|
| HTML parser introduces latency | Slower scans | Profile and optimize, cache parsed DOMs |
| Strict evidence breaks valid findings | Miss real vulns | Gradual rollout, monitor miss rate |
| Differential analysis has false negatives | Miss SQLi | Keep pattern-based as fallback |
| Prompt changes confuse LLM | Inconsistent behavior | A/B test prompt versions |
