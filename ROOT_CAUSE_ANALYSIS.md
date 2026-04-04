# ROOT CAUSE ANALYSIS: System Prompt vs Code

## Executive Summary

After systematic verification of 17 claimed issues, the root causes fall into **three distinct categories**:

| Category | Location | Severity | Fixable By |
|----------|----------|----------|------------|
| **Detection Architecture** | CODE | HIGH | Code changes |
| **Validation Enforcement** | CODE + PROMPT | HIGH | Code changes + prompt refinement |
| **Design Choices** | PROMPT | MEDIUM | Prompt changes |

---

## 1. PROBLEMS IN CODE (Not Prompt)

These issues exist in the codebase and cannot be fixed by prompt changes alone.

### 1.1 Regex-Only Detection Engine (CRITICAL)

**Location:** `phantom/tools/response_analysis/response_analysis_actions.py`

**Problem:** Detection layer uses pure regex patterns without semantic analysis.

```python
# Line 30-96: _ERROR_PATTERNS - all regex
# Line 103-138: _SECRET_PATTERNS - all regex  
# Line 192-222: _VULN_INDICATORS - all regex
```

**Why prompt can't fix:**
- The LLM receives detection results AFTER regex processing
- No amount of prompt instruction can add HTML/JS parsing
- Detection happens in code, not in LLM reasoning

**Impact:**
- False positives: `<script>` in JSON flagged as XSS
- Context-blindness: No distinction between HTML attribute vs content
- No taint tracking: Can't trace input to sink

**Required Fix:** Code changes to add semantic parsers (BeautifulSoup for HTML, esprima for JS).

---

### 1.2 Weak PoC Replay Validation (HIGH)

**Location:** `phantom/tools/reporting/reporting_actions.py:434-493`

**Problem:** PoC replay validates EXECUTION, not EXPLOITATION.

```python
# Line 452-466: Only checks for execution failures
_exec_failure_patterns = (
    "command not found",
    "no such file or directory",
    "traceback (most recent call last)",
    ...
)
if any(p in replay_out.lower() for p in _exec_failure_patterns):
    _replay = "FAILED"
else:
    _replay = "PASSED"  # <-- PASSES if command runs, regardless of exploit success
```

**Why prompt can't fix:**
- Replay is a code function, not LLM reasoning
- Even if LLM provides perfect PoC, validation is weak
- No semantic check of exploitation outcome

**Required Fix:** Code changes to implement exploit success verification:
- SQLi: Check if extracted data appears in output
- XSS: Check if JavaScript executed (via browser automation)
- RCE: Check for expected command output markers

---

### 1.3 XSS Reflection Check Without Encoding Analysis (HIGH)

**Location:** `phantom/tools/response_analysis/response_analysis_actions.py:534-564`

**Problem:** Reflection check is a simple substring match.

```python
def _check_reflection(payload: str, content: str) -> dict | None:
    if payload in content:  # <-- Just checks if string appears
        return {
            "type": "reflection",
            "severity": "high",
            ...
        }
```

**Why prompt can't fix:**
- This function runs before LLM sees results
- No context about WHERE the reflection occurs
- Can't distinguish HTML-escaped vs executable

**Required Fix:** Code to analyze:
- Context (attribute, tag content, script block)
- Encoding state (HTML entities, JS escaping)
- DOM position (inside comment, CDATA, etc.)

---

## 2. PROBLEMS IN BOTH CODE AND PROMPT

These require coordinated fixes in both locations.

### 2.1 SUSPECTED Confidence Tier Bypass (HIGH)

**Prompt Location:** `phantom/agents/PhantomAgent/system_prompt.jinja`
**Code Location:** `phantom/tools/reporting/reporting_actions.py:262-263`

**Prompt says:**
```
NEVER USE THESE WORDS IN REPORTS: potential, possible, suspected...
```

**Code does:**
```python
if confidence != "SUSPECTED":
    required_fields["poc_script_code"] = "PoC script/code is REQUIRED..."
# SUSPECTED bypasses proof requirement
```

**Contradiction:** Prompt discourages SUSPECTED, but code permits it without proof.

**Fix Required:**
- **Code:** Require at least preliminary evidence for SUSPECTED
- **Prompt:** Clarify when SUSPECTED is appropriate (never for final reports)

---

### 2.2 Mandatory Reporting Instruction (MEDIUM)

**Code Location:** `phantom/tools/executor.py:1133-1139`

```python
signal_header += (
    "[MANDATORY] A critical vulnerability signal was detected above. "
    "You MUST call create_vulnerability_report with confidence=SUSPECTED "
    "in your NEXT response. Do NOT delay reporting.\n"
)
```

**Problem:** This instruction FORCES reporting on signals, contradicting the "PROOF OR NO REPORT" rule.

**Why both need fixing:**
- Code injects mandatory instruction
- Prompt doesn't override with "investigate first"

**Fix Required:**
- **Code:** Change MANDATORY to RECOMMENDED, suggest investigation first
- **Prompt:** Add explicit "signals require validation before reporting" instruction

---

### 2.3 LLM-Filled Evidence Fields (MEDIUM)

**Code Location:** `phantom/agents/hypothesis_ledger.py`

**Current:**
```python
def record_result(
    self,
    hyp_id: str,
    outcome: str,  # LLM decides this
    evidence: str = "",  # LLM provides this
    successful_payload: str | None = None,  # LLM provides this
) -> None:
```

**Problem:** All evidence is LLM-provided with no verification.

**Fix Required:**
- **Code:** Add evidence validators (check URL format, response snippets, etc.)
- **Prompt:** Require specific evidence format (e.g., "Include exact response snippet")

---

## 3. PROBLEMS IN PROMPT ONLY

These can be fixed with prompt changes alone.

### 3.1 Phased Methodology Not Enforced (MEDIUM)

**Location:** `phantom/agents/PhantomAgent/system_prompt.jinja:68-77`

**Current:**
```
Phase 1 - Recon (10-15% of time):
- Map endpoints...
Phase 2 - Testing (70-80% of time):
- Test EVERY input field...
```

**Problem:** This is descriptive, not prescriptive. LLM can skip phases.

**Fix Required (Prompt Only):**
```
BEFORE TESTING ANY VULNERABILITY:
1. Confirm you have mapped the attack surface
2. List discovered endpoints in your first message
3. Do NOT proceed to Phase 2 until Phase 1 checklist complete
```

---

### 3.2 Negative Evidence Collection (LOW)

**Current:** `HypothesisLedger` has `evidence_against` field but prompt doesn't emphasize it.

**Fix Required (Prompt Only):**
```
For EVERY hypothesis, you MUST document:
- 3 pieces of evidence FOR the vulnerability
- 3 tests that FAILED to exploit it
A hypothesis without evidence_against is INCOMPLETE.
```

---

## 4. ROOT CAUSE MAPPING

```
┌─────────────────────────────────────────────────────────────────────┐
│                    ROOT CAUSE HIERARCHY                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │ LEVEL 1: ARCHITECTURAL (Code-Only)                           │   │
│  │                                                               │   │
│  │  - Regex detection without semantic parsing                   │   │
│  │  - PoC replay validates execution not exploitation            │   │
│  │  - XSS reflection is substring match only                     │   │
│  │                                                               │   │
│  │  CANNOT BE FIXED BY PROMPT                                    │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                              │                                       │
│                              ▼                                       │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │ LEVEL 2: ENFORCEMENT (Code + Prompt)                         │   │
│  │                                                               │   │
│  │  - SUSPECTED tier bypasses proof requirements                 │   │
│  │  - MANDATORY reporting overrides proof rule                   │   │
│  │  - Evidence fields are LLM-provided, unvalidated             │   │
│  │                                                               │   │
│  │  REQUIRES COORDINATED FIX                                     │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                              │                                       │
│                              ▼                                       │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │ LEVEL 3: GUIDANCE (Prompt-Only)                              │   │
│  │                                                               │   │
│  │  - Phased methodology is suggested not enforced              │   │
│  │  - Negative evidence not emphasized                          │   │
│  │  - No explicit falsification requirement                     │   │
│  │                                                               │   │
│  │  CAN BE FIXED BY PROMPT CHANGES                               │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 5. PRIORITY RANKING

| Priority | Issue | Type | Impact | Effort |
|----------|-------|------|--------|--------|
| P0 | Semantic detection (HTML/JS parsing) | Code | Eliminates false positives | High |
| P0 | PoC exploit validation | Code | Ensures real vulnerabilities | Medium |
| P1 | Remove MANDATORY reporting | Code+Prompt | Stops forced false positives | Low |
| P1 | SUSPECTED tier restrictions | Code+Prompt | Requires minimum evidence | Low |
| P2 | Evidence validation | Code | Verifies LLM claims | Medium |
| P2 | Enforce phased methodology | Prompt | Better coverage | Low |
| P3 | Negative evidence prompting | Prompt | Reduces confirmation bias | Low |

---

## 6. CONCLUSION

**The root cause is NOT a single issue but a layered problem:**

1. **Foundation (Code):** Detection engine lacks semantic analysis - this MUST be fixed in code
2. **Enforcement (Code+Prompt):** Validation exists but doesn't verify semantic correctness
3. **Guidance (Prompt):** Good instructions exist but are not enforced

**Key Insight:** The system prompt is actually quite good ("PROOF OR NO REPORT"). The problem is:
- Code doesn't enforce what prompt instructs
- Some code paths (MANDATORY reporting) contradict prompt guidance
- Detection layer produces context-free signals that mislead the LLM

**Recommended Approach:**
1. Fix code-level detection first (semantic parsing)
2. Align code enforcement with prompt instructions
3. Strengthen prompt guidance for methodology
