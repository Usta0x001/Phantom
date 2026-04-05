# PHANTOM AUDIT REPORT - MEDIUM & LOW SEVERITY ISSUES

**Classification**: MEDIUM (Score Impact: -5 to -9 points) / LOW (Score Impact: -1 to -4 points)  
**Definition**: Issues that reduce quality but don't fundamentally break functionality.

---

## MEDIUM SEVERITY ISSUES

### M-01: NO DIRECTORY BRUTEFORCE / FORCED BROWSING

**Category**: A - Reconnaissance  
**Severity**: MEDIUM  
**Location**: Missing

**Current State**: No capability to discover hidden directories/files.

**What's Missing**:
- No `/admin`, `/backup`, `/.git` discovery
- No common file bruteforce (`.env`, `config.php`, etc.)
- No SecLists integration

**Fix**: Integrate `ffuf`-style directory bruteforce with smart wordlists.

**Effort**: 1 week

---

### M-02: PAYLOAD GENERATION LACKS CONTEXT AWARENESS

**Category**: C - Exploitation Intelligence  
**Severity**: MEDIUM  
**Location**: `payload_gen_actions.py:1-380`

**Current State**:
```python
# Payloads are generated based on vulnerability type only
# No consideration of:
# - Backend technology detected
# - WAF bypass requirements
# - Prior failed payloads
```

**What's Missing**:
- No tech-stack-specific payloads (MySQL vs PostgreSQL vs MSSQL)
- No WAF-aware payload modification
- No learning from failed payloads

**Fix**: 
```python
async def generate_payload(
    vuln_type: str,
    context: dict,  # {backend: "mysql", waf: "cloudflare", failed_payloads: [...]}
) -> dict:
    # Generate payloads optimized for detected context
```

**Effort**: 2 weeks

---

### M-03: BROWSER AUTOMATION LACKS ANTI-DETECTION

**Category**: D - Evasion  
**Severity**: MEDIUM  
**Location**: `browser_actions.py`, `browser_instance.py`

**Current State**: Standard Playwright browser with default fingerprint.

**What's Missing**:
- No fingerprint randomization
- No WebGL spoofing
- No canvas fingerprint masking
- Detectable as automation by bot detection

**Fix**: Integrate `playwright-stealth` or equivalent anti-fingerprinting.

**Effort**: 1 week

---

### M-04: NO RATE LIMIT DETECTION AND BYPASS

**Category**: D - Evasion  
**Severity**: MEDIUM  
**Location**: `fuzzer_actions.py`

**Current State**: Stealth mode adds delays but doesn't detect when rate limited.

**What's Missing**:
- No 429 response detection
- No automatic backoff
- No rate limit bypass strategies (header manipulation, IP rotation)

**Fix**:
```python
async def detect_rate_limit(response: dict) -> dict:
    """Detect rate limiting and return bypass strategies."""

async def adaptive_rate_limit(
    target: str,
    initial_rps: float = 10,
    min_rps: float = 0.5,
) -> float:
    """Find maximum safe request rate without triggering limits."""
```

**Effort**: 1 week

---

### M-05: OAST TOOL LACKS PROTOCOL DIVERSITY

**Category**: B - Vulnerability Assessment  
**Severity**: MEDIUM  
**Location**: `oast_actions.py`

**Current State**:
```python
# Only HTTP/HTTPS OAST payloads
# No DNS, SMTP, FTP, LDAP, etc.
```

**What's Missing**:
- No DNS-based OAST
- No SMTP exfiltration testing
- No LDAP injection OAST
- No FTP/TFTP testing

**Fix**: Integrate Interactsh or similar for multi-protocol OOB.

**Effort**: 2 weeks

---

### M-06: CVE/EXPLOIT SEARCH NOT INTEGRATED INTO SCAN FLOW

**Category**: B - Vulnerability Assessment  
**Severity**: MEDIUM  
**Location**: `vuln_intel_actions.py`

**Current State**: Tools exist but aren't automatically triggered after technology detection.

**What Should Happen**:
1. Detect Apache 2.4.49
2. Automatically query `version_to_cves("Apache", "2.4.49")`
3. Queue exploitation of CVE-2021-41773 if found

**Fix**: Add automatic CVE lookup to post-fingerprint workflow.

**Effort**: 1 week

---

### M-07: NO SCREENSHOT EVIDENCE CAPTURE

**Category**: F - Reporting  
**Severity**: MEDIUM  
**Location**: `reporting_actions.py`

**Current State**: Reports include curl commands but no visual evidence.

**What's Missing**:
- No automated screenshot of vulnerability
- No before/after comparison
- No video recording of exploitation

**Fix**: 
```python
async def capture_vulnerability_evidence(
    url: str,
    payload: str,
    capture_type: str = "screenshot",  # screenshot/video/both
) -> dict:
    """Capture visual evidence of vulnerability for reports."""
```

**Effort**: 1 week

---

### M-08: WEAK PAYLOAD MUTATION

**Category**: C - Exploitation  
**Severity**: MEDIUM  
**Location**: `payload_gen_actions.py`

**Current State**: Payloads are pre-defined with basic encoding options.

**What's Missing**:
- No intelligent mutation (add junk, split payloads)
- No polymorphic payload generation
- No ML-based mutation

**Fix**: Add payload mutation engine with fuzzing strategies.

**Effort**: 2 weeks

---

### M-09: NO API FUZZING SPECIFIC TOOLING

**Category**: B - Vulnerability Assessment  
**Severity**: MEDIUM  
**Location**: `api_schema_actions.py` parses, doesn't fuzz

**Current State**: Can parse OpenAPI schemas but no dedicated API fuzzing.

**What's Missing**:
- No parameter type confusion
- No boundary value testing
- No REST-specific attacks (mass assignment, BOLA)
- No GraphQL-specific attacks

**Fix**: Add API-specific fuzzing tools.

**Effort**: 2 weeks

---

### M-10: HTTP REQUEST SMUGGLING NOT TESTED

**Category**: B - Vulnerability Assessment  
**Severity**: MEDIUM  
**Location**: Not implemented

**Current State**: No HTTP request smuggling detection.

**What's Missing**:
- No CL.TE / TE.CL detection
- No HTTP/2 downgrade testing
- No request tunneling

**Fix**: Add smuggling detection module.

**Effort**: 1 week

---

### M-11: NO CACHE POISONING TESTING

**Category**: B - Vulnerability Assessment  
**Severity**: MEDIUM  
**Location**: Not implemented

**Current State**: No web cache poisoning detection.

**What's Missing**:
- No cache key detection
- No unkeyed header identification
- No cache deception testing

**Fix**: Add cache poisoning module.

**Effort**: 1 week

---

### M-12: CORRELATION ENGINE CHAINS ARE STATIC

**Category**: E - AI Reasoning  
**Severity**: MEDIUM  
**Location**: `correlation_engine.py:45-180`

**Current State**:
```python
# Attack chains are hardcoded:
ATTACK_CHAINS = {
    "ssrf_to_cloud_metadata": ChainDefinition(...),
    # ...
}
```

**What Should Happen**: Learn new chains from successful attacks.

**Fix**: Add chain learning from successful exploitations.

**Effort**: 3 weeks

---

### M-13: NO HOST HEADER INJECTION TESTING

**Category**: B - Vulnerability Assessment  
**Severity**: MEDIUM  
**Location**: Not implemented

**What's Missing**:
- Password reset poisoning
- Cache poisoning via Host
- Virtual host enumeration

**Fix**: Add Host header injection module.

**Effort**: 3 days

---

## LOW SEVERITY ISSUES

### L-01: TYPE ERRORS IN CODEBASE

**Category**: H - Code Quality  
**Severity**: LOW  
**Location**: Multiple files (see LSP errors)

**Current State**: 50+ type errors across codebase.

**Fix**: Run `pyright` and fix all type annotations.

**Effort**: 3 days

---

### L-02: UNUSED IMPORTS

**Category**: H - Code Quality  
**Severity**: LOW  
**Location**: `osint_actions.py:25-28` and others

```python
import os  # Not accessed
from datetime import UTC, datetime  # Not accessed
```

**Fix**: Remove unused imports.

**Effort**: 1 hour

---

### L-03: MAGIC NUMBERS IN CODE

**Category**: H - Code Quality  
**Severity**: LOW  
**Location**: Various

```python
# Examples:
if len(token_value) > 8:  # What's special about 8?
response_text[:10_000]    # Why 10000?
```

**Fix**: Extract to named constants with documentation.

**Effort**: 2 days

---

### L-04: MISSING DOCSTRINGS

**Category**: H - Code Quality  
**Severity**: LOW  
**Location**: Various internal functions

**Current State**: Many internal functions lack docstrings.

**Fix**: Add comprehensive docstrings.

**Effort**: 1 week

---

### L-05: NO INPUT VALIDATION ON TOOL PARAMETERS

**Category**: H - Security  
**Severity**: LOW  
**Location**: Various tool functions

**Current State**: Some tools don't validate input ranges/formats.

**Fix**: Add pydantic validation or explicit checks.

**Effort**: 1 week

---

### L-06: LOGGING INCONSISTENCY

**Category**: H - Operations  
**Severity**: LOW  
**Location**: Various

**Current State**: Some modules use `logger.debug`, others `logger.info` for similar events.

**Fix**: Standardize logging levels.

**Effort**: 2 days

---

### L-07: NO CONFIGURATION VALIDATION

**Category**: H - Operations  
**Severity**: LOW  
**Location**: `config/config.py`

**Current State**: Configuration loaded without schema validation.

**Fix**: Add pydantic config validation.

**Effort**: 2 days

---

### L-08: HARDCODED TIMEOUT VALUES

**Category**: H - Configuration  
**Severity**: LOW  
**Location**: Various

```python
# Scattered throughout:
timeout = 30
httpx.Client(timeout=10)
```

**Fix**: Centralize timeouts in configuration.

**Effort**: 1 day

---

### L-09: NO METRICS/TELEMETRY DASHBOARD

**Category**: H - Operations  
**Severity**: LOW  
**Location**: `telemetry/tracer.py`

**Current State**: Telemetry collected but no visualization.

**Fix**: Add Prometheus/Grafana export.

**Effort**: 1 week

---

### L-10: ERROR MESSAGES COULD LEAK INTERNALS

**Category**: H - Security  
**Severity**: LOW  
**Location**: Various exception handlers

**Current State**: Some errors include full stack traces to LLM.

**Fix**: Sanitize error messages before returning.

**Effort**: 2 days

---

## SUMMARY TABLE

### Medium Issues (13 total)

| ID | Title | Effort |
|----|-------|--------|
| M-01 | No Directory Bruteforce | 1 week |
| M-02 | Payload Context Awareness | 2 weeks |
| M-03 | Browser Anti-Detection | 1 week |
| M-04 | Rate Limit Detection | 1 week |
| M-05 | OAST Protocol Diversity | 2 weeks |
| M-06 | CVE Auto-Integration | 1 week |
| M-07 | Screenshot Evidence | 1 week |
| M-08 | Payload Mutation | 2 weeks |
| M-09 | API-Specific Fuzzing | 2 weeks |
| M-10 | HTTP Smuggling | 1 week |
| M-11 | Cache Poisoning | 1 week |
| M-12 | Dynamic Chain Learning | 3 weeks |
| M-13 | Host Header Injection | 3 days |

**Total Medium Effort**: ~19 weeks

### Low Issues (10 total)

| ID | Title | Effort |
|----|-------|--------|
| L-01 | Type Errors | 3 days |
| L-02 | Unused Imports | 1 hour |
| L-03 | Magic Numbers | 2 days |
| L-04 | Missing Docstrings | 1 week |
| L-05 | Input Validation | 1 week |
| L-06 | Logging Consistency | 2 days |
| L-07 | Config Validation | 2 days |
| L-08 | Hardcoded Timeouts | 1 day |
| L-09 | Metrics Dashboard | 1 week |
| L-10 | Error Message Sanitization | 2 days |

**Total Low Effort**: ~4 weeks

---

*"The medium issues are what separate 'good enough' from 'actually good'. The low issues are what separate 'hacky' from 'professional'."*
