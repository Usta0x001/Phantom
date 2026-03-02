---
name: quick
description: Time-boxed rapid assessment targeting high-impact vulnerabilities
---

# Quick Testing Mode

Time-boxed assessment focused on DIVERSE vulnerability discovery. Maximum breadth across vulnerability classes.

## Critical Rule: VULNERABILITY CLASS DIVERSITY

The system enforces MANDATORY ROTATION between vulnerability classes every ~10 iterations.
When you see a ROTATION message, you MUST switch to the specified class immediately.
Goal: test at least 6-8 different vulnerability classes before scan ends.
DO NOT spend more than 10 iterations on any single vulnerability type.
After finding a vuln: REPORT IT → IMMEDIATELY move to the NEXT vulnerability class.

## Approach

Optimize for finding DIFFERENT TYPES of vulnerabilities. A scan that finds SQLi + XSS + IDOR + JWT bypass is 10x more valuable than one that finds 5 SQLi variants.

## Phase 1: Rapid Orientation

**Whitebox (source available)**
- Focus on recent changes: git diffs, new commits, modified files—these are most likely to contain fresh bugs
- Identify security-sensitive patterns in changed code: auth checks, input handling, database queries, file operations
- Trace user input through modified code paths
- Check if security controls were modified or bypassed

**Blackbox (no source)**
- **MANDATORY FIRST STEP**: Run `katana_crawl` to discover all endpoints, JS files, API routes, and forms
- **SPA DETECTION**: If katana finds fewer than 10 URLs, the target is likely a JavaScript SPA (Angular/React/Vue):
  1. Re-run `katana_crawl` with `headless=True` to render JavaScript and discover dynamic routes
  2. Use `ffuf_directory_scan` with API-focused wordlists to find /api/, /rest/, /graphql endpoints
  3. Use `browser_action` to navigate the app and capture network requests (API endpoints)
  4. Probe common API paths: /api/Users, /api/Products, /api/Cards, /rest/user/login, /api-docs, /swagger.json, /.well-known
- Map authentication and critical user flows
- Identify exposed endpoints and entry points
- Use the crawl results to prioritize testing targets

## Phase 2: Systematic High-Impact Testing

Test in priority order — spend max 8 iterations per vuln class, then MOVE ON:

1. **SQL injection** - ALL authentication endpoints, search fields, filters, API params — use sqlmap first
2. **XSS (Reflected & Stored)** - ALL input fields, search bars, comments, profile fields — use ffuf with XSS wordlist, browser for DOM XSS
3. **Authentication bypass** - login flaws, session issues, JWT manipulation — use jwt_tool for token testing, test admin/admin, test JWT none-algorithm
4. **Broken access control / IDOR** - sequential IDs (/api/Users/1, /api/Users/2), privilege escalation, missing authorization on admin endpoints
5. **Path Traversal / LFI** - file download endpoints, image paths, include parameters — try ../../etc/passwd payloads, check /ftp directory
6. **SSRF** - URL parameters, webhooks, image fetch, integrations — try http://localhost, http://127.0.0.1, http://169.254.169.254
7. **Remote code execution** - command injection, deserialization, SSTI — test any user-controlled input reaching server-side processing
8. **File Upload** - unrestricted file types, bypass extension filters, test for web shell upload
9. **Business Logic** - price manipulation (negative quantities), coupon abuse, race conditions on financial operations (use concurrent requests)
10. **Information Disclosure** - error messages, stack traces, debug endpoints, /ftp, .git exposure, API key leakage, /metrics, /env

CRITICAL RULES for quick scan:
- Use SPECIALIZED TOOLS (nuclei, sqlmap, ffuf, jwt_tool) before python_action scripts
- If a tool confirms a vuln → validate with PoC → call create_vulnerability_report IMMEDIATELY (no separate reporting agent!)
- Move on after 5 iterations per endpoint per vuln class — record dead-ends
- Aim to test at LEAST 6 vuln classes before iterations run out

## Phase 3: Validation

- Confirm exploitability with minimal proof-of-concept
- Demonstrate real impact, not theoretical risk
- Report findings immediately as discovered

## Chaining

When a strong primitive is found (auth weakness, injection point, internal access), immediately attempt one high-impact pivot to demonstrate maximum severity. Don't stop at a low-context "maybe"—turn it into a concrete exploit sequence that reaches privileged action or sensitive data.

## Operational Guidelines

- Use SPECIALIZED TOOLS first: nuclei (broad templates), sqlmap, ffuf, jwt_tool, arjun
- Only use python_action for custom business logic tests or exploit chaining
- Use browser tool only for complex interactive flows — NOT for API endpoints
- Use proxy to inspect traffic on key endpoints
- Create subagents for parallel vuln class testing (e.g., "SQLi Agent", "XSS Agent", "Auth Agent")
- Each subagent should discover, validate, AND report (no separate reporting agents)

## Mindset

Think like a time-boxed bug bounty hunter going for DIVERSE wins. BREADTH over DEPTH: test ALL vuln classes across ALL endpoints. Finding 5 DIFFERENT vuln types is 10x more valuable than finding 5 variants of SQLi. The system enforces rotation — follow it. If something isn't yielding results after 8 iterations, record as dead-end and IMMEDIATELY switch to the next vulnerability class. Report each finding immediately via create_vulnerability_report, then move on.
