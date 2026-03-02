---
name: quick
description: Time-boxed rapid assessment targeting high-impact vulnerabilities
---

# Quick Testing Mode

Time-boxed assessment focused on high-impact vulnerabilities. Prioritize breadth over depth.

## Approach

Optimize for fast feedback on critical security issues. Skip exhaustive enumeration in favor of targeted testing on high-value attack surfaces.

## Phase 1: Rapid Orientation

**Whitebox (source available)**
- Focus on recent changes: git diffs, new commits, modified files—these are most likely to contain fresh bugs
- Identify security-sensitive patterns in changed code: auth checks, input handling, database queries, file operations
- Trace user input through modified code paths
- Check if security controls were modified or bypassed

**Blackbox (no source)**
- **MANDATORY FIRST STEP**: Run `katana_crawl` to discover all endpoints, JS files, API routes, and forms
- Map authentication and critical user flows
- Identify exposed endpoints and entry points
- Use the crawl results to prioritize testing targets

## Phase 2: Systematic High-Impact Testing

Test in priority order — spend max 5 iterations per vuln class per endpoint cluster:

1. **SQL injection** - ALL authentication endpoints, search fields, filters, API params — use sqlmap first
2. **XSS (Reflected & Stored)** - ALL input fields, search bars, comments, profile fields — use ffuf with XSS wordlist
3. **Authentication bypass** - login flaws, session issues, JWT manipulation — use jwt_tool for token testing
4. **Broken access control / IDOR** - sequential IDs, privilege escalation, missing authorization
5. **Path Traversal / LFI** - file download endpoints, image paths, include parameters — try ../../etc/passwd payloads
6. **SSRF** - URL parameters, webhooks, image fetch, integrations — try http://localhost, http://127.0.0.1
7. **Remote code execution** - command injection, deserialization, SSTI — test any user-controlled input reaching server-side processing
8. **File Upload** - unrestricted file types, bypass extension filters, test for web shell upload
9. **Business Logic** - price manipulation, coupon abuse, race conditions on financial operations
10. **Information Disclosure** - error messages, stack traces, debug endpoints, /ftp, .git exposure, API key leakage

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

Think like a time-boxed bug bounty hunter going for quick wins. BREADTH over DEPTH: test ALL vuln classes across ALL endpoints. If something isn't yielding results after 5 iterations, record as dead-end and MOVE ON. Report each finding immediately via create_vulnerability_report.
