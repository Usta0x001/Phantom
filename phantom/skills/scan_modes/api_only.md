---
name: api_only
description: API-focused assessment without browser automation or subdomain discovery
---

# API-Only Testing Mode

Focused security assessment of REST/GraphQL/gRPC APIs. No browser sessions. No subdomain discovery. Maximum depth on API attack surfaces.

## Approach

Treat the application as a pure API consumer. Understand the API contract completely before testing. Systematic coverage of every endpoint and parameter.

## Phase 1: API Discovery

- Probe for API documentation: `/swagger.json`, `/openapi.json`, `/api-docs`, `/graphql`
- Crawl with `katana_crawl` to discover API endpoints from network traffic
- Identify API versioning: `/v1/`, `/v2/`, `/api/v3/`, etc.
- Fingerprint authentication mechanism: Bearer JWT, API keys, OAuth2, cookie-based
- Map HTTP methods per endpoint (GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS)
- Identify content types: JSON, XML, multipart/form-data, protobuf

## Phase 2: Authentication Testing

- Test for missing authentication on every endpoint (try without Authorization header)
- Test token expiration and refresh token handling
- Test JWT algorithm confusion (RSA/HMAC confusion, `alg:none`)
- Test API key in different positions (header, query param, body)
- Test for mass assignment in registration/update endpoints
- Test rate limiting on authentication endpoints

## Phase 3: Authorization Testing

- Horizontal IDOR: access other users' resources by changing IDs
- Vertical privilege escalation: access admin endpoints with regular user token
- Test BOLA (Broken Object Level Authorization) on every resource endpoint
- Test HTTP method-level authorization (GET allowed but PUT should be blocked)
- Test for shadow admin endpoints (`/admin/`, `/internal/`, `/debug/`, `/_api/`)

## Phase 4: Input Validation

- Injection testing on all string parameters (SQL, NoSQL, command, SSTI)
- Mass assignment: send extra fields in POST/PUT requests and check if they persist
- Type juggling: send strings where numbers expected and vice versa
- Boundary testing: null values, empty strings, negative numbers, large payloads
- HTTP parameter pollution: send same parameter twice

## Phase 5: Business Logic

- Test multi-step API workflows: can steps be skipped or re-ordered?
- Race conditions on state-changing endpoints
- Negative or zero values in quantity/amount fields
- Reference objects from other users in requests (IDOR chaining)

## Phase 6: Data Exposure

- Test what fields are returned for non-owners
- Check error messages for stack traces, SQL queries, path disclosure
- Test export/download endpoints for bulk data access

## Operational Guidelines

- Use `send_request` for precise manual API testing
- Use `httpx_probe` for endpoint profiling, not aggressive scanning
- Use `nuclei_scan` for API-specific templates only
- Use `sqlmap_test` on injection-vulnerable endpoints (targeted, not mass scanning)
- Skip: browser tools, subfinder, port scanning

## Mindset

Think like an API penetration tester on a bug bounty engagement. Every endpoint is a potential attack surface. Authorization and input validation are the highest-yield areas. Find and chain logic flaws for maximum impact.
