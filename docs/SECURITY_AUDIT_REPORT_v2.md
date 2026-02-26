# Phantom — Deep Security Audit Report v2

**Date:** 2025-02-25  
**Auditor:** Automated Deep Security Audit  
**Scope:** Phantom project — Dockerfile, dependencies, containers, scripts, tools, CI/CD, tests  
**Severity Scale:** CRITICAL / HIGH / MEDIUM / LOW / INFO

---

## Executive Summary

The audit identified **38 findings** across 15 scanned areas. The most critical issues relate to the sandbox container running with passwordless sudo, excessive Docker capabilities, intentionally suppressed security linting rules, shell command injection surfaces in tool wrappers, and unpinned dependency versions. Many of these are partially mitigated by the application's design (tools run inside an ephemeral sandbox container), but several findings would have impact in the event of sandbox escape or misconfiguration.

| Severity | Count |
|----------|-------|
| CRITICAL | 5 |
| HIGH | 10 |
| MEDIUM | 14 |
| LOW | 7 |
| INFO | 2 |

---

## 1. Docker & Container Security

### FINDING-01 — CRITICAL: Sandbox Container Grants Passwordless Root via Sudo

**File:** `containers/Dockerfile` L11  
```dockerfile
echo "pentester ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
```

**File:** `containers/docker-entrypoint.sh` L108, L112–125, L137–139  
The entrypoint uses `sudo tee` and `sudo -E -u pentester` extensively.

**Impact:** Any code execution inside the sandbox (including AI-generated commands) has a trivial path to full root privileges. If the container escapes (e.g., via Docker socket mount or kernel exploit), this becomes host-level root access.

**Recommendation:** Remove NOPASSWD sudo. Pre-configure all files that need root during the build stage, so the entrypoint never needs `sudo`.

---

### FINDING-02 — CRITICAL: Excessive Docker Capabilities (NET_ADMIN, NET_RAW)

**File:** `phantom/runtime/docker_runtime.py` L153  
```python
cap_add=["NET_ADMIN", "NET_RAW"],
```

**Impact:** `NET_ADMIN` allows the container to modify network interfaces, routing tables, iptables rules, and sniff all traffic. Combined with root access (FINDING-01), this significantly broadens the container escape attack surface.

**Recommendation:** Use only `NET_RAW` (needed for nmap). Drop `NET_ADMIN` unless ARP spoofing features are explicitly required.

---

### FINDING-03 — HIGH: Piping Remote Scripts to Shell During Image Build

**File:** `containers/Dockerfile` L79, L113, L117  
```dockerfile
curl -sSL https://install.python-poetry.org | POETRY_HOME=/opt/poetry python3 -
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
```

**Impact:** Supply-chain attack vector. If any URL is compromised, arbitrary code runs as root during build. No integrity verification is performed.

**Recommendation:** Download scripts first, verify checksums against known-good values, then execute. Pin GitHub raw URLs to specific commit hashes.

---

### FINDING-04 — HIGH: No Docker Image Pinning (Tag Mutability)

**File:** `containers/Dockerfile` L1  
```dockerfile
FROM kalilinux/kali-rolling:latest
```

**File:** `Dockerfile` L9, L24  
```dockerfile
FROM python:3.12-slim AS builder
FROM python:3.12-slim
```

**Impact:** Mutable tags mean builds are non-reproducible and vulnerable to image tag replacement attacks.

**Recommendation:** Pin all base images to SHA256 digest: `FROM kalilinux/kali-rolling@sha256:<digest>`.

---

### FINDING-05 — HIGH: Tool Server Binds to 0.0.0.0

**File:** `phantom/runtime/tool_server.py` L24  
```python
parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
```

**File:** `containers/docker-entrypoint.sh` L148  
```bash
--host=0.0.0.0
```

**Impact:** The tool server API is accessible from any network interface inside the container. If port-forwarding is misconfigured or the container is on a shared network, the tool execution endpoint is network-exposed.

**Recommendation:** Bind to `127.0.0.1` by default. The host communicates via Docker port mapping.

---

### FINDING-06 — MEDIUM: Token Passed via Environment Variable and CLI Argument

**File:** `phantom/runtime/docker_runtime.py` L157  
```python
"TOOL_SERVER_TOKEN": self._tool_server_token,
```

**File:** `containers/docker-entrypoint.sh` L147  
```bash
--token="$TOOL_SERVER_TOKEN"
```

**Impact:** Token visible in `docker inspect`, `/proc/1/environ`, `/proc/*/cmdline`. Any process inside the container can read it.

**Recommendation:** Pass the token via a Docker secret or mounted file with `0600` permissions.

---

### FINDING-07 — MEDIUM: CA Private Key With Empty Passphrase

**File:** `containers/Dockerfile` L54–66  
```dockerfile
openssl pkcs12 -export ... -passout pass:""
```

**Impact:** Any process can import the CA key and generate arbitrary TLS certificates. Since this CA is trusted system-wide, it enables MITM attacks.

**Recommendation:** Use a randomly generated passphrase stored in a restrictively-permissioned file.

---

### FINDING-08 — MEDIUM: Git Clones Without Integrity Verification

**File:** `containers/Dockerfile` L99–104  
```dockerfile
RUN git clone https://github.com/aravind0x7/JS-Snooper.git && \
    git clone https://github.com/xchopath/jsniper.sh.git && \
    git clone https://github.com/ticarpi/jwt_tool.git
```

**Impact:** Cloning at HEAD without pinning to a commit hash. A compromised repository injects malicious code.

**Recommendation:** Pin each clone to a specific commit: `git clone <url> && cd <dir> && git checkout <commit-sha>`.

---

### FINDING-09 — LOW: No HEALTHCHECK in Dockerfiles

**Files:** `Dockerfile`, `containers/Dockerfile`, `containers/Dockerfile.sandbox`

**Impact:** Docker/orchestrators cannot auto-detect unhealthy containers.

**Recommendation:** Add `HEALTHCHECK CMD curl -f http://localhost:48081/health || exit 1`.

---

## 2. Dependency Security (pyproject.toml)

### FINDING-10 — HIGH: Unpinned and Loosely Pinned Dependencies

**File:** `pyproject.toml` L54–66  

| Dependency | Pinning | Risk |
|---|---|---|
| `rich = "*"` | Fully unpinned | Any version installed |
| `fastapi = { version = "*" }` | Fully unpinned | Any version |
| `uvicorn = { version = "*" }` | Fully unpinned | Any version |
| `litellm = "~1.81.1"` | Patch-level | Good |
| `requests = "^2.32.0"` | Major-range | Moderate |

**Impact:** `*` specifiers can silently pull any version, including broken or malicious releases on `poetry update`.

**Recommendation:** Pin all dependencies to at minimum `^major.minor`. Eliminate all `*` version specifiers.

---

### FINDING-11 — HIGH: Bandit Security Linter Skips Critical Shell Injection Rules

**File:** `pyproject.toml` L384  
```toml
skips = ["B101", "B601", "B404", "B603", "B607"]
```

**Impact:** B601 (shell injection via `os.system()`), B603 (`subprocess` with `shell=True`), B607 (partial path) are globally disabled. Genuine injection vulnerabilities won't be caught.

**Recommendation:** Remove project-wide skips. Use per-file `# nosec` annotations only on legitimately safe lines.

---

### FINDING-12 — MEDIUM: Ruff Security Rules Suppressed

**File:** `pyproject.toml` L229–231  
```toml
"S301",   # Use of pickle — suppressed globally
```

**File:** `pyproject.toml` L241  
```toml
"tests/**/*.py" = ["S106"]  # Possible hardcoded password — suppressed in tests
```

**Impact:** Pickle deserialization enables arbitrary code execution if untrusted data is deserialized. `S106` suppression in tests means real secrets could be introduced undetected.

**Recommendation:** Keep `S301` enabled globally. Use inline `# noqa` only where pickle is explicitly safe.

---

### FINDING-13 — MEDIUM: defusedxml Not Used Consistently

**File:** `pyproject.toml` L62 — `xmltodict = "^0.13.0"` is a dependency.  
**File:** `phantom/tools/registry.py` L8 — Correctly uses `defusedxml.ElementTree`.

**Impact:** If `xmltodict` is used to parse untrusted XML (e.g., nmap output), it may be vulnerable to XXE.

**Recommendation:** Audit all XML parsing; ensure `defusedxml` wrappers are used everywhere.

---

## 3. Command Injection & Input Validation

### FINDING-14 — CRITICAL: Shell Command Construction Via `extra_args`

**File:** `phantom/tools/security/nmap_tool.py` L112–113  
**File:** `phantom/tools/security/sqlmap_tool.py` L91–92  
**File:** `phantom/tools/security/subfinder_tool.py` L48–49  
```python
if extra_args:
    cmd_parts.extend(shlex.split(extra_args))
```

**Impact:** The `extra_args` parameter in all security tool wrappers directly injects arguments. While `shlex.split()` does word-splitting, it does NOT prevent injection of dangerous flags. An AI agent (or prompt-injection attack) could pass:
- `--os-shell` (sqlmap — OS shell)
- `--file-read /etc/shadow` (sqlmap — file read)
- `-oG /tmp/backdoor.sh` (nmap — write to arbitrary paths)

With passwordless sudo (FINDING-01), the effective power is unrestricted.

**Recommendation:** Implement an allowlist of permitted extra arguments per tool. Block known-dangerous flags like `--os-shell`, `--os-cmd`, `--file-read`, `--file-write`.

---

### FINDING-15 — CRITICAL: `terminal_execute` Accepts Arbitrary Shell Commands

**File:** `phantom/tools/terminal/terminal_actions.py` L11–16  
```python
def terminal_execute(command: str, ...) -> dict[str, Any]:
```

**Impact:** Executes arbitrary shell commands with no filtering. Combined with FINDING-01 (sudo NOPASSWD), the agent has unrestricted root shell access.

**Mitigation context:** Commands run inside the ephemeral sandbox. However, no scope enforcement exists at the tool level.

**Recommendation:** Implement command audit logging with alerting for suspicious patterns. Consider seccomp profiles or restricted shell.

---

### FINDING-16 — HIGH: `run_shell_cmd` in File Operations Without Proper Escaping

**File:** `phantom/tools/file_edit/file_edit_actions.py` L76–79  
```python
cmd = f"find '{path}' -type f -o -type d | head -500" if recursive else f"ls -1a '{path}'"
exit_code, stdout, stderr = run_shell_cmd(cmd)
```

**File:** `phantom/tools/file_edit/file_edit_actions.py` L127–128  
```python
escaped_regex = regex.replace("'", "'\"'\"'")
cmd = f"rg --line-number --glob '{file_pattern}' '{escaped_regex}' '{path}'"
```

**Impact:** Single-quote escaping is insufficient. A path or regex containing certain patterns can break out of the quoting context.

**Recommendation:** Use `shlex.quote()` for all user-supplied values, or use Python-native `pathlib`/`os` operations.

---

### FINDING-17 — MEDIUM: `sqlmap_dump_database` Parameters Not Sanitized

**File:** `phantom/tools/security/sqlmap_tool.py` L131–159  
```python
cmd_parts.extend(["-D", database, "-T", table])
```

**Impact:** `database`, `table`, `columns` parameters appended without `shlex.quote()`. Injection of additional arguments possible.

**Recommendation:** Apply `shlex.quote()` to all user-supplied parameters.

---

## 4. Path Traversal

### FINDING-18 — HIGH: File Edit Tools Accept Arbitrary Paths

**File:** `phantom/tools/file_edit/file_edit_actions.py` L35–38  
```python
path_obj = Path(path)
if not path_obj.is_absolute():
    path = str(Path("/workspace") / path_obj)
```

**Impact:** Absolute paths bypass the `/workspace` prefix entirely. The AI agent can read/write any file: `/etc/passwd`, `/app/certs/ca.key`, `/etc/shadow`.

**Recommendation:** Enforce that `Path(path).resolve()` starts with `/workspace/`. Reject all other paths.

---

### FINDING-19 — MEDIUM: `list_files` and `search_files` Allow Arbitrary Path Access

**File:** `phantom/tools/file_edit/file_edit_actions.py` L68–70, L115–117  
Same pattern as FINDING-18.

**Recommendation:** Same as FINDING-18.

---

## 5. Secrets & Credentials

### FINDING-20 — MEDIUM: API Key Read From Environment Without Validation

**File:** `phantom/tools/web_search/web_search_actions.py` L38–39  
```python
api_key = os.getenv("PERPLEXITY_API_KEY")
```

**Impact:** Key exposed via `/proc/1/environ` inside the container or debug logs.

**Recommendation:** Ensure environment variables with secrets are never logged or included in error messages.

---

### FINDING-21 — MEDIUM: Caido API Token Written to World-Readable System Files

**File:** `containers/docker-entrypoint.sh` L100–125  
```bash
cat << EOF | sudo tee /etc/profile.d/proxy.sh
export CAIDO_API_TOKEN=${TOKEN}
EOF
cat << EOF | sudo tee /etc/environment
CAIDO_API_TOKEN=${TOKEN}
EOF
```

**Impact:** Token readable by any process/user in the container.

**Recommendation:** Write token to `~/.caido_token` with `chmod 600`.

---

### FINDING-22 — LOW: Test Files Contain Hardcoded Test Credentials

**File:** `tests/test_all_modules.py` L121  
```python
logger.log_tool_call("auth", {"password": "secret123", "user": "admin"})
```

**File:** `phantom/interface/main.py` L372–373  
```python
"admin:password123"
```

**Impact:** Low — test/example credentials. But `S106` is suppressed in tests.

**Recommendation:** Use placeholder constants and document them as non-real.

---

## 6. CI/CD Pipeline Security

### FINDING-23 — HIGH: GitHub Actions Uses Mutable Third-Party Actions

**File:** `.github/workflows/build-release.yml` L27–31  
```yaml
- uses: actions/checkout@v4
- uses: snok/install-poetry@v1
- uses: softprops/action-gh-release@v2
```

**Impact:** Major version tags are mutable. A compromised action repository can push malicious code under existing tags.

**Recommendation:** Pin all actions to full SHA256 commit hash.

---

### FINDING-24 — MEDIUM: No Code Signing for Release Binaries

**File:** `.github/workflows/build-release.yml` L51–56  

**Impact:** Users cannot verify binary integrity. A compromised pipeline distributes malicious binaries.

**Recommendation:** Generate SHA256 checksums and consider Sigstore cosign.

---

### FINDING-25 — MEDIUM: `workflow_dispatch` Allows Unrestricted Manual Releases

**File:** `.github/workflows/build-release.yml` L5  
```yaml
workflow_dispatch:
```

**Impact:** Any collaborator with write access can trigger releases of untested code.

**Recommendation:** Add required review/approval for manual dispatch.

---

## 7. Insecure File Operations

### FINDING-26 — MEDIUM: Nuclei Template ID Sanitization Incomplete

**File:** `phantom/tools/finish/finish_actions.py` L183–189  
```python
safe_id = report.get("id", "unknown").replace("/", "_")
```

**Impact:** Only `/` is replaced. Other path-relevant characters are not handled.

**Recommendation:** Use strict allowlist: `re.sub(r'[^a-zA-Z0-9_-]', '_', id)`.

---

### FINDING-27 — LOW: Report Files Written Without Restrictive Permissions

**File:** `phantom/tools/finish/finish_actions.py` L137, L169  
```python
compliance_file.write_text(compliance_md, encoding="utf-8")
```

**Impact:** Files created with default umask (likely `0644`). Security reports may contain sensitive data.

**Recommendation:** `os.chmod(str(file_path), 0o600)` after writing.

---

## 8. Privilege Escalation

### FINDING-28 — HIGH: nmap setcap With Excessive Capabilities

**File:** `containers/Dockerfile` L48  
```dockerfile
RUN setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)
```

**Impact:** `cap_net_admin` on nmap allows network configuration modification. `cap_net_bind_service` is unnecessary.

**Recommendation:** Only grant `cap_net_raw+eip`.

---

### FINDING-29 — MEDIUM: Docker Cleanup Uses Unsanitized Container Name

**File:** `phantom/runtime/docker_runtime.py` L330–335  
```python
subprocess.Popen(["docker", "rm", "-f", container_name], ...)
```

**Impact:** While list-form `Popen` avoids shell injection, a malicious `scan_id` could target arbitrary containers.

**Recommendation:** Validate `container_name` against `^phantom-scan-[a-zA-Z0-9-]+$`.

---

## 9. Application Logic Vulnerabilities

### FINDING-30 — CRITICAL: Python Code Execution Without Restrictions

**File:** `phantom/tools/python/python_actions.py` L32–33  
```python
case "execute":
    return manager.execute_code(session_id, code, timeout)
```

**Impact:** Arbitrary Python code execution with sudo access. No audit trail specific to code content.

**Recommendation:** Log all Python code execution to audit log with full code content.

---

### FINDING-31 — MEDIUM: No Agent Delegation Depth Limit

**File:** `phantom/tools/agents_graph/agents_graph_actions.py` L204–211  

**Impact:** Recursive sub-agent creation could exhaust system resources (denial of service).

**Recommendation:** Implement max delegation depth (e.g., 5 levels).

---

### FINDING-32 — MEDIUM: Short UUID Collision Risk

**File:** `phantom/tools/notes/notes_actions.py` L54 — `uuid.uuid4()[:5]`  
**File:** `phantom/tools/todo/todo_actions.py` L184 — `uuid.uuid4()[:6]`  

**Impact:** Only 1M–16M possible IDs. Birthday-paradox collisions silently overwrite data.

**Recommendation:** Use at least 8 characters or full UUIDs.

---

### FINDING-33 — LOW: `_notes_storage` Has No Thread Safety

**File:** `phantom/tools/notes/notes_actions.py` L10  
```python
_notes_storage: dict[str, dict[str, Any]] = {}
```

**Impact:** No locking, unlike `_todos_storage`. Concurrent access corrupts data.

**Recommendation:** Add `threading.Lock` consistent with to-do pattern.

---

### FINDING-34 — LOW: Broad Exception Catching Masks Errors

**Files:** Multiple (`agents_graph_actions.py`, `finish_actions.py`)  
Pattern: `except Exception as e: # noqa: BLE001`

**Impact:** Security-relevant errors silently swallowed.

**Recommendation:** Narrow exception types. Log at WARNING/ERROR level.

---

## 10. Install Script Security

### FINDING-35 — HIGH: Install Script Downloads Without Integrity Checks

**File:** `scripts/install.sh` L155–156  
```bash
curl -# -L -o "$filename" "$url"
```

**Impact:** No checksum verification. MITM or compromised release delivers malicious binary.

**Recommendation:** Publish and verify SHA256 checksums.

---

### FINDING-36 — LOW: Install Script Variable Case Mismatch (Bug)

**File:** `scripts/install.sh` L299  
```bash
local which_PHANTOM=$(which phantom 2>/dev/null || echo "")
if [[ "$which_phantom" != ...
```

**Impact:** Variable defined as `which_PHANTOM` but referenced as `$which_phantom`. Verification check always compares empty string.

**Recommendation:** Fix casing: use `which_phantom` consistently.

---

## 11. Skills / Prompt Injection Surface

### FINDING-37 — MEDIUM: Skills Loaded From Filesystem Without Integrity Verification

**File:** `phantom/skills/__init__.py` L117–135  
```python
content = full_path.read_text()
skill_content[var_name] = content
```

**Impact:** Skill `.md` files injected directly into LLM prompts. Filesystem write access enables prompt injection.

**Recommendation:** Verify skill file integrity via checksums at startup.

---

### FINDING-38 — INFO: `PHANTOM_DOCKER_MODE` Not Validated Against Actual Docker Environment

**File:** `Dockerfile` L61  
```dockerfile
ENV PHANTOM_DOCKER_MODE=true
```

**Impact:** Minor — can be set manually outside Docker.

**Recommendation:** Check for actual Docker indicators (e.g., `/.dockerenv`).

---

## Summary of Recommendations (Priority Order)

| Priority | Action | Findings |
|----------|--------|----------|
| **P0** | Remove `NOPASSWD:ALL` sudo access in sandbox | F-01 |
| **P0** | Implement argument allowlists for security tool wrappers | F-14 |
| **P0** | Enforce `/workspace` path boundaries in file edit tools | F-18, F-19 |
| **P1** | Pin base Docker images to SHA256 digests | F-04 |
| **P1** | Pin GitHub Actions to commit SHA hashes | F-23 |
| **P1** | Bind tool server to `127.0.0.1` | F-05 |
| **P1** | Verify checksums for downloaded tools/scripts | F-03, F-08, F-35 |
| **P1** | Remove `NET_ADMIN` Docker capability | F-02 |
| **P1** | Re-enable bandit shell injection rules | F-11 |
| **P1** | Remove excessive nmap capabilities | F-28 |
| **P2** | Pin all dependency versions, eliminate `*` specifiers | F-10 |
| **P2** | Pass tokens via files, not env/CLI args | F-06 |
| **P2** | Add agent delegation depth limit | F-31 |
| **P2** | Add thread safety to notes storage | F-33 |
| **P2** | Generate release checksums and sign binaries | F-24 |
| **P2** | Apply `shlex.quote()` to all tool parameters | F-16, F-17 |
| **P2** | Protect CA private key with passphrase | F-07 |
| **P2** | Restrict Caido token file permissions | F-21 |
| **P3** | Fix install script variable casing bug | F-36 |
| **P3** | Add `HEALTHCHECK` to Dockerfiles | F-09 |
| **P3** | Restrict report file permissions | F-27 |
| **P3** | Use longer UUID identifiers | F-32 |

---

*End of Security Audit Report v2*
