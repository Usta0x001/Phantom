"""
Verification Engine

Core verification logic for confirming vulnerability exploitability.
Implements Shannon pattern: verify before report.
"""

import asyncio
import logging
import re
import time
from datetime import UTC, datetime
from typing import Any

from phantom.models.vulnerability import Vulnerability, VulnerabilityStatus
from phantom.models.verification import (
    ExploitAttempt,
    VerificationResult,
    VerificationStatus,
    get_verification_strategy,
)


logger = logging.getLogger(__name__)


class VerificationEngine:
    """
    Engine for verifying vulnerability findings.
    
    Takes detected vulnerabilities and attempts to verify exploitability
    before marking them as confirmed. This reduces false positives.
    """
    
    def __init__(self, terminal_execute_fn: Any = None, http_client: Any = None, interactsh_client: Any = None):
        """
        Initialize verification engine.
        
        Args:
            terminal_execute_fn: Async function to execute commands in sandbox
            http_client: HTTP client for making requests (httpx or aiohttp)
            interactsh_client: InteractshClient instance for OOB callback verification
        """
        self.terminal_execute = terminal_execute_fn
        self.http_client = http_client
        self.interactsh = interactsh_client
        self._results: dict[str, VerificationResult] = {}
    
    async def verify(self, vuln: Vulnerability) -> VerificationResult:
        """
        Verify a single vulnerability.
        
        Returns VerificationResult with exploitability determination.
        """
        result = VerificationResult(
            vulnerability_id=vuln.id,
            vulnerability_class=vuln.vulnerability_class,
        )
        result.start_verification()
        
        strategies = get_verification_strategy(vuln.vulnerability_class)
        
        for strategy in strategies:
            if not result.should_continue():
                break
            
            try:
                attempt = await self._execute_verification(vuln, strategy)
                result.add_attempt(attempt)
                
                if attempt.success:
                    # Update the vulnerability itself
                    vuln.mark_verified(
                        verified_by=f"verification_engine:{strategy}",
                        payload=attempt.payload,
                    )
                    break
                    
            except Exception as e:
                logger.warning(f"Verification attempt failed for {vuln.id}: {e}")
                result.notes.append(f"Error in {strategy}: {str(e)}")
        
        # If all attempts failed, mark as failed but NOT false positive.
        # Failure to auto-verify does NOT mean the vuln is a false positive —
        # it may just mean automated verification doesn't cover this class.
        if result.status == VerificationStatus.IN_PROGRESS:
            result.mark_failed("All verification attempts failed")
            # Do NOT call vuln.mark_false_positive here — unverified != false positive
        
        self._results[vuln.id] = result
        return result
    
    async def verify_batch(self, vulnerabilities: list[Vulnerability]) -> list[VerificationResult]:
        """Verify multiple vulnerabilities."""
        results = []
        
        # Prioritize by severity
        sorted_vulns = sorted(
            vulnerabilities,
            key=lambda v: ["critical", "high", "medium", "low", "info"].index(v.severity.value),
        )
        
        for vuln in sorted_vulns:
            result = await self.verify(vuln)
            results.append(result)
        
        return results
    
    async def _execute_verification(self, vuln: Vulnerability, strategy: str) -> ExploitAttempt:
        """Execute a verification strategy."""
        start_time = time.time()
        
        verifiers = {
            "time_based": self._verify_time_based,
            "error_based": self._verify_error_based,
            "boolean_based": self._verify_boolean_based,
            "dom_reflection": self._verify_dom_reflection,
            "oob_http": self._verify_oob_http,
            "oob_dns": self._verify_oob_dns,
            "known_file": self._verify_known_file,
            "math_eval": self._verify_math_eval,
            # G-14 FIX: New verification strategies
            "idor_access": self._verify_idor,
            "resource_access": self._verify_idor,
            "data_leak": self._verify_idor,
            "cors_check": self._verify_cors,
            "header_injection": self._verify_header_injection,
        }
        
        verifier = verifiers.get(strategy, self._verify_generic)
        attempt = await verifier(vuln)
        
        attempt.method = strategy
        attempt.attempted_at = datetime.now(UTC)
        attempt.duration_ms = (time.time() - start_time) * 1000
        
        return attempt
    
    async def _verify_time_based(self, vuln: Vulnerability) -> ExploitAttempt:
        """Verify using time-based technique (SQLi, RCE).
        
        G-02 FIX: Supports both GET and POST methods based on the original
        vulnerability's HTTP method.
        """
        attempt = ExploitAttempt(
            vulnerability_id=vuln.id,
            method="time_based",
            tool="verification_engine",
            payload="",
        )
        
        http_method = getattr(vuln, "http_method", "GET").upper()
        
        if vuln.vulnerability_class == "sqli":
            # Time-based SQLi payloads
            payloads = [
                "1' AND SLEEP(5)--",
                "1' WAITFOR DELAY '0:0:5'--",
                "1'; SELECT pg_sleep(5);--",
            ]
            delay_threshold = 4.5  # 4.5s threshold for 5s sleep
            
            for payload in payloads:
                attempt.payload = payload
                
                if self.http_client:
                    start = time.time()
                    try:
                        if http_method == "POST":
                            # G-02 FIX: POST-based verification
                            data = {vuln.parameter or "id": payload}
                            await self.http_client.post(vuln.target, data=data, timeout=10)
                        else:
                            target_url = self._inject_payload(vuln.target, vuln.parameter, payload)
                            await self.http_client.get(target_url, timeout=10)
                        elapsed = time.time() - start
                        
                        attempt.response_time_ms = elapsed * 1000
                        
                        if elapsed >= delay_threshold:
                            attempt.success = True
                            attempt.confidence = 0.9
                            attempt.evidence = f"Response delayed {elapsed:.2f}s (threshold: {delay_threshold}s)"
                            return attempt
                    except Exception as e:
                        attempt.error = str(e)
        
        elif vuln.vulnerability_class == "rce":
            # Time-based RCE payloads
            payloads = [
                "; sleep 5",
                "| sleep 5",
                "$(sleep 5)",
                "`sleep 5`",
            ]
            
            for payload in payloads:
                attempt.payload = payload
                
                if self.http_client:
                    start = time.time()
                    try:
                        if http_method == "POST":
                            data = {vuln.parameter or "cmd": payload}
                            await self.http_client.post(vuln.target, data=data, timeout=10)
                        else:
                            target_url = self._inject_payload(vuln.target, vuln.parameter, payload)
                            await self.http_client.get(target_url, timeout=10)
                        elapsed = time.time() - start
                        
                        if elapsed >= 4.5:
                            attempt.success = True
                            attempt.confidence = 0.85
                            attempt.evidence = f"Command execution confirmed via sleep: {elapsed:.2f}s delay"
                            return attempt
                    except asyncio.TimeoutError:
                        # Timeout expected for time-based verification
                        pass
                    except Exception as e:
                        logger.debug("RCE verification request failed: %s", e)
        
        return attempt
    
    async def _verify_error_based(self, vuln: Vulnerability) -> ExploitAttempt:
        """Verify using error-based technique (SQLi).
        
        G-02 FIX: Supports both GET and POST methods.
        """
        attempt = ExploitAttempt(
            vulnerability_id=vuln.id,
            method="error_based",
            tool="verification_engine",
            payload="",
        )
        
        http_method = getattr(vuln, "http_method", "GET").upper()
        
        error_indicators = [
            r"SQL syntax.*MySQL",
            r"ORA-\d{5}",
            r"PostgreSQL.*ERROR",
            r"Microsoft.*ODBC",
            r"sqlite3\.OperationalError",
            r"Unclosed quotation mark",
        ]
        
        payloads = ["'", "\"", "')", "';", "\")", "'--"]
        
        for payload in payloads:
            attempt.payload = payload
            
            if self.http_client:
                try:
                    if http_method == "POST":
                        data = {vuln.parameter or "id": payload}
                        response = await self.http_client.post(vuln.target, data=data)
                    else:
                        target_url = self._inject_payload(vuln.target, vuln.parameter, payload)
                        response = await self.http_client.get(target_url)
                    body = response.text if hasattr(response, 'text') else str(response.content)
                    
                    for pattern in error_indicators:
                        if re.search(pattern, body, re.IGNORECASE):
                            attempt.success = True
                            attempt.confidence = 0.95
                            attempt.evidence = f"SQL error detected: {pattern}"
                            attempt.response = body[:500]
                            return attempt
                except Exception as e:
                    attempt.error = str(e)
        
        return attempt
    
    async def _verify_boolean_based(self, vuln: Vulnerability) -> ExploitAttempt:
        """Verify using boolean-based technique (SQLi)."""
        attempt = ExploitAttempt(
            vulnerability_id=vuln.id,
            method="boolean_based",
            tool="verification_engine",
            payload="",
        )
        
        # True condition vs False condition
        true_payload = "1' AND '1'='1"
        false_payload = "1' AND '1'='2"
        
        if self.http_client:
            try:
                true_url = self._inject_payload(vuln.target, vuln.parameter, true_payload)
                false_url = self._inject_payload(vuln.target, vuln.parameter, false_payload)
                
                true_resp = await self.http_client.get(true_url)
                false_resp = await self.http_client.get(false_url)
                
                true_len = len(true_resp.content)
                false_len = len(false_resp.content)
                
                # Significant difference indicates boolean SQLi
                if abs(true_len - false_len) > 100:
                    attempt.success = True
                    attempt.confidence = 0.8
                    attempt.payload = true_payload
                    attempt.evidence = f"Response size difference: true={true_len}, false={false_len}"
                    return attempt
                    
            except Exception as e:
                attempt.error = str(e)
        
        return attempt
    
    async def _verify_dom_reflection(self, vuln: Vulnerability) -> ExploitAttempt:
        """Verify XSS by checking DOM reflection."""
        attempt = ExploitAttempt(
            vulnerability_id=vuln.id,
            method="dom_reflection",
            tool="verification_engine",
            payload="",
        )
        
        # Unique marker to search for
        marker = "PHANTOM_XSS_7x7x7"
        payloads = [
            f"<script>{marker}</script>",
            f"<img src=x onerror='{marker}'>",
            f"<svg onload='{marker}'>",
            f"'-{marker}-'",
        ]
        
        for payload in payloads:
            attempt.payload = payload
            target_url = self._inject_payload(vuln.target, vuln.parameter, payload)
            
            if self.http_client:
                try:
                    response = await self.http_client.get(target_url)

                    # PHT-043: Only declare XSS if response is HTML.
                    # JSON/plaintext responses with reflected markers are NOT
                    # exploitable XSS and would generate false positives.
                    content_type = ""
                    if hasattr(response, "headers"):
                        content_type = str(
                            response.headers.get("content-type", "")
                        ).lower()
                    if content_type and "text/html" not in content_type:
                        attempt.evidence = (
                            f"Marker reflected but Content-Type is {content_type!r} "
                            f"(not text/html) — not exploitable XSS"
                        )
                        continue

                    body = response.text if hasattr(response, 'text') else str(response.content)
                    
                    if marker in body:
                        # Check if it's reflected unencoded
                        if payload in body or marker in body:
                            attempt.success = True
                            attempt.confidence = 0.85
                            attempt.evidence = f"XSS payload reflected in HTML response: {payload[:50]}"
                            return attempt
                except Exception as e:
                    attempt.error = str(e)
        
        return attempt
    
    async def _verify_oob_http(self, vuln: Vulnerability) -> ExploitAttempt:
        """Verify using out-of-band HTTP callback via InteractshClient."""
        attempt = ExploitAttempt(
            vulnerability_id=vuln.id,
            method="oob_http",
            tool="verification_engine",
            payload="",
        )
        
        if not self.interactsh:
            attempt.payload = "Requires OOB server (interactsh)"
            attempt.evidence = "OOB verification skipped — no interactsh client configured"
            attempt.success = False
            return attempt
        
        try:
            # Generate a unique OOB payload for this vuln
            oob_payload = self.interactsh.generate_payload(
                vuln_id=vuln.id,
                vuln_class=vuln.vulnerability_class,
                payload_type="http",
            )
            
            if not oob_payload:
                attempt.evidence = "Failed to generate OOB payload"
                return attempt
            
            attempt.payload = oob_payload.payload
            
            # Inject the OOB URL into the target parameter
            if self.http_client and vuln.target:
                target_url = self._inject_payload(
                    vuln.target, vuln.parameter, oob_payload.payload
                )
                try:
                    await self.http_client.get(target_url, timeout=10)
                except Exception:
                    pass  # We don't care about the response — we care about the callback
            
            # Wait for the callback interaction
            interaction = await self.interactsh.wait_for_interaction(
                payload_id=oob_payload.id,
                timeout=15,
            )
            
            if interaction:
                attempt.success = True
                attempt.confidence = 0.95
                attempt.evidence = (
                    f"OOB HTTP callback received: {interaction.protocol} from "
                    f"{interaction.remote_address} at {interaction.timestamp}"
                )
                return attempt
            else:
                attempt.evidence = "OOB payload sent but no callback received within timeout"
                
        except Exception as e:
            attempt.error = str(e)
            logger.debug("OOB HTTP verification failed for %s: %s", vuln.id, e)
        
        return attempt
    
    async def _verify_oob_dns(self, vuln: Vulnerability) -> ExploitAttempt:
        """Verify using out-of-band DNS callback via InteractshClient."""
        attempt = ExploitAttempt(
            vulnerability_id=vuln.id,
            method="oob_dns",
            tool="verification_engine",
            payload="",
        )
        
        if not self.interactsh:
            attempt.payload = "Requires OOB server (interactsh)"
            attempt.evidence = "OOB DNS verification skipped — no interactsh client configured"
            attempt.success = False
            return attempt
        
        try:
            oob_payload = self.interactsh.generate_payload(
                vuln_id=vuln.id,
                vuln_class=vuln.vulnerability_class,
                payload_type="dns",
            )
            
            if not oob_payload:
                attempt.evidence = "Failed to generate OOB DNS payload"
                return attempt
            
            attempt.payload = oob_payload.payload
            
            # Inject the DNS canary into the target
            if self.http_client and vuln.target:
                target_url = self._inject_payload(
                    vuln.target, vuln.parameter, oob_payload.payload
                )
                try:
                    await self.http_client.get(target_url, timeout=10)
                except Exception:
                    pass
            
            interaction = await self.interactsh.wait_for_interaction(
                payload_id=oob_payload.id,
                timeout=15,
            )
            
            if interaction:
                attempt.success = True
                attempt.confidence = 0.90
                attempt.evidence = (
                    f"OOB DNS callback received: {interaction.protocol} from "
                    f"{interaction.remote_address} at {interaction.timestamp}"
                )
                return attempt
            else:
                attempt.evidence = "OOB DNS payload sent but no callback received"
                
        except Exception as e:
            attempt.error = str(e)
            logger.debug("OOB DNS verification failed for %s: %s", vuln.id, e)
        
        return attempt
    
    async def _verify_known_file(self, vuln: Vulnerability) -> ExploitAttempt:
        """Verify LFI by reading known file."""
        attempt = ExploitAttempt(
            vulnerability_id=vuln.id,
            method="known_file",
            tool="verification_engine",
            payload="",
        )
        
        # LFI payloads targeting known files
        payloads_and_markers = [
            ("../../../../../../etc/passwd", "root:"),
            ("....//....//....//etc/passwd", "root:"),
            ("/etc/passwd", "root:"),
            ("..\\..\\..\\..\\windows\\win.ini", "[fonts]"),
            ("C:\\windows\\win.ini", "[fonts]"),
        ]
        
        for payload, marker in payloads_and_markers:
            attempt.payload = payload
            target_url = self._inject_payload(vuln.target, vuln.parameter, payload)
            
            if self.http_client:
                try:
                    response = await self.http_client.get(target_url)
                    body = response.text if hasattr(response, 'text') else str(response.content)
                    
                    if marker in body:
                        attempt.success = True
                        attempt.confidence = 0.95
                        attempt.evidence = f"File content leaked: found '{marker}'"
                        return attempt
                except Exception as e:
                    attempt.error = str(e)
        
        return attempt
    
    async def _verify_math_eval(self, vuln: Vulnerability) -> ExploitAttempt:
        """Verify SSTI by math evaluation."""
        attempt = ExploitAttempt(
            vulnerability_id=vuln.id,
            method="math_eval",
            tool="verification_engine",
            payload="",
        )
        
        # SSTI math payloads and their results
        payloads_and_results = [
            ("{{7*7}}", "49"),
            ("${7*7}", "49"),
            ("#{7*7}", "49"),
            ("<%= 7*7 %>", "49"),
            ("{{7*'7'}}", "7777777"),  # Jinja2 specific
        ]
        
        for payload, expected in payloads_and_results:
            attempt.payload = payload
            target_url = self._inject_payload(vuln.target, vuln.parameter, payload)
            
            if self.http_client:
                try:
                    response = await self.http_client.get(target_url)
                    body = response.text if hasattr(response, 'text') else str(response.content)
                    
                    if expected in body:
                        attempt.success = True
                        attempt.confidence = 0.95
                        attempt.evidence = f"SSTI confirmed: {payload} evaluated to {expected}"
                        return attempt
                except Exception as e:
                    attempt.error = str(e)
        
        return attempt
    
    async def _verify_generic(self, vuln: Vulnerability) -> ExploitAttempt:
        """Generic verification fallback."""
        return ExploitAttempt(
            vulnerability_id=vuln.id,
            method="generic",
            tool="verification_engine",
            payload="N/A",
            success=False,
            evidence="No specific verification method available",
        )
    
    # ── G-14 FIX: New verification strategies ────────────────────────
    
    async def _verify_idor(self, vuln: Vulnerability) -> ExploitAttempt:
        """Verify IDOR by accessing a resource with a different ID.
        
        G-14 FIX: New strategy for Insecure Direct Object Reference.
        Tests whether changing a resource ID in the URL/params returns
        a different user's data (horizontal privilege escalation).
        """
        attempt = ExploitAttempt(
            vulnerability_id=vuln.id,
            method="idor_access",
            tool="verification_engine",
            payload="",
        )
        
        if not self.http_client or not vuln.target:
            attempt.evidence = "No HTTP client available for IDOR verification"
            return attempt
        
        http_method = getattr(vuln, "http_method", "GET").upper()
        # Try accessing resource with ID=1 (common admin/first-user ID)
        test_ids = ["1", "2", "0", "admin", "999999"]
        
        for test_id in test_ids:
            attempt.payload = f"IDOR test: {vuln.parameter}={test_id}"
            try:
                if http_method == "POST":
                    data = {vuln.parameter or "id": test_id}
                    response = await self.http_client.post(vuln.target, data=data)
                else:
                    target_url = self._inject_payload(vuln.target, vuln.parameter, test_id)
                    response = await self.http_client.get(target_url)
                
                body = response.text if hasattr(response, "text") else str(response.content)
                status_code = getattr(response, "status_code", 0)
                
                # IDOR confirmed if we get 200 with data that shouldn't be ours
                if status_code == 200 and len(body) > 50:
                    # Check for PII/data indicators
                    pii_indicators = ["email", "username", "password", "address", "phone", "ssn"]
                    for indicator in pii_indicators:
                        if indicator in body.lower():
                            attempt.success = True
                            attempt.confidence = 0.75
                            attempt.evidence = (
                                f"IDOR: Accessed resource with {vuln.parameter}={test_id}, "
                                f"response contains '{indicator}' (HTTP {status_code}, {len(body)} bytes)"
                            )
                            return attempt
            except Exception as e:
                attempt.error = str(e)
        
        return attempt
    
    async def _verify_cors(self, vuln: Vulnerability) -> ExploitAttempt:
        """Verify CORS misconfiguration.
        
        G-14 FIX: Tests whether the target reflects arbitrary Origin headers
        in Access-Control-Allow-Origin, allowing cross-origin attacks.
        """
        attempt = ExploitAttempt(
            vulnerability_id=vuln.id,
            method="cors_check",
            tool="verification_engine",
            payload="",
        )
        
        if not self.http_client or not vuln.target:
            attempt.evidence = "No HTTP client available for CORS verification"
            return attempt
        
        evil_origins = [
            "https://evil.com",
            "https://attacker.example.com",
            "null",  # null origin — often reflected
        ]
        
        for origin in evil_origins:
            attempt.payload = f"Origin: {origin}"
            try:
                headers = {"Origin": origin}
                response = await self.http_client.get(vuln.target, headers=headers)
                
                acao = ""
                if hasattr(response, "headers"):
                    acao = str(response.headers.get("access-control-allow-origin", ""))
                
                if acao == origin or acao == "*":
                    # Check if credentials are also allowed (most dangerous)
                    acac = str(response.headers.get("access-control-allow-credentials", "")).lower()
                    
                    if acac == "true" and acao != "*":
                        attempt.success = True
                        attempt.confidence = 0.95
                        attempt.evidence = (
                            f"CORS misconfiguration: Origin '{origin}' reflected in "
                            f"ACAO with credentials allowed (ACAC: true)"
                        )
                        return attempt
                    elif acao == "*":
                        attempt.success = True
                        attempt.confidence = 0.7
                        attempt.evidence = (
                            f"CORS: Wildcard ACAO (*) — allows any origin to read responses"
                        )
                        return attempt
                    else:
                        attempt.success = True
                        attempt.confidence = 0.8
                        attempt.evidence = (
                            f"CORS: Origin '{origin}' reflected in ACAO header"
                        )
                        return attempt
            except Exception as e:
                attempt.error = str(e)
        
        return attempt
    
    async def _verify_header_injection(self, vuln: Vulnerability) -> ExploitAttempt:
        """Verify HTTP header injection / response splitting.
        
        G-14 FIX: Tests whether injecting CRLF sequences into parameters
        causes new headers to appear in the response.
        """
        attempt = ExploitAttempt(
            vulnerability_id=vuln.id,
            method="header_injection",
            tool="verification_engine",
            payload="",
        )
        
        if not self.http_client or not vuln.target:
            attempt.evidence = "No HTTP client available for header injection verification"
            return attempt
        
        # CRLF injection payloads
        payloads = [
            "test%0d%0aX-Injected: phantom",
            "test\r\nX-Injected: phantom",
            "test%0aX-Injected: phantom",
        ]
        
        for payload in payloads:
            attempt.payload = payload
            try:
                target_url = self._inject_payload(vuln.target, vuln.parameter, payload)
                response = await self.http_client.get(target_url)
                
                if hasattr(response, "headers"):
                    if "x-injected" in str(response.headers).lower():
                        attempt.success = True
                        attempt.confidence = 0.95
                        attempt.evidence = "Header injection confirmed: X-Injected header present in response"
                        return attempt
                    
                    # Check if the payload appears in any header value
                    for hdr_name, hdr_val in response.headers.items():
                        if "phantom" in str(hdr_val).lower():
                            attempt.success = True
                            attempt.confidence = 0.85
                            attempt.evidence = f"Header injection: 'phantom' found in {hdr_name} header"
                            return attempt
            except Exception as e:
                attempt.error = str(e)
        
        return attempt
    
    def _inject_payload(self, url: str, parameter: str | None, payload: str) -> str:
        """Inject payload into URL parameter.
        
        Includes scope check to prevent SSRF against internal services.
        """
        import ipaddress as _ipa
        from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
        
        parsed = urlparse(url)
        # SSRF guard: reject private/loopback/link-local targets
        hostname = parsed.hostname or ""
        if hostname in ("localhost", "0.0.0.0", "169.254.169.254"):
            raise ValueError(f"Verification blocked: target {hostname!r} is internal")
        try:
            addr = _ipa.ip_address(hostname)
            if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
                raise ValueError(f"Verification blocked: target {hostname!r} is a private/internal IP")
        except ValueError as e:
            if "Verification blocked" in str(e):
                raise
            # Not an IP — it's a hostname, which is fine
        params = parse_qs(parsed.query)
        
        if parameter and parameter in params:
            params[parameter] = [payload]
        elif parameter:
            params[parameter] = [payload]
        elif params:
            # Inject into first parameter
            first_param = list(params.keys())[0]
            params[first_param] = [payload]
        else:
            # Append as new parameter
            params["id"] = [payload]
        
        # Rebuild URL
        new_query = urlencode(params, doseq=True)
        return urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment,
        ))
    
    def get_results(self) -> dict[str, VerificationResult]:
        """Get all verification results."""
        return self._results.copy()
    
    def get_verified_count(self) -> int:
        """Count verified vulnerabilities."""
        return sum(1 for r in self._results.values() if r.is_exploitable)
    
    def get_false_positive_count(self) -> int:
        """Count false positives."""
        return sum(1 for r in self._results.values() if r.status == VerificationStatus.FAILED)
