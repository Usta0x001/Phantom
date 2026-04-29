"""
Detection Module - P2.4

Provides tools for detecting and confirming vulnerabilities through:
- Pattern-based detection (response analysis)
- Behavioral detection (timing, differential analysis)
- OAST integration for blind vulnerability detection
- Error-based detection
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Any, Literal

DetectionType = Literal[
    "pattern",  # String/regex pattern in response
    "error",    # Error message detection
    "timing",   # Time-based blind detection
    "oast",     # Out-of-band detection via OAST
    "behavior", # Behavioral differences
]


@dataclass
class DetectionResult:
    """Result from a vulnerability detection check."""
    
    detected: bool
    confidence: float  # 0.0 - 1.0
    detection_type: DetectionType
    evidence: list[str]
    details: dict[str, Any]
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "detected": self.detected,
            "confidence": self.confidence,
            "detection_type": self.detection_type,
            "evidence": self.evidence,
            "details": self.details,
        }


class VulnerabilityDetector:
    """
    Detects and confirms vulnerabilities using various detection techniques.
    """

    # Common SQL error patterns
    SQL_ERROR_PATTERNS = [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_.*",
        r"valid MySQL result",
        r"MySqlClient\.",
        r"PostgreSQL.*ERROR",
        r"Warning.*\Wpg_.*",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"PG::SyntaxError:",
        r"org\.postgresql\.util\.PSQLException",
        r"ERROR:\s+syntax error at or near",
        r"Microsoft SQL.*Driver",
        r"SQLServer JDBC Driver",
        r"com\.microsoft\.sqlserver\.jdbc",
        r"ORA-\d{5}",
        r"Oracle error",
        r"Oracle.*Driver",
        r"SQLite/JDBCDriver",
        r"SQLite\.Exception",
        r"System\.Data\.SQLite\.SQLiteException",
    ]

    # Common XSS confirmation patterns
    # FIX M4: Made more specific to avoid false positives on legitimate pages.
    # The old <script>.*</script> matched every modern website.
    XSS_PATTERNS = [
        # Reflected script tags in response (not just any script)
        r"<script[^>]*>\s*alert\s*\(",
        r"<script[^>]*>\s*document\.cookie",
        r"<script[^>]*>\s*eval\s*\(",
        r"<script[^>]*>\s*location\.",
        # Event handlers with suspicious payloads
        r"on\w+\s*=\s*['\"]?\s*javascript:",
        r"on\w+\s*=\s*['\"]?\s*alert\s*\(",
        r"on\w+\s*=\s*['\"]?\s*eval\s*\(",
        # JavaScript protocol in URLs
        r"javascript:\s*alert\s*\(",
        r"javascript:\s*eval\s*\(",
        # Common XSS vectors
        r"<img[^>]+onerror\s*=\s*['\"]?\s*alert\s*\(",
        r"<svg[^>]+onload\s*=\s*['\"]?\s*alert\s*\(",
    ]

    # Command injection patterns
    CMD_INJECTION_PATTERNS = [
        r"root:.*:0:0:",  # /etc/passwd
        r"uid=\d+\(.*?\)\s+gid=\d+",  # id output
        r"total \d+.*drwx",  # ls -la output
        r"Windows.*Volume Serial Number",  # dir output
        r"PING.*\d+ bytes of data",  # ping output
    ]

    # Path traversal patterns
    PATH_TRAVERSAL_PATTERNS = [
        r"\[boot loader\]",  # boot.ini
        r"root:.*:0:0:",  # /etc/passwd
        r"\[extensions\]",  # win.ini
        r"for 16-bit app support",
    ]

    # SSRF patterns
    SSRF_PATTERNS = [
        r"metadata\.google\.internal",
        r"169\.254\.169\.254",
        r"AWS_ACCESS_KEY_ID",
        r"AWS_SECRET_ACCESS_KEY",
    ]

    def __init__(self) -> None:
        """Initialize the detector."""
        pass

    def detect_pattern(
        self,
        response_body: str,
        patterns: list[str] | None = None,
        vuln_class: str | None = None,
        case_sensitive: bool = False,
    ) -> DetectionResult:
        """
        Detect vulnerability based on response patterns.
        
        Args:
            response_body: HTTP response body to analyze
            patterns: Custom patterns to search for (overrides vuln_class)
            vuln_class: Vulnerability class to use built-in patterns
            case_sensitive: Whether pattern matching is case-sensitive
            
        Returns:
            DetectionResult
        """
        # Get patterns
        if patterns:
            search_patterns = patterns
        elif vuln_class:
            search_patterns = self._get_patterns_for_vuln_class(vuln_class)
        else:
            return DetectionResult(
                detected=False,
                confidence=0.0,
                detection_type="pattern",
                evidence=[],
                details={"error": "No patterns or vuln_class specified"},
            )

        # Search for patterns
        evidence = []
        flags = 0 if case_sensitive else re.IGNORECASE
        
        for pattern in search_patterns:
            matches = re.findall(pattern, response_body, flags=flags)
            if matches:
                # Limit evidence to prevent token bloat
                for match in matches[:3]:
                    if isinstance(match, tuple):
                        match = match[0]
                    evidence.append(f"Pattern '{pattern}' matched: {match[:200]}")

        detected = len(evidence) > 0
        confidence = min(len(evidence) * 0.3, 1.0)  # More matches = higher confidence
        
        return DetectionResult(
            detected=detected,
            confidence=confidence,
            detection_type="pattern",
            evidence=evidence,
            details={
                "patterns_searched": len(search_patterns),
                "patterns_matched": len(evidence),
                "vuln_class": vuln_class or "unknown",
                "surface": response_body[:500] if detected else "",
            },
        )

    def detect_error_based(
        self,
        response_body: str,
        vuln_class: str,
    ) -> DetectionResult:
        """
        Detect vulnerability based on error messages.
        
        Args:
            response_body: HTTP response body
            vuln_class: Vulnerability class (sqli, xxe, etc.)
            
        Returns:
            DetectionResult
        """
        patterns = self._get_error_patterns_for_vuln_class(vuln_class)
        
        evidence = []
        for pattern in patterns:
            matches = re.finditer(pattern, response_body, re.IGNORECASE)
            for match in matches:
                error_snippet = match.group(0)[:200]
                evidence.append(f"Error detected: {error_snippet}")
                if len(evidence) >= 5:  # Limit evidence
                    break
            if len(evidence) >= 5:
                break

        detected = len(evidence) > 0
        # Error-based detection is high confidence
        confidence = 0.9 if detected else 0.0
        
        return DetectionResult(
            detected=detected,
            confidence=confidence,
            detection_type="error",
            evidence=evidence,
            details={
                "vuln_class": vuln_class,
                "error_patterns_searched": len(patterns),
                "surface": response_body[:500] if detected else "",
            },
        )

    def detect_timing_based(
        self,
        baseline_time: float,
        test_time: float,
        delay_expected: float = 5.0,
        tolerance: float = 2.0,
    ) -> DetectionResult:
        """
        Detect blind vulnerabilities using timing analysis.
        
        Args:
            baseline_time: Response time for normal request (seconds)
            test_time: Response time for payload request (seconds)
            delay_expected: Expected delay from payload (seconds)
            tolerance: Acceptable deviation (seconds)
            
        Returns:
            DetectionResult
        """
        time_diff = test_time - baseline_time
        
        # Check if delay matches expected (within tolerance)
        delay_matches = abs(time_diff - delay_expected) <= tolerance
        
        detected = delay_matches and time_diff >= (delay_expected - tolerance)
        
        # Confidence based on how close the delay is to expected
        if detected:
            deviation = abs(time_diff - delay_expected)
            confidence = max(0.5, 1.0 - (deviation / delay_expected))
        else:
            confidence = 0.0

        evidence = [
            f"Baseline response time: {baseline_time:.2f}s",
            f"Payload response time: {test_time:.2f}s",
            f"Time difference: {time_diff:.2f}s",
            f"Expected delay: {delay_expected:.2f}s",
        ]

        return DetectionResult(
            detected=detected,
            confidence=confidence,
            detection_type="timing",
            evidence=evidence,
            details={
                "baseline_time": baseline_time,
                "test_time": test_time,
                "time_diff": time_diff,
                "delay_expected": delay_expected,
                "tolerance": tolerance,
            },
        )

    def detect_differential(
        self,
        baseline_response: dict[str, Any],
        test_response: dict[str, Any],
        vuln_class: str,
    ) -> DetectionResult:
        """
        Detect vulnerabilities through differential analysis.
        
        Compares responses to identify behavioral differences that indicate
        vulnerability (e.g., boolean-based blind SQLi).
        
        Args:
            baseline_response: Response dict (status, body, headers)
            test_response: Response dict for payload
            vuln_class: Vulnerability class
            
        Returns:
            DetectionResult
        """
        evidence = []
        score = 0.0

        baseline_status = baseline_response.get("status_code", 0)
        test_status = test_response.get("status_code", 0)
        baseline_body = baseline_response.get("body", "")
        test_body = test_response.get("body", "")

        # Status code differences
        if baseline_status != test_status:
            evidence.append(
                f"Status code changed: {baseline_status} → {test_status}"
            )
            score += 0.3

        # Content length differences
        baseline_len = len(baseline_body)
        test_len = len(test_body)
        len_diff = abs(baseline_len - test_len)
        len_ratio = len_diff / max(baseline_len, 1)
        
        if len_ratio > 0.1:  # >10% difference
            evidence.append(
                f"Response length changed significantly: {baseline_len} → {test_len} ({len_ratio:.1%})"
            )
            score += min(len_ratio, 0.5)

        # For SQL injection: check for boolean-based patterns
        if vuln_class == "sqli":
            # True vs False conditions should produce different responses
            if len_diff > 50 or baseline_status != test_status:
                evidence.append("Boolean-based blind SQLi indicator detected")
                score += 0.4

        detected = score > 0.3
        confidence = min(score, 1.0)

        return DetectionResult(
            detected=detected,
            confidence=confidence,
            detection_type="behavior",
            evidence=evidence,
            details={
                "vuln_class": vuln_class,
                "baseline_status": baseline_status,
                "test_status": test_status,
                "baseline_length": baseline_len,
                "test_length": test_len,
                "length_diff_ratio": len_ratio,
                "surface": test_body[:500] if detected else "",
            },
        )

    def _get_patterns_for_vuln_class(self, vuln_class: str) -> list[str]:
        """Get detection patterns for a vulnerability class."""
        patterns_map = {
            "sqli": self.SQL_ERROR_PATTERNS,
            "xss": self.XSS_PATTERNS,
            "cmd_injection": self.CMD_INJECTION_PATTERNS,
            "rce": self.CMD_INJECTION_PATTERNS,
            "lfi": self.PATH_TRAVERSAL_PATTERNS,
            "path_traversal": self.PATH_TRAVERSAL_PATTERNS,
            "ssrf": self.SSRF_PATTERNS,
        }
        return patterns_map.get(vuln_class, [])

    def _get_error_patterns_for_vuln_class(self, vuln_class: str) -> list[str]:
        """Get error patterns for a vulnerability class."""
        if vuln_class == "sqli":
            return self.SQL_ERROR_PATTERNS
        return []


# Global detector instance (stateless, so safe to share)
_detector = VulnerabilityDetector()


# FIX 6: Import register_tool for LLM accessibility
from phantom.tools.registry import register_tool


@register_tool(sandbox_execution=False)
def detect_pattern(
    response_body: str,
    patterns: list[str] | None = None,
    vuln_class: str | None = None,
    case_sensitive: bool = False,
) -> dict[str, Any]:
    """
    Detect vulnerability based on response patterns.
    
    Use this to analyze HTTP response bodies for vulnerability indicators.
    Supports both custom regex patterns and built-in patterns for common vuln classes.
    
    Args:
        response_body: HTTP response body to analyze
        patterns: Custom regex patterns to search for (optional)
        vuln_class: Use built-in patterns for this vuln class: sqli, xss, cmd_injection, lfi, ssrf
        case_sensitive: Whether pattern matching is case-sensitive (default: False)
        
    Returns:
        Detection result with:
        - detected: Boolean indicating if vulnerability was detected
        - confidence: Float 0.0-1.0 confidence level
        - detection_type: "pattern"
        - evidence: List of matched patterns
        
    Example:
        detect_pattern(
            response_body="Error: You have an error in your SQL syntax near...",
            vuln_class="sqli"
        )
    """
    result = _detector.detect_pattern(
        response_body=response_body,
        patterns=patterns,
        vuln_class=vuln_class,
        case_sensitive=case_sensitive,
    )
    return result.to_dict()


@register_tool(sandbox_execution=False)
def detect_error_based(
    response_body: str,
    vuln_class: str,
) -> dict[str, Any]:
    """
    Detect vulnerability based on error messages in response.
    
    Specialized for detecting database errors, stack traces, and other
    error-based vulnerability indicators. High confidence detection.
    
    Args:
        response_body: HTTP response body to analyze
        vuln_class: Vulnerability class to detect errors for (sqli recommended)
        
    Returns:
        Detection result with:
        - detected: Boolean indicating if vulnerability was detected
        - confidence: Float 0.0-1.0 (error-based is typically 0.9 when detected)
        - detection_type: "error"
        - evidence: List of error messages found
        
    Example:
        detect_error_based(
            response_body="MySQL error: Unknown column 'test' in 'where clause'",
            vuln_class="sqli"
        )
    """
    result = _detector.detect_error_based(
        response_body=response_body,
        vuln_class=vuln_class,
    )
    return result.to_dict()


@register_tool(sandbox_execution=False)
def detect_timing_based(
    baseline_time: float,
    test_time: float,
    delay_expected: float = 5.0,
    tolerance: float = 2.0,
) -> dict[str, Any]:
    """
    Detect blind vulnerabilities using timing analysis.
    
    Essential for detecting time-based blind SQL injection, command injection,
    and other blind vulnerabilities where the only signal is response time.
    
    Args:
        baseline_time: Response time for normal request (seconds)
        test_time: Response time for payload request (seconds)
        delay_expected: Expected delay from payload like SLEEP(5) (default: 5.0 seconds)
        tolerance: Acceptable deviation from expected delay (default: 2.0 seconds)
        
    Returns:
        Detection result with:
        - detected: Boolean indicating if timing-based vulnerability was detected
        - confidence: Float 0.0-1.0 based on how close delay matches expected
        - detection_type: "timing"
        - evidence: List of timing measurements
        
    Example:
        # For time-based blind SQLi with SLEEP(5)
        detect_timing_based(
            baseline_time=0.3,  # Normal request took 0.3s
            test_time=5.4,      # Payload request took 5.4s  
            delay_expected=5.0,  # We injected SLEEP(5)
            tolerance=2.0
        )
    """
    result = _detector.detect_timing_based(
        baseline_time=baseline_time,
        test_time=test_time,
        delay_expected=delay_expected,
        tolerance=tolerance,
    )
    return result.to_dict()


@register_tool(sandbox_execution=False)
def detect_differential(
    baseline_response: dict[str, Any],
    test_response: dict[str, Any],
    vuln_class: str,
) -> dict[str, Any]:
    """
    Detect vulnerabilities through differential (boolean-based) analysis.
    
    Compares two responses to identify behavioral differences indicating
    a vulnerability. Essential for boolean-based blind SQL injection
    where true/false conditions produce different responses.
    
    Args:
        baseline_response: Dict with response data (status_code, body, headers)
        test_response: Dict with payload response data
        vuln_class: Vulnerability class (e.g., "sqli" for boolean-based SQLi)
        
    Returns:
        Detection result with:
        - detected: Boolean indicating if differential vulnerability was detected
        - confidence: Float 0.0-1.0 based on significance of differences
        - detection_type: "behavior"
        - evidence: List of differences found
        
    Example:
        detect_differential(
            baseline_response={"status_code": 200, "body": "Welcome admin"},
            test_response={"status_code": 200, "body": "Login failed"},
            vuln_class="sqli"
        )
    """
    result = _detector.detect_differential(
        baseline_response=baseline_response,
        test_response=test_response,
        vuln_class=vuln_class,
    )
    return result.to_dict()
