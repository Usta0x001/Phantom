"""
Vulnerability Class Rotation Engine

Forces the agent to test DIFFERENT vulnerability classes systematically
rather than fixating on one class (e.g., SQLi) for the entire scan.

Each class has an iteration budget. When the budget is exhausted, the engine
injects a mandatory rotation message into the agent's conversation, telling
it to move to the next untested class.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

_logger = logging.getLogger(__name__)

# Ordered from highest-impact to lowest — agent will test in this order
VULN_CLASSES: list[dict[str, str]] = [
    {
        "id": "sqli",
        "name": "SQL Injection",
        "tools": "sqlmap_test, send_request, python_action",
        "description": "Test ALL form inputs and API params with sqlmap. Try blind, error-based, UNION, time-based.",
    },
    {
        "id": "xss",
        "name": "Cross-Site Scripting (XSS)",
        "tools": "ffuf_directory_scan (XSS wordlist), send_request, browser_action, python_action",
        "description": "Test reflected AND stored XSS on ALL input fields: search, comments, profile, contact forms. Try DOM-based XSS via browser.",
    },
    {
        "id": "auth_jwt",
        "name": "Authentication & JWT",
        "tools": "python_action, send_request, terminal_execute (jwt_tool)",
        "description": "Test JWT none-algorithm, weak secrets (jwt_tool), token manipulation, session fixation, weak passwords, default creds (admin/admin).",
    },
    {
        "id": "idor",
        "name": "IDOR / Broken Access Control",
        "tools": "send_request, python_action",
        "description": "Test sequential IDs on /api/Users, /api/Cards, /api/Deliverys. Access other users' data. Test role escalation (user→admin).",
    },
    {
        "id": "path_traversal",
        "name": "Path Traversal / LFI",
        "tools": "send_request, ffuf_directory_scan, python_action",
        "description": "Test file endpoints with ../../etc/passwd. Check /ftp, /encryptionkeys, /support/logs. Try null bytes, URL encoding.",
    },
    {
        "id": "ssrf",
        "name": "Server-Side Request Forgery (SSRF)",
        "tools": "send_request, python_action",
        "description": "Test any URL input, image URL, redirect parameter with http://localhost, http://169.254.169.254, http://[::1].",
    },
    {
        "id": "info_disclosure",
        "name": "Information Disclosure",
        "tools": "ffuf_directory_scan, send_request, nuclei_scan",
        "description": "Check /api-docs, /.well-known, error pages, metrics, environment vars, debug endpoints, .git exposure.",
    },
    {
        "id": "business_logic",
        "name": "Business Logic & Race Conditions",
        "tools": "python_action, send_request",
        "description": "Test price manipulation (negative quantities), coupon reuse, race conditions on purchases/transfers using concurrent requests.",
    },
    {
        "id": "csrf_upload",
        "name": "CSRF & File Upload",
        "tools": "send_request, python_action, browser_action",
        "description": "Test state-changing actions without CSRF tokens. Test file upload with malicious extensions, polyglot files.",
    },
    {
        "id": "xxe_deser",
        "name": "XXE & Deserialization",
        "tools": "send_request, python_action",
        "description": "Test XML inputs with XXE payloads, check for unsafe deserialization in cookies/tokens.",
    },
]


@dataclass
class VulnClassTracker:
    """Tracks which vulnerability classes have been tested and enforces rotation."""

    # Max iterations allowed per vuln class before forced rotation
    max_iters_per_class: int = 10

    # Current class index in VULN_CLASSES
    current_class_idx: int = 0

    # Iterations spent on the current class
    current_class_iters: int = 0

    # Set of class IDs that have been completed (either found vulns or exhausted budget)
    completed_classes: set[str] = field(default_factory=set)

    # Map: class_id → iterations spent
    class_iterations: dict[str, int] = field(default_factory=dict)

    # Map: class_id → number of findings
    class_findings: dict[str, int] = field(default_factory=dict)

    # Total iterations tracked
    total_iterations: int = 0

    # Last rotation message iteration (to avoid spamming)
    last_rotation_iter: int = -99

    def tick(self) -> str | None:
        """Called every iteration. Returns a rotation advisory message if it's time to switch, else None."""
        self.total_iterations += 1
        current_class = self._current_class()
        if current_class is None:
            return None  # All classes done

        cid = current_class["id"]
        self.current_class_iters += 1
        self.class_iterations[cid] = self.class_iterations.get(cid, 0) + 1

        # Check if we should rotate
        if self.current_class_iters >= self.max_iters_per_class:
            return self._rotate()

        return None

    def record_finding(self, class_id: str | None = None) -> None:
        """Record that a finding was made in the current (or specified) class."""
        cid = class_id or (self._current_class() or {}).get("id", "unknown")
        self.class_findings[cid] = self.class_findings.get(cid, 0) + 1

    def force_check(self, iteration: int) -> str | None:
        """Check at key iteration milestones whether we need to diversify.

        Called by the agent loop at periodic intervals.
        Returns an advisory message or None.
        """
        if iteration - self.last_rotation_iter < 8:
            return None  # Don't spam rotations

        # If the agent has been going for a while with few classes tested
        classes_tested = len(self.completed_classes) + (1 if self.current_class_iters > 0 else 0)
        target_classes = min(len(VULN_CLASSES), max(3, iteration // 10))

        if classes_tested < target_classes:
            self.last_rotation_iter = iteration
            current = self._current_class()
            if current:
                next_classes = self._get_upcoming_classes(3)
                names = ", ".join(c["name"] for c in next_classes)
                return (
                    f"⚠️ DIVERSITY CHECK: You've tested {classes_tested} vuln class(es) "
                    f"in {iteration} iterations. You should have tested at least {target_classes}.\n"
                    f"WRAP UP current testing and MOVE ON to: {names}\n"
                    f"Use the specialized tools listed for each class. Don't keep retesting the same vuln type."
                )

        return None

    def get_current_directive(self) -> str:
        """Get a directive string describing what the agent should be testing NOW."""
        current = self._current_class()
        if current is None:
            return "All vulnerability classes have been tested. Focus on verifying findings and finishing."

        remaining = self.max_iters_per_class - self.current_class_iters
        return (
            f"CURRENT VULN CLASS: {current['name']} ({remaining} iterations remaining)\n"
            f"Tools to use: {current['tools']}\n"
            f"What to test: {current['description']}\n"
            f"Classes completed: {len(self.completed_classes)}/{len(VULN_CLASSES)}"
        )

    def get_progress_summary(self) -> str:
        """Get a summary of vuln-class testing progress."""
        lines = ["VULNERABILITY CLASS TESTING PROGRESS:"]
        for vc in VULN_CLASSES:
            cid = vc["id"]
            iters = self.class_iterations.get(cid, 0)
            findings = self.class_findings.get(cid, 0)
            status = "✅ Done" if cid in self.completed_classes else (
                "🔄 Active" if self._current_class() and self._current_class()["id"] == cid else "⬜ Pending"
            )
            lines.append(f"  {status} {vc['name']}: {iters} iters, {findings} findings")
        return "\n".join(lines)

    def _current_class(self) -> dict[str, str] | None:
        """Get the current vuln class to test, skipping completed ones."""
        while self.current_class_idx < len(VULN_CLASSES):
            vc = VULN_CLASSES[self.current_class_idx]
            if vc["id"] not in self.completed_classes:
                return vc
            self.current_class_idx += 1
        return None

    def _get_upcoming_classes(self, count: int) -> list[dict[str, str]]:
        """Get the next N untested classes."""
        result = []
        idx = self.current_class_idx
        while idx < len(VULN_CLASSES) and len(result) < count:
            vc = VULN_CLASSES[idx]
            if vc["id"] not in self.completed_classes:
                result.append(vc)
            idx += 1
        return result

    def _rotate(self) -> str:
        """Force rotation to the next vulnerability class. Returns the rotation message."""
        old_class = self._current_class()
        old_name = old_class["name"] if old_class else "Unknown"
        old_id = old_class["id"] if old_class else "unknown"

        # Mark current class as completed
        self.completed_classes.add(old_id)
        self.current_class_iters = 0
        self.current_class_idx += 1

        # Find next untested class
        new_class = self._current_class()
        if new_class is None:
            return (
                f"✅ ROTATION: Finished testing {old_name}. "
                f"All {len(VULN_CLASSES)} vulnerability classes have been tested!\n"
                f"Focus on verifying findings and preparing the final report."
            )

        self.last_rotation_iter = self.total_iterations

        return (
            f"🔄 MANDATORY ROTATION: Time budget for {old_name} is EXHAUSTED.\n"
            f"SWITCH NOW to: {new_class['name']}\n"
            f"Tools: {new_class['tools']}\n"
            f"What to test: {new_class['description']}\n"
            f"You have {self.max_iters_per_class} iterations for this class.\n"
            f"Progress: {len(self.completed_classes)}/{len(VULN_CLASSES)} classes done."
        )
