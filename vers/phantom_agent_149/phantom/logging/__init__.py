"""Phantom audit logging package.

Enable with ``PHANTOM_AUDIT_LOG=true``.

WARNING: Audit mode writes full, un-redacted LLM prompts, responses, and tool
arguments to disk.  Do NOT enable in production environments against real targets
unless you have reviewed and accepted the data-handling implications.
"""

from .audit import AuditLogger, get_audit_logger, init_audit_logger

__all__ = ["AuditLogger", "get_audit_logger", "init_audit_logger"]
