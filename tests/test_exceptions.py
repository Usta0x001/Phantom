"""Tests for phantom.core.exceptions — exception hierarchy and MRO."""

import pytest

from phantom.core.exceptions import (
    AuditTamperError,
    BasePhantomError,
    CheckpointTamperError,
    CostLimitExceeded,
    OperationalError,
    ResourceExhaustedError,
    ScopeViolationError,
    SecurityViolationError,
)


class TestExceptionHierarchy:
    """Verify the exception MRO so catch blocks work correctly."""

    def test_security_violation_is_base_phantom(self):
        assert issubclass(SecurityViolationError, BasePhantomError)

    def test_scope_violation_is_security_violation(self):
        assert issubclass(ScopeViolationError, SecurityViolationError)

    def test_audit_tamper_is_security_violation(self):
        assert issubclass(AuditTamperError, SecurityViolationError)

    def test_checkpoint_tamper_is_security_violation(self):
        assert issubclass(CheckpointTamperError, SecurityViolationError)

    def test_resource_exhausted_is_base_phantom(self):
        assert issubclass(ResourceExhaustedError, BasePhantomError)

    def test_cost_limit_is_resource_exhausted(self):
        assert issubclass(CostLimitExceeded, ResourceExhaustedError)

    def test_operational_error_is_base_phantom(self):
        assert issubclass(OperationalError, BasePhantomError)


class TestSecurityViolationEscapesGenericCatch:
    """SecurityViolationError must NOT be caught by `except Exception` that
    is meant for operational errors when there's a specific catch above."""

    def test_security_violation_not_caught_by_value_error(self):
        with pytest.raises(SecurityViolationError):
            try:
                raise SecurityViolationError("test")
            except (ValueError, RuntimeError):
                pass  # Should NOT catch SecurityViolationError

    def test_scope_violation_carries_metadata(self):
        err = ScopeViolationError(
            message="out of scope",
            tool_name="nuclei_scan",
            target="http://evil.com",
        )
        assert err.tool_name == "nuclei_scan"
        assert err.target == "http://evil.com"
        assert "out of scope" in str(err)

    def test_cost_limit_carries_amounts(self):
        err = CostLimitExceeded("budget blown", 25.0, 25.0)
        assert err.current_cost == 25.0
        assert err.limit == 25.0
