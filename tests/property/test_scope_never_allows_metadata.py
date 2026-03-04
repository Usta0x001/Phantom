"""Property-based test: 169.254.169.254 (cloud metadata) always rejected."""

from hypothesis import given, settings, strategies as st
from unittest import mock

from phantom.core.scope_validator import ScopeValidator


# Various encodings of the metadata IP
METADATA_VARIANTS = [
    "169.254.169.254",
    "http://169.254.169.254/",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::ffff:a9fe:a9fe]/",  # IPv4-mapped IPv6
    "http://metadata.google.internal/",
]


@given(
    target=st.sampled_from(METADATA_VARIANTS),
    scope_targets=st.lists(
        st.sampled_from([
            "10.0.0.0/8",
            "example.com",
            "*.target.com",
            "192.168.1.0/24",
        ]),
        min_size=1,
        max_size=4,
    ),
)
@settings(max_examples=50)
def test_metadata_ip_always_rejected(target: str, scope_targets: list[str]):
    """169.254.169.254 must never be allowed, regardless of scope config."""
    sv = ScopeValidator.from_targets(scope_targets)

    with mock.patch("socket.getaddrinfo", return_value=[
        (None, None, None, None, ("169.254.169.254", 80)),
    ]):
        result = sv.is_in_scope(target)
        # Link-local / metadata IP should always be rejected
        assert result is False, (
            f"Metadata IP allowed! target={target}, scope={scope_targets}"
        )


def test_localhost_always_rejected():
    """127.0.0.1 as DNS resolution should be blocked."""
    sv = ScopeValidator.from_targets(["safe.com"])
    with mock.patch("socket.getaddrinfo", return_value=[
        (None, None, None, None, ("127.0.0.1", 80)),
    ]):
        assert sv.is_in_scope("malicious-redirect.com") is False


def test_internal_10_range_blocked():
    """10.x.x.x as DNS resolution should be blocked."""
    sv = ScopeValidator.from_targets(["safe.com"])
    with mock.patch("socket.getaddrinfo", return_value=[
        (None, None, None, None, ("10.0.0.1", 80)),
    ]):
        assert sv.is_in_scope("external-looking.com") is False
