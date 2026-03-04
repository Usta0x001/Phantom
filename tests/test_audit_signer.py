"""Tests for phantom.core.audit_signer — Ed25519 sign/verify/chain."""

import json
import tempfile
from pathlib import Path

import pytest

from phantom.core.audit_signer import AuditSigner
from phantom.core.exceptions import AuditTamperError


@pytest.fixture
def signer(tmp_path):
    return AuditSigner(key_dir=tmp_path / "keys")


class TestSignVerifyRoundTrip:
    def test_sign_and_verify(self, signer):
        entry = {"event": "tool_call", "tool": "nmap_scan"}
        signed = signer.sign_entry(entry)
        assert "_sig" in signed
        assert "_seq" in signed
        assert "_prev_hash" in signed
        # Verify should pass
        assert signer.verify_entry(
            dict(signed),
            expected_seq=signed["_seq"],
            expected_prev_hash=signed.get("_prev_hash", ""),
        )

    def test_signature_format(self, signer):
        entry = signer.sign_entry({"event": "test"})
        # _sig should be base64-encoded
        import base64
        base64.b64decode(entry["_sig"])  # Should not raise

    def test_sequence_increments(self, signer):
        e1 = signer.sign_entry({"event": "first"})
        e2 = signer.sign_entry({"event": "second"})
        assert e1["_seq"] == 0
        assert e2["_seq"] == 1


class TestChainVerification:
    def test_verify_chain_passes(self, signer):
        entries = []
        for i in range(5):
            entries.append(signer.sign_entry({"event": f"event_{i}"}))

        # Create a fresh signer with same keys for verification
        verifier = AuditSigner(key_dir=signer._key_dir)
        assert verifier.verify_chain(entries)

    def test_tampered_entry_detected(self, signer):
        entries = []
        for i in range(3):
            entries.append(signer.sign_entry({"event": f"event_{i}"}))

        # Tamper with middle entry
        entries[1]["event"] = "TAMPERED"

        verifier = AuditSigner(key_dir=signer._key_dir)
        with pytest.raises(AuditTamperError, match="Signature verification failed"):
            verifier.verify_chain(entries)


class TestTamperDetection:
    def test_missing_sig_raises(self, signer):
        entry = {"event": "test", "_seq": 0, "_prev_hash": ""}
        with pytest.raises(AuditTamperError, match="missing _sig"):
            signer.verify_entry(entry, expected_seq=0, expected_prev_hash="")

    def test_wrong_sequence_raises(self, signer):
        entry = signer.sign_entry({"event": "test"})
        with pytest.raises(AuditTamperError, match="Sequence mismatch"):
            signer.verify_entry(
                dict(entry), expected_seq=999, expected_prev_hash="",
            )

    def test_wrong_prev_hash_raises(self, signer):
        entry = signer.sign_entry({"event": "test"})
        with pytest.raises(AuditTamperError, match="Hash chain break"):
            signer.verify_entry(
                dict(entry), expected_seq=0, expected_prev_hash="wrong_hash",
            )


class TestKeyPersistence:
    def test_keys_persisted_to_disk(self, tmp_path):
        key_dir = tmp_path / "persist_keys"
        s1 = AuditSigner(key_dir=key_dir)
        entry = s1.sign_entry({"event": "persist_test"})

        # Create new signer from same directory — should load same keys
        s2 = AuditSigner(key_dir=key_dir)
        assert s2.verify_entry(
            dict(entry), expected_seq=0, expected_prev_hash="",
        )

    def test_key_files_created(self, tmp_path):
        key_dir = tmp_path / "new_keys"
        AuditSigner(key_dir=key_dir)
        assert (key_dir / "audit_ed25519.key").exists()
        assert (key_dir / "audit_ed25519.pub").exists()
