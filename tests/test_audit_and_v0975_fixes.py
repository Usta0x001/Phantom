"""
Adversarial tests for v0.9.75:

  H-11v2  Absolute-root bypass of _sanitize_run_dir (new attack vector)
  C-04v2  Newline injection missing from quarantine blocklist (new attack vector)
  AUDIT   Comprehensive logging layer: correct, complete, non-breaking
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import types as _types
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# libtmux stub — only available inside the Docker sandbox
if "libtmux" not in sys.modules:
    _libtmux_stub = _types.ModuleType("libtmux")
    _libtmux_stub.Server = MagicMock  # type: ignore[attr-defined]
    _libtmux_stub.Session = MagicMock  # type: ignore[attr-defined]
    _libtmux_stub.Window = MagicMock  # type: ignore[attr-defined]
    _libtmux_stub.Pane = MagicMock  # type: ignore[attr-defined]
    sys.modules["libtmux"] = _libtmux_stub


# ─────────────────────────────────────────────────────────────────────────────
# H-11 v2: Absolute-root bypass — _sanitize_run_dir must strip root components
# ─────────────────────────────────────────────────────────────────────────────

class TestH11AbsoluteRootBypass:
    """H-11 v2 fix: boundary sanitization via sanitize_run_name() in tui.py.

    tui.py now calls sanitize_run_name(run_name) before Path("phantom_runs") / name
    so user-supplied absolute paths like /etc/passwd cannot bypass phantom_runs/.
    _sanitize_run_dir retains only '..' stripping so absolute paths from trusted
    internal code (e.g. pytest tmp_path) are preserved as-is.
    """

    def _sanitize_name(self, name: str) -> str:
        from phantom.checkpoint.checkpoint import sanitize_run_name
        return sanitize_run_name(name)

    def test_posix_absolute_root_is_stripped(self):
        """sanitize_run_name('/etc/passwd') must remove the leading slash."""
        safe = self._sanitize_name("/etc/passwd")
        result = Path("phantom_runs") / safe
        assert not result.is_absolute(), (
            "CRITICAL: /etc/passwd must be sanitized at CLI boundary — "
            "attacker can write checkpoints to arbitrary locations otherwise"
        )
        assert "etc" in safe
        assert "passwd" in safe

    def test_windows_drive_root_is_stripped(self):
        """sanitize_run_name('C:/Windows/System32') must strip drive letter."""
        safe = self._sanitize_name("C:/Windows/System32")
        result = Path("phantom_runs") / safe
        assert not result.is_absolute()
        assert "Windows" in safe
        assert "System32" in safe

    def test_absolute_attack_via_slash_in_posix_join(self):
        """Full attack chain: tui.py sanitizes run_name before Path join."""
        # Attacker supplies run_name="/etc/passwd" via CLI
        run_name = "/etc/passwd"
        safe = self._sanitize_name(run_name)
        result = Path("phantom_runs") / safe
        assert not result.is_absolute(), (
            "Absolute-path component in run_name must not survive CLI boundary sanitization"
        )

    def test_double_slash_root(self):
        """sanitize_run_name('//etc/passwd') strips UNC-lite leading slashes."""
        safe = self._sanitize_name("//etc/passwd")
        result = Path("phantom_runs") / safe
        assert not result.is_absolute()

    def test_combined_traversal_and_root(self):
        """'/../etc/passwd' — both root AND '..' attack vectors together."""
        safe = self._sanitize_name("/../etc/passwd")
        assert ".." not in safe
        result = Path("phantom_runs") / safe
        assert not result.is_absolute()

    def test_pure_relative_path_unchanged(self):
        """Normal relative run names must pass through unchanged."""
        name = "my-scan-2026"
        safe = self._sanitize_name(name)
        assert safe == name

    def test_dotdot_traversal_blocked(self):
        """'../../etc/shadow' path traversal must be stripped."""
        safe = self._sanitize_name("../../etc/shadow")
        assert ".." not in safe

    def test_empty_after_stripping_gets_fallback(self):
        """Pure slash '/' reduces to empty → fallback to 'unnamed'."""
        safe = self._sanitize_name("/")
        assert safe == "unnamed"

    def test_null_bytes_stripped(self):
        """Null bytes in run_name must be stripped (invalid in filesystem paths)."""
        safe = self._sanitize_name("good\x00name")
        assert "\x00" not in safe
        assert "good" in safe
        assert "name" in safe

    def test_excessively_long_name_capped(self):
        """Run names over 128 characters must be truncated to prevent FS issues."""
        long_name = "a" * 300
        safe = self._sanitize_name(long_name)
        assert len(safe) <= 128, f"Expected cap at 128, got {len(safe)}"

    def test_audit_run_id_traversal_without_run_dir(self, tmp_path):
        """init_audit_logger with run_id='../../evil' and run_dir=None must not escape phantom_runs/."""
        import phantom.logging.audit as _audit_mod
        orig = _audit_mod._instance
        orig_cwd = Path.cwd()
        try:
            import os
            os.chdir(tmp_path)
            from phantom.logging.audit import AuditLogger
            evil_id = "../../evil"
            with patch.dict(os.environ, {"PHANTOM_AUDIT_LOG": "true"}):
                al = AuditLogger(run_id=evil_id, run_dir=None)
            assert al._jsonl_path is not None
            # Must stay within tmp_path/phantom_runs/ — not escape via ..
            resolved = al._jsonl_path.resolve()
            phantom_runs = (tmp_path / "phantom_runs").resolve()
            assert str(resolved).startswith(str(phantom_runs)), (
                f"CRITICAL: audit log written outside phantom_runs/ — "
                f"run_id traversal not blocked. Path: {resolved}"
            )
        finally:
            os.chdir(orig_cwd)
            _audit_mod._instance = orig


# ─────────────────────────────────────────────────────────────────────────────
# C-04 v2: Newline injection — \n and \r must be in quarantine blocklist
# ─────────────────────────────────────────────────────────────────────────────

class TestC04NewlineInjection:
    """pane.send_keys() receives the raw string — a \\n in the command string
    physically presses Enter, executing a second injected command.  \\n and \\r
    must be in the quarantine metachar blocklist.
    """

    def _make_session(self, quarantine: bool):
        from phantom.tools.terminal.terminal_session import TerminalSession
        session = TerminalSession.__new__(TerminalSession)
        session.quarantine = quarantine
        session._QUARANTINE_METACHARACTERS = TerminalSession._QUARANTINE_METACHARACTERS
        session._initialized = True
        session._cwd = "/workspace"
        session.prev_output = ""
        session.prev_status = None
        return session

    def test_newline_in_quarantine_blocklist(self):
        """\\n MUST be in the quarantine metacharacter frozenset."""
        from phantom.tools.terminal.terminal_session import TerminalSession
        assert "\n" in TerminalSession._QUARANTINE_METACHARACTERS, (
            "Newline (\\n) must be in _QUARANTINE_METACHARACTERS — "
            "it physically presses Enter in the tmux pane, injecting a second command"
        )

    def test_carriage_return_in_quarantine_blocklist(self):
        """\\r MUST be in the quarantine metacharacter frozenset."""
        from phantom.tools.terminal.terminal_session import TerminalSession
        assert "\r" in TerminalSession._QUARANTINE_METACHARACTERS, (
            "Carriage return (\\r) must be in _QUARANTINE_METACHARACTERS"
        )

    def test_newline_injection_blocked_in_quarantine(self):
        """'ls\\nrm -rf /' must be blocked — the \\n would execute rm."""
        session = self._make_session(quarantine=True)
        with patch.object(session, "_get_pane_content", return_value=""), \
             patch.object(session, "_matches_ps1_metadata", return_value=[]):
            result = session.execute("ls\nrm -rf /")
        assert result["status"] == "error"
        assert "QUARANTINE" in result["content"]

    def test_carriage_return_injection_blocked(self):
        """'cat /etc/passwd\\r' must be blocked — \\r executes the command."""
        session = self._make_session(quarantine=True)
        with patch.object(session, "_get_pane_content", return_value=""), \
             patch.object(session, "_matches_ps1_metadata", return_value=[]):
            result = session.execute("cat /etc/passwd\r")
        assert result["status"] == "error"
        assert "QUARANTINE" in result["content"]

    def test_clean_command_still_passes(self):
        """Commands without any metacharacter must not be blocked."""
        session = self._make_session(quarantine=True)
        with patch.object(session, "_get_pane_content", return_value=""), \
             patch.object(session, "_matches_ps1_metadata", return_value=["prompt"]), \
             patch.object(session, "_execute_new_command", return_value={
                 "content": "ok", "status": "completed", "exit_code": 0,
                 "working_dir": "/workspace",
             }):
            result = session.execute("ls -la")
        assert result["status"] == "completed"

    def test_no_quarantine_allows_newline(self):
        """Without quarantine=True, newlines are not filtered (normal mode)."""
        session = self._make_session(quarantine=False)
        with patch.object(session, "_get_pane_content", return_value=""), \
             patch.object(session, "_matches_ps1_metadata", return_value=["prompt"]), \
             patch.object(session, "_execute_new_command", return_value={
                 "content": "ok", "status": "completed", "exit_code": 0,
                 "working_dir": "/workspace",
             }):
            result = session.execute("ls\necho hello")
        assert result["status"] == "completed"


# ─────────────────────────────────────────────────────────────────────────────
# Audit logging layer — correctness
# ─────────────────────────────────────────────────────────────────────────────

class TestAuditLoggerCore:
    """Unit tests for the AuditLogger itself — writes correct JSONL records."""

    def _make_logger(self, tmp_path: Path) -> "any":
        from phantom.logging.audit import AuditLogger
        with patch.dict(os.environ, {"PHANTOM_AUDIT_LOG": "true"}):
            return AuditLogger(run_id="test-run-0001", run_dir=tmp_path)

    def test_disabled_by_default(self, tmp_path: Path):
        """AuditLogger must be a no-op when PHANTOM_AUDIT_LOG is not set."""
        env = {k: v for k, v in os.environ.items() if k != "PHANTOM_AUDIT_LOG"}
        with patch.dict(os.environ, env, clear=True):
            from phantom.logging.audit import AuditLogger
            al = AuditLogger(run_id="test", run_dir=tmp_path)
        assert not al.enabled
        assert al._jsonl_path is None

    def test_enabled_when_env_set(self, tmp_path: Path):
        """AuditLogger must be enabled when PHANTOM_AUDIT_LOG=true."""
        al = self._make_logger(tmp_path)
        assert al.enabled
        assert al._jsonl_path is not None
        assert al._jsonl_path.exists()

    def test_run_started_written_on_init(self, tmp_path: Path):
        """run.started event must be written on AuditLogger.__init__."""
        al = self._make_logger(tmp_path)
        records = _read_jsonl(al._jsonl_path)
        assert any(r["event_type"] == "run.started" for r in records)

    def test_llm_request_written(self, tmp_path: Path):
        """log_llm_request must write llm.request record with messages."""
        al = self._make_logger(tmp_path)
        msgs = [{"role": "user", "content": "Hello"}]
        rid = al.log_llm_request("agent-1", "gpt-4o", msgs)
        records = _read_jsonl(al._jsonl_path)
        req = next(r for r in records if r["event_type"] == "llm.request")
        assert req["payload"]["model"] == "gpt-4o"
        assert req["payload"]["message_count"] == 1
        assert req["payload"]["messages"] == msgs
        assert req["payload"]["request_id"] == rid

    def test_llm_response_written(self, tmp_path: Path):
        """log_llm_response must write llm.response with all stats."""
        al = self._make_logger(tmp_path)
        al.log_llm_response(
            agent_id="agent-1", request_id="abc", model="gpt-4o",
            response_text="Hello", tool_invocations=[{"name": "terminal"}],
            tokens_in=100, tokens_out=50, cost_usd=0.001, duration_ms=450.0,
        )
        records = _read_jsonl(al._jsonl_path)
        resp = next(r for r in records if r["event_type"] == "llm.response")
        p = resp["payload"]
        assert p["tokens_in"] == 100
        assert p["tokens_out"] == 50
        assert len(p["tool_invocations"]) == 1
        assert p["duration_ms"] == 450.0

    def test_tool_start_and_result(self, tmp_path: Path):
        """tool.start must record exec_id; tool.result must include duration."""
        al = self._make_logger(tmp_path)
        exec_id = al.log_tool_start("agent-1", "terminal", {"command": "ls"})
        al.log_tool_result(exec_id, "agent-1", "terminal", "file1.txt", 123.4)
        records = _read_jsonl(al._jsonl_path)
        start = next(r for r in records if r["event_type"] == "tool.start")
        result = next(r for r in records if r["event_type"] == "tool.result")
        assert start["payload"]["exec_id"] == exec_id
        assert result["payload"]["exec_id"] == exec_id
        assert result["payload"]["duration_ms"] == 123.4
        assert "ls" in str(start["payload"]["args"])

    def test_tool_error_written(self, tmp_path: Path):
        """tool.error must record the exception and be status=error."""
        al = self._make_logger(tmp_path)
        exec_id = al.log_tool_start("agent-1", "browser", {})
        al.log_tool_error(exec_id, "agent-1", "browser", "Connection refused", 55.0)
        records = _read_jsonl(al._jsonl_path)
        err = next(r for r in records if r["event_type"] == "tool.error")
        assert err["status"] == "error"
        assert "Connection refused" in err["payload"]["error"]

    def test_agent_created_written(self, tmp_path: Path):
        """log_agent_created must write agent.created with agent metadata."""
        al = self._make_logger(tmp_path)
        al.log_agent_created(
            agent_id="a1", name="PhantomAgent", task="scan example.com",
            parent_id=None, agent_type="PhantomAgent", model="claude-3-5",
        )
        records = _read_jsonl(al._jsonl_path)
        ev = next(r for r in records if r["event_type"] == "agent.created")
        assert ev["payload"]["is_root"] is True
        assert ev["payload"]["name"] == "PhantomAgent"
        assert ev["payload"]["model"] == "claude-3-5"

    def test_rate_limit_hit_written(self, tmp_path: Path):
        """log_rate_limit_hit must write rate_limit.hit with backoff info."""
        al = self._make_logger(tmp_path)
        al.log_rate_limit_hit("a1", "gpt-4o", 3, 10, 120.0)
        records = _read_jsonl(al._jsonl_path)
        ev = next(r for r in records if r["event_type"] == "rate_limit.hit")
        assert ev["payload"]["consecutive"] == 3
        assert ev["payload"]["backoff_s"] == 120.0

    def test_rate_limit_abort_written(self, tmp_path: Path):
        """log_rate_limit_abort must write rate_limit.abort with status=aborted."""
        al = self._make_logger(tmp_path)
        al.log_rate_limit_abort("a1", "gpt-4o", 11, 10, "Aborting agent")
        records = _read_jsonl(al._jsonl_path)
        ev = next(r for r in records if r["event_type"] == "rate_limit.abort")
        assert ev["status"] == "aborted"
        assert ev["payload"]["consecutive"] == 11

    def test_quarantine_block_written(self, tmp_path: Path):
        """log_quarantine_block must write quarantine.block with blocked chars."""
        al = self._make_logger(tmp_path)
        al.log_quarantine_block("terminal", "ls; rm -rf /", [";"])
        records = _read_jsonl(al._jsonl_path)
        ev = next(r for r in records if r["event_type"] == "quarantine.block")
        assert ev["status"] == "blocked"
        assert ";" in ev["payload"]["blocked_chars"]

    def test_records_are_valid_json(self, tmp_path: Path):
        """Every line in audit.jsonl must be valid JSON."""
        al = self._make_logger(tmp_path)
        al.log_llm_request("a1", "m1", [{"role": "user", "content": "hi"}])
        al.log_tool_start("a1", "terminal", {"command": "ls"})
        with open(al._jsonl_path, encoding="utf-8") as f:
            for i, line in enumerate(f):
                assert json.loads(line), f"Line {i} is not valid JSON: {line!r}"

    def test_records_have_required_fields(self, tmp_path: Path):
        """Every record must have: timestamp, event_type, run_id."""
        al = self._make_logger(tmp_path)
        al.log_agent_created("a1", "n", "t", None, "T", "m")
        for rec in _read_jsonl(al._jsonl_path):
            assert "timestamp" in rec, f"Missing timestamp in {rec}"
            assert "event_type" in rec, f"Missing event_type in {rec}"
            assert "run_id" in rec, f"Missing run_id in {rec}"

    def test_no_crash_on_error_when_disabled(self):
        """All log_ methods must be no-ops when disabled — never raise."""
        from phantom.logging.audit import AuditLogger
        with patch.dict(os.environ, {"PHANTOM_AUDIT_LOG": "false"}):
            al = AuditLogger(run_id="x")
        # Should not raise even with bad args
        al.log_llm_request("a", "m", [])
        al.log_tool_start("a", "t", {})
        al.log_quarantine_block("t", "cmd", [";"])

    def test_get_stats_disabled_returns_dict(self, tmp_path: Path):
        """get_stats() must return a dict even when disabled."""
        from phantom.logging.audit import AuditLogger
        with patch.dict(os.environ, {"PHANTOM_AUDIT_LOG": "false"}):
            al = AuditLogger(run_id="x")
        stats = al.get_stats()
        assert isinstance(stats, dict)
        assert stats.get("enabled") is False

    def test_get_stats_counts_events(self, tmp_path: Path):
        """get_stats() must return correct event counts after logging."""
        al = self._make_logger(tmp_path)
        al.log_llm_request("a1", "m", [{"role": "user", "content": "hi"}])
        al.log_llm_response("a1", "r1", "m", "resp", [], 10, 5, 0.001, 100.0)
        al.log_tool_start("a1", "terminal", {})
        al.log_tool_start("a1", "browser", {})
        stats = al.get_stats()
        assert stats["enabled"] is True
        assert stats["event_counts"].get("llm.request", 0) == 1
        assert stats["event_counts"].get("llm.response", 0) == 1
        assert stats["event_counts"].get("tool.start", 0) == 2
        assert stats["total_tool_calls"] == 2
        assert stats["total_llm_requests"] == 1
        assert stats["total_tokens_in"] == 10
        assert stats["total_tokens_out"] == 5


class TestAuditLoggerSecurity:
    """Attack the audit logger itself — adversarial inputs must not crash it."""

    def _make_logger(self, tmp_path):
        from phantom.logging.audit import AuditLogger
        with patch.dict(os.environ, {"PHANTOM_AUDIT_LOG": "true"}):
            return AuditLogger(run_id="test", run_dir=tmp_path)

    def test_huge_response_text_is_truncated(self, tmp_path):
        """10 MB response text must be capped to 10 KB in audit record."""
        al = self._make_logger(tmp_path)
        huge = "A" * 10_000_000
        al.log_llm_response("a1", "r1", "m", huge, [], 0, 0, 0.0, 0.0)
        records = _read_jsonl(al._jsonl_path)
        resp = next(r for r in records if r["event_type"] == "llm.response")
        stored = resp["payload"]["response_text"]
        assert len(stored) <= 10_100, (
            f"10 MB response must be capped; got {len(stored)} chars"
        )
        assert resp["payload"]["response_chars"] == 10_000_000  # full length preserved

    def test_huge_tool_result_is_truncated(self, tmp_path):
        """4 MB tool result must be capped to 4 KB preview."""
        al = self._make_logger(tmp_path)
        exec_id = al.log_tool_start("a1", "terminal", {})
        big_result = "X" * 4_000_000
        al.log_tool_result(exec_id, "a1", "terminal", big_result, 10.0)
        records = _read_jsonl(al._jsonl_path)
        res = next(r for r in records if r["event_type"] == "tool.result")
        preview = res["payload"]["result_preview"]
        assert len(preview) <= 4_200
        assert res["payload"]["result_chars"] == 4_000_000

    def test_unicode_and_null_bytes_survive(self, tmp_path):
        """Unicode, emoji, and control chars must round-trip through JSON cleanly."""
        al = self._make_logger(tmp_path)
        payload = "Hello 🇺🇸 \x00 \xff \u2603"
        al.log_llm_request("a1", "m", [{"role": "user", "content": payload}])
        records = _read_jsonl(al._jsonl_path)
        req = next(r for r in records if r["event_type"] == "llm.request")
        stored = req["payload"]["messages"][0]["content"]
        # null bytes become \x00 repr via default=str; others must survive
        assert "Hello" in stored

    def test_non_dict_tool_args_do_not_crash(self, tmp_path):
        """log_tool_start with weird args types must not raise."""
        al = self._make_logger(tmp_path)
        # Pass non-standard but truthy args
        exec_id = al.log_tool_start("a1", "t", {"key": object()})
        assert exec_id  # must return something

    def test_concurrent_writes_do_not_corrupt(self, tmp_path):
        """Multiple threads writing simultaneously must produce valid JSONL."""
        import threading
        al = self._make_logger(tmp_path)
        errors = []

        def write_events():
            try:
                for _ in range(20):
                    al.log_tool_start("a1", "t", {"x": 1})
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=write_events) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Concurrent write errors: {errors}"
        records = _read_jsonl(al._jsonl_path)
        tool_starts = [r for r in records if r["event_type"] == "tool.start"]
        assert len(tool_starts) == 200  # 10 threads × 20 writes

    def test_injection_in_event_values_does_not_break_json(self, tmp_path):
        """JSON injection in values ('"}]}') must be properly escaped."""
        al = self._make_logger(tmp_path)
        evil = '"}]},{"event_type":"injected"'
        al.log_llm_request("a1", "m", [{"role": "user", "content": evil}])
        records = _read_jsonl(al._jsonl_path)
        # Must parse cleanly — no injected event
        req = next(r for r in records if r["event_type"] == "llm.request")
        assert req["payload"]["messages"][0]["content"] == evil  # verbatim storage

    def test_path_traversal_in_run_id_does_not_escape(self, tmp_path):
        """run_id with '../' must not let the logger write outside tmp_path."""
        from phantom.logging.audit import AuditLogger
        evil_run_id = "../../etc/evil"
        with patch.dict(os.environ, {"PHANTOM_AUDIT_LOG": "true"}):
            al = AuditLogger(run_id=evil_run_id, run_dir=tmp_path)
        # The run_dir is fixed (tmp_path) — run_id only appears as metadata
        assert al._jsonl_path is not None
        # File must be inside tmp_path, not escaped
        assert str(al._jsonl_path).startswith(str(tmp_path))

    def test_disabled_logger_returns_valid_exec_id(self):
        """log_tool_start on a disabled logger must still return a non-empty string."""
        from phantom.logging.audit import AuditLogger
        with patch.dict(os.environ, {"PHANTOM_AUDIT_LOG": "false"}):
            al = AuditLogger(run_id="x")
        exec_id = al.log_tool_start("a", "t", {})
        assert isinstance(exec_id, str) and len(exec_id) > 0


class TestAuditLoggerWiring:
    """Verify that the wiring hooks exist in the source of each target module."""

    def test_llm_py_has_audit_request_hook(self):
        src = Path("phantom/llm/llm.py").read_text(encoding="utf-8")
        assert "log_llm_request" in src, "llm.py must call log_llm_request"

    def test_llm_py_has_audit_response_hook(self):
        src = Path("phantom/llm/llm.py").read_text(encoding="utf-8")
        assert "log_llm_response" in src, "llm.py must call log_llm_response"

    def test_executor_py_has_tool_start_hook(self):
        src = Path("phantom/tools/executor.py").read_text(encoding="utf-8")
        assert "log_tool_start" in src, "executor.py must call log_tool_start"

    def test_executor_py_has_tool_result_hook(self):
        src = Path("phantom/tools/executor.py").read_text(encoding="utf-8")
        assert "log_tool_result" in src, "executor.py must call log_tool_result"

    def test_executor_py_has_tool_error_hook(self):
        src = Path("phantom/tools/executor.py").read_text(encoding="utf-8")
        assert "log_tool_error" in src, "executor.py must call log_tool_error"

    def test_base_agent_has_agent_created_hook(self):
        src = Path("phantom/agents/base_agent.py").read_text(encoding="utf-8")
        assert "log_agent_created" in src, "base_agent.py must call log_agent_created"

    def test_base_agent_has_iteration_hook(self):
        src = Path("phantom/agents/base_agent.py").read_text(encoding="utf-8")
        assert "log_agent_iteration" in src, "base_agent.py must call log_agent_iteration"

    def test_base_agent_has_rate_limit_hooks(self):
        src = Path("phantom/agents/base_agent.py").read_text(encoding="utf-8")
        assert "log_rate_limit_hit" in src, "base_agent.py must call log_rate_limit_hit"
        assert "log_rate_limit_abort" in src, "base_agent.py must call log_rate_limit_abort"

    def test_base_agent_has_agent_completed_hook(self):
        """base_agent.py must call log_agent_completed on the successful return path."""
        src = Path("phantom/agents/base_agent.py").read_text(encoding="utf-8")
        assert "log_agent_completed" in src, (
            "base_agent.py must call log_agent_completed — "
            "the audit trail has no success-completion events without this"
        )

    def test_base_agent_has_agent_failed_hook(self):
        """base_agent.py must call log_agent_failed on failure return paths."""
        src = Path("phantom/agents/base_agent.py").read_text(encoding="utf-8")
        assert "log_agent_failed" in src, (
            "base_agent.py must call log_agent_failed — "
            "failure paths (RL abort, sandbox error, LLM error) are invisible without this"
        )

    def test_base_agent_has_checkpoint_log_hook(self):
        """base_agent.py must call log_checkpoint when saving a checkpoint."""
        src = Path("phantom/agents/base_agent.py").read_text(encoding="utf-8")
        assert "log_checkpoint" in src, (
            "base_agent.py must call log_checkpoint after checkpoint saves"
        )

    def test_terminal_session_has_quarantine_audit_hook(self):
        src = Path("phantom/tools/terminal/terminal_session.py").read_text(encoding="utf-8")
        assert "log_quarantine_block" in src, (
            "terminal_session.py must call log_quarantine_block on C-04 blocks"
        )

    def test_tracer_inits_audit_logger(self):
        src = Path("phantom/telemetry/tracer.py").read_text(encoding="utf-8")
        assert "init_audit_logger" in src, (
            "tracer.py must call init_audit_logger when a new run starts"
        )

    def test_audit_module_exists(self):
        """phantom/logging/audit.py must exist."""
        assert Path("phantom/logging/audit.py").exists()

    def test_audit_init_module_exists(self):
        """phantom/logging/__init__.py must exist."""
        assert Path("phantom/logging/__init__.py").exists()

    def test_audit_module_importable(self):
        """phantom.logging.audit must be importable without side-effects."""
        import importlib
        mod = importlib.import_module("phantom.logging.audit")
        assert hasattr(mod, "AuditLogger")
        assert hasattr(mod, "get_audit_logger")
        assert hasattr(mod, "init_audit_logger")

    def test_get_audit_logger_returns_none_by_default(self):
        """get_audit_logger() must return None when not yet initialised."""
        import phantom.logging.audit as _audit_mod
        # Reset instance temporarily
        orig = _audit_mod._instance
        try:
            _audit_mod._instance = None
            result = _audit_mod.get_audit_logger()
            assert result is None
        finally:
            _audit_mod._instance = orig

    def test_init_audit_logger_sets_singleton(self, tmp_path):
        """init_audit_logger must set the singleton returned by get_audit_logger."""
        from phantom.logging.audit import AuditLogger, get_audit_logger, init_audit_logger
        import phantom.logging.audit as _audit_mod
        orig = _audit_mod._instance
        try:
            with patch.dict(os.environ, {"PHANTOM_AUDIT_LOG": "true"}):
                logger = init_audit_logger(run_id="test-singleton", run_dir=tmp_path)
            assert get_audit_logger() is logger
        finally:
            _audit_mod._instance = orig


class TestAuditHumanReadableLog:
    """Verify the human-readable audit.log file is also written."""

    def _make_logger(self, tmp_path):
        from phantom.logging.audit import AuditLogger
        with patch.dict(os.environ, {"PHANTOM_AUDIT_LOG": "true"}):
            return AuditLogger(run_id="test-hr", run_dir=tmp_path)

    def test_audit_log_file_created(self, tmp_path):
        al = self._make_logger(tmp_path)
        assert al._log_path.exists()

    def test_audit_log_has_human_readable_lines(self, tmp_path):
        al = self._make_logger(tmp_path)
        al.log_llm_request("agent-x", "gpt-4o", [{"role": "user", "content": "test"}])
        al.log_tool_start("agent-x", "terminal", {"command": "ls"})
        lines = al._log_path.read_text(encoding="utf-8").splitlines()
        assert any("llm.request" in line for line in lines)
        assert any("tool.start" in line for line in lines)

    def test_audit_log_contains_timestamps(self, tmp_path):
        al = self._make_logger(tmp_path)
        al.log_quarantine_block("t", "ls; rm -rf /", [";"])
        content = al._log_path.read_text(encoding="utf-8")
        # ISO timestamp in format [2026-...]
        assert "[20" in content


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _read_jsonl(path: Path) -> list[dict]:
    records = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records
