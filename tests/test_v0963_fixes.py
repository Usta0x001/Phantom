"""Tests for v0.9.63 bug fixes.

Bug C (MEDIUM): _check_error_result() in executor.py did not recognise
    the "Error executing {tool_name}: ..." prefix returned by
    execute_tool_with_validation() when it catches an exception.
    Result: tracer falsely recorded all wrapped tool exceptions as
    "completed" instead of "error".

Bug D (LOW): _summarize_messages() in memory_compressor.py passed
    "thinking": None to every litellm provider, including non-Anthropic
    models that reject the parameter with 400 Bad Request.
    Fix: only pass thinking=None when model.startswith("anthropic/").
"""

from __future__ import annotations

import inspect
import unittest
from unittest.mock import AsyncMock, MagicMock, patch


# ── BUG C — _check_error_result prefix detection ────────────────────────────


class TestBugCCheckErrorResultPrefix(unittest.TestCase):
    """_check_error_result must flag both 'Error:' AND 'Error executing X:' forms."""

    def _check(self, result):
        from phantom.tools.executor import _check_error_result
        return _check_error_result(result)

    # Original "Error:" prefix still works
    def test_error_colon_prefix_is_error(self):
        is_err, payload = self._check("Error: tool 'foo' is not available")
        self.assertTrue(is_err)
        self.assertEqual(payload, "Error: tool 'foo' is not available")

    def test_error_colon_case_insensitive(self):
        is_err, _ = self._check("error: something went wrong")
        self.assertTrue(is_err)

    # NEW: "Error executing X: ..." prefix (from execute_tool_with_validation)
    def test_error_executing_prefix_is_error(self):
        is_err, payload = self._check("Error executing nuclei: connection timeout")
        self.assertTrue(is_err, "'Error executing X: Y' must be classified as error")
        self.assertEqual(payload, "Error executing nuclei: connection timeout")

    def test_error_executing_case_insensitive(self):
        is_err, _ = self._check("error executing run_command: subprocess failed")
        self.assertTrue(is_err)

    def test_error_executing_different_tool_name(self):
        is_err, _ = self._check("Error executing python_repl: NameError: name 'x' is not defined")
        self.assertTrue(is_err)

    # False-positive guard: success strings must NOT be flagged
    def test_success_string_not_error(self):
        is_err, _ = self._check("All steps completed successfully")
        self.assertFalse(is_err)

    def test_string_containing_error_but_not_prefix(self):
        is_err, _ = self._check("No errors found in scan output")
        self.assertFalse(is_err)

    def test_empty_string_not_error(self):
        is_err, _ = self._check("")
        self.assertFalse(is_err)

    # Dict error form still works
    def test_dict_with_error_key_is_error(self):
        is_err, payload = self._check({"error": "something bad"})
        self.assertTrue(is_err)
        self.assertEqual(payload, {"error": "something bad"})

    def test_dict_without_error_key_is_not_error(self):
        is_err, _ = self._check({"result": "ok", "data": [1, 2, 3]})
        self.assertFalse(is_err)


# ── BUG D — thinking=None scoped to Anthropic models only ────────────────────


class TestBugDThinkingParamScope(unittest.TestCase):
    """_summarize_messages must only pass thinking=None for anthropic/ models."""

    def test_thinking_guard_present_in_source(self):
        from phantom.llm import memory_compressor
        src = inspect.getsource(memory_compressor._summarize_messages)
        self.assertIn(
            'startswith("anthropic/")',
            src,
            "thinking=None guard must check model.startswith('anthropic/')",
        )

    def test_no_unconditional_thinking_in_completion_args_literal(self):
        """The dict literal for completion_args must NOT hard-code thinking=None."""
        from phantom.llm import memory_compressor
        src = inspect.getsource(memory_compressor._summarize_messages)
        # Locate the completion_args dict literal (the initial assignment)
        dict_start = src.find("completion_args: dict[str, Any] = {")
        if dict_start == -1:
            dict_start = src.find("completion_args = {")
        self.assertGreater(dict_start, -1, "completion_args dict not found in source")
        # Find closing brace of the dict literal
        brace_depth = 0
        in_dict = False
        dict_literal = ""
        for ch in src[dict_start:]:
            if ch == "{":
                brace_depth += 1
                in_dict = True
            elif ch == "}":
                brace_depth -= 1
            dict_literal += ch
            if in_dict and brace_depth == 0:
                break
        self.assertNotIn(
            '"thinking"',
            dict_literal,
            "thinking key must not appear unconditionally inside completion_args dict literal",
        )

    def test_anthropic_model_gets_thinking_none(self):
        """For anthropic/ models, thinking=None must be added to completion_args."""
        from phantom.llm import memory_compressor
        src = inspect.getsource(memory_compressor._summarize_messages)
        # The guard block assigns thinking=None
        self.assertIn('completion_args["thinking"] = None', src)

    def test_non_anthropic_model_no_thinking_key_in_call(self):
        """For non-anthropic models, litellm.completion must NOT receive thinking=None."""
        import litellm
        from phantom.llm.memory_compressor import _summarize_messages

        captured_kwargs: dict = {}

        def fake_completion(**kwargs):
            captured_kwargs.update(kwargs)
            resp = MagicMock()
            resp.choices = [MagicMock()]
            resp.choices[0].message.content = "A concise summary of past activity."
            return resp

        with patch.object(litellm, "completion", side_effect=fake_completion):
            msgs = [
                {"role": "user", "content": "Hello"},
                {"role": "assistant", "content": "World"},
            ]
            _summarize_messages(msgs, "openai/gpt-4o", timeout=30)

        self.assertNotIn(
            "thinking",
            captured_kwargs,
            "thinking must NOT be passed to non-anthropic litellm calls",
        )

    def test_anthropic_model_thinking_none_passed(self):
        """For anthropic/ models, litellm.completion must receive thinking=None."""
        import litellm
        from phantom.llm.memory_compressor import _summarize_messages

        captured_kwargs: dict = {}

        def fake_completion(**kwargs):
            captured_kwargs.update(kwargs)
            resp = MagicMock()
            resp.choices = [MagicMock()]
            resp.choices[0].message.content = "Summary."
            return resp

        with patch.object(litellm, "completion", side_effect=fake_completion):
            msgs = [{"role": "user", "content": "scan results"}]
            _summarize_messages(msgs, "anthropic/claude-sonnet-4-6", timeout=30)

        self.assertIn("thinking", captured_kwargs)
        self.assertIsNone(captured_kwargs["thinking"])


# ── Integration: execute_tool_with_validation exception → tracer sees error ──


class TestBugCTracerSeesToolError(unittest.TestCase):
    """When execute_tool_with_validation wraps an exception, tracer must see 'error' status."""

    def test_wrapped_exception_classified_as_error_for_tracer(self):
        """Simulate the full _execute_single_tool path with a tool that raises."""
        from phantom.tools.executor import _check_error_result

        # Simulate what execute_tool_with_validation returns for a RuntimeError
        simulated_result = "Error executing run_command: subprocess returned exit code 1"
        is_err, payload = _check_error_result(simulated_result)
        self.assertTrue(is_err, "Tracer must see this as an error, not a success")
        self.assertEqual(payload, simulated_result)


if __name__ == "__main__":
    unittest.main()
