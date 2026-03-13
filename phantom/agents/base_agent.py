import asyncio
import contextlib
import logging
import random
from typing import TYPE_CHECKING, Any, Optional


if TYPE_CHECKING:
    from phantom.telemetry.tracer import Tracer

from jinja2 import (
    Environment,
    FileSystemLoader,
    select_autoescape,
)

from phantom.agents.hypothesis_ledger import HypothesisLedger  # Rec 6 (SF-005)
from phantom.llm import LLM, LLMConfig, LLMRequestFailedError
from phantom.llm.utils import clean_content
from phantom.config import Config
from phantom.runtime import SandboxInitializationError
from phantom.tools import process_tool_invocations
from phantom.utils.resource_paths import get_phantom_resource_path

from .state import AgentState


logger = logging.getLogger(__name__)


class AgentMeta(type):
    agent_name: str
    jinja_env: Environment

    def __new__(cls, name: str, bases: tuple[type, ...], attrs: dict[str, Any]) -> type:
        new_cls = super().__new__(cls, name, bases, attrs)

        if name == "BaseAgent":
            return new_cls

        prompt_dir = get_phantom_resource_path("agents", name)

        new_cls.agent_name = name
        new_cls.jinja_env = Environment(
            loader=FileSystemLoader(prompt_dir),
            autoescape=select_autoescape(enabled_extensions=(), default_for_string=False),
        )

        return new_cls


class BaseAgent(metaclass=AgentMeta):
    max_iterations = 300
    agent_name: str = ""
    jinja_env: Environment
    default_llm_config: LLMConfig | None = None

    def __init__(self, config: dict[str, Any]):
        self.config = config

        self.local_sources = config.get("local_sources", [])
        self.non_interactive = config.get("non_interactive", False)

        if "max_iterations" in config:
            self.max_iterations = config["max_iterations"]

        self.llm_config_name = config.get("llm_config_name", "default")
        self.llm_config = config.get("llm_config", self.default_llm_config)
        if self.llm_config is None:
            raise ValueError("llm_config is required but not provided")
        state_from_config = config.get("state")
        if state_from_config is not None:
            self.state = state_from_config
        else:
            self.state = AgentState(
                agent_name="Root Agent",
                max_iterations=self.max_iterations,
            )

        self.llm = LLM(self.llm_config, agent_name=self.agent_name)

        with contextlib.suppress(Exception):
            self.llm.set_agent_identity(self.state.agent_name, self.state.agent_id)
        self._current_task: asyncio.Task[Any] | None = None
        self._force_stop = False

        # Rec 6 (SF-005): Hypothesis Ledger — structured external memory that
        # survives context compression and prevents redundant payload testing.
        # Root agents get a fresh ledger; sub-agents share the ledger if one is
        # passed via config (enabling cross-agent deduplication).
        self.hypothesis_ledger: HypothesisLedger = config.get(
            "hypothesis_ledger"
        ) or HypothesisLedger()

        from phantom.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer:
            tracer.log_agent_creation(
                agent_id=self.state.agent_id,
                name=self.state.agent_name,
                task=self.state.task,
                parent_id=self.state.parent_id,
            )
            if self.state.parent_id is None:
                scan_config = tracer.scan_config or {}
                exec_id = tracer.log_tool_execution_start(
                    agent_id=self.state.agent_id,
                    tool_name="scan_start_info",
                    args=scan_config,
                )
                tracer.update_tool_execution(execution_id=exec_id, status="completed", result={})

            else:
                exec_id = tracer.log_tool_execution_start(
                    agent_id=self.state.agent_id,
                    tool_name="subagent_start_info",
                    args={
                        "name": self.state.agent_name,
                        "task": self.state.task,
                        "parent_id": self.state.parent_id,
                    },
                )
                tracer.update_tool_execution(execution_id=exec_id, status="completed", result={})

        self._add_to_agents_graph()

        # ── Audit: log agent creation ──────────────────────────────────────────────────
        from phantom.logging.audit import get_audit_logger as _get_audit
        _audit = _get_audit()
        if _audit:
            _audit.log_agent_created(
                agent_id=self.state.agent_id,
                name=self.state.agent_name,
                task=self.state.task,
                parent_id=self.state.parent_id,
                agent_type=self.__class__.__name__,
                model=getattr(self.llm_config, "litellm_model", "unknown") or "unknown",
            )
        # ──────────────────────────────────────────────────────────────────────────────

    def _add_to_agents_graph(self) -> None:
        from phantom.tools.agents_graph import agents_graph_actions

        node = {
            "id": self.state.agent_id,
            "name": self.state.agent_name,
            "task": self.state.task,
            "status": "running",
            "parent_id": self.state.parent_id,
            "created_at": self.state.start_time,
            "finished_at": None,
            "result": None,
            "llm_config": self.llm_config_name,
            "agent_type": self.__class__.__name__,
            "state": self.state.model_dump(),
        }
        agents_graph_actions._agent_graph["nodes"][self.state.agent_id] = node

        agents_graph_actions._agent_instances[self.state.agent_id] = self
        agents_graph_actions._agent_states[self.state.agent_id] = self.state

        if self.state.parent_id:
            agents_graph_actions._agent_graph["edges"].append(
                {"from": self.state.parent_id, "to": self.state.agent_id, "type": "delegation"}
            )

        if self.state.agent_id not in agents_graph_actions._agent_messages:
            agents_graph_actions._agent_messages[self.state.agent_id] = []

        if self.state.parent_id is None:
            with agents_graph_actions._ROOT_AGENT_LOCK:
                if agents_graph_actions._root_agent_id is None:
                    agents_graph_actions._root_agent_id = self.state.agent_id

    async def agent_loop(self, task: str) -> dict[str, Any]:  # noqa: PLR0912, PLR0915
        import time as _time_mod
        from phantom.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        # P1.4: Capture start time for accurate duration_ms in audit logs.
        # Previously all audit-log callsites passed a placeholder zero.
        self._agent_start_time: float = _time_mod.monotonic()

        try:
            await self._initialize_sandbox_and_state(task)
        except SandboxInitializationError as e:
            return self._handle_sandbox_error(e, tracer)

        _rl_consecutive = 0  # consecutive rate-limit hits for exponential backoff
        while True:
            if self._force_stop:
                self._force_stop = False
                await self._enter_waiting_state(tracer, was_cancelled=True)
                continue

            self._check_agent_messages(self.state)

            if self.state.is_waiting_for_input():
                await self._wait_for_input()
                continue

            if self.state.should_stop():
                if self.non_interactive:
                    return self.state.final_result or {}
                await self._enter_waiting_state(tracer)
                continue

            if self.state.llm_failed:
                await self._wait_for_input()
                continue

            self.state.increment_iteration()

            # ── Audit: log iteration ──────────────────────────────────────────
            from phantom.logging.audit import get_audit_logger as _get_audit_it
            _audit_it = _get_audit_it()
            if _audit_it:
                _audit_it.log_agent_iteration(
                    self.state.agent_id, self.state.iteration, self.state.max_iterations
                )
            # ─────────────────────────────────────────────────────────────────

            if (
                self.state.is_approaching_max_iterations()
                and not self.state.max_iterations_warning_sent
            ):
                self.state.max_iterations_warning_sent = True
                remaining = self.state.max_iterations - self.state.iteration
                warning_msg = (
                    f"URGENT: You are approaching the maximum iteration limit. "
                    f"Current: {self.state.iteration}/{self.state.max_iterations} "
                    f"({remaining} iterations remaining). "
                    f"Please prioritize completing your required task(s) and calling "
                    f"the appropriate finish tool (finish_scan for root agent, "
                    f"agent_finish for sub-agents) as soon as possible."
                )
                self.state.add_message("user", warning_msg)

            if self.state.iteration >= self.state.max_iterations - 3:
                final_warning_msg = (
                    "CRITICAL: You have only 3 iterations left! "
                    "Your next message MUST be the tool call to the appropriate "
                    "finish tool: finish_scan if you are the root agent, or "
                    "agent_finish if you are a sub-agent. "
                    "No other actions should be taken except finishing your work "
                    "immediately."
                )
                self.state.add_message("user", final_warning_msg)

            try:
                iteration_task = asyncio.create_task(self._process_iteration(tracer))
                self._current_task = iteration_task
                should_finish = await iteration_task
                self._current_task = None
                _rl_consecutive = 0  # successful iteration — reset rate-limit backoff counter

                # Periodic checkpoint save ─────────────────────────────────
                self._maybe_save_checkpoint(tracer)
                # ──────────────────────────────────────────────────────────

                if should_finish:
                    if self.non_interactive:
                        self.state.set_completed({"success": True})
                        if tracer:
                            tracer.update_agent_status(self.state.agent_id, "completed")
                        # ── Audit: log agent completed ────────────────────────────
                        from phantom.logging.audit import get_audit_logger as _get_audit_done
                        _audit_done = _get_audit_done()
                        if _audit_done:
                            _audit_done.log_agent_completed(
                                agent_id=self.state.agent_id,
                                name=self.state.agent_name,
                                task=self.state.task,
                                result=self.state.final_result,
                                iterations=self.state.iteration,
                                duration_ms=(_time_mod.monotonic() - self._agent_start_time) * 1000,
                            )
                        # ─────────────────────────────────────────────────────────
                        return self.state.final_result or {}
                    await self._enter_waiting_state(tracer, task_completed=True)
                    continue

            except asyncio.CancelledError:
                self._current_task = None
                if tracer:
                    partial_content = tracer.finalize_streaming_as_interrupted(self.state.agent_id)
                    if partial_content and partial_content.strip():
                        self.state.add_message(
                            "assistant", f"{partial_content}\n\n[ABORTED BY USER]"
                        )
                if self.non_interactive:
                    raise
                await self._enter_waiting_state(tracer, error_occurred=False, was_cancelled=True)
                continue

            except LLMRequestFailedError as e:
                # Rate-limit errors are transient — pause and retry the agent loop
                # rather than aborting (applies in both interactive and non-interactive modes).
                error_lower = str(e).lower()
                if "rate limit" in error_lower or "ratelimit" in error_lower or "rate_limit" in error_lower:
                    _rl_consecutive += 1
                    # H-03 follow-up: hard cap — abort if API key appears revoked/exhausted
                    _rl_max = int(Config.get("phantom_llm_ratelimit_max_agent_retries") or "10")
                    if _rl_consecutive > _rl_max:
                        _abort_msg = (
                            f"LLM rate limit hit {_rl_consecutive} consecutive times "
                            f"(limit={_rl_max}). API key may be revoked, quota permanently "
                            f"exhausted, or provider down. Aborting agent to prevent "
                            f"infinite loop."
                        )
                        logger.error(_abort_msg)
                        # ── Audit: log RL abort ──────────────────────────────
                        from phantom.logging.audit import get_audit_logger as _get_audit_rl
                        _audit_rl = _get_audit_rl()
                        if _audit_rl:
                            _audit_rl.log_rate_limit_abort(
                                agent_id=self.state.agent_id,
                                model=getattr(self.llm_config, "litellm_model", "?") or "?",
                                consecutive=_rl_consecutive,
                                max_consecutive=_rl_max,
                                abort_message=_abort_msg,
                            )
                        # ────────────────────────────────────────────────────
                        self.state.set_completed({"success": False, "error": _abort_msg})
                        if tracer:
                            tracer.update_agent_status(self.state.agent_id, "failed")
                        # S-03: Emergency checkpoint save before abort so work is not lost.
                        self._maybe_save_checkpoint(tracer, force=True)
                        # ── Audit: log agent failed (RL abort) ───────────────────
                        from phantom.logging.audit import get_audit_logger as _get_audit_rla
                        _audit_rla = _get_audit_rla()
                        if _audit_rla:
                            _audit_rla.log_agent_failed(
                                agent_id=self.state.agent_id,
                                name=self.state.agent_name,
                                error=_abort_msg,
                                iterations=_rl_consecutive,
                                duration_ms=(_time_mod.monotonic() - self._agent_start_time) * 1000,
                            )
                        # ────────────────────────────────────────────────────────
                        return self.state.final_result or {"success": False, "error": _abort_msg}
                    _backoff = min(300.0, 30.0 * (2.0 ** (_rl_consecutive - 1)))
                    _jitter = _backoff * random.uniform(0.0, 0.2)
                    _sleep = _backoff + _jitter
                    logger.warning(
                        "LLM rate limit exhausted after all retries (hit #%d/%d); "
                        "backing off %.0fs before resuming agent loop...",
                        _rl_consecutive,
                        _rl_max,
                        _sleep,
                    )
                    # ── Audit: log RL backoff hit ────────────────────────────
                    from phantom.logging.audit import get_audit_logger as _get_audit_rlh
                    _audit_rlh = _get_audit_rlh()
                    if _audit_rlh:
                        _audit_rlh.log_rate_limit_hit(
                            agent_id=self.state.agent_id,
                            model=getattr(self.llm_config, "litellm_model", "?") or "?",
                            consecutive=_rl_consecutive,
                            max_consecutive=_rl_max,
                            backoff_s=_sleep,
                        )
                    # ────────────────────────────────────────────────────────
                    await asyncio.sleep(_sleep)
                    continue
                result = self._handle_llm_error(e, tracer)
                if result is not None:
                    return result
                continue

            except (RuntimeError, ValueError, TypeError) as e:
                if not await self._handle_iteration_error(e, tracer):
                    if self.non_interactive:
                        self.state.set_completed({"success": False, "error": str(e)})
                        if tracer:
                            tracer.update_agent_status(self.state.agent_id, "failed")
                        # ── Audit: log agent failed (unhandled error) ─────────────
                        from phantom.logging.audit import get_audit_logger as _get_audit_err
                        _audit_err = _get_audit_err()
                        if _audit_err:
                            _audit_err.log_agent_failed(
                                agent_id=self.state.agent_id,
                                name=self.state.agent_name,
                                error=str(e),
                                iterations=self.state.iteration,
                                duration_ms=(_time_mod.monotonic() - self._agent_start_time) * 1000,
                            )
                        # ────────────────────────────────────────────────────────
                        raise
                    await self._enter_waiting_state(tracer, error_occurred=True)
                    continue

    async def _wait_for_input(self) -> None:
        if self._force_stop:
            return

        if self.state.has_waiting_timeout():
            self.state.resume_from_waiting()
            self.state.add_message("user", "Waiting timeout reached. Resuming execution.")

            from phantom.telemetry.tracer import get_global_tracer

            tracer = get_global_tracer()
            if tracer:
                tracer.update_agent_status(self.state.agent_id, "running")

            try:
                from phantom.tools.agents_graph.agents_graph_actions import _agent_graph

                if self.state.agent_id in _agent_graph["nodes"]:
                    _agent_graph["nodes"][self.state.agent_id]["status"] = "running"
            except (ImportError, KeyError):
                pass

            return

        await asyncio.sleep(0.5)

    async def _enter_waiting_state(
        self,
        tracer: Optional["Tracer"],
        task_completed: bool = False,
        error_occurred: bool = False,
        was_cancelled: bool = False,
    ) -> None:
        self.state.enter_waiting_state()

        if tracer:
            if task_completed:
                tracer.update_agent_status(self.state.agent_id, "completed")
            elif error_occurred:
                tracer.update_agent_status(self.state.agent_id, "error")
            elif was_cancelled:
                tracer.update_agent_status(self.state.agent_id, "stopped")
            else:
                tracer.update_agent_status(self.state.agent_id, "stopped")

        if task_completed:
            self.state.add_message(
                "assistant",
                "Task completed. I'm now waiting for follow-up instructions or new tasks.",
            )
        elif error_occurred:
            self.state.add_message(
                "assistant", "An error occurred. I'm now waiting for new instructions."
            )
        elif was_cancelled:
            self.state.add_message(
                "assistant", "Execution was cancelled. I'm now waiting for new instructions."
            )
        else:
            self.state.add_message(
                "assistant",
                "Execution paused. I'm now waiting for new instructions or any updates.",
            )

    async def _initialize_sandbox_and_state(self, task: str) -> None:
        import os

        sandbox_mode = os.getenv("PHANTOM_SANDBOX_MODE", "false").lower() == "true"
        if not sandbox_mode and self.state.sandbox_id is None:
            from phantom.runtime import get_runtime

            runtime = get_runtime()
            sandbox_info = await runtime.create_sandbox(
                self.state.agent_id, self.state.sandbox_token, self.local_sources
            )
            self.state.sandbox_id = sandbox_info["workspace_id"]
            self.state.sandbox_token = sandbox_info["auth_token"]
            self.state.sandbox_info = sandbox_info

            if "agent_id" in sandbox_info:
                self.state.sandbox_info["agent_id"] = sandbox_info["agent_id"]

            caido_port = sandbox_info.get("caido_port")
            if caido_port:
                from phantom.telemetry.tracer import get_global_tracer

                tracer = get_global_tracer()
                if tracer:
                    tracer.caido_url = f"localhost:{caido_port}"

        if not self.state.task:
            self.state.task = task

        # Only add the initial task message when the history is fresh.
        # When resuming from a checkpoint, messages are already populated.
        if not self.state.messages:
            self.state.add_message("user", task)

    async def _process_iteration(self, tracer: Optional["Tracer"]) -> bool:
        final_response = None

        # Rec 6 (SF-005): Inject Hypothesis Ledger summary every 10 iterations.
        # Keeps the LLM aware of the scan's coverage state without bloating every
        # message with the full ledger (which would waste tokens massively).
        _LEDGER_INJECT_EVERY = int(Config.get("phantom_ledger_inject_interval") or "10")
        if (
            len(self.hypothesis_ledger) > 0
            and self.state.iteration > 0
            and self.state.iteration % _LEDGER_INJECT_EVERY == 0
        ):
            ledger_summary = self.hypothesis_ledger.to_prompt_summary(top_n=10)
            if ledger_summary:
                self.state.add_message("user", ledger_summary)

        # S-07: Phase-gate reporting reminders at 33%, 66%, and 90% of max iterations.
        # Forces the agent to transition from recon → exploit → report
        # instead of endlessly looping in reconnaissance.
        _max_iter = self.state.max_iterations
        _cur_iter = self.state.iteration
        if _max_iter and _max_iter > 0 and _cur_iter > 1:
            _pct = _cur_iter / _max_iter
            _gate_msg = None
            if _cur_iter == max(2, int(_max_iter * 0.33)):
                _gate_msg = (
                    "[PHASE GATE — RECON → EXPLOIT] You have used 33% of your iterations. "
                    "If you have identified ANY potential vulnerability targets, you MUST now "
                    "transition to active exploitation. Stop mapping and start testing payloads. "
                    "Report findings via create_vulnerability_report as you go."
                )
            elif _cur_iter == max(3, int(_max_iter * 0.66)):
                _gate_msg = (
                    "[PHASE GATE — EXPLOIT → REPORT] You have used 66% of your iterations. "
                    "URGENT: If you have found ANY vulnerabilities and have NOT yet called "
                    "create_vulnerability_report, you MUST do so NOW. Every unreported finding "
                    "is LOST. Even SUSPECTED findings must be reported with confidence=SUSPECTED."
                )
            elif _cur_iter == max(4, int(_max_iter * 0.90)):
                _gate_msg = (
                    "[FINAL WARNING — REPORT NOW] You have used 90% of your iterations. "
                    "You are about to run out of time. If you have ANY unreported findings, "
                    "call create_vulnerability_report IMMEDIATELY in your next action. "
                    "A scan with 0 reports is a FAILURE."
                )
            if _gate_msg:
                self.state.add_message("user", _gate_msg)

        async for response in self.llm.generate(self.state.get_conversation_history()):
            final_response = response
            if tracer and response.content:
                tracer.update_streaming_content(self.state.agent_id, response.content)

        if final_response is None:
            return False

        content_stripped = (final_response.content or "").strip()

        if not content_stripped:
            corrective_message = (
                "You MUST NOT respond with empty messages. "
                "If you currently have nothing to do or say, use an appropriate tool instead:\n"
                "- Use agents_graph_actions.wait_for_message to wait for messages "
                "from user or other agents\n"
                "- Use agents_graph_actions.agent_finish if you are a sub-agent "
                "and your task is complete\n"
                "- Use finish_actions.finish_scan if you are the root/main agent "
                "and the scan is complete"
            )
            self.state.add_message("user", corrective_message)
            return False

        thinking_blocks = getattr(final_response, "thinking_blocks", None)
        self.state.add_message("assistant", final_response.content, thinking_blocks=thinking_blocks)
        if tracer:
            tracer.clear_streaming_content(self.state.agent_id)
            tracer.log_chat_message(
                content=clean_content(final_response.content),
                role="assistant",
                agent_id=self.state.agent_id,
            )

        actions = (
            final_response.tool_invocations
            if hasattr(final_response, "tool_invocations") and final_response.tool_invocations
            else []
        )

        if actions:
            return await self._execute_actions(actions, tracer)

        return False

    async def _execute_actions(self, actions: list[Any], tracer: Optional["Tracer"]) -> bool:
        """Execute actions and return True if agent should finish."""
        for action in actions:
            self.state.add_action(action)

        conversation_history = self.state.get_conversation_history()

        tool_task = asyncio.create_task(
            process_tool_invocations(actions, conversation_history, self.state)
        )
        self._current_task = tool_task

        try:
            should_agent_finish = await tool_task
            self._current_task = None
        except asyncio.CancelledError:
            self._current_task = None
            self.state.add_error("Tool execution cancelled by user")
            raise

        self.state.messages = conversation_history

        if should_agent_finish:
            self.state.set_completed({"success": True})
            if tracer:
                tracer.update_agent_status(self.state.agent_id, "completed")
            if self.non_interactive and self.state.parent_id is None:
                return True
            return True

        return False

    def _check_agent_messages(self, state: AgentState) -> None:  # noqa: PLR0912
        try:
            from phantom.tools.agents_graph.agents_graph_actions import _agent_graph, _agent_messages

            agent_id = state.agent_id
            if not agent_id or agent_id not in _agent_messages:
                return

            messages = _agent_messages[agent_id]
            if messages:
                has_new_messages = False
                for message in messages:
                    if not message.get("read", False):
                        sender_id = message.get("from")

                        if state.is_waiting_for_input():
                            if state.llm_failed:
                                if sender_id == "user":
                                    state.resume_from_waiting()
                                    has_new_messages = True

                                    from phantom.telemetry.tracer import get_global_tracer

                                    tracer = get_global_tracer()
                                    if tracer:
                                        tracer.update_agent_status(state.agent_id, "running")
                            else:
                                state.resume_from_waiting()
                                has_new_messages = True

                                from phantom.telemetry.tracer import get_global_tracer

                                tracer = get_global_tracer()
                                if tracer:
                                    tracer.update_agent_status(state.agent_id, "running")

                        if sender_id == "user":
                            sender_name = "User"
                            state.add_message("user", message.get("content", ""))
                        else:
                            # BUG FIX B: initialise sender_name with a safe fallback
                            # so the f-string below never raises NameError when
                            # sender_id is absent from the agent graph.
                            sender_name = sender_id or "unknown-agent"
                            if sender_id and sender_id in _agent_graph.get("nodes", {}):
                                sender_name = _agent_graph["nodes"][sender_id]["name"]

                            # Escape all dynamic values before embedding into XML to
                            # prevent XML/prompt injection via crafted agent names,
                            # message types, or content.
                            import html as _html

                            safe_sender_name = _html.escape(str(sender_name))
                            safe_sender_id = _html.escape(str(sender_id or ""))
                            safe_msg_type = _html.escape(
                                str(message.get("message_type", "information"))
                            )
                            safe_priority = _html.escape(str(message.get("priority", "normal")))
                            safe_timestamp = _html.escape(str(message.get("timestamp", "")))
                            safe_content = _html.escape(str(message.get("content", "")))

                            message_content = f"""<inter_agent_message>
    <delivery_notice>
        <important>You have received a message from another agent. You should acknowledge
        this message and respond appropriately based on its content. However, DO NOT echo
        back or repeat the entire message structure in your response. Simply process the
        content and respond naturally as/if needed.</important>
    </delivery_notice>
    <sender>
        <agent_name>{safe_sender_name}</agent_name>
        <agent_id>{safe_sender_id}</agent_id>
    </sender>
    <message_metadata>
        <type>{safe_msg_type}</type>
        <priority>{safe_priority}</priority>
        <timestamp>{safe_timestamp}</timestamp>
    </message_metadata>
    <content>
{safe_content}
    </content>
    <delivery_info>
        <note>This message was delivered during your task execution.
        Please acknowledge and respond if needed.</note>
    </delivery_info>
</inter_agent_message>"""
                            state.add_message("user", message_content.strip())

                        message["read"] = True

                if has_new_messages and not state.is_waiting_for_input():
                    from phantom.telemetry.tracer import get_global_tracer

                    tracer = get_global_tracer()
                    if tracer:
                        tracer.update_agent_status(agent_id, "running")

        except (AttributeError, KeyError, TypeError) as e:
            logger.warning("Error checking agent messages: %s", e)

    def _maybe_save_checkpoint(self, tracer: Optional["Tracer"], force: bool = False) -> None:
        """Save a checkpoint if the checkpoint manager is configured and it's time to do so."""
        # Only the root agent (no parent) saves checkpoint state
        if self.state.parent_id is not None:
            return
        checkpoint_mgr = self.config.get("_checkpoint_manager")
        if checkpoint_mgr is None:
            return
        if not force and not checkpoint_mgr.should_save(self.state.iteration):
            return
        try:
            from phantom.checkpoint.checkpoint import CheckpointManager

            cp = CheckpointManager.build(
                run_name=tracer.run_name if tracer else (self.config.get("_run_name") or "unknown"),
                state=self.state,
                tracer=tracer,
                scan_config=tracer.scan_config or {} if tracer else {},
            )
            checkpoint_mgr.save(cp)
            # ── Audit: log checkpoint saved ──────────────────────────────
            from phantom.logging.audit import get_audit_logger as _get_audit_ck
            _audit_ck = _get_audit_ck()
            if _audit_ck:
                _audit_ck.log_checkpoint(
                    agent_id=self.state.agent_id,
                    run_dir=str(checkpoint_mgr.run_dir),
                    iteration=self.state.iteration,
                )
            # ────────────────────────────────────────────────────────────
        except Exception:  # noqa: BLE001
            logger.warning("Checkpoint save failed", exc_info=True)

    def _handle_sandbox_error(
        self,
        error: SandboxInitializationError,
        tracer: Optional["Tracer"],
    ) -> dict[str, Any]:
        error_msg = str(error.message)
        error_details = error.details
        self.state.add_error(error_msg)

        if self.non_interactive:
            self.state.set_completed({"success": False, "error": error_msg})
            if tracer:
                tracer.update_agent_status(self.state.agent_id, "failed", error_msg)
                if error_details:
                    exec_id = tracer.log_tool_execution_start(
                        self.state.agent_id,
                        "sandbox_error_details",
                        {"error": error_msg, "details": error_details},
                    )
                    tracer.update_tool_execution(exec_id, "failed", {"details": error_details})
            # ── Audit: log agent failed (sandbox error) ───────────────────
            from phantom.logging.audit import get_audit_logger as _get_audit_sb
            _audit_sb = _get_audit_sb()
            if _audit_sb:
                _audit_sb.log_agent_failed(
                    agent_id=self.state.agent_id,
                    name=self.state.agent_name,
                    error=error_msg,
                    iterations=self.state.iteration,
                    duration_ms=(__import__('time').monotonic() - getattr(self, '_agent_start_time', __import__('time').monotonic())) * 1000,
                )
            # ─────────────────────────────────────────────────────────────
            return {"success": False, "error": error_msg, "details": error_details}

        self.state.enter_waiting_state()
        if tracer:
            tracer.update_agent_status(self.state.agent_id, "sandbox_failed", error_msg)
            if error_details:
                exec_id = tracer.log_tool_execution_start(
                    self.state.agent_id,
                    "sandbox_error_details",
                    {"error": error_msg, "details": error_details},
                )
                tracer.update_tool_execution(exec_id, "failed", {"details": error_details})

        return {"success": False, "error": error_msg, "details": error_details}

    def _handle_llm_error(
        self,
        error: LLMRequestFailedError,
        tracer: Optional["Tracer"],
    ) -> dict[str, Any] | None:
        error_msg = str(error)
        error_details = getattr(error, "details", None)
        self.state.add_error(error_msg)

        if self.non_interactive:
            self.state.set_completed({"success": False, "error": error_msg})
            if tracer:
                tracer.update_agent_status(self.state.agent_id, "failed", error_msg)
                if error_details:
                    exec_id = tracer.log_tool_execution_start(
                        self.state.agent_id,
                        "llm_error_details",
                        {"error": error_msg, "details": error_details},
                    )
                    tracer.update_tool_execution(exec_id, "failed", {"details": error_details})
            # ── Audit: log agent failed (LLM error) ───────────────────────
            from phantom.logging.audit import get_audit_logger as _get_audit_llme
            _audit_llme = _get_audit_llme()
            if _audit_llme:
                _audit_llme.log_agent_failed(
                    agent_id=self.state.agent_id,
                    name=self.state.agent_name,
                    error=error_msg,
                    iterations=self.state.iteration,
                    duration_ms=(__import__('time').monotonic() - getattr(self, '_agent_start_time', __import__('time').monotonic())) * 1000,
                )
            # ─────────────────────────────────────────────────────────────
            return {"success": False, "error": error_msg}

        self.state.enter_waiting_state(llm_failed=True)
        if tracer:
            tracer.update_agent_status(self.state.agent_id, "llm_failed", error_msg)
            if error_details:
                exec_id = tracer.log_tool_execution_start(
                    self.state.agent_id,
                    "llm_error_details",
                    {"error": error_msg, "details": error_details},
                )
                tracer.update_tool_execution(exec_id, "failed", {"details": error_details})

        return None

    async def _handle_iteration_error(
        self,
        error: RuntimeError | ValueError | TypeError | asyncio.CancelledError,
        tracer: Optional["Tracer"],
    ) -> bool:
        error_msg = f"Error in iteration {self.state.iteration}: {error!s}"
        logger.exception(error_msg)
        self.state.add_error(error_msg)
        if tracer:
            tracer.update_agent_status(self.state.agent_id, "error")
        return True

    def cancel_current_execution(self) -> None:
        self._force_stop = True
        if self._current_task and not self._current_task.done():
            try:
                loop = self._current_task.get_loop()
                loop.call_soon_threadsafe(self._current_task.cancel)
            except RuntimeError:
                self._current_task.cancel()
        self._current_task = None
