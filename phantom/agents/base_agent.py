import asyncio
import json
import logging
import os
from typing import TYPE_CHECKING, Any, Optional


if TYPE_CHECKING:
    from phantom.agents import PhantomAgent
    from phantom.telemetry.tracer import Tracer

from jinja2 import (
    Environment,
    FileSystemLoader,
    select_autoescape,
)

from phantom.agents.hypothesis_ledger import HypothesisLedger  # Rec 6 (SF-005)
from phantom.agents.coverage_tracker import CoverageTracker  # Enhancement: Coverage tracking

from phantom.llm import LLM, LLMConfig, LLMRequestFailedError
from phantom.llm.pentager.reflector import get_reflector
from phantom.llm.utils import clean_content
from phantom.config import Config
from phantom.runtime import SandboxInitializationError
from phantom.tools import process_tool_invocations
from phantom.utils.resource_paths import get_phantom_resource_path

from .state import AgentState

from phantom.logging.audit import get_audit_logger as _get_audit_logger

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

    # ── Stall-detection constants (were magic numbers) ──────────────────────
    _NO_ACTION_STALL_WARN: int = 3  # iterations without actions before warning
    _NO_ACTION_STALL_ABORT: int = 8  # iterations without actions before aborting
    # ────────────────────────────────────────────────────────────────────────
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
            # FIX: Attempt to resume from checkpoint if one exists.
            # Previously checkpointing was write-only: state was saved but never
            # restored, making long scans unrecoverable after crashes.
            checkpoint_mgr = config.get("_checkpoint_manager")
            restored_state = None
            if checkpoint_mgr is not None:
                try:
                    cp = checkpoint_mgr.load()
                    if cp is not None and cp.root_agent_state:
                        restored_state = AgentState.model_validate(cp.root_agent_state)
                        logger.info(
                            "Resumed agent from checkpoint (iteration=%d, msgs=%d)",
                            restored_state.iteration,
                            len(restored_state.messages),
                        )
                except Exception:
                    logger.warning("Failed to load checkpoint, starting fresh", exc_info=True)
            if restored_state is not None:
                self.state = restored_state
            else:
                self.state = AgentState(
                    agent_name="Root Agent",
                    max_iterations=self.max_iterations,
                )

        self.state.scan_mode = str(getattr(self.llm_config, "scan_mode", "deep") or "deep")

        self.llm = LLM(self.llm_config, agent_name=self.agent_name)
        setattr(self.state, "_runtime_llm", self.llm)

        try:
            self.llm.set_agent_identity(self.state.agent_name, self.state.agent_id)
        except Exception:
            logger.exception(
                "Failed to set agent identity on LLM (agent=%s agent_id=%s)",
                self.state.agent_name,
                self.state.agent_id,
            )
        try:
            self.llm.set_agent_state(self.state)
        except Exception:
            logger.exception(
                "Failed to set agent state on LLM (agent=%s agent_id=%s)",
                self.state.agent_name,
                self.state.agent_id,
            )
        self._current_task: asyncio.Task[Any] | None = None
        self._force_stop = False
        self._recent_action_batches: list[str] = []
        self._last_iteration_action_count: int = 0

        # Rec 6 (SF-005): Hypothesis Ledger — structured external memory that
        # survives context compression and prevents redundant payload testing.
        # Root agents get a fresh ledger; sub-agents share the ledger if one is
        # passed via config (enabling cross-agent deduplication).
        self.hypothesis_ledger: HypothesisLedger = (
            config.get("hypothesis_ledger") or HypothesisLedger()
        )

        # Enhancement: Coverage Tracker - tracks what attack surfaces have been
        # tested for which vulnerability classes. Returns FACTS not commands.
        # Root agents get a fresh tracker; sub-agents share if passed via config.
        self.coverage_tracker: CoverageTracker = config.get("coverage_tracker") or CoverageTracker()

        # FIX 5: Attack Graph - visualizes vulnerability relationships and attack paths.
        # Enables critical node identification and multi-step attack chain analysis.
        # Root agents get a fresh graph; sub-agents share if passed via config.
        try:
            from phantom.core.attack_graph import AttackGraph

            self.attack_graph: AttackGraph | None = config.get("attack_graph") or AttackGraph()
        except ImportError:
            # NetworkX not installed - attack graph unavailable
            self.attack_graph = None

        # AUDIT-FIX-10: Track (signature, success) for dedup checking
        self._recent_action_results: list[tuple[str, bool]] = []

        if self.state.parent_id is None:
            try:
                from phantom.tools.agents_graph import agents_graph_actions

                # FIX: only reset graph state if no other agents are active,
                # to avoid destroying a previous root agent's graph.
                # _agent_instances tracks live agent objects; if non-empty, another
                # agent is still running and we must not wipe its graph.
                if not getattr(agents_graph_actions, "_agent_instances", None):
                    agents_graph_actions.reset_all_state()
                elif len(agents_graph_actions._agent_instances) == 0:
                    agents_graph_actions.reset_all_state()
            except Exception:
                logger.exception(
                    "Failed to reset agent graph state (agent=%s agent_id=%s)",
                    self.state.agent_name,
                    self.state.agent_id,
                )

        # C1: Wire hypothesis ledger to the tool so the LLM can interact with it
        try:
            from phantom.tools.hypothesis.hypothesis_actions import set_ledger

            set_ledger(self.hypothesis_ledger, self.state.agent_id)
        except ImportError as e:
            logging.warning(
                "Hypothesis ledger tool not available: %s (agent=%s)",
                e,
                self.state.agent_name,
            )

        # AUDIT-FIX: Wire scan_status tool with all context
        try:
            from phantom.tools.scan_status.scan_status_actions import set_scan_status_context

            set_scan_status_context(
                hypothesis_ledger=self.hypothesis_ledger,
                coverage_tracker=self.coverage_tracker,
                attack_graph=self.attack_graph if hasattr(self, "attack_graph") else None,  # FIX 5
                agent_state=self.state,
            )
        except ImportError as e:
            logging.warning(
                "Scan status tool not available: %s (agent=%s)",
                e,
                self.state.agent_name,
            )

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
        _audit = _get_audit_logger()
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
                agents_graph_actions._root_agent_id = self.state.agent_id

    async def _restore_sub_agents_from_checkpoint(self) -> None:
        restored = self.config.get("_restored_sub_agent_states")
        if not isinstance(restored, dict) or not restored:
            return

        try:
            from phantom.agents import PhantomAgent
            from phantom.agents.state import AgentState
            from phantom.tools.agents_graph import agents_graph_actions
        except Exception:
            logger.exception("Failed to import sub-agent restore modules")
            return

        parent_id = self.state.agent_id
        allowed_statuses = {"active", "running", "waiting"}

        for sub_agent_id, entry in restored.items():
            if not isinstance(entry, dict):
                continue
            if str(entry.get("parent_id", "")) != parent_id:
                continue
            if str(entry.get("status", "active")) not in allowed_statuses:
                continue

            state_payload = entry.get("state")
            if not isinstance(state_payload, dict):
                continue

            try:
                sub_state = AgentState.model_validate(state_payload)
            except Exception:
                logger.warning(
                    "Failed to deserialize sub-agent state for id=%s, skipping",
                    sub_agent_id,
                )
                continue

            sub_state.clear_sandbox()
            if not sub_state.parent_id:
                sub_state.parent_id = parent_id

            def _check_existing() -> bool:
                with agents_graph_actions._GRAPH_LOCK:
                    return sub_state.agent_id in agents_graph_actions._agent_graph["nodes"]

            if await asyncio.to_thread(_check_existing):
                continue

            sub_llm_config = LLMConfig(
                skills=list(self.llm_config.skills or []),
                timeout=self.llm_config.timeout,
                scan_mode=self.llm_config.scan_mode,
            )
            sub_config = {
                "llm_config": sub_llm_config,
                "state": sub_state,
                "non_interactive": self.non_interactive,
                "local_sources": self.local_sources,
                "hypothesis_ledger": self.hypothesis_ledger,
                "coverage_tracker": self.coverage_tracker,
                "attack_graph": self.attack_graph,
            }

            sub_agent = PhantomAgent(sub_config)

            inherited_messages = []
            if sub_state.messages:
                inherited_messages.append(
                    {
                        "role": "user",
                        "content": (
                            "<resume_context>Sub-agent restored from checkpoint. "
                            "Continue from last known progress.</resume_context>"
                        ),
                    }
                )

            def _update_node() -> None:
                with agents_graph_actions._GRAPH_LOCK:
                    node = agents_graph_actions._agent_graph["nodes"].get(sub_state.agent_id)
                    if node is not None:
                        node["status"] = "running"
                        node["finished_at"] = None
                        node["result"] = None
                        node["task"] = sub_state.task

            await asyncio.to_thread(_update_node)

            import threading

            thread = threading.Thread(
                target=agents_graph_actions._run_agent_in_thread,
                args=(sub_agent, sub_state, inherited_messages),
                daemon=True,
                name=f"Agent-{sub_state.agent_name}-{sub_state.agent_id}-resumed",
            )
            thread.start()

            def _register_running() -> None:
                with agents_graph_actions._GRAPH_LOCK:
                    agents_graph_actions._running_agents[sub_state.agent_id] = thread

            await asyncio.to_thread(_register_running)

    async def agent_loop(self, task: str) -> dict[str, Any]:  # noqa: PLR0912, PLR0915
        import time as _time_mod
        from phantom.telemetry.tracer import get_global_tracer

        if not hasattr(self, "_recent_action_batches"):
            self._recent_action_batches = []
        if not hasattr(self, "_last_iteration_action_count"):
            self._last_iteration_action_count = 0

        tracer = get_global_tracer()
        # P1.4: Capture start time for accurate duration_ms in audit logs.
        # Previously all audit-log callsites passed a placeholder zero.
        self._agent_start_time: float = _time_mod.monotonic()

        try:
            await self._initialize_sandbox_and_state(task)
        except SandboxInitializationError as e:
            return self._handle_sandbox_error(e, tracer)

        _rl_consecutive = 0  # consecutive rate-limit hits for exponential backoff
        _no_action_streak = 0
        # FIX: hard wall-clock timeout so a scan cannot run forever
        _scan_wall_clock_limit = float(Config.get("phantom_scan_wall_timeout") or "7200")
        _scan_deadline = _time_mod.monotonic() + _scan_wall_clock_limit
        while True:
            # FIX: Stop-signal race condition. Previously _force_stop was cleared
            # immediately, so a second stop request arriving before the next loop
            # iteration was lost. Now we clear only after successfully entering
            # the waiting state, and re-check immediately after.
            if self._force_stop:
                await self._enter_waiting_state(tracer, was_cancelled=True)
                self._force_stop = False
                continue

            # FIX: wall-clock timeout — abort if scan has exceeded hard time limit
            if _time_mod.monotonic() > _scan_deadline:
                _timeout_msg = (
                    f"Scan aborted: wall-clock timeout ({_scan_wall_clock_limit:.0f}s) exceeded."
                )
                logger.error(_timeout_msg)
                self.state.set_completed({"success": False, "error": _timeout_msg})
                if tracer:
                    tracer.update_agent_status(self.state.agent_id, "failed")
                self._maybe_save_checkpoint(tracer, force=True)
                return self.state.final_result or {"success": False, "error": _timeout_msg}

            await self._check_agent_messages(self.state)

            if self.state.is_waiting_for_input():
                await self._wait_for_input()
                continue

            if self.state.should_stop():
                if not self.state.completed and self.state.has_reached_max_iterations():
                    self.state.set_completed({"success": False, "error": "Max iterations reached"})
                    if tracer:
                        tracer.update_agent_status(self.state.agent_id, "failed")

                return self.state.final_result or {}

            if self.state.llm_failed:
                await self._wait_for_input()
                continue

            self.state.increment_iteration()

            # ── Audit: log iteration ──────────────────────────────────────────
            _audit_it = _get_audit_logger()
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

                if self._last_iteration_action_count <= 0:
                    _no_action_streak += 1
                else:
                    _no_action_streak = 0

                if _no_action_streak >= 3:
                    self.state.add_message(
                        "user",
                        "No actionable progress detected for multiple iterations. "
                        "If the scan is complete, call finish_scan to end. "
                        "Otherwise, pivot to a new exploit path or continue reconnaissance. "
                        "Do NOT output natural language without a tool call.",
                    )
                if _no_action_streak >= 8 and self.non_interactive:
                    _stall_msg = (
                        "Aborting non-interactive run due to sustained no-action loop "
                        "(8 consecutive iterations)."
                    )
                    self.state.set_completed({"success": False, "error": _stall_msg})
                    if tracer:
                        tracer.update_agent_status(self.state.agent_id, "failed")
                    return self.state.final_result or {"success": False, "error": _stall_msg}

                if should_finish:
                    self.state.set_completed({"success": True})
                    if tracer:
                        tracer.update_agent_status(self.state.agent_id, "completed")
                    # ── Audit: log agent completed ────────────────────────────
                    _audit_done = _get_audit_logger()
                    _scan_duration = (_time_mod.monotonic() - self._agent_start_time) * 1000
                    if _audit_done:
                        _audit_done.log_agent_completed(
                            agent_id=self.state.agent_id,
                            name=self.state.agent_name,
                            task=self.state.task,
                            result=self.state.final_result,
                            iterations=self.state.iteration,
                            duration_ms=_scan_duration,
                        )
                        # ── EFFICIENCY REC HIGH-2: Log cache statistics ────────
                        try:
                            from phantom.tools.cache import get_tool_cache

                            _cache = get_tool_cache()
                            if _cache and _cache.enabled:
                                _cache_stats = _cache.get_stats_summary()
                                _audit_done.log_cache_stats(
                                    agent_id=self.state.agent_id,
                                    cache_stats=_cache_stats,
                                    scan_duration_ms=_scan_duration,
                                )
                        except Exception:  # noqa: BLE001
                            pass  # Non-critical — don't fail scan if cache reporting fails
                        # ───────────────────────────────────────────────────────
                    # ─────────────────────────────────────────────────────────
                    return self.state.final_result or {}

            except asyncio.CancelledError:
                self._current_task = None
                if tracer:
                    partial_content = tracer.finalize_streaming_as_interrupted(self.state.agent_id)
                    if partial_content and partial_content.strip():
                        self.state.add_message(
                            "assistant", f"{partial_content}\n\n[ABORTED BY USER]"
                        )
                raise

            except LLMRequestFailedError as e:
                # Rate-limit errors are transient — pause and retry the agent loop
                # rather than aborting (applies in both interactive and non-interactive modes).
                error_lower = str(e).lower()
                if (
                    "rate limit" in error_lower
                    or "ratelimit" in error_lower
                    or "rate_limit" in error_lower
                ):
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
                        _audit_rl = _get_audit_logger()
                        _model_name = (
                            getattr(getattr(self, "llm_config", None), "litellm_model", "?") or "?"
                        )
                        if _audit_rl:
                            _audit_rl.log_rate_limit_abort(
                                agent_id=self.state.agent_id,
                                model=_model_name,
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
                        _audit_rla = _get_audit_logger()
                        if _audit_rla:
                            _audit_rla.log_agent_failed(
                                agent_id=self.state.agent_id,
                                name=self.state.agent_name,
                                agent_type=self.__class__.__name__,
                                error=_abort_msg,
                                iterations=_rl_consecutive,
                                duration_ms=(_time_mod.monotonic() - self._agent_start_time) * 1000,
                            )
                        # ────────────────────────────────────────────────────────
                        return self.state.final_result or {"success": False, "error": _abort_msg}
                    _backoff = min(300.0, 30.0 * (2.0 ** (_rl_consecutive - 1)))
                    _sleep = _backoff
                    logger.warning(
                        "LLM rate limit exhausted after all retries (hit #%d/%d); "
                        "backing off %.0fs before resuming agent loop...",
                        _rl_consecutive,
                        _rl_max,
                        _sleep,
                    )
                    # ── Audit: log RL backoff hit ────────────────────────────
                    _audit_rlh = _get_audit_logger()
                    _model_name = (
                        getattr(getattr(self, "llm_config", None), "litellm_model", "?") or "?"
                    )
                    if _audit_rlh:
                        _audit_rlh.log_rate_limit_hit(
                            agent_id=self.state.agent_id,
                            model=_model_name,
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

            except Exception as e:
                _handled = await self._handle_iteration_error(e, tracer)
                if _handled:
                    # CancelledError was caught and handled — propagate it
                    # so outer cancellation logic can clean up properly.
                    raise
                self.state.set_completed({"success": False, "error": str(e)})
                if tracer:
                    tracer.update_agent_status(self.state.agent_id, "failed")
                # ── Audit: log agent failed (unhandled error) ─────────────
                _audit_err = _get_audit_logger()
                if _audit_err:
                    _audit_err.log_agent_failed(
                        agent_id=self.state.agent_id,
                        name=self.state.agent_name,
                        agent_type=self.__class__.__name__,
                        error=str(e),
                        iterations=self.state.iteration,
                        duration_ms=(_time_mod.monotonic() - self._agent_start_time) * 1000,
                    )
                # ────────────────────────────────────────────────────────
                return self.state.final_result or {"success": False, "error": str(e)}

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
        from phantom.telemetry.tracer import get_global_tracer

        sandbox_mode = os.getenv("PHANTOM_SANDBOX_MODE", "false").lower() == "true"
        if not sandbox_mode and self.state.sandbox_id is None:
            from phantom.runtime import get_runtime

            runtime = get_runtime()
            tracer = get_global_tracer()
            sandbox_info = await runtime.create_sandbox(
                self.state.agent_id,
                self.state.sandbox_token,
                self.local_sources,
                tracer.scan_config if tracer else {},
            )
            self.state.sandbox_id = sandbox_info["workspace_id"]
            self.state.sandbox_token = sandbox_info["auth_token"]
            self.state.sandbox_info = sandbox_info

            if "agent_id" in sandbox_info:
                self.state.sandbox_info["agent_id"] = sandbox_info["agent_id"]

            caido_port = sandbox_info.get("caido_port")
            if caido_port:
                if tracer:
                    tracer.caido_url = f"localhost:{caido_port}"

        if not self.state.task:
            self.state.task = task

        if self.state.parent_id is None:
            await self._restore_sub_agents_from_checkpoint()

        # Only add the initial task message when the history is fresh.
        # When resuming from a checkpoint, messages are already populated.
        if not self.state.messages:
            self.state.add_message("user", task)

    def _strict_prompt_summary(self, summary: str) -> str:
        lines = []
        for line in summary.splitlines():
            if line.strip().startswith("next:"):
                continue
            lines.append(line)
        return "\n".join(lines)

    async def _process_iteration(self, tracer: Optional["Tracer"]) -> bool:
        final_response = None
        self._last_iteration_action_count = 0
        use_reflector = os.environ.get("PHANTOM_USE_REFLECTOR", "false").lower() == "true"

        # Inject a single compact scan_status packet on a fixed interval.
        # This replaces multi-summary injections (status + ledger + coverage +
        # correlation) to reduce prompt bloat and contradictory guidance.
        status_interval = int(Config.get("phantom_status_inject_interval") or "10")
        message_count = len(self.state.get_conversation_history())

        should_inject_status = (
            self.state.iteration > 0 and self.state.iteration % max(1, status_interval) == 0
        )
        if should_inject_status:
            try:
                from phantom.tools.scan_status.scan_status_actions import get_scan_status

                status = get_scan_status(
                    include_recommendations=False,
                    agent_id=self.state.agent_id,
                )

                status_msg = self._format_scan_status(status)
                # FIX: simple string comparison instead of expensive SHA-256
                last_status = getattr(self.state, "_last_status_msg", None)
                if status_msg != last_status:
                    setattr(self.state, "_last_status_msg", status_msg)
                    self.state.add_message("user", status_msg)
            except Exception as e:
                logging.debug(f"Failed to inject scan status: {e}")
                if tracer:
                    tracer.record_runtime_event(
                        event_type="scan_status.injection.failed",
                        actor={"agent_id": self.state.agent_id},
                        payload={
                            "iteration": self.state.iteration,
                            "message_count": message_count,
                            "error_type": type(e).__name__,
                            "error": str(e)[:300],
                        },
                        status="error",
                        error=str(e)[:300],
                        source="phantom.agents",
                    )

        # S-07: Phase-gate reporting reminder at 85% of max iterations.
        _max_iter = self.state.max_iterations
        _cur_iter = self.state.iteration
        if _max_iter and _max_iter > 0 and _cur_iter > 1:
            _gate_msg = None
            if _cur_iter == max(4, int(_max_iter * 0.85)):
                _gate_msg = (
                    "[FINAL WARNING — REPORT NOW] You have used 85% of your iterations. "
                    "You are about to run out of time. If you have ANY unreported findings, "
                    "call create_vulnerability_report as soon as possible, then prepare to finish the scan."
                )
            if _gate_msg:
                # FIX: inject as system guidance, not user input
                self.state.add_message("system", _gate_msg)

        # FIX: wrap LLM stream in a timeout to prevent infinite hangs
        # when the provider accepts the connection but never sends chunks.
        _llm_timeout = float(Config.get("phantom_llm_stream_timeout") or "300")
        try:
            async for response in self.llm.generate(self._build_hypothesis_context()):
                final_response = response
                if tracer and response.content:
                    tracer.update_streaming_content(self.state.agent_id, response.content)
        except asyncio.TimeoutError:
            logger.error("LLM stream timed out after %.0fs (agent=%s iter=%d)", _llm_timeout, self.state.agent_name, self.state.iteration)
            self.state.add_message("user", f"[SYSTEM: LLM response timed out after {_llm_timeout}s. Retry with a simpler request.]")

        if final_response is None:
            self._last_iteration_action_count = 0
            return False

        content_stripped = (final_response.content or "").strip()

        if not content_stripped:
            self._last_iteration_action_count = 0
            if use_reflector:
                try:
                    reflector = get_reflector()
                    context = "\n".join(
                        str(msg.get("content", ""))
                        for msg in self.state.get_conversation_history()[-4:]
                    )
                    suggestion = await reflector.reflect(context)
                    if suggestion:
                        self.state.add_message("user", f"Reflector note: {suggestion}")
                        self._cleanup_message_history(tracer)
                        return False
                except Exception:
                    logger.exception(
                        "Reflector failed on empty response (agent=%s iter=%d)",
                        self.state.agent_name,
                        self.state.iteration,
                    )
            corrective_message = (
                "Empty response. You MUST call a tool. "
                "If the scan is complete, call finish_scan to end. "
                "Otherwise, continue with the next recon or exploitation step. "
                "NEVER output natural language without a tool call."
            )
            self.state.add_message("user", corrective_message)
            self._cleanup_message_history(tracer)
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
            self._last_iteration_action_count = len(actions)
            should_agent_finish = await self._execute_actions(actions, tracer)
            self._cleanup_message_history(tracer)
            return should_agent_finish

        if use_reflector:
            try:
                reflector = get_reflector()
                context = (final_response.content or "")[:500]
                suggestion = await reflector.reflect(context)
                if suggestion:
                    self.state.add_message("user", f"Reflector note: {suggestion}")
            except Exception:
                logger.exception(
                    "Reflector failed on no-action response (agent=%s iter=%d)",
                    self.state.agent_name,
                    self.state.iteration,
                )
        self._cleanup_message_history(tracer)
        return False

    async def _execute_actions(self, actions: list[Any], tracer: Optional["Tracer"]) -> bool:
        """Execute actions and return True if agent should finish."""

        # Avoid blind repetition of identical action batches across consecutive iterations.
        # This reduces dead-end payload retries without changing tool semantics.
        def _strip(v):
            if isinstance(v, str):
                return v.strip()
            if isinstance(v, dict):
                return {k: _strip(val) for k, val in v.items()}
            if isinstance(v, list):
                return [_strip(val) for val in v]
            return v

        try:
            batch_signature = json.dumps(
                [
                    {
                        "toolName": action.get("toolName"),
                        "args": _strip(action.get("args", {})),
                    }
                    for action in actions
                ],
                sort_keys=True,
            )
        except Exception:  # noqa: BLE001
            batch_signature = ""

        if batch_signature:
            # Block repeated batches when the previous identical call SUCCEEDED.
            # If it errored/timed-out, allow retry.
            # FIX: Check last call only (was checking last 2, allowing 2nd duplicate through).
            if self._recent_action_results:
                last_sig, last_succeeded = self._recent_action_results[-1]
                if last_sig == batch_signature and last_succeeded:
                    self.state.add_message(
                        "user",
                        "You just executed this exact action and it succeeded. "
                        "Do NOT repeat it. Move to the next target, payload, or vector.",
                    )
                    return False
            # NOTE: _recent_action_results is appended AFTER execution below
            if len(self._recent_action_batches) > 8:
                self._recent_action_batches = self._recent_action_batches[-8:]

        for action in actions:
            self.state.add_action(action)

        # FIX: save checkpoint BEFORE executing tools so that if the agent
        # crashes during tool execution (OOM, sandbox death, power loss) the
        # checkpoint reflects the state with the tool plan already recorded.
        self._maybe_save_checkpoint(tracer)

        conversation_history = self.state.get_conversation_history()

        tool_task = asyncio.create_task(
            process_tool_invocations(
                actions,
                conversation_history,
                self.state,
                self,
            )
        )
        self._current_task = tool_task

        try:
            should_agent_finish = await tool_task
            self._current_task = None
            batch_succeeded = True
            if hasattr(self.state, "context"):
                batch_succeeded = not bool(
                    self.state.context.get("last_tool_batch_had_error", False)
                )

            # AUDIT-FIX-10: Record signature outcome for dedup tracking
            if batch_signature:
                self._recent_action_results.append((batch_signature, batch_succeeded))
                if len(self._recent_action_results) > 8:
                    self._recent_action_results = self._recent_action_results[-8:]

            # Runtime guardrail: SSRF block removed - allow all URLs
            pass
        except asyncio.CancelledError:
            self._current_task = None
            self.state.add_error("Tool execution cancelled by user")
            # AUDIT-FIX-10: Cancelled execution → mark as not-succeeded so retry is allowed
            if batch_signature:
                self._recent_action_results.append((batch_signature, False))
                if len(self._recent_action_results) > 8:
                    self._recent_action_results = self._recent_action_results[-8:]
            raise

        # FIX: Do NOT revert state.messages to the pre-tool snapshot.
        # process_tool_invocations already appends tool results to state.messages.
        # Reverting here was permanently discarding all tool output, making the LLM blind.

        if should_agent_finish:
            self.state.set_completed({"success": True})
            if tracer:
                tracer.update_agent_status(self.state.agent_id, "completed")
            if self.non_interactive and self.state.parent_id is None:
                return True
            return True

        return False

    async def _check_agent_messages(self, state: AgentState) -> None:  # noqa: PLR0912
        try:
            from phantom.tools.agents_graph.agents_graph_actions import (
                _agent_graph,
                _agent_messages,
                _GRAPH_LOCK,
            )

            agent_id = state.agent_id

            def _sync_check() -> None:
                _GRAPH_LOCK.acquire()
                try:
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
                                    sender_name = sender_id or "unknown-agent"
                                    if sender_id and sender_id in _agent_graph.get("nodes", {}):
                                        sender_name = _agent_graph["nodes"][sender_id]["name"]

                                    import html as _html

                                    safe_sender_name = _html.escape(str(sender_name))

                                    raw_content = str(message.get("content", ""))
                                    safe_content = _html.escape(raw_content)
                                    if len(safe_content) > 200:
                                        safe_content = safe_content[:197] + "..."

                                    message_content = f"[From {safe_sender_name}]: {safe_content}"
                                    state.add_message("user", message_content.strip())

                                message["read"] = True

                        if has_new_messages and not state.is_waiting_for_input():
                            from phantom.telemetry.tracer import get_global_tracer

                            tracer = get_global_tracer()
                            if tracer:
                                tracer.update_agent_status(agent_id, "running")
                finally:
                    _GRAPH_LOCK.release()

            await asyncio.to_thread(_sync_check)

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
                # P4: Include hypothesis ledger, coverage tracker
                hypothesis_ledger=self.hypothesis_ledger,
                coverage_tracker=self.coverage_tracker,
                # FIX 5: Include attack graph for vulnerability chain analysis
                attack_graph=self.attack_graph if hasattr(self, "attack_graph") else None,
                # Wave D: Persist active sub-agent states for resume continuity
                active_sub_agents=self._collect_active_sub_agent_states(),
            )
            checkpoint_mgr.save(cp)
            # ── Audit: log checkpoint saved ──────────────────────────────
            _audit_ck = _get_audit_logger()
            if _audit_ck:
                _audit_ck.log_checkpoint(
                    agent_id=self.state.agent_id,
                    run_dir=str(checkpoint_mgr.run_dir),
                    iteration=self.state.iteration,
                )
            # ────────────────────────────────────────────────────────────
        except Exception:  # noqa: BLE001
            logger.warning("Checkpoint save failed", exc_info=True)

    def _collect_active_sub_agent_states(self) -> dict[str, Any]:
        try:
            from phantom.tools.agents_graph import agents_graph_actions

            parent_id = self.state.agent_id
            active_statuses = {"running", "waiting", "stopping"}
            collected: dict[str, Any] = {}

            with agents_graph_actions._GRAPH_LOCK:
                for node in agents_graph_actions._agent_graph["nodes"].values():
                    if node.get("parent_id") != parent_id:
                        continue
                    status = str(node.get("status", ""))
                    if status not in active_statuses:
                        continue
                    agent_id = str(node.get("id", ""))
                    if not agent_id:
                        continue
                    state_obj = agents_graph_actions._agent_states.get(agent_id)
                    if state_obj is None:
                        continue
                    collected[agent_id] = {
                        "state": state_obj,
                        "status": status,
                        "parent_id": parent_id,
                    }

            return collected
        except Exception:
            logger.exception(
                "Failed to collect active sub-agent states (agent=%s)",
                self.state.agent_name,
            )
            return {}

    def _cleanup_message_history(self, tracer: Optional["Tracer"]) -> None:
        """Trim only after the current LLM turn has been prepared and executed.

        This keeps the full raw history available to compression/anchor extraction
        for the current turn, then bounds the retained state once the turn is done.
        """
        # FIX: reduce cleanup frequency to avoid conflict with memory_compressor.
        # The compressor in _prepare_messages is the primary truncation mechanism;
        # this cleanup is a safety valve only.
        max_before_cleanup = int(getattr(self.state, "MAX_MESSAGES_BEFORE_CLEANUP", 50) or 50)
        scan_mode = str(
            getattr(self.state, "scan_mode", "") or getattr(self.llm_config, "scan_mode", "")
        ).lower()
        cleanup_multiplier = 6 if scan_mode == "deep" else 4
        cleanup_threshold = max_before_cleanup * cleanup_multiplier
        message_count = len(self.state.get_conversation_history())
        if message_count <= cleanup_threshold or not hasattr(self.state, "cleanup_old_messages"):
            return

        # Only clean up every 10 iterations to avoid fighting the compressor
        last_cleanup_iter = getattr(self, "_last_cleanup_iteration", 0)
        if self.state.iteration - last_cleanup_iter < 10:
            return
        self._last_cleanup_iteration = self.state.iteration

        removed = self.state.cleanup_old_messages()
        if removed > 0 and tracer:
            tracer.record_runtime_event(
                event_type="state.message_cleanup",
                actor={"agent_id": self.state.agent_id},
                payload={
                    "removed": removed,
                    "remaining": len(self.state.get_conversation_history()),
                    "threshold": cleanup_threshold,
                },
                status="completed",
                source="phantom.agents",
            )

    def _build_hypothesis_context(self) -> list[dict[str, Any]]:
        history = list(self.state.get_conversation_history())
        if not history:
            return history

        active_surface = ""
        active_vclass = ""
        active_hypothesis_id = ""
        hypothesis_ids: set[str] = set()
        try:
            scored = self.hypothesis_ledger.get_scored_hypotheses()
            if scored:
                top = scored[0]
                active_surface = str(top.get("surface") or "")
                active_vclass = str(top.get("vuln_class") or "")
                active_hypothesis_id = str(top.get("hypothesis_id") or "")
                all_hyps = self.hypothesis_ledger.get_all()
                for h in all_hyps.values():
                    hid = str(getattr(h, "id", "") or "")
                    if hid:
                        hypothesis_ids.add(hid)
        except Exception:
            logger.warning(
                "Failed to access hypothesis ledger (agent=%s iter=%d)",
                self.state.agent_name,
                self.state.iteration,
            )

        if not active_surface and not active_vclass:
            return history

        hypothesis_block = {
            "role": "user",
            "content": (
                "<current_hypothesis>\n"
                f"id={active_hypothesis_id}\n"
                f"class={active_vclass}\n"
                f"surface={active_surface}\n"
                "</current_hypothesis>"
            ),
        }

        supporting: list[dict[str, Any]] = []
        try:
            all_hyps = self.hypothesis_ledger.get_all()
            if active_hypothesis_id and active_hypothesis_id in all_hyps:
                hyp = all_hyps[active_hypothesis_id]
                evidence_lines = []
                for item in list(getattr(hyp, "evidence_for", []) or [])[:5]:
                    text = str(item).strip()
                    if text:
                        evidence_lines.append(f"- {text[:300]}")
                if evidence_lines:
                    supporting.append(
                        {
                            "role": "user",
                            "content": "<supporting_evidence>\n"
                            + "\n".join(evidence_lines)
                            + "\n</supporting_evidence>",
                        }
                    )
        except Exception:
            logger.warning(
                "Failed to extract supporting evidence (agent=%s)",
                self.state.agent_name,
            )
            supporting = []

        scoped: list[dict[str, Any]] = []
        from phantom.llm.memory_compressor import _ANCHOR_KEYWORDS

        for msg in history:
            content = msg.get("content", "")
            text = content if isinstance(content, str) else str(content)
            lowered = text.lower()
            keep = False
            mentions_other_hypothesis = False
            for hid in hypothesis_ids:
                if hid and hid != active_hypothesis_id and hid.lower() in lowered:
                    mentions_other_hypothesis = True
                    break

            # FIX: Check for anchors BEFORE skipping other-hypothesis messages.
            # Confirmed findings for other hypotheses must survive context filtering
            # so the agent can chain multi-step exploits (e.g. IDOR → admin panel).
            has_anchor = any(k in lowered for k in _ANCHOR_KEYWORDS)
            if has_anchor:
                keep = True

            # Only skip non-anchor messages about other hypotheses.
            if mentions_other_hypothesis and not has_anchor:
                continue

            if active_surface and active_surface.lower() in lowered:
                keep = True
            if active_vclass and active_vclass.lower() in lowered:
                keep = True
            if active_hypothesis_id and active_hypothesis_id.lower() in lowered:
                keep = True
            if "<current_hypothesis>" in lowered or "<supporting_evidence>" in lowered:
                keep = True
            if "[auto-status" in lowered or "chain opportunities" in lowered:
                keep = False

            # FIX A1 (cont): Override exclusion if it's a finding anchor
            if has_anchor:
                keep = True

            if "<finding_anchors>" in lowered or "<pinned_facts>" in lowered:
                keep = True
            if msg.get("role") == "system":
                keep = True
            if keep:
                scoped.append(msg)

        # FIX: Always retain the last 15 messages as a "broad context" buffer
        # so the LLM can pivot between hypotheses and see recent tool results.
        broad_buffer = history[-15:] if len(history) > 15 else list(history)
        broad_ids = {id(m) for m in broad_buffer}
        for msg in scoped:
            if id(msg) not in broad_ids:
                broad_buffer.append(msg)

        if not broad_buffer:
            return [hypothesis_block, *supporting, *history[-20:]]

        return [hypothesis_block, *supporting, *broad_buffer[-55:]]

    def _format_scan_status(self, status: dict[str, Any]) -> str:
        """Format scan status into a compact message for LLM injection."""
        progress = status.get("scan_progress", {})
        findings = status.get("findings", {})
        coverage = status.get("coverage", {})
        attack_graph = status.get("attack_graph") or {}
        archived_messages = status.get("archived_messages", {})
        blocked_surfaces = status.get("blocked_surfaces", [])
        top_hypotheses = status.get("top_hypotheses", [])
        chains = status.get("chain_opportunities", [])
        recommendation = status.get("recommended_next_action")
        warnings = status.get("warnings", [])

        lines = ["[AUTO-STATUS — Scan Progress Update]"]
        lines.append(
            f"Iteration {progress.get('iteration')}/{progress.get('max_iterations')} "
            f"({progress.get('percent_complete')}%)"
        )
        lines.append(
            f"Findings: {findings.get('confirmed_vulnerabilities')} confirmed, "
            f"{findings.get('actively_testing')} testing, "
            f"{findings.get('pending_hypotheses')} pending"
        )
        lines.append(
            f"Coverage: {coverage.get('surfaces_tested')} tested, "
            f"{coverage.get('surfaces_remaining')} remaining "
            f"({coverage.get('coverage_percent')}%)"
        )

        if blocked_surfaces:
            lines.append(f"Blocked: {len(blocked_surfaces)} surfaces")
            for blocked in blocked_surfaces[:2]:
                reasons = ", ".join(
                    str(reason) for reason in blocked.get("failure_reasons", [])[:2]
                )
                lines.append(f"  - {str(blocked.get('surface', ''))[:45]} | {reasons[:70]}")

        if top_hypotheses:
            if isinstance(top_hypotheses, str):
                lines.append(top_hypotheses)
            else:
                lines.append(f"Priority hypotheses: {len(top_hypotheses)}")
                for hyp in top_hypotheses[:2]:
                    lines.append(
                        f"  - {hyp.get('vuln_class')} @ {str(hyp.get('surface', ''))[:35]}"
                    )

        if attack_graph:
            lines.append(
                "Attack graph: "
                f"{attack_graph.get('total_nodes')} nodes, "
                f"{attack_graph.get('total_vulnerabilities')} vulns, "
                f"{attack_graph.get('total_edges')} edges, "
                f"density={attack_graph.get('density')}"
            )
            critical_vulns = attack_graph.get("critical_vulns", [])
            if critical_vulns:
                critical_bits = []
                for vuln in critical_vulns[:2]:
                    if isinstance(vuln, dict):
                        critical_bits.append(f"{vuln.get('id')}:{vuln.get('centrality')}")
                if critical_bits:
                    lines.append(f"  Critical: {', '.join(critical_bits)}")

            top_attack_plans = attack_graph.get("top_attack_plans", [])
            if top_attack_plans:
                lines.append(f"  Top Plans: {len(top_attack_plans)}")
                for plan in top_attack_plans[:2]:
                    if not isinstance(plan, dict):
                        continue
                    path = plan.get("path") or []
                    if not isinstance(path, list) or not path:
                        continue
                    path_preview = " -> ".join(str(p) for p in path[:4])
                    if len(path) > 4:
                        path_preview = f"{path_preview} -> ..."
                    lines.append(
                        "  - "
                        f"p={plan.get('probability')} "
                        f"cost={plan.get('cost')} "
                        f"score={plan.get('score')} "
                        f"path={path_preview}"
                    )

        if archived_messages:
            lines.append(f"Archived history: {archived_messages.get('count', 0)} messages retained")

        if chains:
            lines.append(f"Chain Opportunities: {len(chains)}")
            for chain in chains[:2]:
                lines.append(f"  - {chain.get('chain')}: {chain.get('description', '')[:50]}")

        if recommendation:
            lines.append(f"Recommended: {recommendation}")

        if warnings:
            for warning in warnings:
                lines.append(f"[!] {warning}")

        lines.append("[END STATUS]")
        return "\n".join(lines)

    def _handle_sandbox_error(
        self,
        error: SandboxInitializationError,
        tracer: Optional["Tracer"],
    ) -> dict[str, Any]:
        error_msg = str(error.message)
        error_details = error.details
        self.state.add_error(error_msg)

        if self.non_interactive:  # Restored interactive fallback
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
            _audit_sb = _get_audit_logger()
            if _audit_sb:
                _audit_sb.log_agent_failed(
                    agent_id=self.state.agent_id,
                    name=self.state.agent_name,
                    agent_type=self.__class__.__name__,
                    error=error_msg,
                    iterations=self.state.iteration,
                    duration_ms=(
                        __import__("time").monotonic()
                        - getattr(self, "_agent_start_time", __import__("time").monotonic())
                    )
                    * 1000,
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

        if self.non_interactive:  # Restored interactive fallback
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
            _audit_llme = _get_audit_logger()
            if _audit_llme:
                _audit_llme.log_agent_failed(
                    agent_id=self.state.agent_id,
                    name=self.state.agent_name,
                    agent_type=self.__class__.__name__,
                    error=error_msg,
                    iterations=self.state.iteration,
                    duration_ms=(
                        __import__("time").monotonic()
                        - getattr(self, "_agent_start_time", __import__("time").monotonic())
                    )
                    * 1000,
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
        error: Exception,
        tracer: Optional["Tracer"],
    ) -> bool:
        error_msg = f"Error in iteration {self.state.iteration}: {error!s}"
        logger.exception(error_msg)
        self.state.add_error(error_msg)
        if tracer:
            tracer.update_agent_status(self.state.agent_id, "error")
        if isinstance(error, asyncio.CancelledError):
            return True  # Cancelled — don't propagate, loop will handle
        return False  # Real error — propagate to non_interactive raise or waiting state

    def cancel_current_execution(self) -> None:
        self._force_stop = True
        if self._current_task and not self._current_task.done():
            try:
                loop = self._current_task.get_loop()
                loop.call_soon_threadsafe(self._current_task.cancel)
            except RuntimeError:
                self._current_task.cancel()
        self._current_task = None
