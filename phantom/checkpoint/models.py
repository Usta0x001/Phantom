"""Pydantic model for scan checkpoint data."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class CheckpointData(BaseModel):
    """Full scan state persisted to disk so a scan can be resumed after any interruption."""

    version: str = "1"
    run_name: str
    status: str = "in_progress"
    # in_progress | interrupted | completed | crashed
    interruption_reason: str | None = None

    # ── Agent progress ───────────────────────────────────────────────────────
    iteration: int = 0
    task_description: str = ""
    scan_config: dict[str, Any] = Field(default_factory=dict)

    # Full AgentState dump — contains the entire message history for the root agent.
    # Sub-agents are ephemeral; their output is already embedded in the root history.
    root_agent_state: dict[str, Any] = Field(default_factory=dict)

    # ── Findings already discovered ─────────────────────────────────────────
    vulnerability_reports: list[dict[str, Any]] = Field(default_factory=list)
    final_result: dict[str, Any] | None = None

    # ── Runtime metrics snapshot at checkpoint time ──────────────────────────
    llm_stats_at_checkpoint: dict[str, Any] = Field(default_factory=dict)
    # Format mirrors Tracer.get_total_llm_stats():
    # {total: {input_tokens, output_tokens, cached_tokens, cost, requests}, total_tokens: int}

    # Per-model breakdown for analytics (keyed by model name)
    per_model_stats: dict[str, dict[str, Any]] = Field(default_factory=dict)

    # Compression calls separated from agent calls
    compression_calls: int = 0
    agent_calls: int = 0
    error_calls: int = 0
