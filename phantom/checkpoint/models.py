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
    root_agent_state: dict[str, Any] = Field(default_factory=dict)
    
    # FIX ISSUE#6: Sub-agent states for active sub-agents at checkpoint time
    # Previously, sub-agents were considered ephemeral and their state was lost on crash.
    # This caused massive token waste when resuming - all sub-agent work had to be redone.
    # Now we save active sub-agent states so they can be resumed from where they left off.
    # Format: {agent_id: {state_dict, status: "active"|"completed", parent_id: str}}
    sub_agent_states: dict[str, dict[str, Any]] = Field(default_factory=dict)

    # ── Findings already discovered ─────────────────────────────────────────
    vulnerability_reports: list[dict[str, Any]] = Field(default_factory=list)
    final_result: dict[str, Any] | None = None

    # ── Runtime metrics snapshot at checkpoint time ──────────────────────────
    llm_stats_at_checkpoint: dict[str, Any] = Field(default_factory=dict)
    # Format mirrors Tracer.get_total_llm_stats():
    # {total: {input_tokens, output_tokens, cached_tokens, cost, requests, completed_requests}, total_tokens: int}

    # Per-model breakdown for analytics (keyed by model name)
    per_model_stats: dict[str, dict[str, Any]] = Field(default_factory=dict)

    # Compression calls separated from agent calls
    compression_calls: int = 0
    agent_calls: int = 0
    error_calls: int = 0

    # S-05: Conversation summary for post-mortem debugging.
    # Stores last N messages (role + truncated content) to allow trace analysis
    # without bloating the checkpoint with full conversation history.
    conversation_summary: list[dict[str, str]] = Field(default_factory=list)

    # ISO timestamp of when this checkpoint was saved.
    saved_at: str | None = None
    
    # P4 ENHANCEMENT: Hypothesis Ledger and Correlation Engine state
    # These critical components track testing progress and vulnerability chains.
    # Without checkpointing them, scan resume would lose:
    # - Which hypotheses have been tested (causes redundant fuzzing)
    # - Which payloads confirmed vulnerabilities (loses validation state)
    # - Detected vulnerability chains (SSRF→cloud metadata, SQLi→RCE)
    
    # Hypothesis ledger state (dict of hypothesis_id -> Hypothesis.to_dict())
    hypothesis_ledger_state: dict[str, dict[str, Any]] = Field(default_factory=dict)
    
    # Coverage tracker state (attack surfaces tested per vuln class)
    coverage_tracker_state: dict[str, Any] = Field(default_factory=dict)
