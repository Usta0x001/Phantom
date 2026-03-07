from typing import Any

from phantom.tools.registry import register_tool

# BUG-018 FIX: Persistent thought storage so reasoning chains survive
# memory compression and can be reviewed in audit logs.
_thought_log: list[dict[str, Any]] = []
_MAX_THOUGHTS = 500


@register_tool(sandbox_execution=False)
def think(thought: str, agent_state: Any = None) -> dict[str, Any]:
    """Record a reasoning step. Stored persistently in agent state and thought log."""
    try:
        if not thought or not thought.strip():
            return {"success": False, "message": "Thought cannot be empty"}

        cleaned = thought.strip()
        entry = {
            "thought": cleaned,
            "char_count": len(cleaned),
        }

        # Store in module-level log (survives memory compression)
        if len(_thought_log) >= _MAX_THOUGHTS:
            _thought_log[:] = _thought_log[-_MAX_THOUGHTS // 2 :]
        _thought_log.append(entry)

        # Store in agent state findings ledger so it persists across checkpoints
        if agent_state is not None and hasattr(agent_state, "add_finding"):
            # Prefix with [THOUGHT] so the ledger distinguishes reasoning from findings
            agent_state.add_finding(f"[THOUGHT] {cleaned[:300]}")

        return {
            "success": True,
            "message": f"Thought recorded ({len(cleaned)} chars, {len(_thought_log)} total)",
        }

    except (ValueError, TypeError) as e:
        return {"success": False, "message": f"Failed to record thought: {e!s}"}


def get_thought_log() -> list[dict[str, Any]]:
    """Retrieve the full thought log for audit/debugging."""
    return list(_thought_log)
