from typing import Any


def think(thought: str) -> dict[str, Any]:
    try:
        if not thought or not thought.strip():
            return {"success": False, "message": "Thought cannot be empty"}

        return {
            "success": True,
            "message": f"Thought recorded successfully with {len(thought.strip())} characters",
        }

    except (ValueError, TypeError) as e:
        return {"success": False, "message": f"Failed to record thought: {e!s}"}
