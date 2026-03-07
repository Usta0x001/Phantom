from typing import Any, Literal

from phantom.core.python_sandbox import CodeValidationError, validate_python_code
from phantom.tools.registry import register_tool


PythonAction = Literal["new_session", "execute", "close", "list_sessions"]


@register_tool
def python_action(
    action: PythonAction,
    code: str | None = None,
    timeout: int = 30,
    session_id: str | None = None,
) -> dict[str, Any]:
    from .python_manager import get_python_session_manager

    def _validate_code(action_name: str, code: str | None) -> None:
        if not code:
            raise ValueError(f"code parameter is required for {action_name} action")

    def _validate_action(action_name: str) -> None:
        raise ValueError(f"Unknown action: {action_name}")

    manager = get_python_session_manager()

    try:
        match action:
            case "new_session":
                # V2-TOOL-001 FIX: Validate code before creating session
                if code:
                    violations = validate_python_code(code)
                    if violations:
                        return {
                            "stderr": f"Code validation failed: {'; '.join(violations[:5])}",
                            "session_id": session_id,
                            "stdout": "",
                            "is_running": False,
                        }
                return manager.create_session(session_id, code, timeout)

            case "execute":
                _validate_code(action, code)
                assert code is not None
                # V2-TOOL-001 FIX: AST-based validation before execution
                # Blocks dangerous imports (os, subprocess, socket, etc.),
                # unsafe builtins (exec, eval, __import__), and dangerous
                # attribute access (__class__, __subclasses__, etc.)
                violations = validate_python_code(code)
                if violations:
                    return {
                        "stderr": f"Code validation failed: {'; '.join(violations[:5])}",
                        "session_id": session_id,
                        "stdout": "",
                        "is_running": False,
                    }
                return manager.execute_code(session_id, code, timeout)

            case "close":
                return manager.close_session(session_id)

            case "list_sessions":
                return manager.list_sessions()

            case _:
                _validate_action(action)  # type: ignore[unreachable]

    except (ValueError, RuntimeError) as e:
        return {"stderr": str(e), "session_id": session_id, "stdout": "", "is_running": False}
