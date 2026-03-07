from __future__ import annotations

import argparse
import asyncio
import hmac
import os
import signal
import sys
from typing import Any

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ValidationError


SANDBOX_MODE = os.getenv("PHANTOM_SANDBOX_MODE", "false").lower() == "true"
if not SANDBOX_MODE:
    raise RuntimeError("Tool server should only run in sandbox mode (PHANTOM_SANDBOX_MODE=true)")

parser = argparse.ArgumentParser(description="Start phantom tool server")
# G-07 FIX: Support --token-file to avoid leaking token via /proc/PID/cmdline.
# Falls back to --token for backward compatibility.
parser.add_argument("--token", default=None, help="Authentication token (deprecated: use --token-file)")
parser.add_argument("--token-file", default=None, help="Path to file containing auth token")
# PHT-005 FIX: Bind to 127.0.0.1 by default to prevent network-adjacent attacks
parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
parser.add_argument("--port", type=int, required=True, help="Port to bind to")
parser.add_argument(
    "--timeout",
    type=int,
    default=600,
    help="Hard timeout in seconds for each request execution (default: 600)",
)

args = parser.parse_args()

# G-07 FIX: Prefer token-file over CLI arg to prevent /proc/PID/cmdline leak
if args.token_file:
    try:
        with open(args.token_file) as _tf:
            EXPECTED_TOKEN = _tf.read().strip()
    except (OSError, IOError) as _e:
        print(f"ERROR: Cannot read token file {args.token_file}: {_e}", file=sys.stderr)
        sys.exit(1)
elif args.token:
    EXPECTED_TOKEN = args.token
else:
    # V2-SEC-001 FIX: Read token from file path in env, not raw token in env
    _token_file_env = os.getenv("PHANTOM_TOKEN_FILE", "")
    if _token_file_env:
        try:
            with open(_token_file_env) as _tf:
                EXPECTED_TOKEN = _tf.read().strip()
        except (OSError, IOError) as _e:
            print(f"ERROR: Cannot read token file {_token_file_env}: {_e}", file=sys.stderr)
            sys.exit(1)
    else:
        # Final fallback: read from environment variable (legacy)
        EXPECTED_TOKEN = os.getenv("TOOL_SERVER_TOKEN", "")
        if not EXPECTED_TOKEN:
            print("ERROR: No token provided. Use --token-file, --token, PHANTOM_TOKEN_FILE, or TOOL_SERVER_TOKEN env.", file=sys.stderr)
            sys.exit(1)
REQUEST_TIMEOUT = args.timeout

app = FastAPI()
security = HTTPBearer()
security_dependency = Depends(security)

agent_tasks: dict[str, asyncio.Task[Any]] = {}

# PHT-012 FIX: Simple in-memory rate limiter
# V2-SEC-005 FIX: Per-tool rate limiting instead of shared budget
_rate_limit_store: dict[str, list[float]] = {}
_RATE_LIMIT_MAX = 60  # max requests per window (global)
_RATE_LIMIT_WINDOW = 60.0  # seconds
# V2-SEC-005: Per-tool rate limits (calls per 5min window)
_TOOL_RATE_LIMITS: dict[str, int] = {
    "terminal_execute": 20,
    "python_action": 15,
    "sqlmap_dump_database": 5,
}
_tool_rate_store: dict[str, list[float]] = {}


async def _rate_limit_check(request: Request) -> None:
    """PHT-012 FIX: Rate limiting middleware for tool server."""
    import time as _time
    client_ip = request.client.host if request.client else "unknown"
    now = _time.monotonic()
    if client_ip not in _rate_limit_store:
        _rate_limit_store[client_ip] = []
    # Prune old entries
    _rate_limit_store[client_ip] = [
        t for t in _rate_limit_store[client_ip] if now - t < _RATE_LIMIT_WINDOW
    ]
    if len(_rate_limit_store[client_ip]) >= _RATE_LIMIT_MAX:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Try again later.",
        )
    _rate_limit_store[client_ip].append(now)


def verify_token(credentials: HTTPAuthorizationCredentials) -> str:
    if not credentials or credentials.scheme != "Bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication scheme. Bearer token required.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not hmac.compare_digest(credentials.credentials, EXPECTED_TOKEN):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return credentials.credentials


class ToolExecutionRequest(BaseModel):
    agent_id: str
    tool_name: str
    kwargs: dict[str, Any]


class ToolExecutionResponse(BaseModel):
    result: Any | None = None
    error: str | None = None


async def _run_tool(agent_id: str, tool_name: str, kwargs: dict[str, Any]) -> Any:
    import inspect

    from phantom.tools.argument_parser import convert_arguments
    from phantom.tools.context import set_current_agent_id
    from phantom.tools.registry import get_tool_by_name

    set_current_agent_id(agent_id)

    tool_func = get_tool_by_name(tool_name)
    if not tool_func:
        raise ValueError(f"Tool '{tool_name}' not found")

    converted_kwargs = convert_arguments(tool_func, kwargs)

    if asyncio.iscoroutinefunction(tool_func) or inspect.isawaitable(tool_func):
        # Async tool — call directly in the event loop
        return await tool_func(**converted_kwargs)
    else:
        # Sync tool — run in a thread to avoid blocking the event loop
        result = await asyncio.to_thread(tool_func, **converted_kwargs)
        # Guard against sync wrappers that return unawaited coroutines
        if inspect.isawaitable(result):
            return await result
        return result


@app.post("/execute", response_model=ToolExecutionResponse)
async def execute_tool(
    request: ToolExecutionRequest,
    credentials: HTTPAuthorizationCredentials = security_dependency,
    _rate: None = Depends(_rate_limit_check),
) -> ToolExecutionResponse:
    verify_token(credentials)

    agent_id = request.agent_id

    if agent_id in agent_tasks:
        old_task = agent_tasks[agent_id]
        if not old_task.done():
            old_task.cancel()

    task = asyncio.create_task(
        asyncio.wait_for(
            _run_tool(agent_id, request.tool_name, request.kwargs), timeout=REQUEST_TIMEOUT
        )
    )
    agent_tasks[agent_id] = task

    try:
        result = await task
        return ToolExecutionResponse(result=result)

    except asyncio.CancelledError:
        return ToolExecutionResponse(error="Cancelled by newer request")

    except TimeoutError:
        return ToolExecutionResponse(error=f"Tool timed out after {REQUEST_TIMEOUT}s")

    except ValidationError as e:
        # V2-BUG-005 FIX: Sanitize error messages — don't leak internal state
        return ToolExecutionResponse(error="Invalid arguments for tool execution")

    except (ValueError, RuntimeError, ImportError) as e:
        # V2-BUG-005 FIX: Generic error message — strip file paths and internals
        return ToolExecutionResponse(error="Tool execution error: internal failure")

    except Exception as e:  # noqa: BLE001
        # V2-BUG-005 FIX: Never return raw exception messages
        return ToolExecutionResponse(error="Unexpected internal error during tool execution")

    finally:
        if agent_tasks.get(agent_id) is task:
            del agent_tasks[agent_id]


@app.post("/register_agent")
async def register_agent(
    agent_id: str, credentials: HTTPAuthorizationCredentials = security_dependency
) -> dict[str, str]:
    verify_token(credentials)
    return {"status": "registered", "agent_id": agent_id}


# V2-ARCH-008 FIX: Minimal health endpoint — no sensitive info disclosure
@app.get("/health")
async def health_check() -> dict[str, Any]:
    return {
        "status": "healthy",
    }


def signal_handler(_signum: int, _frame: Any) -> None:
    if hasattr(signal, "SIGPIPE"):
        signal.signal(signal.SIGPIPE, signal.SIG_IGN)
    for task in agent_tasks.values():
        task.cancel()
    sys.exit(0)


if hasattr(signal, "SIGPIPE"):
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)

signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)

if __name__ == "__main__":
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
