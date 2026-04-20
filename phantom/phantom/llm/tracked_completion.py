import json
from collections.abc import Callable
from typing import Any

import litellm

from phantom.config import Config


def estimate_message_tokens(model: str | None, messages: list[dict[str, Any]]) -> int:
    if not messages:
        return 0
    try:
        estimated = litellm.token_counter(model=model, messages=messages)
        return max(int(estimated), 1)
    except Exception:
        try:
            serialized = json.dumps(messages, ensure_ascii=False, default=str)
        except Exception:
            serialized = str(messages)
        return max(len(serialized) // 4, 1)


def _max_request_tokens() -> int:
    raw = (
        Config.get("phantom_max_request_estimated_tokens")
        or Config.get("phantom_ollama_context_length")
        or "220000"
    )
    try:
        return max(int(raw), 1)
    except ValueError:
        return 220000


def _enforce_budget_with_optional_reduce(
    kwargs: dict[str, Any],
    reducer: Callable[[list[dict[str, Any]]], list[dict[str, Any]]] | None,
) -> tuple[dict[str, Any], int]:
    model = kwargs.get("model")
    messages = kwargs.get("messages")
    if not isinstance(messages, list):
        return kwargs, 0

    estimated_tokens = estimate_message_tokens(str(model) if model else None, messages)
    budget = _max_request_tokens()
    if estimated_tokens <= budget:
        return kwargs, estimated_tokens

    if reducer is None:
        raise RuntimeError(
            f"LLM request exceeds token budget: estimated={estimated_tokens} budget={budget}"
        )

    reduced_messages = reducer(messages)
    if not isinstance(reduced_messages, list):
        raise RuntimeError("Reducer must return a list of messages")

    updated_kwargs = dict(kwargs)
    updated_kwargs["messages"] = reduced_messages
    reduced_estimate = estimate_message_tokens(str(model) if model else None, reduced_messages)
    if reduced_estimate > budget:
        raise RuntimeError(
            "Reduced LLM request still exceeds token budget: "
            f"estimated={reduced_estimate} budget={budget}"
        )
    return updated_kwargs, reduced_estimate


def _record_completion_usage(
    response: Any,
    model: str | None,
    messages: list[dict[str, Any]] | None,
    estimated_tokens: int,
) -> None:
    try:
        from phantom.llm.llm import record_external_completion_usage

        record_external_completion_usage(
            response=response,
            model_name=str(model) if model else "unknown",
            messages=messages,
            estimated_tokens=estimated_tokens,
        )
    except Exception:
        pass


def tracked_completion(
    *,
    reducer: Callable[[list[dict[str, Any]]], list[dict[str, Any]]] | None = None,
    **kwargs: Any,
) -> Any:
    adjusted_kwargs, estimated_tokens = _enforce_budget_with_optional_reduce(kwargs, reducer)
    response = litellm.completion(**adjusted_kwargs)
    if not adjusted_kwargs.get("stream"):
        model = adjusted_kwargs.get("model")
        messages = adjusted_kwargs.get("messages")
        _record_completion_usage(
            response=response,
            model=str(model) if model else None,
            messages=messages if isinstance(messages, list) else None,
            estimated_tokens=estimated_tokens,
        )
    return response


async def tracked_acompletion(
    *,
    reducer: Callable[[list[dict[str, Any]]], list[dict[str, Any]]] | None = None,
    **kwargs: Any,
) -> Any:
    adjusted_kwargs, estimated_tokens = _enforce_budget_with_optional_reduce(kwargs, reducer)
    response = await litellm.acompletion(**adjusted_kwargs)
    if not adjusted_kwargs.get("stream"):
        model = adjusted_kwargs.get("model")
        messages = adjusted_kwargs.get("messages")
        _record_completion_usage(
            response=response,
            model=str(model) if model else None,
            messages=messages if isinstance(messages, list) else None,
            estimated_tokens=estimated_tokens,
        )
    return response
