import contextlib
import inspect
import json
import logging
import types
from collections.abc import Callable
from typing import Any, Union, get_args, get_origin

logger = logging.getLogger(__name__)

# Common parameter name aliases that LLMs frequently hallucinate.
# Maps (wrong_name, correct_name) — applied when wrong_name is NOT in
# the function signature but correct_name IS.
_PARAM_ALIASES: dict[str, list[str]] = {
    "target": ["targets", "url", "domain"],   # LLMs generalise "target" across tools
    "targets": ["target"],                     # inverse
    "host": ["target", "url"],
    "headers": ["extra_args"],                 # LLMs try "headers" on tools like sqlmap
}


class ArgumentConversionError(Exception):
    def __init__(self, message: str, param_name: str | None = None) -> None:
        self.param_name = param_name
        super().__init__(message)


def convert_arguments(func: Callable[..., Any], kwargs: dict[str, Any]) -> dict[str, Any]:
    try:
        sig = inspect.signature(func)
        converted = {}

        # Check if function accepts **kwargs (VAR_KEYWORD parameter)
        has_var_keyword = any(
            p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()
        )

        # First pass: resolve aliases for unknown parameter names
        resolved_kwargs: dict[str, Any] = {}
        for param_name, value in kwargs.items():
            if param_name in sig.parameters:
                resolved_kwargs[param_name] = value
            elif param_name in _PARAM_ALIASES:
                # Try each alias candidate
                matched = False
                for alias in _PARAM_ALIASES[param_name]:
                    if alias in sig.parameters and alias not in kwargs and alias not in resolved_kwargs:
                        logger.info(
                            "Auto-corrected parameter '%s' -> '%s' for %s",
                            param_name, alias, func.__name__,
                        )
                        resolved_kwargs[alias] = value
                        matched = True
                        break
                if not matched:
                    resolved_kwargs[param_name] = value  # pass through
            else:
                resolved_kwargs[param_name] = value

        for param_name, value in resolved_kwargs.items():
            if param_name not in sig.parameters:
                if has_var_keyword:
                    # Function accepts **kwargs, pass unknown params through
                    converted[param_name] = value
                else:
                    # Log dropped parameters for debugging
                    logger.warning(
                        "Dropped unknown parameter '%s' for tool %s (not in signature, no alias found)",
                        param_name, func.__name__,
                    )
                continue

            param = sig.parameters[param_name]
            param_type = param.annotation

            if param_type == inspect.Parameter.empty or value is None:
                converted[param_name] = value
                continue

            if not isinstance(value, str):
                converted[param_name] = value
                continue

            try:
                converted[param_name] = convert_string_to_type(value, param_type)
            except (ValueError, TypeError, json.JSONDecodeError) as e:
                raise ArgumentConversionError(
                    f"Failed to convert argument '{param_name}' to type {param_type}: {e}",
                    param_name=param_name,
                ) from e

    except (ValueError, TypeError, AttributeError) as e:
        raise ArgumentConversionError(f"Failed to process function arguments: {e}") from e

    return converted


def convert_string_to_type(value: str, param_type: Any) -> Any:
    origin = get_origin(param_type)
    if origin is Union or isinstance(param_type, types.UnionType):
        args = get_args(param_type)
        for arg_type in args:
            if arg_type is not type(None):
                with contextlib.suppress(ValueError, TypeError, json.JSONDecodeError):
                    return convert_string_to_type(value, arg_type)
        return value

    if hasattr(param_type, "__args__"):
        args = getattr(param_type, "__args__", ())
        if len(args) == 2 and type(None) in args:
            non_none_type = args[0] if args[1] is type(None) else args[1]
            with contextlib.suppress(ValueError, TypeError, json.JSONDecodeError):
                return convert_string_to_type(value, non_none_type)
            return value

    return _convert_basic_types(value, param_type, origin)


def _convert_basic_types(value: str, param_type: Any, origin: Any = None) -> Any:
    basic_type_converters: dict[Any, Callable[[str], Any]] = {
        int: int,
        float: float,
        bool: _convert_to_bool,
        str: str,
    }

    if param_type in basic_type_converters:
        return basic_type_converters[param_type](value)

    if list in (origin, param_type):
        return _convert_to_list(value)
    if dict in (origin, param_type):
        return _convert_to_dict(value)

    with contextlib.suppress(json.JSONDecodeError):
        return json.loads(value)
    return value


def _convert_to_bool(value: str) -> bool:
    if value.lower() in ("true", "1", "yes", "on"):
        return True
    if value.lower() in ("false", "0", "no", "off"):
        return False
    # Empty string is falsy; any other non-empty string is truthy (standard Python semantics)
    return bool(value)


def _convert_to_list(value: str) -> list[Any]:
    try:
        parsed = json.loads(value)
        if isinstance(parsed, list):
            return parsed
    except json.JSONDecodeError:
        if "," in value:
            return [item.strip() for item in value.split(",")]
        return [value]
    else:
        return [parsed]


def _convert_to_dict(value: str) -> dict[str, Any]:
    try:
        parsed = json.loads(value)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        # Try key=value parsing as fallback before giving up
        if "=" in value:
            result = {}
            for pair in value.split(","):
                if "=" in pair:
                    k, _, v = pair.partition("=")
                    result[k.strip()] = v.strip()
            if result:
                return result
        # Wrap non-dict scalars instead of silently returning empty
        return {"value": value} if value.strip() else {}
    else:
        # Parsed successfully but not a dict — wrap it
        return {"value": parsed} if parsed is not None else {}
