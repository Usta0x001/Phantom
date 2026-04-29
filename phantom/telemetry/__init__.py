import logging

_logger = logging.getLogger(__name__)

try:
    from .tracer import Tracer, clear_global_tracer, get_global_tracer, set_global_tracer
except ImportError as _e:
    _logger.warning("Telemetry tracer unavailable: %s", _e)
    Tracer = None  # type: ignore[assignment]

    def get_global_tracer() -> None:
        return None

    def set_global_tracer(_tracer: object) -> None:
        return None

    def clear_global_tracer() -> None:
        return None


__all__ = [
    "Tracer",
    "clear_global_tracer",
    "get_global_tracer",
    "set_global_tracer",
]
