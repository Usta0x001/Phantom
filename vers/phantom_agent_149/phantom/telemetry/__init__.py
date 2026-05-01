try:
    from .tracer import Tracer, get_global_tracer, set_global_tracer
except Exception:  # noqa: BLE001
    Tracer = None  # type: ignore[assignment]

    def get_global_tracer() -> None:
        return None

    def set_global_tracer(_tracer: object) -> None:
        return None


__all__ = [
    "Tracer",
    "get_global_tracer",
    "set_global_tracer",
]
