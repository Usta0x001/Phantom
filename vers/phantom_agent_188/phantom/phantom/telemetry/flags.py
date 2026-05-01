def is_otel_enabled() -> bool:
    from phantom.config import Config

    enabled = (Config.get("phantom_otel_telemetry") or "1").strip().lower()
    return enabled in {"1", "true", "yes"}



