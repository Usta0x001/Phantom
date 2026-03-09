from phantom.config import Config


_DISABLED_VALUES = {"0", "false", "no", "off"}


def _is_enabled(raw_value: str | None, default: str = "1") -> bool:
    value = (raw_value if raw_value is not None else default).strip().lower()
    return value not in _DISABLED_VALUES


def is_otel_enabled() -> bool:
    explicit = Config.get("phantom_otel_telemetry")
    if explicit is not None:
        return _is_enabled(explicit)
    return _is_enabled(Config.get("phantom_telemetry"), default="1")


def is_posthog_enabled() -> bool:
    # Telemetry is permanently disabled — no PostHog API key is configured.
    # To opt-in, set phantom_posthog_api_key in ~/.phantom/config.yaml and
    # set PHANTOM_POSTHOG_TELEMETRY=1 (or phantom_posthog_telemetry: "1").
    return False
