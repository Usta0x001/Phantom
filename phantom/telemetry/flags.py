from phantom.config import Config


_DISABLED_VALUES = {"0", "false", "no", "off"}


def _is_enabled(raw_value: str | None, default: str = "1") -> bool:
    value = (raw_value if raw_value is not None else default).strip().lower()
    return value not in _DISABLED_VALUES


def is_otel_enabled() -> bool:
    # Telemetry is permanently disabled — no OTel endpoint is configured.
    # To opt-in, configure an OTEL_EXPORTER_OTLP_ENDPOINT and set
    # PHANTOM_OTEL_TELEMETRY=1 (or phantom_otel_telemetry: "1").
    return False



