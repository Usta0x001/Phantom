def is_otel_enabled() -> bool:
    # Telemetry is permanently disabled — no OTel endpoint is configured.
    # To opt-in, configure an OTEL_EXPORTER_OTLP_ENDPOINT and set
    # PHANTOM_OTEL_TELEMETRY=1 (or phantom_otel_telemetry: "1").
    return False



