# ============================================================
# Phantom CLI — Docker Distribution Image
# ============================================================
# This Dockerfile builds the Phantom CLI tool for Docker Hub.
# The sandbox container (containers/Dockerfile) is separate
# and pulled automatically at scan time.
# ============================================================

FROM python:3.12-slim AS builder

WORKDIR /build

RUN pip install --no-cache-dir poetry && \
    poetry config virtualenvs.in-project true

COPY pyproject.toml poetry.lock ./
RUN poetry install --no-root --without dev --no-interaction

COPY phantom/ phantom/
COPY README.md LICENSE ./
RUN poetry install --only-root --no-interaction

# ============================================================
# Runtime stage
# ============================================================
FROM python:3.12-slim

LABEL maintainer="Usta0x001 <r_gadouri@estin.dz>"
LABEL org.opencontainers.image.title="Phantom"
LABEL org.opencontainers.image.description="Autonomous AI-Powered Penetration Testing"
LABEL org.opencontainers.image.source="https://github.com/Usta0x001/Phantom"
LABEL org.opencontainers.image.version="0.8.0"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# Docker CLI (needed to manage sandbox containers)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates curl gnupg && \
    install -m 0755 -d /etc/apt/keyrings && \
    curl -fsSL https://download.docker.com/linux/debian/gpg | \
        gpg --dearmor -o /etc/apt/keyrings/docker.gpg && \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
        https://download.docker.com/linux/debian $(. /etc/os-release && echo $VERSION_CODENAME) stable" \
        > /etc/apt/sources.list.d/docker.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends docker-ce-cli && \
    apt-get purge -y gnupg && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

# Copy virtualenv from builder and fix shebangs
COPY --from=builder /build/.venv /app/.venv
COPY --from=builder /build/phantom /app/phantom
COPY --from=builder /build/README.md /build/LICENSE /app/

# Fix shebangs that point to /build/.venv → /app/.venv
RUN find /app/.venv/bin -type f -exec \
    sed -i 's|#!/build/.venv/bin/python|#!/app/.venv/bin/python|g' {} + 2>/dev/null || true

ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONPATH="/app"
ENV PHANTOM_DOCKER_MODE=true

WORKDIR /app

ENTRYPOINT ["phantom"]
CMD ["--help"]
