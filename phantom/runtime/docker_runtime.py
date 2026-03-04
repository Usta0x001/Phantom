import contextlib
import os
import secrets
import socket
import threading
import time
from pathlib import Path
from typing import cast

import docker
import httpx
from docker.errors import DockerException, ImageNotFound, NotFound
from docker.models.containers import Container
from requests.exceptions import ConnectionError as RequestsConnectionError
from requests.exceptions import Timeout as RequestsTimeout

from phantom.config import Config

from . import SandboxInitializationError
from .runtime import AbstractRuntime, SandboxInfo


HOST_GATEWAY_HOSTNAME = "host.docker.internal"
DOCKER_TIMEOUT = 180  # Increased from 60 — prevents NpipeHTTPConnectionPool Read timeouts on slow Docker Desktop
CONTAINER_TOOL_SERVER_PORT = 48081


class DockerRuntime(AbstractRuntime):
    def __init__(self) -> None:
        try:
            self.client = docker.from_env(timeout=DOCKER_TIMEOUT)
        except (DockerException, RequestsConnectionError, RequestsTimeout) as e:
            raise SandboxInitializationError(
                "Docker is not available",
                "Please ensure Docker Desktop is installed and running.",
            ) from e

        self._scan_container: Container | None = None
        self._tool_server_port: int | None = None
        self._tool_server_token: str | None = None
        # G-11 FIX: Thread-safe cleanup to prevent double-cleanup race
        self._cleanup_lock = threading.Lock()

        # P1-FIX5: Clean up orphaned phantom containers from previous crashed runs
        self._cleanup_orphaned_containers()

    def _cleanup_orphaned_containers(self) -> None:
        """P1-FIX5: Remove stale phantom-scan-* containers from previous crashed runs.
        
        On startup, checks for any stopped/exited containers with the phantom-scan-
        prefix and removes them. Running containers are left alone (they belong to
        an active scan in another process).
        """
        import logging as _log
        _logger = _log.getLogger(__name__)
        try:
            containers = self.client.containers.list(
                all=True,  # include stopped containers
                filters={"name": "phantom-scan-"},
            )
            for container in containers:
                try:
                    container.reload()
                    if container.status in ("exited", "dead", "created"):
                        _logger.info(
                            "Removing orphaned container: %s (status=%s)",
                            container.name, container.status,
                        )
                        container.remove(force=True)
                except Exception as e:  # noqa: BLE001
                    _logger.debug("Failed to clean orphan %s: %s", container.name, e)
        except DockerException as e:
            _logger.debug("Orphan cleanup skipped: %s", e)

    def _find_available_port(self) -> int:
        """Find an available port with minimal TOCTOU window.

        Binds to port 0 to let the OS pick a free port, stores the socket
        so it stays bound until Docker takes over.  The caller must call
        ``_release_port_reservation()`` after the container has started.
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("", 0))
        port = cast("int", s.getsockname()[1])
        # Keep the socket alive to block other processes from grabbing
        # the same port before Docker binds to it.
        self._port_reservation_socket: socket.socket | None = s
        return port

    def _release_port_reservation(self) -> None:
        """Release the port-reservation socket after Docker has bound the port."""
        sock = getattr(self, "_port_reservation_socket", None)
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
            self._port_reservation_socket = None

    def _get_scan_id(self, agent_id: str) -> str:
        try:
            from phantom.telemetry.tracer import get_global_tracer

            tracer = get_global_tracer()
            if tracer and tracer.scan_config:
                return str(tracer.scan_config.get("scan_id", "default-scan"))
        except (ImportError, AttributeError):
            pass
        return f"scan-{agent_id.split('-')[0]}"

    def _verify_image_available(self, image_name: str, max_retries: int = 3) -> None:
        for attempt in range(max_retries):
            try:
                image = self.client.images.get(image_name)
                if not image.id or not image.attrs:
                    raise ImageNotFound(f"Image {image_name} metadata incomplete")  # noqa: TRY301
            except (ImageNotFound, DockerException):
                if attempt == max_retries - 1:
                    raise
                time.sleep(2**attempt)
            else:
                return

    def _recover_container_state(self, container: Container) -> None:
        for env_var in container.attrs["Config"]["Env"]:
            if env_var.startswith("TOOL_SERVER_TOKEN="):
                self._tool_server_token = env_var.split("=", 1)[1]
                break

        port_bindings = container.attrs.get("NetworkSettings", {}).get("Ports", {})
        port_key = f"{CONTAINER_TOOL_SERVER_PORT}/tcp"
        if port_bindings.get(port_key):
            self._tool_server_port = int(port_bindings[port_key][0]["HostPort"])

    def _wait_for_tool_server(self, max_retries: int = 30, timeout: int = 5) -> None:
        host = self._resolve_docker_host()
        health_url = f"http://{host}:{self._tool_server_port}/health"

        for attempt in range(max_retries):
            try:
                with httpx.Client(trust_env=False, timeout=timeout) as client:
                    response = client.get(health_url)
                    if response.status_code == 200:
                        data = response.json()
                        if data.get("status") == "healthy":
                            return
            except (httpx.ConnectError, httpx.TimeoutException, httpx.RequestError):
                pass

            time.sleep(min(0.5 * (1.5 ** attempt), 5))

        raise SandboxInitializationError(
            "Tool server failed to start",
            "Container initialization timed out. Please try again.",
        )

    def _create_container(self, scan_id: str, max_retries: int = 2) -> Container:
        container_name = f"phantom-scan-{scan_id}"
        image_name = Config.get("phantom_image")
        if not image_name:
            raise ValueError("PHANTOM_IMAGE must be configured")

        self._verify_image_available(image_name)

        last_error: Exception | None = None
        for attempt in range(max_retries + 1):
            try:
                with contextlib.suppress(NotFound):
                    existing = self.client.containers.get(container_name)
                    with contextlib.suppress(Exception):
                        existing.stop(timeout=5)
                    existing.remove(force=True)
                    time.sleep(1)

                self._tool_server_port = self._find_available_port()
                self._tool_server_token = secrets.token_urlsafe(32)
                execution_timeout = Config.get("phantom_sandbox_execution_timeout") or "600"

                container = self.client.containers.run(
                    image_name,
                    command=["sleep", "infinity"],
                    detach=True,
                    name=container_name,
                    hostname=container_name,
                    ports={f"{CONTAINER_TOOL_SERVER_PORT}/tcp": ("127.0.0.1", self._tool_server_port)},
                    # P2-FIX10: Security hardening — drop dangerous capabilities
                    # Cannot use cap_drop=ALL because the sandbox runs security tools
                    # (Caido proxy, nmap, sqlmap) that need standard container caps.
                    # Instead, add only the extra caps needed for pentest tooling.
                    cap_add=["NET_ADMIN", "NET_RAW", "SYS_PTRACE"],
                    labels={"phantom-scan-id": scan_id},
                    # PHT-006 FIX: Per-container resource limits to prevent DoS
                    mem_limit="4g",
                    memswap_limit="6g",
                    cpu_period=100000,
                    cpu_quota=200000,  # 2 CPUs max
                    pids_limit=512,    # Limit process spawning
                    # NOTE: storage_opt (disk quota) only supported with devicemapper.
                    # On overlay2/overlayfs it is silently ignored or errors out.
                    # Omitted for maximum Docker compatibility.
                    environment={
                        "PYTHONUNBUFFERED": "1",
                        "TOOL_SERVER_PORT": str(CONTAINER_TOOL_SERVER_PORT),
                        "TOOL_SERVER_TOKEN": self._tool_server_token,
                        "PHANTOM_SANDBOX_EXECUTION_TIMEOUT": str(execution_timeout),
                        "HOST_GATEWAY": HOST_GATEWAY_HOSTNAME,
                        "PHANTOM_SANDBOX_MODE": "true",
                        # Bypass proxy for target hosts — prevents 502 when Caido
                        # proxy becomes unreachable or overloaded.
                        "no_proxy": f"{HOST_GATEWAY_HOSTNAME},localhost,127.0.0.1",
                        "NO_PROXY": f"{HOST_GATEWAY_HOSTNAME},localhost,127.0.0.1",
                    },
                    extra_hosts={HOST_GATEWAY_HOSTNAME: "host-gateway"},
                    tty=True,
                )

                self._scan_container = container
                # Release port reservation BEFORE health check — Docker needs the port
                self._release_port_reservation()
                # Give entrypoint time to start Caido + tool server
                # Entrypoint takes ~15-20s: Caido start, token fetch, project create, proxy config
                time.sleep(10)
                self._wait_for_tool_server()

            except (DockerException, RequestsConnectionError, RequestsTimeout, SandboxInitializationError) as e:
                last_error = e
                self._release_port_reservation()
                if attempt < max_retries:
                    self._tool_server_port = None
                    self._tool_server_token = None
                    # Clean up the failed container before retrying
                    if self._scan_container is not None:
                        with contextlib.suppress(Exception):
                            self._scan_container.stop(timeout=5)
                        with contextlib.suppress(Exception):
                            self._scan_container.remove(force=True)
                        self._scan_container = None
                    time.sleep(2**attempt)
            else:
                return container

        raise SandboxInitializationError(
            "Failed to create container",
            f"Container creation failed after {max_retries + 1} attempts: {last_error}",
        ) from last_error

    def _get_or_create_container(self, scan_id: str) -> Container:
        container_name = f"phantom-scan-{scan_id}"

        if self._scan_container:
            try:
                self._scan_container.reload()
                if self._scan_container.status == "running":
                    return self._scan_container
                # P2-FIX7: Container auto-recovery — if container died, recreate it
                if self._scan_container.status in ("exited", "dead"):
                    import logging as _log
                    _log.getLogger(__name__).warning(
                        "Container %s died (status=%s), auto-recovering...",
                        container_name, self._scan_container.status,
                    )
                    with contextlib.suppress(Exception):
                        self._scan_container.remove(force=True)
                    self._scan_container = None
                    self._tool_server_port = None
                    self._tool_server_token = None
                    return self._create_container(scan_id)
            except NotFound:
                self._scan_container = None
                self._tool_server_port = None
                self._tool_server_token = None

        try:
            container = self.client.containers.get(container_name)
            container.reload()

            if container.status != "running":
                container.start()
                time.sleep(2)

            self._scan_container = container
            self._recover_container_state(container)
        except NotFound:
            pass
        else:
            return container

        try:
            containers = self.client.containers.list(
                all=True, filters={"label": f"phantom-scan-id={scan_id}"}
            )
            if containers:
                container = containers[0]
                if container.status != "running":
                    container.start()
                    time.sleep(2)

                self._scan_container = container
                self._recover_container_state(container)
                return container
        except DockerException:
            pass

        return self._create_container(scan_id)

    def _copy_local_directory_to_container(
        self, container: Container, local_path: str, target_name: str | None = None
    ) -> None:
        import tarfile
        from io import BytesIO

        # M25 FIX: limit total tar archive size to prevent memory exhaustion
        _MAX_TAR_BYTES = 500 * 1024 * 1024  # 500 MB

        try:
            local_path_obj = Path(local_path).resolve()
            if not local_path_obj.exists() or not local_path_obj.is_dir():
                return

            tar_buffer = BytesIO()
            total_bytes = 0
            with tarfile.open(fileobj=tar_buffer, mode="w") as tar:
                for item in local_path_obj.rglob("*"):
                    # H8 FIX: skip symlinks to prevent path traversal
                    if item.is_symlink():
                        continue
                    if item.is_file():
                        file_size = item.stat().st_size
                        total_bytes += file_size
                        if total_bytes > _MAX_TAR_BYTES:
                            import logging as _log_m25
                            _log_m25.getLogger(__name__).warning(
                                "Tar size limit reached (%d bytes), skipping remaining files",
                                total_bytes,
                            )
                            break
                        rel_path = item.relative_to(local_path_obj)
                        arcname = Path(target_name) / rel_path if target_name else rel_path
                        tar.add(item, arcname=arcname)

            tar_buffer.seek(0)
            container.put_archive("/workspace", tar_buffer.getvalue())
            container.exec_run(
                "chown -R pentester:pentester /workspace && chmod -R 755 /workspace",
                user="root",
            )
        except (OSError, DockerException):
            pass

    async def create_sandbox(
        self,
        agent_id: str,
        existing_token: str | None = None,
        local_sources: list[dict[str, str]] | None = None,
    ) -> SandboxInfo:
        scan_id = self._get_scan_id(agent_id)
        container = self._get_or_create_container(scan_id)

        source_copied_key = f"_source_copied_{scan_id}"
        if local_sources and not hasattr(self, source_copied_key):
            for index, source in enumerate(local_sources, start=1):
                source_path = source.get("source_path")
                if not source_path:
                    continue
                target_name = (
                    source.get("workspace_subdir") or Path(source_path).name or f"target_{index}"
                )
                self._copy_local_directory_to_container(container, source_path, target_name)
            setattr(self, source_copied_key, True)

        if container.id is None:
            raise RuntimeError("Docker container ID is unexpectedly None")

        token = existing_token or self._tool_server_token
        if self._tool_server_port is None or token is None:
            raise RuntimeError("Tool server not initialized")

        host = self._resolve_docker_host()
        api_url = f"http://{host}:{self._tool_server_port}"

        await self._register_agent(api_url, agent_id, token)

        return {
            "workspace_id": container.id,
            "api_url": api_url,
            "auth_token": token,
            "tool_server_port": self._tool_server_port,
            "agent_id": agent_id,
        }

    async def _register_agent(self, api_url: str, agent_id: str, token: str) -> None:
        max_retries = 3
        for attempt in range(1, max_retries + 1):
            try:
                async with httpx.AsyncClient(trust_env=False) as client:
                    response = await client.post(
                        f"{api_url}/register_agent",
                        params={"agent_id": agent_id},
                        headers={"Authorization": f"Bearer {token}"},
                        timeout=30,
                    )
                    response.raise_for_status()
                    return  # success
            except httpx.RequestError as exc:
                import logging
                _log = logging.getLogger(__name__)
                _log.warning(
                    "Agent registration attempt %d/%d failed: %s",
                    attempt, max_retries, exc,
                )
                if attempt < max_retries:
                    import asyncio
                    await asyncio.sleep(2 * attempt)
        # All retries exhausted — log error but don't crash the scan
        import logging
        logging.getLogger(__name__).error(
            "Agent registration failed after %d retries for %s", max_retries, agent_id
        )

    async def get_sandbox_url(self, container_id: str, port: int) -> str:
        # Cache the resolved URL to avoid hitting Docker API on every tool call.
        # The NpipeHTTPConnectionPool timeout (60s→180s) still applies but we
        # skip the Docker round-trip entirely for subsequent calls.
        cache_key = f"_url_cache_{container_id}_{port}"
        cached = getattr(self, cache_key, None)
        if cached:
            return cached
        try:
            self.client.containers.get(container_id)
            url = f"http://{self._resolve_docker_host()}:{port}"
            setattr(self, cache_key, url)
            return url
        except NotFound:
            raise ValueError(f"Container {container_id} not found.") from None

    def _resolve_docker_host(self) -> str:
        docker_host = os.getenv("DOCKER_HOST", "")
        if docker_host:
            from urllib.parse import urlparse

            parsed = urlparse(docker_host)
            if parsed.scheme in ("tcp", "http", "https") and parsed.hostname:
                return parsed.hostname
        return "127.0.0.1"

    async def destroy_sandbox(self, container_id: str) -> None:
        try:
            container = self.client.containers.get(container_id)
            container.stop(timeout=5)
            container.remove(force=True)  # G-12 FIX: force=True for reliable cleanup
            self._scan_container = None
            self._tool_server_port = None
            self._tool_server_token = None
        except (NotFound, DockerException):
            pass

    def cleanup(self) -> None:
        # G-11 FIX: Acquire lock to prevent double-cleanup race condition
        with self._cleanup_lock:
            if self._scan_container is not None:
                container = self._scan_container
                self._scan_container = None
                self._tool_server_port = None
                self._tool_server_token = None

                # Use Docker SDK (already initialised) instead of fire-and-forget subprocess
                try:
                    container.stop(timeout=5)
                    container.remove(force=True)
                except Exception as exc:  # noqa: BLE001
                    import logging
                    logging.getLogger(__name__).warning(
                        "Container cleanup failed for %s: %s", getattr(container, 'id', '?'), exc
                    )
