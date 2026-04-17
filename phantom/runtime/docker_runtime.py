import contextlib
import logging
import os
import random
import re
import secrets
import socket
import subprocess
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
DOCKER_TIMEOUT = 60
CONTAINER_TOOL_SERVER_PORT = 48081
CONTAINER_CAIDO_PORT = 48080

# Container names must match this pattern (prevents command injection via names)
_CONTAINER_NAME_RE = re.compile(r"^phantom-scan-[a-zA-Z0-9_-]+$")
logger = logging.getLogger(__name__)


class DockerRuntime(AbstractRuntime):
    def __init__(self) -> None:
        try:
            self.client = self._connect_or_start_docker_client()
        except (DockerException, RequestsConnectionError, RequestsTimeout) as e:
            raise SandboxInitializationError(
                "Docker is not available",
                str(e),
            ) from e

        self._scan_container: Container | None = None
        self._tool_server_port: int | None = None
        self._tool_server_token: str | None = None
        self._caido_port: int | None = None

    def _start_docker_desktop_windows(self) -> bool:
        if os.name != "nt":
            return False

        candidates = [
            Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Docker" / "Docker" / "Docker Desktop.exe",
            Path(os.environ.get("LocalAppData", "")) / "Docker" / "Docker Desktop.exe",
        ]
        for exe in candidates:
            if exe.exists():
                with contextlib.suppress(OSError):
                    subprocess.Popen([str(exe)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)  # noqa: S603
                    return True
        return False

    def _connect_docker_client(self) -> docker.DockerClient:
        client = docker.from_env(timeout=DOCKER_TIMEOUT)
        client.ping()
        return client

    def _connect_or_start_docker_client(self) -> docker.DockerClient:
        try:
            return self._connect_docker_client()
        except (DockerException, RequestsConnectionError, RequestsTimeout) as e:
            if os.name == "nt" and self._start_docker_desktop_windows():
                deadline = time.time() + 120
                while time.time() < deadline:
                    try:
                        return self._connect_docker_client()
                    except (DockerException, RequestsConnectionError, RequestsTimeout):
                        time.sleep(3)
                raise SandboxInitializationError(
                    "Docker is not available",
                    "Phantom attempted to auto-start Docker Desktop but it did not become ready in time.",
                ) from e

            raise SandboxInitializationError(
                "Docker is not available",
                "Please ensure Docker Desktop is installed and running.",
            ) from e

    def _find_available_port(self, max_attempts: int = 5) -> int:
        """Find a free TCP port with jittered exponential back-off.

        Each attempt picks a fresh ephemeral port and then tries a strict
        re-bind (no SO_REUSEADDR) to confirm the port is still unclaimed.
        If the re-bind fails the port was seized in the TOCTOU window; back
        off and pick a new one.  _create_container's retry loop handles the
        residual rare collision between this method and Docker binding.
        """
        for attempt in range(max_attempts):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("", 0))
                port = cast("int", s.getsockname()[1])
            # Strict re-bind: no SO_REUSEADDR means it fails if port is in use.
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as chk:
                    chk.bind(("127.0.0.1", port))
                return port
            except OSError:
                delay = min(0.025 * (2**attempt), 0.4) + random.uniform(0, 0.010)
                time.sleep(delay)
        # All probes collided — return best-effort; _create_container retries.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("", 0))
            return cast("int", s.getsockname()[1])

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
        self.client = self._connect_or_start_docker_client()
        port_bindings = container.attrs.get("NetworkSettings", {}).get("Ports", {})

        self._tool_server_token = None
        try:
            token_res = container.exec_run(["cat", "/run/secrets/tool_server_token"], user="root")
            if getattr(token_res, "exit_code", 1) == 0:
                token_bytes = getattr(token_res, "output", b"") or b""
                if isinstance(token_bytes, bytes):
                    token = token_bytes.decode("utf-8", errors="ignore").strip()
                else:
                    token = str(token_bytes).strip()
                if token:
                    self._tool_server_token = token
        except Exception:  # noqa: BLE001
            self._tool_server_token = None

        if not self._tool_server_token:
            for env_var in container.attrs["Config"]["Env"]:
                if env_var.startswith("TOOL_SERVER_TOKEN="):
                    self._tool_server_token = env_var.split("=", 1)[1]
                    break

        port_key = f"{CONTAINER_TOOL_SERVER_PORT}/tcp"
        if port_bindings.get(port_key):
            self._tool_server_port = int(port_bindings[port_key][0]["HostPort"])

        caido_port_key = f"{CONTAINER_CAIDO_PORT}/tcp"
        if port_bindings.get(caido_port_key):
            self._caido_port = int(port_bindings[caido_port_key][0]["HostPort"])

    def _wait_for_tool_server(self, max_retries: int = 30, timeout: int = 5) -> None:
        host = self._resolve_docker_host()
        health_url = f"http://{host}:{self._tool_server_port}/health"

        time.sleep(5)

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

            time.sleep(min(2**attempt * 0.5, 5))

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

        # Rec 3 (SF-003): Docker resource limits — configurable per scan mode.
        # Prevents container resource exhaustion and host destabilisation.
        mem_limit: str = Config.get("phantom_container_mem_limit") or "4g"
        cpu_quota: int = int(Config.get("phantom_container_cpu_quota") or "200000")  # 2 CPUs
        pids_limit: int = int(Config.get("phantom_container_pids_limit") or "512")

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
                self._caido_port = self._find_available_port()
                self._tool_server_token = secrets.token_urlsafe(32)
                execution_timeout = Config.get("phantom_sandbox_execution_timeout") or "120"

                container = self.client.containers.run(
                    image_name,
                    command="sleep infinity",
                    detach=True,
                    name=container_name,
                    hostname=container_name,
                    ports={
                        f"{CONTAINER_TOOL_SERVER_PORT}/tcp": self._tool_server_port,
                        f"{CONTAINER_CAIDO_PORT}/tcp": self._caido_port,
                    },
                    cap_add=["NET_ADMIN", "NET_RAW"],
                    # SECURITY FIX: Drop dangerous capabilities that could enable container escape
                    # SYS_ADMIN: Prevents mount/namespace manipulation for container escape
                    # SYS_PTRACE: Prevents process debugging/injection attacks
                    cap_drop=["SYS_ADMIN", "SYS_PTRACE"],
                    labels={"phantom-scan-id": scan_id},
                    environment={
                        "PYTHONUNBUFFERED": "1",
                        "TOOL_SERVER_PORT": str(CONTAINER_TOOL_SERVER_PORT),
                        # Rec 8 (B-13): Token also injected via env for backward-compat.
                        # Primary path is the secret file written below.
                        "TOOL_SERVER_TOKEN": self._tool_server_token,
                        "PHANTOM_SANDBOX_EXECUTION_TIMEOUT": str(execution_timeout),
                        "HOST_GATEWAY": HOST_GATEWAY_HOSTNAME,
                        # Allow SSRF to target hosts (docker internal addresses)
                        "PHANTOM_ALLOWED_SSRF_HOSTS": "host.docker.internal,localhost,127.0.0.1",
                    },
                    extra_hosts={HOST_GATEWAY_HOSTNAME: "host-gateway"},
                    tty=True,
                    # Rec 3 (SF-003): Resource limits
                    mem_limit=mem_limit,
                    memswap_limit=mem_limit,  # disable swap
                    cpu_period=100_000,
                    cpu_quota=cpu_quota,
                    pids_limit=pids_limit,
                )

                self._scan_container = container

                # Connect to phantom-internal network so the sandbox can reach
                # other Docker containers (e.g. juice-shop, vulnerable apps) by
                # their container names instead of relying on host port forwards.
                try:
                    self.client.networks.get("phantom-internal")
                except NotFound:
                    self.client.networks.create("phantom-internal", driver="bridge")
                try:
                    self.client.networks.get("phantom-internal").connect(container)
                except Exception as e:  # noqa: BLE001
                    logger.warning("Could not connect container to phantom-internal network: %s", e)

                # Rec 8 (B-13): Write token to /run/secrets so it's NOT readable
                # via /proc/self/environ (which is world-readable by default in
                # many Linux distros).  chmod 600 ensures only root can read it.
                #
                # AUDIT-FIX CRIT-01: Use Docker put_archive API instead of
                # bash printf with f-string interpolation. The old code was:
                #   printf '%s' '{token}' > /run/secrets/tool_server_token
                # which would break or allow shell injection if the token
                # ever contained single-quotes or shell metacharacters.
                try:
                    import tarfile as _tarfile
                    from io import BytesIO as _BytesIO

                    # Create secrets dir first (no user data in this command)
                    container.exec_run(
                        ["mkdir", "-p", "/run/secrets"],
                        user="root",
                    )
                    # Write token via tar archive — no shell interpolation
                    token_bytes = self._tool_server_token.encode("utf-8")
                    tar_buf = _BytesIO()
                    with _tarfile.open(fileobj=tar_buf, mode="w") as tar:
                        info = _tarfile.TarInfo(name="tool_server_token")
                        info.size = len(token_bytes)
                        info.mode = 0o600
                        info.uid = 0
                        info.gid = 0
                        tar.addfile(info, _BytesIO(token_bytes))
                    tar_buf.seek(0)
                    container.put_archive("/run/secrets", tar_buf.getvalue())
                except Exception:  # noqa: BLE001
                    # Non-fatal: env-var fallback is still present.
                    logger.warning("Could not write tool_server_token to /run/secrets — "
                                   "falling back to environment variable.")

                self._wait_for_tool_server()

            except (DockerException, RequestsConnectionError, RequestsTimeout) as e:
                last_error = e
                if attempt < max_retries:
                    self._tool_server_port = None
                    self._tool_server_token = None
                    self._caido_port = None
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
            except NotFound:
                self._scan_container = None
                self._tool_server_port = None
                self._tool_server_token = None
                self._caido_port = None

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

    def _extract_scope_targets(self, scan_config: dict | None) -> str:
        """
        SEC-002 FIX: Extract target hosts from scan_config for scope enforcement.
        
        Returns comma-separated list of target hosts/IPs.
        """
        if not scan_config:
            return ""
        
        targets = scan_config.get("targets", [])
        if not targets:
            return ""
        
        extracted: list[str] = []
        for target_info in targets:
            if isinstance(target_info, dict):
                details = target_info.get("details", {})
                if not isinstance(details, dict):
                    details = {}
                # Try different keys where host might be stored
                host = (
                    target_info.get("host")
                    or target_info.get("hostname")
                    or target_info.get("ip")
                    or details.get("target_url")
                    or details.get("host")
                    or details.get("hostname")
                    or details.get("ip")
                    or target_info.get("target_url")
                    or target_info.get("original", "")
                )
                if host:
                    # Strip protocol and path, keep just the host
                    if "://" in host:
                        host = host.split("://", 1)[1]
                    if "/" in host:
                        host = host.split("/", 1)[0]
                    if ":" in host and not host.startswith("["):
                        # Remove port from host:port, but keep IPv6 [::1]:port
                        host = host.rsplit(":", 1)[0]
                    if host:
                        extracted.append(host)
            elif isinstance(target_info, str):
                extracted.append(target_info)
        
        return ",".join(extracted)

    def _configure_scope_firewall(self, container: Container, scan_target: str) -> None:
        """
        Rec 7 (AI-SEC-008): Enforce scan scope at the network level via iptables.

        Inserts ACCEPT rules for the authorised target IP/CIDR so that the
        container cannot be redirected to scan unintended hosts by a prompt
        injection.  DNS-based targets are resolved before inserting rules.

        The container must already have NET_ADMIN capability (set in
        _create_container).  Failures are logged but non-fatal — the scan
        continues without the firewall if the container cannot be configured.
        """
        if not scan_target:
            return
        try:
            import ipaddress
            import socket

            # Resolve hostname → IP if needed
            try:
                ipaddress.ip_network(scan_target, strict=False)
                allowed_cidr = scan_target  # already an IP/CIDR
            except ValueError:
                # Treat as hostname — resolve to IP
                try:
                    resolved_ip = socket.gethostbyname(scan_target)
                    allowed_cidr = resolved_ip
                except OSError:
                    logger.warning(
                        "Scope firewall: could not resolve '%s' — skipping iptables rules",
                        scan_target,
                    )
                    return

            # Apply iptables: allow TCP to scan target, drop all other external output
            rules = [
                # Allow DNS (needed to resolve target sub-domains during scan)
                f"iptables -A OUTPUT -p udp --dport 53 -j ACCEPT",
                f"iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT",
                # Allow traffic to the authorised target
                f"iptables -A OUTPUT -d {allowed_cidr} -j ACCEPT",
                # Allow loopback and host gateway (tool server communication)
                f"iptables -A OUTPUT -o lo -j ACCEPT",
            ]

            try:
                container.reload()
                gateway_ip = container.attrs.get("NetworkSettings", {}).get("Gateway")
                if gateway_ip:
                    rules.append(f"iptables -A OUTPUT -d {gateway_ip} -j ACCEPT")
            except Exception:
                pass

            rules.extend([
                # Log then drop everything else
                f"iptables -A OUTPUT -j LOG --log-prefix 'PHANTOM-OOB: ' --log-level 4",
                f"iptables -A OUTPUT -j DROP",
            ])
            for rule in rules:
                result = container.exec_run(
                    ["bash", "-c", rule],
                    user="root",
                )
                if result.exit_code != 0:
                    logger.warning(
                        "Scope firewall rule failed (exit %d): %s",
                        result.exit_code,
                        rule,
                    )
        except Exception as e:  # noqa: BLE001
            logger.warning("Scope firewall configuration failed: %s", e)

    def _copy_local_directory_to_container(
        self, container: Container, local_path: str, target_name: str | None = None
    ) -> None:
        import tarfile
        from io import BytesIO

        try:
            local_path_obj = Path(local_path).resolve()
            if not local_path_obj.exists() or not local_path_obj.is_dir():
                return

            tar_buffer = BytesIO()
            with tarfile.open(fileobj=tar_buffer, mode="w") as tar:
                for item in local_path_obj.rglob("*"):
                    if item.is_file():
                        rel_path = item.relative_to(local_path_obj)
                        arcname = Path(target_name) / rel_path if target_name else rel_path
                        tar.add(item, arcname=arcname)

            tar_buffer.seek(0)
            container.put_archive("/workspace", tar_buffer.getvalue())
            container.exec_run(
                "chown -R pentester:pentester /workspace && chmod -R 755 /workspace",
                user="root",
            )
        except (OSError, DockerException) as copy_err:
            logger.warning(
                "Failed to copy local directory '%s' to container workspace: %s",
                local_path,
                copy_err,
            )

    async def create_sandbox(
        self,
        agent_id: str,
        existing_token: str | None = None,
        local_sources: list[dict[str, str]] | None = None,
        scan_config: dict | None = None,
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

        # Rec 7 / FIX: Actually invoke the scope firewall after container boot.
        # Previously _configure_scope_firewall was defined but never called.
        # SEC-002 FIX: Enable by default using scan targets when phantom_scope_enforcement="true"
        scope_key = f"_scope_configured_{scan_id}"
        if not hasattr(self, scope_key):
            scope_enforcement = Config.get("phantom_scope_enforcement") or "false"
            if scope_enforcement.lower() not in ("false", "0", "no", ""):
                # SEC-002: If "true", derive targets from scan_config
                if scope_enforcement.lower() in ("true", "1", "yes", "auto"):
                    # Extract target hosts from scan_config
                    scope_targets = self._extract_scope_targets(scan_config)
                else:
                    # User explicitly specified target(s)
                    scope_targets = scope_enforcement
                
                if scope_targets:
                    # Configure firewall for each target
                    for target in scope_targets.split(","):
                        target = target.strip()
                        if target:
                            self._configure_scope_firewall(container, target)
                    logger.info("Scope firewall configured for targets: %s", scope_targets)
            setattr(self, scope_key, True)

        if container.id is None:
            raise RuntimeError("Docker container ID is unexpectedly None")

        token = existing_token or self._tool_server_token
        if self._tool_server_port is None or self._caido_port is None or token is None:
            raise RuntimeError("Tool server not initialized")

        host = self._resolve_docker_host()
        api_url = f"http://{host}:{self._tool_server_port}"

        await self._register_agent(api_url, agent_id, token)

        return {
            "workspace_id": container.id,
            "api_url": api_url,
            "auth_token": token,
            "tool_server_port": self._tool_server_port,
            "caido_port": self._caido_port,
            "agent_id": agent_id,
        }

    async def _register_agent(self, api_url: str, agent_id: str, token: str) -> None:
        try:
            async with httpx.AsyncClient(trust_env=False) as client:
                response = await client.post(
                    f"{api_url}/register_agent",
                    params={"agent_id": agent_id},
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=30,
                )
                response.raise_for_status()
        except httpx.RequestError:
            pass

    async def get_sandbox_url(self, container_id: str, port: int) -> str:
        try:
            self.client.containers.get(container_id)
            return f"http://{self._resolve_docker_host()}:{port}"
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
            container.stop()
            container.remove()
            self._scan_container = None
            self._tool_server_port = None
            self._tool_server_token = None
            self._caido_port = None
        except (NotFound, DockerException):
            pass

    def cleanup(self, wait: bool = False) -> None:
        """
        Clean up Docker containers.
        
        P1.3 CRITICAL FIX: Properly clean up containers on Ctrl+C/signal.
        
        Args:
            wait: If True, wait for cleanup to complete (blocking).
                  If False, cleanup runs async (for normal exit).
        """
        if self._scan_container is not None:
            container_name = self._scan_container.name
            self._scan_container = None
            self._tool_server_port = None
            self._tool_server_token = None
            self._caido_port = None

            if container_name is None:
                return

            # Validate container name before passing to subprocess
            if not _CONTAINER_NAME_RE.match(container_name):
                return

            import subprocess

            if wait:
                # P1.3: Blocking cleanup for signal handlers - ensure container is killed
                try:
                    subprocess.run(
                        ["docker", "rm", "-f", container_name],  # noqa: S603, S607
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=10,  # Don't hang forever
                    )
                except (subprocess.TimeoutExpired, OSError):
                    pass  # Best effort
            else:
                # Non-blocking cleanup for normal exit
                subprocess.Popen(  # noqa: S603
                    ["docker", "rm", "-f", container_name],  # noqa: S607
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
    
    def cleanup_all_phantom_containers(self) -> int:
        """
        P1.3: Clean up ALL phantom containers, not just the current one.
        
        This handles zombie containers from crashed scans.
        Returns the number of containers cleaned up.
        """
        import subprocess
        
        cleaned = 0
        try:
            # Find all phantom containers (running or stopped)
            result = subprocess.run(
                ["docker", "ps", "-a", "--filter", "name=phantom-scan-", "--format", "{{.Names}}"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            
            if result.returncode == 0:
                container_names = result.stdout.strip().split("\n")
                for name in container_names:
                    if name and _CONTAINER_NAME_RE.match(name):
                        try:
                            subprocess.run(
                                ["docker", "rm", "-f", name],
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL,
                                timeout=10,
                            )
                            cleaned += 1
                            logger.info("Cleaned up zombie container: %s", name)
                        except (subprocess.TimeoutExpired, OSError):
                            pass
        except Exception as e:
            logger.warning("Failed to clean up phantom containers: %s", e)
        
        return cleaned
