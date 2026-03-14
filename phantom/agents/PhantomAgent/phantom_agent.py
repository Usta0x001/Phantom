from typing import Any
from urllib.parse import urlparse

from phantom.agents.base_agent import BaseAgent
from phantom.llm.config import LLMConfig


class PhantomAgent(BaseAgent):
    max_iterations = 300

    def __init__(self, config: dict[str, Any]):
        default_skills = []

        state = config.get("state")
        if state is None or (hasattr(state, "parent_id") and state.parent_id is None):
            default_skills = ["root_agent"]

        self.default_llm_config = LLMConfig(skills=default_skills)

        super().__init__(config)

    async def execute_scan(self, scan_config: dict[str, Any]) -> dict[str, Any]:  # noqa: PLR0912
        user_instructions = scan_config.get("user_instructions", "")
        targets = scan_config.get("targets", [])

        repositories = []
        local_code = []
        urls = []
        ip_addresses = []

        for target in targets:
            target_type = target["type"]
            details = target["details"]
            workspace_subdir = details.get("workspace_subdir")
            workspace_path = f"/workspace/{workspace_subdir}" if workspace_subdir else "/workspace"

            if target_type == "repository":
                repo_url = details["target_repo"]
                cloned_path = details.get("cloned_repo_path")
                repositories.append(
                    {
                        "url": repo_url,
                        "workspace_path": workspace_path if cloned_path else None,
                    }
                )

            elif target_type == "local_code":
                original_path = details.get("target_path", "unknown")
                local_code.append(
                    {
                        "path": original_path,
                        "workspace_path": workspace_path,
                    }
                )

            elif target_type == "web_application":
                target_url = details["target_url"]
                urls.append(target_url)
                # Register hostname so SSRF check allows requests to the scan target.
                try:
                    from phantom.tools.proxy.proxy_manager import allow_ssrf_host
                    hostname = urlparse(target_url).hostname or ""
                    if hostname:
                        allow_ssrf_host(hostname)
                        _h = hostname.lower()
                        if _h in {"localhost", "127.0.0.1", "::1"}:
                            allow_ssrf_host("host.docker.internal")
                        elif _h == "host.docker.internal":
                            allow_ssrf_host("localhost")
                except Exception:  # noqa: BLE001
                    pass
            elif target_type == "ip_address":
                ip_addresses.append(details["target_ip"])

        task_parts = []

        if repositories:
            task_parts.append("\n\nRepositories:")
            for repo in repositories:
                if repo["workspace_path"]:
                    task_parts.append(f"- {repo['url']} (available at: {repo['workspace_path']})")
                else:
                    task_parts.append(f"- {repo['url']}")

        if local_code:
            task_parts.append("\n\nLocal Codebases:")
            task_parts.extend(
                f"- {code['path']} (available at: {code['workspace_path']})" for code in local_code
            )

        if urls:
            task_parts.append("\n\nURLs:")
            task_parts.extend(f"- {url}" for url in urls)

        if ip_addresses:
            task_parts.append("\n\nIP Addresses:")
            task_parts.extend(f"- {ip}" for ip in ip_addresses)

        task_description = " ".join(task_parts)

        if user_instructions:
            task_description += (
                "\n\nUser-supplied mission constraints (highest priority):\n"
                f"{user_instructions}\n"
                "\nYou must explicitly incorporate these constraints while planning "
                "and executing the scan."
            )

        return await self.agent_loop(task=task_description)
