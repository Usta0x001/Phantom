from typing import Any

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

        # Apply scan profile if provided
        self.scan_profile = config.get("scan_profile")

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
                urls.append(details["target_url"])
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

        # ── Inject scan profile constraints into task ──
        if self.scan_profile:
            profile = self.scan_profile
            profile_name = profile.name if hasattr(profile, "name") else str(profile.get("name", "unknown"))
            max_iter = profile.max_iterations if hasattr(profile, "max_iterations") else profile.get("max_iterations", 300)
            task_description += f"\n\n--- SCAN PROFILE: {profile_name} ---"
            task_description += f"\nYou have a STRICT LIMIT of {max_iter} tool-call iterations."
            task_description += "\nBe efficient and focused. Report vulnerabilities as soon as you find them."

            skip_tools = profile.skip_tools if hasattr(profile, "skip_tools") else profile.get("skip_tools", [])
            if skip_tools:
                task_description += f"\nDO NOT use these tools: {', '.join(skip_tools)}"

            priority_tools = profile.priority_tools if hasattr(profile, "priority_tools") else profile.get("priority_tools", [])
            if priority_tools:
                task_description += f"\nPRIORITIZE these tools: {', '.join(priority_tools)}"

            enable_browser = profile.enable_browser if hasattr(profile, "enable_browser") else profile.get("enable_browser", True)
            if not enable_browser:
                task_description += "\nDo NOT use browser-based tools (open_browser, browser_navigate, etc.)."

            task_description += "\nCall create_vulnerability_report IMMEDIATELY after confirming each vulnerability."
            task_description += "\n--- END SCAN PROFILE ---"

        if user_instructions:
            task_description += f"\n\nSpecial instructions: {user_instructions}"

        return await self.agent_loop(task=task_description)
