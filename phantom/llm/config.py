from phantom.config import Config
from phantom.config.config import resolve_llm_config
from phantom.llm.utils import resolve_phantom_model

_VALID_SCAN_MODES = {"quick", "standard", "deep", "stealth", "api_only"}

# Tools to skip per scan mode. Stealth avoids loud/noisy scanners; api_only
# drops tools that are irrelevant when targeting REST/GraphQL APIs.
_SKIP_TOOLS_BY_MODE: dict[str, list[str]] = {
    "stealth": [
        "nmap_scan",
        "nmap_vuln_scan",
        "sqlmap_test",
        "sqlmap_dump_database",
        "sqlmap_forms",
        "ffuf_directory_scan",
        "ffuf_parameter_fuzz",
        "ffuf_vhost_fuzz",
        "subfinder_enumerate",
        "subfinder_with_sources",
    ],
    "api_only": [
        "ffuf_vhost_fuzz",
        "subfinder_enumerate",
        "subfinder_with_sources",
        "httpx_screenshot",
    ],
}


class LLMConfig:
    def __init__(
        self,
        model_name: str | None = None,
        enable_prompt_caching: bool = True,
        skills: list[str] | None = None,
        timeout: int | None = None,
        scan_mode: str = "deep",
    ):
        resolved_model, self.api_key, self.api_base = resolve_llm_config()
        self.model_name = model_name or resolved_model

        if not self.model_name:
            raise ValueError("PHANTOM_LLM environment variable must be set and not empty")

        api_model, canonical = resolve_phantom_model(self.model_name)
        self.litellm_model: str = api_model or self.model_name
        self.canonical_model: str = canonical or self.model_name

        self.enable_prompt_caching = enable_prompt_caching
        self.skills = skills or []

        self.timeout = timeout or int(Config.get("llm_timeout") or "300")

        self.scan_mode = scan_mode if scan_mode in _VALID_SCAN_MODES else "deep"
        self.skip_tools: list[str] = _SKIP_TOOLS_BY_MODE.get(self.scan_mode, [])
