from phantom.config import Config


class LLMConfig:
    def __init__(
        self,
        model_name: str | None = None,
        enable_prompt_caching: bool = True,
        skills: list[str] | None = None,
        timeout: int | None = None,
        scan_mode: str = "deep",
        temperature: float | None = None,
    ):
        self.model_name = model_name or Config.get("phantom_llm")

        if not self.model_name:
            raise ValueError("PHANTOM_LLM environment variable must be set and not empty")

        self.enable_prompt_caching = enable_prompt_caching
        self.skills = skills or []

        self.timeout = timeout or int(Config.get("llm_timeout") or "300")

        # BUG-01 FIX: Include all valid scan modes, not just quick/standard/deep
        valid_modes = {"quick", "standard", "deep", "stealth", "api_only"}
        self.scan_mode = scan_mode if scan_mode in valid_modes else "deep"

        # v0.9.34: Temperature NOT set by default.
        # Let the model use its native default (typically 0.7-1.0).
        # Low temperature (0.4) was killing creative attack exploration.
        self.temperature: float | None = temperature
