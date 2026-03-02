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

        self.scan_mode = scan_mode if scan_mode in ["quick", "standard", "deep"] else "deep"

        # Temperature controls LLM creativity vs determinism.
        # 0.6 balances structured tool-calling with creative attack exploration.
        # Industry benchmarks for agentic tool-calling: optimal at 0.5-0.7.
        self.temperature: float = temperature if temperature is not None else 0.6
