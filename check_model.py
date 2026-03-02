from phantom.llm.provider_registry import get_model_config
for m in ['openrouter/deepseek/deepseek-v3.2', 'openrouter/deepseek/deepseek-chat-v3-0324']:
    cfg = get_model_config(m)
    print(f"{m}: max_tokens={cfg.get('max_tokens')}, context={cfg.get('context_window')}")
