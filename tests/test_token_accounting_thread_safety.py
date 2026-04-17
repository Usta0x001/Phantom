import threading


def test_reset_global_llm_stats_clears_totals_and_per_model() -> None:
    from phantom.llm.config import LLMConfig
    from phantom.llm.llm import LLM, reset_global_llm_stats

    reset_global_llm_stats()
    llm = LLM(LLMConfig(model_name="openai/gpt-4o-mini"), agent_name=None)

    llm._total_stats.input_tokens = 10
    llm._total_stats.output_tokens = 5
    llm._per_model_stats[llm.config.litellm_model] = llm._total_stats

    reset_global_llm_stats()
    assert llm._total_stats.input_tokens == 0
    assert llm._total_stats.output_tokens == 0
    assert llm._per_model_stats == {}


def test_total_stats_updates_are_lock_safe_under_threads() -> None:
    from phantom.llm.config import LLMConfig
    from phantom.llm.llm import LLM, reset_global_llm_stats

    reset_global_llm_stats()
    llm = LLM(LLMConfig(model_name="openai/gpt-4o-mini"), agent_name=None)

    def _worker() -> None:
        for _ in range(200):
            llm._update_usage_stats(
                response=type(
                    "R",
                    (),
                    {
                        "usage": type(
                            "U",
                            (),
                            {
                                "prompt_tokens": 10,
                                "completion_tokens": 2,
                                "prompt_tokens_details": type("D", (), {"cached_tokens": 3})(),
                            },
                        )(),
                    },
                )(),
                messages=[],
            )

    threads = [threading.Thread(target=_worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # 4 threads * 200 calls * (10-3) input, 2 output, 3 cached
    assert llm._total_stats.input_tokens == 5600
    assert llm._total_stats.output_tokens == 1600
    assert llm._total_stats.cached_tokens == 2400
    assert llm._total_stats.completed_requests == 800
