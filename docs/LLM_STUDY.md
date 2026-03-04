# Phantom LLM Selection Guide
**Version:** 1.0 | **Date:** March 2026 | **Author:** [Usta0x001](https://github.com/Usta0x001)

---

## 1. Overview

Phantom is LLM-agnostic — it works with **any model** that speaks the OpenAI-compatible API through [LiteLLM](https://github.com/BerriAI/litellm). This guide evaluates **35 models** across **8 providers** to help you pick the right one for your scans.

**Bottom Line:** DeepSeek V3.2 via OpenRouter delivers the best bang for your buck — 7 vulnerabilities found in 26 iterations at **$0.36/scan**.

---

## 2. What Makes a Good LLM for Phantom?

Before picking a model, here's what Phantom actually needs from it:

| Requirement | Why | Minimum |
|---|---|---|
| **Structured output (XML tool calls)** | Phantom parses `<function>` XML tags from model output | Must generate valid XML reliably |
| **Large context window** | Security scans produce 50K–150K tokens of conversation history | ≥64K tokens |
| **Multi-step reasoning** | Exploit chains require 10–50 step plans | Strong chain-of-thought |
| **Code understanding** | Must read/write HTTP, SQL, JS, Python, Bash | Top-tier coding benchmark |
| **Tool-use capability** | 55 tools require reliable function calling | Native or near-native |
| **Streaming support** | Real-time output parsing for responsive UI | SSE/streaming API |
| **Cost efficiency** | Full scans use 50K–500K tokens | ≤$5.00/scan preferred |

---

## 3. Pre-Configured Models (Ready to Use)

These 18 models are already pre-configured in Phantom — just set `PHANTOM_LLM` and go:

| # | Model ID | Provider | Context Window | Cost/1K In | Cost/1K Out | Vision | Reasoning |
|---|---|---|---|---|---|---|---|
| 1 | `groq/llama-3.3-70b-versatile` | Groq | 128K | Free | Free | ✗ | ✗ |
| 2 | `groq/llama-3.1-8b-instant` | Groq | 128K | Free | Free | ✗ | ✗ |
| 3 | `groq/llama3-70b-8192` | Groq | 8K | Free | Free | ✗ | ✗ |
| 4 | `gpt-4o` | OpenAI | 128K | $0.0025 | $0.0100 | ✓ | ✗ |
| 5 | `gpt-4o-mini` | OpenAI | 128K | $0.00015 | $0.0006 | ✓ | ✗ |
| 6 | `anthropic/claude-sonnet-4-20250514` | Anthropic | 200K | $0.003 | $0.015 | ✓ | ✓ |
| 7 | `anthropic/claude-3-5-haiku-latest` | Anthropic | 200K | $0.001 | $0.005 | ✓ | ✗ |
| 8 | `gemini/gemini-2.5-flash` | Google | 1M | $0.00015 | $0.0006 | ✓ | ✗ |
| 9 | `ollama/llama3:70b` | Ollama | 128K | Free | Free | ✗ | ✗ |
| 10 | `openrouter/deepseek/deepseek-v3.2` | OpenRouter | 163K | $0.00025 | $0.0004 | ✗ | ✓ |
| 11 | `openrouter/deepseek/deepseek-chat-v3-0324` | OpenRouter | 163K | $0.0008 | $0.002 | ✗ | ✓ |
| 12 | `openrouter/deepseek/deepseek-v3.1-terminus` | OpenRouter | 163K | $0.00021 | $0.00079 | ✗ | ✓ |
| 13 | `openrouter/meta-llama/llama-3.3-70b-instruct` | OpenRouter | 128K | Free | Free | ✗ | ✗ |
| 14 | `openrouter/google/gemma-3-27b-it:free` | OpenRouter | 131K | Free | Free | ✗ | ✗ |
| 15 | `openrouter/nousresearch/hermes-3-llama-3.1-405b:free` | OpenRouter | 131K | Free | Free | ✗ | ✗ |
| 16 | `openrouter/qwen/qwen3-coder:free` | OpenRouter | 262K | Free | Free | ✗ | ✗ |
| 17 | `openrouter/mistralai/mistral-small-3.1-24b-instruct:free` | OpenRouter | 128K | Free | Free | ✗ | ✗ |
| 18 | `openrouter/x-ai/grok-4.1-fast` | OpenRouter | 2M | $0.0002 | $0.0005 | ✓ | ✓ |

---

## 4. Full 35-Model Comparison

### 4.1 Tier 1 — Top Picks (Best Performance)

#### 1. DeepSeek V3.2 (via OpenRouter)
- **Model ID:** `openrouter/deepseek/deepseek-v3.2`
- **Context:** 163,840 tokens | **Cost:** $0.25/$0.40 per 1M tokens
- **Strengths:** Proven in Phantom benchmarks (7 vulns, $0.36/scan), excellent structured output, strong coding, MoE architecture (37B active of 685B total)
- **Weaknesses:** No vision, occasional verbosity
- **Phantom Rating:** ★★★★★ (5/5)
- **Estimated cost per full scan:** $0.30–$1.00

#### 2. Claude Sonnet 4 (Anthropic)
- **Model ID:** `anthropic/claude-sonnet-4-20250514`
- **Context:** 200,000 tokens | **Cost:** $3.00/$15.00 per 1M tokens
- **Strengths:** Superior reasoning, excellent tool use, 200K context, vision support, best for complex exploit chains
- **Weaknesses:** 10–20× more expensive than DeepSeek
- **Phantom Rating:** ★★★★★ (5/5)
- **Estimated cost per full scan:** $5.00–$15.00

#### 3. GPT-4o (OpenAI)
- **Model ID:** `gpt-4o`
- **Context:** 128,000 tokens | **Cost:** $2.50/$10.00 per 1M tokens
- **Strengths:** Excellent tool use, vision, wide ecosystem support, reliable structured output
- **Weaknesses:** Expensive, 128K context weaker than competitors
- **Phantom Rating:** ★★★★★ (5/5)
- **Estimated cost per full scan:** $4.00–$12.00

#### 4. Gemini 2.5 Flash (Google)
- **Model ID:** `gemini/gemini-2.5-flash`
- **Context:** 1,000,000 tokens | **Cost:** $0.15/$0.60 per 1M tokens
- **Strengths:** Massive 1M context eliminates compression, very cheap, fast, vision support
- **Weaknesses:** Slightly weaker tool-use reliability than Claude/GPT-4o
- **Phantom Rating:** ★★★★★ (5/5)
- **Estimated cost per full scan:** $0.20–$0.80

#### 5. Grok 4.1 Fast (xAI via OpenRouter)
- **Model ID:** `openrouter/x-ai/grok-4.1-fast`
- **Context:** 2,000,000 tokens | **Cost:** $0.20/$0.50 per 1M tokens
- **Strengths:** Largest context window (2M), vision, reasoning, ultra-cheap
- **Weaknesses:** Newer model, less battle-tested, xAI platform maturity
- **Phantom Rating:** ★★★★☆ (4/5)
- **Estimated cost per full scan:** $0.15–$0.60

#### 6. Qwen3.5-122B-A10B (via OpenRouter)
- **Model ID:** `openrouter/qwen/qwen3.5-122b-a10b`
- **Context:** 262,144 tokens | **Cost:** $0.30/$2.40 per 1M tokens
- **Strengths:** Large MoE (122B total, 10B active), 262K context, excellent reasoning
- **Weaknesses:** Higher output cost, not yet battle-tested in Phantom
- **Phantom Rating:** ★★★★☆ (4/5)
- **Estimated cost per full scan:** $0.80–$3.00

---

### 4.2 Tier 2 — Strong Alternatives

#### 7. DeepSeek Chat V3-0324 (via OpenRouter)
- **Model ID:** `openrouter/deepseek/deepseek-chat-v3-0324`
- **Context:** 163,840 tokens | **Cost:** $0.80/$2.00 per 1M tokens
- **Strengths:** Pre-configured in Phantom, proven reliability, good reasoning
- **Weaknesses:** 3× more expensive than V3.2 for similar performance
- **Phantom Rating:** ★★★★☆ (4/5)

#### 8. Claude 3.5 Haiku (Anthropic)
- **Model ID:** `anthropic/claude-3-5-haiku-latest`
- **Context:** 200,000 tokens | **Cost:** $1.00/$5.00 per 1M tokens
- **Strengths:** Fast, 200K context, Anthropic quality at lower cost
- **Weaknesses:** Less capable than Sonnet 4 for complex chains
- **Phantom Rating:** ★★★★☆ (4/5)

#### 9. GPT-4o Mini (OpenAI)
- **Model ID:** `gpt-4o-mini`
- **Context:** 128,000 tokens | **Cost:** $0.15/$0.60 per 1M tokens
- **Strengths:** Very cheap, reliable tool use, vision, same API as GPT-4o
- **Weaknesses:** Reduced reasoning vs full GPT-4o
- **Phantom Rating:** ★★★★☆ (4/5)

#### 10. Qwen3.5-27B (via OpenRouter)
- **Model ID:** `openrouter/qwen/qwen3.5-27b`  
- **Context:** 262,144 tokens | **Cost:** $0.27/$2.16 per 1M tokens
- **Strengths:** Dense 27B model, large context, affordable
- **Weaknesses:** Smaller than 122B variant
- **Phantom Rating:** ★★★★☆ (4/5)

#### 11. Qwen3.5-Flash (via OpenRouter)
- **Model ID:** `openrouter/qwen/qwen3.5-flash`
- **Context:** 1,000,000 tokens | **Cost:** $0.10/$0.40 per 1M tokens
- **Strengths:** 1M context like Gemini, ultra-cheap
- **Weaknesses:** Flash variant = less reasoning depth
- **Phantom Rating:** ★★★★☆ (4/5)

#### 12. Gemini 3.1 Flash Lite (Google via OpenRouter)
- **Model ID:** `openrouter/google/gemini-3.1-flash-lite`
- **Context:** 1,050,000 tokens | **Cost:** $0.25/$1.50 per 1M tokens
- **Strengths:** Largest context (1.05M), Google infrastructure, very fast
- **Weaknesses:** "Lite" variant has reduced capability
- **Phantom Rating:** ★★★★☆ (4/5)

#### 13. Qwen3-Next 80B-A3B Thinking (via OpenRouter)
- **Model ID:** `openrouter/qwen/qwen3-next-80b-a3b-thinking`
- **Context:** 131,072 tokens | **Cost:** $0.16/$0.70 per 1M tokens
- **Strengths:** Thinking model, MoE (80B total/3B active), cheap
- **Weaknesses:** Only 3B active parameters limits capability
- **Phantom Rating:** ★★★☆☆ (3/5)

#### 14. Llama 3.3 70B Versatile (Groq)
- **Model ID:** `groq/llama-3.3-70b-versatile`
- **Context:** 128,000 tokens | **Cost:** Free (Groq free tier)
- **Strengths:** Free, Groq hardware gives ultra-fast inference, 128K context
- **Weaknesses:** Rate limited (30 RPM), less reliable tool use than proprietary models
- **Phantom Rating:** ★★★★☆ (4/5)

---

### 4.3 Tier 3 — Budget & Free Options

#### 15. Llama 3.3 70B Instruct (OpenRouter Free)
- **Model ID:** `openrouter/meta-llama/llama-3.3-70b-instruct:free`
- **Context:** 128,000 tokens | **Cost:** Free
- **Strengths:** Free, large context, Meta's best open model
- **Weaknesses:** 20 RPM limit, occasional tool-call formatting issues
- **Phantom Rating:** ★★★☆☆ (3/5)

#### 16. Hermes 3 Llama 405B (OpenRouter Free)
- **Model ID:** `openrouter/nousresearch/hermes-3-llama-3.1-405b:free`
- **Context:** 131,072 tokens | **Cost:** Free
- **Strengths:** 405B parameters (largest free model), good instruction following
- **Weaknesses:** Slow inference, 20 RPM, unreliable availability
- **Phantom Rating:** ★★★☆☆ (3/5)

#### 17. Qwen3-Coder (OpenRouter Free)
- **Model ID:** `openrouter/qwen/qwen3-coder:free`
- **Context:** 262,000 tokens | **Cost:** Free
- **Strengths:** Coding-specialised, large 262K context, free
- **Weaknesses:** Optimised for code generation, not exploit chain reasoning
- **Phantom Rating:** ★★★☆☆ (3/5)

#### 18. Gemma 3 27B IT (OpenRouter Free)
- **Model ID:** `openrouter/google/gemma-3-27b-it:free`
- **Context:** 131,072 tokens | **Cost:** Free
- **Strengths:** Google's open model, free, decent reasoning
- **Weaknesses:** 27B limits capability, 20 RPM
- **Phantom Rating:** ★★★☆☆ (3/5)

#### 19. Mistral Small 3.1 24B (OpenRouter Free)
- **Model ID:** `openrouter/mistralai/mistral-small-3.1-24b-instruct:free`
- **Context:** 128,000 tokens | **Cost:** Free
- **Strengths:** Good multilingual support, 128K context, free
- **Weaknesses:** 24B is small for complex exploit chains
- **Phantom Rating:** ★★★☆☆ (3/5)

#### 20. DeepSeek V3.1 Terminus (OpenRouter)
- **Model ID:** `openrouter/deepseek/deepseek-v3.1-terminus`
- **Context:** 163,840 tokens | **Cost:** $0.21/$0.79 per 1M tokens
- **Strengths:** Cheap DeepSeek variant, reasoning support
- **Weaknesses:** Intermediate release, superseded by V3.2
- **Phantom Rating:** ★★★☆☆ (3/5)

#### 21. ByteDance Seed 2.0 Mini (OpenRouter)
- **Model ID:** `openrouter/bytedance/seed-2.0-mini`
- **Context:** 262,144 tokens | **Cost:** $0.10/$0.40 per 1M tokens
- **Strengths:** Ultra-cheap, large context, ByteDance engineering
- **Weaknesses:** New model, unproven for security use cases
- **Phantom Rating:** ★★★☆☆ (3/5)

#### 22. LFM2-24B-A2B (Liquid AI via OpenRouter)
- **Model ID:** `openrouter/liquid/lfm2-24b-a2b`
- **Context:** 33,000 tokens | **Cost:** $0.03/$0.12 per 1M tokens
- **Strengths:** Cheapest model available, novel architecture
- **Weaknesses:** Only 33K context (too small for deep scans), 2B active params
- **Phantom Rating:** ★★☆☆☆ (2/5)

#### 23. Llama 3.1 8B Instant (Groq)
- **Model ID:** `groq/llama-3.1-8b-instant`
- **Context:** 128,000 tokens | **Cost:** Free
- **Strengths:** Ultra-fast on Groq, free, good for testing
- **Weaknesses:** 8B too small for real scanning, poor tool use
- **Phantom Rating:** ★★☆☆☆ (2/5)

#### 24. Llama 3 70B 8192 (Groq)
- **Model ID:** `groq/llama3-70b-8192`
- **Context:** 8,192 tokens | **Cost:** Free
- **Strengths:** Free, fast
- **Weaknesses:** 8K context is far too small — constant compression, data loss
- **Phantom Rating:** ★★☆☆☆ (2/5)

#### 25. Qwen3.5-35B-A3B (OpenRouter)
- **Model ID:** `openrouter/qwen/qwen3.5-35b-a3b`
- **Context:** 131,072 tokens | **Cost:** $0.14/$0.60 per 1M tokens
- **Strengths:** MoE 35B/3B, cheap, good context
- **Weaknesses:** Only 3B active — limited for complex security reasoning
- **Phantom Rating:** ★★★☆☆ (3/5)

---

### 4.4 Tier 4 — Self-Hosted / Local (Ollama)

#### 26. Llama 3:70B (Ollama)
- **Model ID:** `ollama/llama3:70b`
- **Context:** 128,000 tokens | **Cost:** Free (hardware only)
- **Hardware:** Requires ~40GB VRAM (A100 80GB or 2× A6000)
- **Strengths:** Air-gapped, no data leaves your network, no API costs
- **Weaknesses:** Requires expensive GPU, slower than cloud
- **Phantom Rating:** ★★★☆☆ (3/5)

#### 27. Qwen2.5-72B (Ollama)
- **Model ID:** `ollama/qwen2.5:72b`
- **Context:** 128,000 tokens | **Cost:** Free (hardware only)
- **Hardware:** ~40GB VRAM
- **Strengths:** Excellent coding, large context, active development
- **Phantom Rating:** ★★★☆☆ (3/5)

#### 28. Mistral Large 2 123B (Ollama)
- **Model ID:** `ollama/mistral-large:123b`
- **Context:** 128,000 tokens | **Cost:** Free (hardware only)
- **Hardware:** ~70GB VRAM (2× A100)
- **Strengths:** Strong multilingual, large model
- **Phantom Rating:** ★★★☆☆ (3/5)

#### 29. DeepSeek-R1-Distill 70B (Ollama)
- **Model ID:** `ollama/deepseek-r1:70b`
- **Context:** 128,000 tokens | **Cost:** Free (hardware only)
- **Hardware:** ~40GB VRAM
- **Strengths:** Reasoning model, good for exploit chain planning
- **Phantom Rating:** ★★★☆☆ (3/5)

#### 30. CodeLlama 70B (Ollama)
- **Model ID:** `ollama/codellama:70b`
- **Context:** 16,384 tokens | **Cost:** Free (hardware only)
- **Hardware:** ~40GB VRAM
- **Strengths:** Code-specialised
- **Weaknesses:** 16K context too small, not designed for tool use
- **Phantom Rating:** ★★☆☆☆ (2/5)

---

### 4.5 Tier 5 — Premium / Enterprise

#### 31. Claude Opus 4 (Anthropic)
- **Model ID:** `anthropic/claude-opus-4`
- **Context:** 200,000 tokens | **Cost:** $15.00/$75.00 per 1M tokens
- **Strengths:** Most capable Claude, best reasoning, agentic capabilities
- **Weaknesses:** Extremely expensive — $50–$150 per scan
- **Phantom Rating:** ★★★★★ (5/5) quality, ★★☆☆☆ cost
- **Recommended for:** High-value targets where cost is irrelevant

#### 32. GPT-4.5 (OpenAI)
- **Model ID:** `gpt-4.5`
- **Context:** 128,000 tokens | **Cost:** $75.00/$150.00 per 1M tokens
- **Strengths:** OpenAI's flagship research model
- **Weaknesses:** Prohibitively expensive ($100+ per scan)
- **Phantom Rating:** ★★★★☆ (4/5) quality, ★☆☆☆☆ cost

#### 33. Gemini 2.5 Pro (Google)
- **Model ID:** `gemini/gemini-2.5-pro`
- **Context:** 1,000,000 tokens | **Cost:** $1.25/$10.00 per 1M tokens
- **Strengths:** 1M context, excellent reasoning, vision, moderate cost
- **Weaknesses:** Higher latency than Flash variants
- **Phantom Rating:** ★★★★★ (5/5)

#### 34. GPT-o3 (OpenAI)
- **Model ID:** `openai/o3`
- **Context:** 200,000 tokens | **Cost:** $10.00/$40.00 per 1M tokens
- **Strengths:** Reasoning model, extended thinking for complex chains
- **Weaknesses:** Very expensive, slow due to reasoning phase
- **Phantom Rating:** ★★★★☆ (4/5)

#### 35. Grok 4.1 (xAI)
- **Model ID:** `openrouter/x-ai/grok-4.1`
- **Context:** 2,000,000 tokens | **Cost:** $6.00/$18.00 per 1M tokens
- **Strengths:** Massive 2M context, reasoning, vision
- **Weaknesses:** Expensive, platform less mature
- **Phantom Rating:** ★★★★☆ (4/5)

---

## 5. Cost at a Glance

| Model | Est. Cost per Scan* | Vulns Expected | Cost per Vuln |
|---|---|---|---|
| **DeepSeek V3.2** | $0.30–$1.00 | 7–12 | $0.04–$0.14 |
| **Gemini 2.5 Flash** | $0.20–$0.80 | 6–10 | $0.03–$0.13 |
| **Grok 4.1 Fast** | $0.15–$0.60 | 5–10 | $0.03–$0.12 |
| **GPT-4o Mini** | $0.25–$0.90 | 5–8 | $0.05–$0.18 |
| **Claude 3.5 Haiku** | $1.50–$5.00 | 6–10 | $0.25–$0.83 |
| **GPT-4o** | $4.00–$12.00 | 7–12 | $0.57–$1.71 |
| **Claude Sonnet 4** | $5.00–$15.00 | 8–15 | $0.63–$1.88 |
| **Gemini 2.5 Pro** | $2.00–$8.00 | 7–12 | $0.29–$1.14 |
| **Free (Groq/OR)** | $0.00 | 3–6 | $0.00 |
| **Ollama (local)** | $0.00** | 4–7 | $0.00** |

*Based on 100–300 iterations, 50K–200K input tokens, 10K–50K output tokens.  
**Hardware cost not included (GPU: $1,000–$15,000).

---

## 6. Recommended Setups

Here are the configurations we recommend depending on your situation:

### 6.1 Best All-Round (Cost-Performance Champion)
```bash
export PHANTOM_LLM="openrouter/deepseek/deepseek-v3.2"
export LLM_API_KEY="sk-or-v1-..."
```
- **Why:** Proven in benchmarks, $0.36/scan for 7 vulns, 163K context
- **When:** Default choice for all scan types

### 6.2 Best Free Setup
```bash
export PHANTOM_LLM="groq/llama-3.3-70b-versatile"
export GROQ_API_KEY="gsk_..."
export PHANTOM_LLM_FALLBACK="openrouter/qwen/qwen3-coder:free,openrouter/meta-llama/llama-3.3-70b-instruct:free"
```
- **Why:** Free tier with fallback chain, 128K context, Groq hardware speed
- **When:** Development, testing, budget-constrained environments

### 6.3 Best Premium (Maximum Accuracy)
```bash
export PHANTOM_LLM="anthropic/claude-sonnet-4-20250514"
export ANTHROPIC_API_KEY="sk-ant-..."
```
- **Why:** Best reasoning for complex exploit chains, 200K context
- **When:** High-value targets, compliance audits, red team engagements

### 6.4 Best Context Window (Deep Scans)
```bash
export PHANTOM_LLM="gemini/gemini-2.5-flash"
export GEMINI_API_KEY="..."
```
- **Why:** 1M context eliminates compression, $0.15/M input
- **When:** Deep profile scans (300 iterations), large targets

### 6.5 Best Self-Hosted (Air-Gapped)
```bash
export PHANTOM_LLM="ollama/llama3:70b"
# No API key needed — runs locally
```
- **Why:** No data leaves your network, free inference
- **When:** Classified environments, regulatory requirements (ITAR, HIPAA)

### 6.6 Multi-Model Routing (Coming in v0.10.x)
```bash
# Cheap model for recon, expensive for exploitation
export PHANTOM_LLM_RECON="gemini/gemini-2.5-flash"
export PHANTOM_LLM_EXPLOIT="anthropic/claude-sonnet-4-20250514"
```

---

## 7. Provider Reliability

Who stays up and who has limits:

| Provider | Uptime | Rate Limits | Payment | Notes |
|---|---|---|---|---|
| **OpenRouter** | 99.5%+ | 200 RPM (paid) | Prepaid credits | Best multi-model gateway |
| **Groq** | 99%+ | 30 RPM (free) | Free tier | Hardware-accelerated, very fast |
| **OpenAI** | 99.9%+ | Varies by tier | Pay-as-you-go | Most reliable, widest tooling |
| **Anthropic** | 99.5%+ | 50 RPM (base) | Pay-as-you-go | Best safety/reasoning |
| **Google** | 99.9%+ | Generous free tier | Pay-as-you-go | Largest context windows |
| **xAI** | 98%+ | Varies | Pay-as-you-go | Newest, rapidly improving |
| **Ollama** | 100% (local) | Unlimited | Hardware only | Air-gapped, no rate limits |
| **Together AI** | 99%+ | Varies | Pay-as-you-go | Good open-source model hosting |
| **Fireworks AI** | 99%+ | Varies | Pay-as-you-go | Fast inference for open models |

---

## 8. Expected Performance by Model

Based on the Juice Shop benchmark (v0.9.38 engine):

| Model | Expected Vulns | Expected Time | Expected Cost | Confidence |
|---|---|---|---|---|
| DeepSeek V3.2 (proven) | 7–12 | 15–45 min | $0.36–$1.00 | **High** |
| Claude Sonnet 4 | 10–18 | 20–60 min | $5–$15 | Medium |
| GPT-4o | 8–15 | 20–50 min | $4–$12 | Medium |
| Gemini 2.5 Flash | 6–12 | 15–40 min | $0.20–$0.80 | Medium |
| Grok 4.1 Fast | 6–12 | 15–40 min | $0.15–$0.60 | Low |
| Groq Llama 3.3 70B | 4–8 | 10–30 min | $0.00 | Medium |
| Ollama Llama 3:70b | 3–7 | 30–120 min | $0.00 | Low |

---

## 9. Conclusion

Phantom’s LiteLLM integration gives you exceptional flexibility. For everyday scanning, **DeepSeek V3.2** via OpenRouter is the sweet spot — $0.36/scan for 7+ vulnerabilities. For maximum capability, **Claude Sonnet 4** gives you the deepest reasoning at higher cost. For zero-cost operation, **Groq’s Llama 3.3 70B** with free-tier fallbacks gets the job done.

The system is fully model-agnostic: any new model can be used immediately by setting `PHANTOM_LLM` to any LiteLLM-compatible identifier, even without a pre-configured preset.

---

*Part of the [Phantom](https://github.com/Usta0x001/Phantom) documentation.*  
*Author: [Usta0x001](https://github.com/Usta0x001)*
