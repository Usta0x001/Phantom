# Phantom Cost Optimization Summary

## Problem
$1.23 for 57 LLM calls = 2.1M input tokens. Root cause: static overhead ~37K tokens/call (system prompt + ALL tool schemas sent every time).

## Fixes Applied

### P0 — Critical
| Fix | File | Change |
|-----|------|--------|
| P0.A | `config.py` | `phantom_max_cost = "10.00"` (hard $10 ceiling) |
| P0.A | `config.py` | Added `phantom_subagent_max_iterations = "50"` |
| P0.B | `llm/config.py` | Added `is_subagent: bool = False` param to LLMConfig |
| P0.B | `tools/registry.py` | `get_tools_prompt(excluded_modules=list)` filters schemas |
| P0.B | `llm/llm.py` | Passes lambda + `scan_mode` + `is_subagent` to Jinja |
| P0.B | `agents_graph_actions.py` | Passes `is_subagent=True` to LLMConfig |
| P0.C | `system_prompt.jinja` | Added RECON-FIRST GATE: no sub-agents until port scan + dir discovery + surface_map.txt done |

### P1 — High Impact
| Fix | File | Change |
|-----|------|--------|
| P1.A | `agents_graph_actions.py` | Caps sub-agent iterations: `min(50, parent_max)` instead of inheriting 300 |
| P1.B | `system_prompt.jinja` | API-FIRST FOR ACCOUNT SETUP: use POST /api/Users/ not browser form-fill |
| P1.C | `reporting_actions_schema.xml` | Removed giant SSRF example (378→73 lines, ~4.5K tokens saved) |
| P1.C | `finish_actions_schema.xml` | Removed giant pentest report example (167→68 lines, ~2.4K tokens saved) |
| P1.D | `system_prompt.jinja` | CONTEXT HAND-OFF: use `context_summary` not `inherit_context=true` |

### P2-A — Medium Impact
| Fix | File | Change |
|-----|------|--------|
| P2.A | `system_prompt.jinja` | Aggressive "GO SUPER HARD" block wrapped in `{% if scan_mode in ['deep', 'standard'] %}` |

## Token Savings Estimate
| Source | Before | After | Savings |
|--------|--------|-------|---------|
| Schema examples | ~9K tokens/call | ~1.5K tokens/call | ~7.5K tokens/call |
| `finish` tool excluded for sub-agents | 3.2K tokens/call | 0 (sub-agents only) | ~3.2K tokens/call |
| Sub-agent iteration cap | 300→50 | Prevents cascade | Massive |
| Scan mode gating | Full aggression | Conditionally applied | Varies |
| **Total** | ~37K/call | ~20K/call | **~46% reduction** |

## Env Vars to Set
```bash
PHANTOM_MAX_COST=10.00                    # Hard spending cap (default)
PHANTOM_SUBAGENT_MAX_ITERATIONS=50        # Sub-agent cap (default)
PHANTOM_COMPRESSOR_LLM=openai/minimax-text-01  # Free model for context compression
```

## Files Modified
```
phantom/config/config.py
phantom/llm/config.py
phantom/tools/registry.py
phantom/llm/llm.py
phantom/tools/agents_graph/agents_graph_actions.py
phantom/agents/PhantomAgent/system_prompt.jinja
phantom/tools/reporting/reporting_actions_schema.xml
phantom/tools/finish/finish_actions_schema.xml
```

## All P0/P1/P2-A Fixes Complete ✓
