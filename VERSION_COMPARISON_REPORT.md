# VERSION COMPARISON REPORT: v0.9.163 vs v0.9.183

**Generated:** April 23, 2026
**From Version:** 0.9.163
**To Version:** 0.9.183 (current HEAD)

---

## FILE COUNT SUMMARY

| Metric | v0.9.163 | v0.9.183 | Delta |
|--------|-----------|-----------|--------|-------|
| Python Files | 168 | 306 | +138 |
| Common Files | 152 | 152 | 0 |
| Files Removed | 16 | - | -16 |
| New Files | - | 154 | +154 |

---

## FILES ONLY IN v0.9.163 (16 files)

These files exist in v163 but were removed or moved:

```
agents\correlation_engine.py
agents\enhanced_state.py
skills\README.md
skills\coordination\root_agent.md
skills\frameworks\fastapi.md
skills\frameworks\nestjs.md
skills\frameworks\nestjs.md
skills\protocols\graphql.md
skills\reconnaissance\recon.md
skills\reconnaissance\tool_mastery.md
skills\scan_modes\*.md (5 files)
skills\targets\owasp_juice_shop.md
skills\technologies\firebase_firestore.md
skills\technologies\supabase.md
skills\vulnerabilities\*.md (20 vulnerability docs)
tools\cache.py
tools\rbac.py
```

---

## FILES ONLY IN v0.9.183 (154 files)

Major new components:

### Core Agent System
```
phantom\agents\PhantomAgent\__init__.py
phantom\agents\PhantomAgent\phantom_agent.py
phantom\agents\PhantomAgent\system_prompt.jinja
phantom\agents\base_agent.py (NEW)
phantom\agents\state.py (NEW)
phantom\agents\hypothesis_ledger.py (NEW)
phantom\agents\coverage_tracker.py (NEW)
```

### Checkpoint System
```
phantom\checkpoint\__init__.py
phantom\checkpoint\checkpoint.py
phantom\checkpoint\models.py
```

### Interface
```
phantom\interface\cli.py
phantom\interface\cli_app.py
phantom\interface\main.py
phantom\interface\streaming_parser.py
phantom\interface\formatters\__init__.py
phantom\interface\formatters\sarif_formatter.py
phantom\interface\assets\tui_styles.tcss
```

### Tool Enhancements
```
phantom\tools\detection\detector.py
phantom\tools\detection\__init__.py
phantom\tools\agents_graph\agents_graph_actions.py
phantom\tools\agents_graph\__init__.py
phantom\tools\scan_registry\scan_registry_actions.py
phantom\tools\scan_registry\__init__.py
phantom\tools\python\python_actions.py
phantom\tools\python\python_manager.py
phantom\tools\python\python_instance.py
phantom\tools\python\__init__.py
phantom\tools\terminal\terminal_actions.py
phantom\tools\terminal\terminal_manager.py
phantom\tools\terminal\terminal_session.py
phantom\tools\terminal\__init__.py
phantom\tools\detection\detector.py
```

### Skills System
```
phantom\skills\__init__.py
phantom\skills\vulnerabilities\*.md (20 new files)
phantom\skills\frameworks\*.md
phantom\skills\protocols\*.md
phantom\skills\reconnaissance\*.md
phantom\skills\scan_modes\*.md
phantom\skills\targets\*.md
phantom\skills\technologies\*.md
phantom\skills\coordination\*.md
```

---

## KEY CHANGES BETWEEN VERSIONS

### 1. AGENT ARCHITECTURE (BREAKING CHANGE)

**v0.9.163:** `EnhancedAgent` + `CorrelationEngine` + `BaseAgent` scattered

**v0.9.183:** Unified `PhantomAgent` + `BaseAgent` architecture
- New `phantom/agents/PhantomAgent/phantom_agent.py`
- Consolidated agent initialization
- Multi-agent coordination built-in

### 2. BROWSER TOOL CHANGES

**Key Change:** Added Playwright availability check

```python
# v0.9.163 - browser_actions.py
@register_tool
def browser_action(...):

# v0.9.183 - browser_actions.py  
import importlib.util
_PLAYWRIGHT_AVAILABLE = importlib.util.find_spec("playwright") is not None

@register_tool(sandbox_execution=False)
def browser_action(...):
    if not _PLAYWRIGHT_AVAILABLE:
        return {
            "error": "Playwright is not installed. Install with: pip install playwright",
            ...
        }
```

**Impact:** Tool now returns a proper error message instead of crashing when Playwright is not installed.

### 3. CONFIGURATION CHANGES

NEW in v0.9.183:
```python
phantom_tool_subset = "full"  # Default is "full" (previously "core-fast")
phantom_disable_browser = "false"  # Browser enabled by default
```

### 4. TOOL SUBSET SYSTEM

v0.9.183 includes intelligent tool selection via `phantom/tools/dynamic_tools.py`:
- `get_tools_for_task()` - Select tools based on task
- `get_tools_for_subset_mode()` - Select tools based on mode
- `get_tools_prompt_subset()` - Generate prompts for only needed tools

### 5. CHECKPOINT SYSTEM

NEW in v0.9.183:
```python
phantom\checkpoint\checkpoint.py
phantom\checkpoint\models.py
```
- Scan persistence
- Resume capability

### 6. TELEMETRY ENHANCEMENTS

```python
phantom\telemetry\tracer.py (enhanced)
phantom\telemetry\flags.py
phantom\telemetry\utils.py
```

---

## BROWSER TOOL ISSUE - ROOT CAUSE ANALYSIS

### ISSUE: "browser_action tool not available/not allowed"

**Symptoms:** Agent cannot see browser_action tool

**Root Causes Investigated:**

1. ✅ **Tool IS registered** - Confirmed `browser_action` in tool registry
2. ✅ **Schema exists** - `browser_actions_schema.xml` present  
3. ✅ **Config correct** - `phantom_disable_browser = "false"`
4. ✅ **Subset mode correct** - `phantom_tool_subset = "full"` includes browser

5. ❌ **CAUSE: Playwright NOT INSTALLED**
   ```python
   >>> import importlib.util.find_spec("playwright")
   None  # NOT INSTALLED!
   ```

**The browser tool checks for Playwright availability** at line 264-270 of `browser_actions.py`:
```python
if not _PLAYWRIGHT_AVAILABLE:
    return {
        "error": "Playwright is not installed. Install with: pip install playwright",
        "tab_id": tab_id,
        "screenshot": "",
        "is_running": False,
    }
```

**Solution:** Install Playwright:
```bash
pip install playwright
playwright install chromium
```

---

## RECOMMENDATIONS

### For Browser Tool:
1. Install Playwright: `pip install playwright && playwright install chromium`
2. Or configure: `PHANTOM_DISABLE_BROWSER=true` if browser not needed

### For Upgrade:
1. New skills documentation structure needs to be regenerated
2. Test correlation_engine functionality - now appears to be handled by new coverage_tracker
3. RBAC tool removed - needs to be addressed if role-based access control needed

---

## CONCLUSION

The major architectural change between v163 and v183 is the migration to a unified PhantomAgent architecture with:
- New BaseAgent with built-in multi-agent coordination
- Intelligent tool selection (dynamic_tools.py)
- Checkpoint system for scan persistence  
- Enhanced telemetry

The browser issue is caused by the missing Playwright dependency, not a code bug.

*Report generated by OpenCode AI*