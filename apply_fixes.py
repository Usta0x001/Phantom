import re

# -------------
# FIX STATE.PY (NEW-01)
# -------------
state_path = "phantom/agents/state.py"
with open(state_path, "r", encoding="utf-8") as f:
    text = f.read()

# Safely extract parts before add_message and from add_action
parts = re.split(r'    def add_message\(.*?def add_action\(', text, flags=re.DOTALL)
if len(parts) == 2:
    new_add_msg = """    def add_message(
        self, role: str, content: Any, thinking_blocks: list[dict[str, Any]] | None = None, force: bool = False
    ) -> None:
        if isinstance(content, str) and not force:
            content_hash = hashlib.sha256(f"{role}\\x1f{content}".encode("utf-8")).hexdigest()
            if content_hash in self._message_hashes:
                return
            self._message_hashes.add(content_hash)

        if isinstance(content, str) and self.messages and not force:
            _window = self.messages[-5:]
            for m in reversed(_window):
                if m.get("role") == role and m.get("content") == content:
                    return
        
        message = {"role": role, "content": content}
        self.messages.append(message)
        self.last_updated = datetime.now(UTC).isoformat()

    def add_action("""
    with open(state_path, "w", encoding="utf-8") as f:
        f.write(parts[0] + new_add_msg + parts[1])
    print("Fixed state.py")

# -------------
# FIX BASE_AGENT.PY (NEW-01 force calls, AF-06 regex, SF-05 timeout, DC-01, CA-01)
# -------------
agent_path = "phantom/agents/base_agent.py"
with open(agent_path, "r", encoding="utf-8") as f:
    atext = f.read()

# DC-01: Remove _strict_prompt_summary
atext = re.sub(r'    def _strict_prompt_summary\(.*?return result\n', '', atext, flags=re.DOTALL)

# NEW-01: Use force=True for corrective notes
atext = atext.replace('self.state.add_message("user", "[SYSTEM: Empty response', 'self.state.add_message("user", "[SYSTEM: Empty response', 1) # Wait, regex is safer
atext = re.sub(r'self\.state\.add_message\("user", "\[SYSTEM:(.*?)"\)', r'self.state.add_message("user", "[SYSTEM:\1", force=True)', atext)
atext = re.sub(r'self\.state\.add_message\("user", "\<system_warning\>(.*?)"\)', r'self.state.add_message("user", "<system_warning>\1", force=True)', atext)

# SF-05: Enable loop break for interactive mode timeout
# Search for the wait_for_input sleep loop
atext = atext.replace('if self.non_interactive:', 'if True:  # SF-05 FIX: Also timeout in interactive mode')

# AF-06: Fix O(N*K) scan in _build_hypothesis_context
scan_bad = """        def _is_relevant(msg: dict[str, Any]) -> bool:
            content = str(msg.get("content", ""))
            if not content:
                return False
            
            content_lower = content.lower()
            
            # 1. Mention of active surface or class
            if active_surface.lower() in content_lower:
                return True
            if active_vclass and active_vclass.lower() in content_lower:
                return True
            
            # 2. Check anchor keywords
            from phantom.llm.memory_compressor import _ANCHOR_KEYWORDS
            if any(k in content_lower for k in _ANCHOR_KEYWORDS):
                return True
                
            # 3. Check hypothesis specifically
            if "<current_hypothesis>" in content_lower:
                return True
            if "<finding_anchors>" in content_lower or "pinned_facts" in content_lower:
                return True
                
            return msg.get("role") == "system\""""

scan_good = """        def _is_relevant(msg: dict[str, Any]) -> bool:
            from phantom.llm.memory_compressor import _ANCHOR_KEYWORDS_PATTERN
            content = str(msg.get("content", ""))
            if not content:
                return False
            
            # 1. Mention of active surface or class
            content_lower = content.lower()
            if active_surface.lower() in content_lower:
                return True
            if active_vclass and active_vclass.lower() in content_lower:
                return True
            
            # 2. Check anchor keywords O(1) via compiled regex
            if _ANCHOR_KEYWORDS_PATTERN.search(content):
                return True
                
            # 3. Check hypothesis specifically
            if "<current_hypothesis>" in content_lower:
                return True
            if "<finding_anchors>" in content_lower or "pinned_facts" in content_lower:
                return True
                
            return msg.get("role") == "system\""""

atext = atext.replace(scan_bad, scan_good)

with open(agent_path, "w", encoding="utf-8") as f:
    f.write(atext)
print("Fixed base_agent.py")

# -------------
# FIX EXECUTOR.PY (SF-04, SR-01, NEW-02)
# -------------
exec_path = "phantom/tools/executor.py"
with open(exec_path, "r", encoding="utf-8") as f:
    etext = f.read()

# SF-04 / SR-01: Remove _is_hardened_mode checks to enable validation everywhere
etext = etext.replace('if not _is_hardened_mode():\n        return None', '')
etext = etext.replace('if _is_hardened_mode():\n            return text', 'return text')

# NEW-02: Fix allowed_tools None check mapping
etext = etext.replace('if allowed_tools is None:\n        raise Exception("Tool not allowed")', 'if allowed_tools is not None and tool_name not in allowed_tools:\n        raise Exception(f"Tool {tool_name} not allowed by current policy")')
etext = etext.replace('if tool_name not in allowed_tools:\n        raise Exception', 'if allowed_tools is not None and tool_name not in allowed_tools:\n        raise Exception')

with open(exec_path, "w", encoding="utf-8") as f:
    f.write(etext)
print("Fixed executor.py")

# -------------
# FIX LLM.PY (CA-04, NEW-03, NEW-02)
# -------------
llm_path = "phantom/llm/llm.py"
with open(llm_path, "r", encoding="utf-8") as f:
    ltext = f.read()

# NEW-02: return None when no tools selected
new2_bad = """    def _resolve_runtime_allowed_tools(self) -> set[str] | None:
        tool_names = self._select_tool_names(self._prompt_agent_name)
        if not tool_names:
            return set()
        return set(tool_names)"""
new2_good = """    def _resolve_runtime_allowed_tools(self) -> set[str] | None:
        tool_names = self._select_tool_names(self._prompt_agent_name)
        if not tool_names:
            return None
        return set(tool_names)"""
ltext = ltext.replace(new2_bad, new2_good)

with open(llm_path, "w", encoding="utf-8") as f:
    f.write(ltext)
print("Fixed llm.py")
