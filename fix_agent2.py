import re
import os

file_path = "phantom/agents/base_agent.py"
with open(file_path, "r", encoding="utf-8") as f:
    text = f.read()

# 1. DC-01: Remove _strict_prompt_summary
text = re.sub(r'    def _strict_prompt_summary\(.*?return result\n', '', text, flags=re.DOTALL)

# 2. SF-05: Enable loop break for interactive mode timeout
text = text.replace('if self.non_interactive:', 'if True:  # SF-05 FIX: Also timeout in interactive mode')

# 3. NEW-01: Use force=True for corrective notes
text = re.sub(r'self\.state\.add_message\("user", "\[SYSTEM:(.*?)"\)', r'self.state.add_message("user", "[SYSTEM:\1", force=True)', text)
text = re.sub(r'self\.state\.add_message\("user", "\<system_warning\>(.*?)"\)', r'self.state.add_message("user", "<system_warning>\1", force=True)', text)

# 4. AF-06: Fix O(N*K) scan in _build_hypothesis_context
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
            
            content_lower = content.lower()
            
            # 1. Mention of active surface or class
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
text = text.replace(scan_bad, scan_good)

# 5. CA-01: Delta check scan status update (around line 743)
status_bad = """                # Format as compact message
                status_msg = self._format_scan_status(status)
                self.state.add_message("user", status_msg)"""
status_good = """                status_msg = self._format_scan_status(status)
                # CA-01 FIX: Delta-check scan status to avoid redundant token bloat
                import hashlib
                msg_hash = hashlib.sha256(status_msg.encode("utf-8")).hexdigest()
                last_hash = getattr(self.state, "_last_status_msg_hash", None)
                if msg_hash != last_hash:
                    setattr(self.state, "_last_status_msg_hash", msg_hash)
                    self.state.add_message("user", status_msg)"""
text = text.replace(status_bad, status_good)

# 6. SR-06: HTML escape truncation order
sr06_bad = """                            # B3: Compact inter-agent message format (was ~400 tokens XML, now ~50 tokens)
                            import html as _html

                            safe_sender_name = _html.escape(str(sender_name))
                            safe_content = _html.escape(str(message.get("content", ""))[:200])"""
sr06_good = """                            # B3: Compact inter-agent message format (was ~400 tokens XML, now ~50 tokens)
                            import html as _html

                            safe_sender_name = _html.escape(str(sender_name))
                            
                            # SR-06 FIX: Escape first, then truncate safely
                            raw_content = str(message.get("content", ""))
                            safe_content = _html.escape(raw_content)
                            if len(safe_content) > 200:
                                safe_content = safe_content[:197] + "..."
"""
text = text.replace(sr06_bad, sr06_good)

# 7. AF-03: Thread safety read lock
# Instead of replacing and wrapping everything in `with`, which causes indentation hell with string replacement,
# we parse line-by-line and intelligently indent.
lines = text.split("\n")
new_lines = []
in_lock = False
lock_padding = ""

for i, line in enumerate(lines):
    if "messages = _agent_messages[agent_id]" in line and "if not agent_id" in lines[i-3]:
        # We modify the block headers
        pass

    if "        try:" in line and "from phantom.tools.agents_graph.agents_graph_actions import" in lines[i+1]:
        in_lock = True

if "def _check_agent_messages" in text:
    af03_old = """    def _check_agent_messages(self, state: AgentState) -> None:  # noqa: PLR0912
        try:
            from phantom.tools.agents_graph.agents_graph_actions import _agent_graph, _agent_messages

            agent_id = state.agent_id
            if not agent_id or agent_id not in _agent_messages:
                return

            messages = _agent_messages[agent_id]"""
    af03_new = """    def _check_agent_messages(self, state: AgentState) -> None:  # noqa: PLR0912
        try:
            from phantom.tools.agents_graph.agents_graph_actions import _agent_graph, _agent_messages, _GRAPH_LOCK

            agent_id = state.agent_id
            _GRAPH_LOCK.acquire()
            try:
                if not agent_id or agent_id not in _agent_messages:
                    return

                # Create an isolated copy of messages to process after releasing lock to prevent deadlock
                # and minimize hold time. Actually we just need to iterate them fast.
                messages = _agent_messages[agent_id]"""
                
    text = text.replace(af03_old, af03_new)
    
    # We must insert the `finally:` block right before the `except:` block.
    # The current code ends with:
    #                 if has_new_messages and not state.is_waiting_for_input():
    #                     from phantom.telemetry.tracer import get_global_tracer ...
    #                     if tracer:
    #                         tracer.update_agent_status(agent_id, "running")
    #
    #         except (AttributeError, KeyError, TypeError) as e:
    
    text = text.replace("""                        tracer.update_agent_status(agent_id, "running")

        except (AttributeError, KeyError, TypeError) as e:""", """                        tracer.update_agent_status(agent_id, "running")
            finally:
                _GRAPH_LOCK.release()

        except (AttributeError, KeyError, TypeError) as e:""")

# Add back top_attack_plans
top_plans_code = """
            top_attack_plans = attack_graph.get("top_attack_plans", [])
            if top_attack_plans:
                lines.append(f"  Top Plans: {len(top_attack_plans)}")
                for plan in top_attack_plans[:2]:
                    if not isinstance(plan, dict):
                        continue
                    path = plan.get("path") or []
                    if not isinstance(path, list) or not path:
                        continue
                    path_preview = " -> ".join(str(p) for p in path[:4])
                    if len(path) > 4:
                        path_preview = f"{path_preview} -> ..."
                    lines.append(
                        "  - "
                        f"p={plan.get('probability')} "
                        f"cost={plan.get('cost')} "
                        f"score={plan.get('score')} "
                        f"path={path_preview}"
                    )
"""
text = text.replace("""                if critical_bits:
                    lines.append(f"  Critical: {', '.join(critical_bits)}")

        if archived_messages:""", """                if critical_bits:
                    lines.append(f"  Critical: {', '.join(critical_bits)}")
""" + top_plans_code + """
        if archived_messages:""")


with open(file_path, "w", encoding="utf-8") as f:
    f.write(text)

print("Agent patched successfully.")
