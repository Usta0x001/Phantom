import re

file_path = "phantom/agents/base_agent.py"
with open(file_path, "r", encoding="utf-8") as f:
    text = f.read()

# Fix 1
bad_insertion = """            from phantom.tools.agents_graph.agents_graph_actions import _agent_graph, _agent_messages, _GRAPH_LOCK

            agent_id = self.state.agent_id
            
            with _GRAPH_LOCK:
                if not agent_id or agent_id not in _agent_messages:
                    pass
                else:
                    messages = _agent_messages[agent_id]
                    if messages:
                        for message in messages:
                            pass
"""
text = text.replace(bad_insertion, "")

# Fix 2
search2 = """                            # sender_id is absent from the agent graph.
                            sender_name = sender_id or "unknown-agent"
                            if sender_id and sender_id in _agent_graph.get("nodes", {}):

                if has_new_messages and not state.is_waiting_for_input():"""

replacement2 = """                            # sender_id is absent from the agent graph.
                            sender_name = sender_id or "unknown-agent"
                            if sender_id and sender_id in _agent_graph.get("nodes", {}):
                                sender_name = _agent_graph["nodes"][sender_id]["name"]

                            # B3: Compact inter-agent message format
                            import html as _html

                            safe_sender_name = _html.escape(str(sender_name))
                            
                            # SR-06 FIX: Escape first, then truncate safely
                            raw_content = str(message.get("content", ""))
                            safe_content = _html.escape(raw_content)
                            if len(safe_content) > 200:
                                safe_content = safe_content[:197] + "..."

                            message_content = f"[From {safe_sender_name}]: {safe_content}"
                            state.add_message("user", message_content.strip())

                        message["read"] = True

                if has_new_messages and not state.is_waiting_for_input():"""
text = text.replace(search2, replacement2)

# Fix 3
search3 = """        try:
            from phantom.tools.agents_graph.agents_graph_actions import _agent_graph, _agent_messages

            agent_id = state.agent_id
            if not agent_id or agent_id not in _agent_messages:
                return

            messages = _agent_messages[agent_id]
            if messages:
                has_new_messages = False
                for message in messages:"""

replacement3 = """        try:
            from phantom.tools.agents_graph.agents_graph_actions import _agent_graph, _agent_messages, _GRAPH_LOCK

            agent_id = state.agent_id
            
            with _GRAPH_LOCK:
                if not agent_id or agent_id not in _agent_messages:
                    return

                messages = _agent_messages[agent_id]
                if messages:
                    has_new_messages = False
                    for message in messages:"""
text = text.replace(search3, replacement3)

with open(file_path, "w", encoding="utf-8") as f:
    f.write(text)
print("Patch applied.")
