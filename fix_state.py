import sys
import hashlib

file_path = 'phantom/agents/state.py'
with open(file_path, 'r', encoding='utf-8') as f:
    text = f.read()

bad_chunk = """    def add_message(
        self, role: str, content: Any, thinking_blocks: list[dict[str, Any]] | None = None, force: bool = False
    ) -> None:
        # SECURITY FIX: Hash-based deduplication to prevent context poisoning
        # Uses SHA-256 hash to efficiently detect duplicate messages
        if isinstance(content, str) and not force:
            content_hash = hashlib.sha256(f"{role}\\x1f{content}".encode("utf-8")).hexdigest()
            if content_hash in self._message_hashes:
                return  # Duplicate message - skip to prevent flooding
            self._message_hashes.add(content_hash)
"""

replaced = """    def add_message(
        self, role: str, content: Any, thinking_blocks: list[dict[str, Any]] | None = None, force: bool = False
    ) -> None:
        # SECURITY FIX: Hash-based deduplication to prevent context poisoning
        if isinstance(content, str) and not force:
            content_hash = hashlib.sha256(f"{role}\\x1f{content}".encode("utf-8")).hexdigest()
            if content_hash in self._message_hashes:
                return
            self._message_hashes.add(content_hash)

        # AUDIT-QW-05: Also keep window-based dedup as secondary defense
        if isinstance(content, str) and self.messages and not force:
            _window = self.messages[-5:]
            for m in reversed(_window):
                if m.get("role") == role and m.get("content") == content:
                    return
        
        message = {"role": role, "content": content}
        self.messages.append(message)
        self.last_updated = datetime.now(UTC).isoformat()
"""

if "def add_message" in text:
    # Let's just do a regex replace from def add_message up to the next def
    import re
    new_text = re.sub(
        r'    def add_message\(.*?def add_action\(',
        replaced + "\n    def add_action(",
        text,
        flags=re.DOTALL
    )
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(new_text)
    print("Fixed state.py")
else:
    print("Could not find add_message")
