"""
ChainAST - Pentager-style threshold-based conversation summarization.

Ported from Pentager's pkg/csum/chain_summary.go

KEY DIFFERENCE from Phantom's MemoryCompressor:
- MemoryCompressor: Triggers LLM calls for summarization (expensive)
- ChainAST: Uses token count thresholds (cheap)

Import from: Pentager's chain summarization algorithm
"""
import logging
from dataclasses import dataclass, field
from typing import Any

import litellm

from phantom.config.config import Config


logger = logging.getLogger(__name__)

# Pentager-style thresholds
LAST_SEC_BYTES = 50_000  # Max size of last section
MAX_BP_BYTES = 16_000  # Max size of single body pair
MAX_QA_SECTIONS = 10  # Keep last N QA pairs
PRESERVE_LAST = True  # Never summarize most recent section


@dataclass
class SectionHeader:
    """System message or human message header."""
    role: str
    content: str
    token_count: int = 0


@dataclass
class BodyPair:
    """Request-Response pair in the conversation."""
    request: str
    response: str
    tool_calls: list[dict] = field(default_factory=list)
    tool_results: list[str] = field(default_factory=list)
    token_count: int = 0
    pair_type: str = "request_response"  # summarization, request_response, completion


@dataclass
class ChainSection:
    """A section of the conversation chain."""
    header: SectionHeader
    body_pairs: list[BodyPair] = field(default_factory=list)
    section_type: str = "conversation"  # system, human, conversation


@dataclass
class ChainAST:
    """
    Abstract Syntax Tree representation of conversation.
    
    Parses messages into structured sections for intelligent summarization.
    """
    sections: list[ChainSection] = field(default_factory=list)
    total_tokens: int = 0
    
    @classmethod
    def parse(cls, messages: list[dict[str, Any]]) -> "ChainAST":
        """Parse message list into ChainAST structure."""
        ast = cls()
        
        pending_user: dict[str, Any] | None = None
        
        for msg in messages:
            role = msg.get("role", "unknown")
            content = msg.get("content", "")
            
            if isinstance(content, list):
                content = " ".join(
                    p.get("text", "") 
                    for p in content 
                    if isinstance(p, dict) and p.get("type") == "text"
                )
            
            tokens = _count_tokens(content)
            ast.total_tokens += tokens
            
            if role == "system":
                header = SectionHeader(role=role, content=content, token_count=tokens)
                section = ChainSection(header=header, section_type="system")
                ast.sections.append(section)
            
            elif role == "user":
                tool_result_prefix = "Tool Results:\n\n"
                if content.startswith(tool_result_prefix):
                    full_result = content
                    stripped_content = content[len(tool_result_prefix):]
                    if pending_user is None and ast.sections:
                        last_section = ast.sections[-1]
                        if last_section.body_pairs:
                            last_section.body_pairs[-1].tool_results.append(full_result)
                            continue
                    if pending_user:
                        pending_user["tool_results"].append(full_result)
                    else:
                        pending_user = {"role": role, "content": stripped_content, "tokens": tokens, "tool_results": [full_result]}
                else:
                    pending_user = {"role": role, "content": content, "tokens": tokens, "tool_results": []}
            
            elif role == "assistant":
                if pending_user:
                    header = SectionHeader(role="user", content=pending_user["content"], 
                                          token_count=pending_user["tokens"])
                    section = ChainSection(header=header, section_type="conversation")
                    bp = BodyPair(
                        request=pending_user["content"],
                        response=content,
                        token_count=tokens + pending_user["tokens"],
                        tool_results=pending_user.get("tool_results", [])
                    )
                    section.body_pairs.append(bp)
                    ast.sections.append(section)
                    pending_user = None
                else:
                    header = SectionHeader(role=role, content=content, token_count=tokens)
                    section = ChainSection(header=header, section_type="assistant")
                    ast.sections.append(section)
        
        return ast
    
    def get_message_count(self) -> int:
        """Count total messages."""
        count = 0
        for section in self.sections:
            if section.section_type == "system":
                count += 1
            count += len(section.body_pairs) * 2  # request + response
        return count
    
    def get_total_bytes(self) -> int:
        """Get total byte size of all content."""
        total = 0
        for section in self.sections:
            total += len(section.header.content.encode())
            for bp in section.body_pairs:
                total += len(bp.request.encode()) + len(bp.response.encode())
        return total
    
    def to_messages(self) -> list[dict[str, Any]]:
        """Convert ChainAST back to message list."""
        messages = []
        
        for section in self.sections:
            if section.section_type == "system":
                messages.append({
                    "role": section.header.role,
                    "content": section.header.content
                })
            
            for bp in section.body_pairs:
                if bp.request:
                    messages.append({
                        "role": "user",
                        "content": bp.request
                    })
                if bp.response:
                    messages.append({
                        "role": "assistant", 
                        "content": bp.response
                    })
                for tr in bp.tool_results:
                    messages.append({
                        "role": "user",
                        "content": tr
                    })
            
            if section.section_type == "assistant" and section.header.content:
                messages.append({
                    "role": section.header.role,
                    "content": section.header.content
                })
        
        return messages


def _count_tokens(text: str, model: str = "gpt-4o") -> int:
    """Count tokens for text using litellm."""
    try:
        return int(litellm.token_counter(model=model, text=text))
    except Exception:
        # Fallback: rough estimate
        return len(text) // 4


class ChainSummarizer:
    """
    Pentager-style threshold-based conversation summarizer.
    
    KEY FEATURE: No LLM calls for summarization decisions.
    Uses token count thresholds instead.
    
    Import from: Pentager's pkg/csum/chain_summary.go
    
    Usage:
        summarizer = ChainSummarizer()
        if summarizer.should_summarize(messages):
            messages = summarizer.summarize(messages)
    """
    
    def __init__(
        self,
        model_name: str | None = None,
        max_input_tokens: int = 128_000,
        compressor_model: str | None = None,
    ):
        self.model_name = model_name or Config.get("phantom_llm") or "gpt-4o"
        self.max_input_tokens = max_input_tokens
        
        # Compressor model for actual LLM summarization (cheaper model)
        self.compressor_model = (
            compressor_model 
            or Config.get("phantom_compressor_llm") 
            or self.model_name
        )
        
        # Threshold: trigger summarization at 35% of max_input_tokens.
        # MemoryCompressor fires at 60% (~76,800 for 128K context), so this fires
        # FIRST at ~53,760 as a FREE pre-pass before the expensive LLM call.
        self.threshold = int(max_input_tokens * 0.35)
        
        logger.info(
            "ChainSummarizer initialized: model=%s threshold=%d",
            self.model_name, self.threshold
        )
    
    def should_summarize(self, messages: list[dict[str, Any]]) -> bool:
        """
        Check if summarization should be triggered.
        
        Pentager-style: Uses token count threshold, NOT LLM calls.
        """
        total_tokens = self._count_messages_tokens(messages)
        
        should = total_tokens > self.threshold
        
        if should:
            logger.info(
                "ChainSummarizer: triggering summary at %d tokens (threshold=%d)",
                total_tokens, self.threshold
            )
        
        return should
    
    def summarize(self, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Summarize conversation using Pentager's ChainAST algorithm.
        
        Strategy:
        1. Parse messages into ChainAST
        2. Summarize oldest sections first (threshold-based, not LLM)
        3. Preserve last N QA pairs
        4. Return compressed messages
        
        KEY DIFFERENCE: No LLM calls for compression decisions!
        """
        if not messages:
            return messages
        
        # Parse into ChainAST
        ast = ChainAST.parse(messages)
        
        total_bytes = ast.get_total_bytes()
        total_tokens = self._count_messages_tokens(messages)
        
        logger.info(
            "ChainSummarizer: chain bytes=%d tokens=%d sections=%d",
            total_bytes, total_tokens, len(ast.sections)
        )
        
        # Strategy 1: If total bytes < LAST_SEC_BYTES, no summarization needed
        if total_bytes <= LAST_SEC_BYTES:
            return messages
        
        # Strategy 2: Extract and preserve the most recent QA pairs
        preserved_messages = self._preserve_recent_qa(messages, keep=MAX_QA_SECTIONS)
        
        # Check if we need more aggressive summarization
        if self._count_messages_tokens(preserved_messages) > self.threshold:
            # Strategy 3: Aggressive summarization of oldest content
            preserved_messages = self._aggressive_summarize(preserved_messages)
        
        logger.info(
            "ChainSummarizer: compressed from %d to %d tokens",
            total_tokens, self._count_messages_tokens(preserved_messages)
        )
        
        return preserved_messages
    
    def _preserve_recent_qa(self, messages: list[dict[str, Any]], keep: int = 10) -> list[dict[str, Any]]:
        """Preserve the last N QA pairs, with Phantom tool results correctly grouped per iteration.

        Phantom message order per iteration:
            user(request) -> assistant(response) -> user(tool_results)

        We collect triples (blocks) in reverse, keeping them as atomic units so
        tool_results stay with the correct iteration.
        """
        qa_blocks = []
        tool_result_prefix = "Tool Results:\n\n"

        i = len(messages) - 1
        while i >= 0 and len(qa_blocks) < keep:
            msg = messages[i]
            role = msg.get("role", "")
            content = msg.get("content", "")

            if isinstance(content, list):
                content = " ".join(
                    p.get("text", "")
                    for p in content
                    if isinstance(p, dict) and p.get("type") == "text"
                )

            if role == "assistant" and i >= 2:
                resp = content
                tool_results = []
                req = None

                i_next = i - 1
                while i_next >= 0:
                    prev_role = messages[i_next].get("role", "")
                    prev_content = messages[i_next].get("content", "")
                    if isinstance(prev_content, list):
                        prev_content = " ".join(
                            p.get("text", "") for p in prev_content
                            if isinstance(p, dict) and p.get("type") == "text"
                        )
                    if prev_role == "user" and prev_content.startswith(tool_result_prefix):
                        tool_results.insert(0, prev_content)
                        i_next -= 1
                        continue
                    if prev_role == "user" and not prev_content.startswith(tool_result_prefix):
                        req = prev_content
                        i_next -= 1
                    break

                if req is not None:
                    block = {
                        "request": req,
                        "response": resp,
                        "tool_results": tool_results,
                    }
                    qa_blocks.append(block)
                    i = i_next
                    continue

            i -= 1

        # FIX-4: Removed the 'if len(qa_blocks) < keep: return messages' guard.
        # This was causing the free ChainSummarizer to do NOTHING for early iterations
        # (when the conversation is short but token-heavy due to scanner outputs),
        # falling through to the expensive LLM memory compressor instead.
        if len(qa_blocks) == 0:
            return messages

        result = []

        for msg in messages:
            if msg.get("role") == "system":
                result.append(msg)
            else:
                break

        if len(result) < len(messages) - (keep * 3):
            summary = self._create_summary_message(
                f"Previous conversation summarized ({keep} recent QA pairs preserved)"
            )
            result.append(summary)

        for block in reversed(qa_blocks):
            result.append({"role": "user", "content": block["request"]})
            result.append({"role": "assistant", "content": block["response"]})
            for tr in block.get("tool_results", []):
                result.append({"role": "user", "content": tr})

        return result
    
    def _aggressive_summarize(self, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Aggressive summarization for very long conversations."""
        # Keep system + last 5 QA pairs
        return self._preserve_recent_qa(messages, keep=5)
    
    def _create_summary_message(self, text: str) -> dict[str, Any]:
        """Create a summary message."""
        return {
            "role": "system",
            "content": f"<context_summary>{text}</context_summary>"
        }
    
    def _count_messages_tokens(self, messages: list[dict[str, Any]]) -> int:
        """Count total tokens in messages."""
        total = 0
        for msg in messages:
            content = msg.get("content", "")
            if isinstance(content, list):
                content = " ".join(
                    p.get("text", "") 
                    for p in content 
                    if isinstance(p, dict) and p.get("type") == "text"
                )
            total += _count_tokens(content, self.model_name)
        return total


def create_chain_summarizer() -> ChainSummarizer:
    """Factory function to create ChainSummarizer with config."""
    max_tokens = int(Config.get("phantom_max_input_tokens") or "128000")
    model = Config.get("phantom_llm") or "gpt-4o"
    compressor = Config.get("phantom_compressor_llm")
    
    return ChainSummarizer(
        model_name=model,
        max_input_tokens=max_tokens,
        compressor_model=compressor,
    )
