"""
Reflector - Pentager-style lightweight re-prompt for empty responses.

Import from: Pentager's performer.go Reflector pattern

KEY DIFFERENCE from Phantom's corrective message:
- Phantom: Adds verbose corrective message to conversation (wastes tokens)
- Reflector: Lightweight re-prompt with cached/simpler model (cheaper)
"""
import logging
import re
from typing import Optional

from phantom.config.config import Config
from phantom.llm.tracked_completion import tracked_acompletion

logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════════════════════
# SECURITY FIX: Prompt injection patterns to sanitize from reflector context
# ════════════════════════════════════════════════════════════════════════════════
_REFLECTOR_INJECTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # System prompt manipulation
    (re.compile(r"</?system\s*>", re.IGNORECASE), "[REMOVED]"),
    (re.compile(r"\[/?system\]", re.IGNORECASE), "[REMOVED]"),
    (re.compile(r"<</?SYS>>", re.IGNORECASE), "[REMOVED]"),
    # Instruction override attempts
    (re.compile(r"ignore\s+(all\s+)?previous\s+instructions?", re.IGNORECASE), "[REMOVED]"),
    (re.compile(r"forget\s+(all\s+)?previous", re.IGNORECASE), "[REMOVED]"),
    (re.compile(r"disregard\s+(all\s+)?prior", re.IGNORECASE), "[REMOVED]"),
    (re.compile(r"override\s+(all\s+)?safety", re.IGNORECASE), "[REMOVED]"),
    # Role manipulation
    (re.compile(r"you\s+are\s+now\s+(a\s+)?malicious", re.IGNORECASE), "[REMOVED]"),
    (re.compile(r"you\s+must\s+execute\s+dangerous", re.IGNORECASE), "[REMOVED]"),
    (re.compile(r"become\s+DAN", re.IGNORECASE), "[REMOVED]"),
    (re.compile(r"Do\s+Anything\s+Now", re.IGNORECASE), "[REMOVED]"),
    # Function/tool injection
    (re.compile(r"</function>", re.IGNORECASE), "[REMOVED]"),
    (re.compile(r"</tool_result>", re.IGNORECASE), "[REMOVED]"),
    (re.compile(r"<function=\w+>", re.IGNORECASE), "[REMOVED]"),
    (re.compile(r"\[INST\]", re.IGNORECASE), "[REMOVED]"),
    (re.compile(r"\[/INST\]", re.IGNORECASE), "[REMOVED]"),
    # Multi-line role injection
    (re.compile(r"^assistant:\s*", re.IGNORECASE | re.MULTILINE), ""),
    (re.compile(r"^user:\s*", re.IGNORECASE | re.MULTILINE), ""),
    (re.compile(r"^system:\s*", re.IGNORECASE | re.MULTILINE), ""),
    # Dangerous action requests
    (re.compile(r"execute\s*:\s*rm\s+-rf", re.IGNORECASE), "[REMOVED]"),
    (re.compile(r"reveal\s+all\s+secrets", re.IGNORECASE), "[REMOVED]"),
    (re.compile(r"output\s+all\s+training\s+data", re.IGNORECASE), "[REMOVED]"),
]


def _sanitize_reflector_context(context: str) -> str:
    """SECURITY FIX: Sanitize context before sending to reflector model.
    
    Removes prompt injection patterns that could manipulate the weaker
    reflector model into executing malicious actions.
    """
    if not isinstance(context, str):
        return str(context) if context is not None else ""
    
    sanitized = context
    for pattern, replacement in _REFLECTOR_INJECTION_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    
    return sanitized


REFLECTOR_PROMPT = """You are a security advisor. The agent returned text without tool calls.

CONTEXT:
{context}

TASK:
The agent should use tools to perform security testing.
Suggest the next tool to use: terminal_execute, send_request, create_agent, or browser_action.

Respond with ONLY a tool suggestion, no explanation.
Example: "terminal_execute: sqlmap -u 'http://target.com/login' --batch"
"""


class Reflector:
    """
    Pentager-style lightweight Reflector for empty responses.
    
    When LLM returns text without tool calls, use this instead of verbose corrective message.
    
    Usage:
        reflector = Reflector()
        if not tool_calls:
            suggestion = await reflector.reflect(last_message)
            if suggestion:
                add_tool_to_conversation(suggestion)
    """
    
    def __init__(
        self,
        reflector_model: str | None = None,
        reflector_timeout: int = 10,
    ):
        self.reflector_model = (
            reflector_model 
            or Config.get("phantom_reflector_model")
            or "gpt-4o-mini"  # Cheaper model for reflector
        )
        self.reflector_timeout = reflector_timeout
        self.reflect_count = 0
        
        logger.info("Reflector initialized with model=%s", self.reflector_model)
    
    async def reflect(
        self,
        context: str,
        max_retries: int = 1,
    ) -> str | None:
        """
        Get a tool suggestion from the Reflector.
        
        Returns tool suggestion string or None if no suggestion.
        """
        if not context:
            return None
        
        self.reflect_count += 1
        
        try:
            # SECURITY FIX: Sanitize context before sending to reflector model
            sanitized_context = _sanitize_reflector_context(context[:500])
            prompt = REFLECTOR_PROMPT.format(context=sanitized_context)
            
            response = await tracked_acompletion(
                model=self.reflector_model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=100,  # Keep it short
                timeout=self.reflector_timeout,
            )
            
            suggestion = response.choices[0].message.content.strip()
            
            logger.info(
                "Reflector suggestion #%d: %s",
                self.reflect_count, suggestion[:100]
            )
            
            return suggestion
            
        except Exception as e:
            logger.warning("Reflector failed: %s", e)
            return None
    
    def get_reflect_count(self) -> int:
        """Get number of times Reflector was invoked."""
        return self.reflect_count


# Global reflector instance (lazy initialization)
_reflector: Reflector | None = None


def get_reflector() -> Reflector:
    """Get or create global Reflector instance."""
    global _reflector
    if _reflector is None:
        _reflector = Reflector()
    return _reflector
