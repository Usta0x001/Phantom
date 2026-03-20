"""
Reflector - Pentager-style lightweight re-prompt for empty responses.

Import from: Pentager's performer.go Reflector pattern

KEY DIFFERENCE from Phantom's corrective message:
- Phantom: Adds verbose corrective message to conversation (wastes tokens)
- Reflector: Lightweight re-prompt with cached/simpler model (cheaper)
"""
import logging
from typing import Any

from phantom.config.config import Config

logger = logging.getLogger(__name__)


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
            import litellm
            
            prompt = REFLECTOR_PROMPT.format(context=context[:500])  # Limit context
            
            response = await litellm.acompletion(
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
