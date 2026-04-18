import sys
sys.path.insert(0, ".")

from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape


def test_system_prompt_length():
    """Test the system prompt rendered length."""
    from phantom.llm.llm import LLM
    
    llm = LLM()
    prompt = llm._load_system_prompt("PhantomAgent")
    
    print(f"System prompt length: {len(prompt):,} characters")
    print(f"System prompt length: {len(prompt) / 1024:.1f} KB")
    print(f"System prompt length: {len(prompt) / (1024*1024):.2f} MB")
    

if __name__ == "__main__":
    test_system_prompt_length()