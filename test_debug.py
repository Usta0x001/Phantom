import re
import os
os.environ["PHANTOM_LLM"] = "claude-3-haiku-20240307"

from phantom.llm.memory_compressor import (
    _ANCHOR_KEYWORDS_PATTERN,
    _ANCHOR_TESTING_PATTERN,
    _ANCHOR_CONFIRM_PATTERN,
)

test_texts = [
    "Testing",
    "trying", 
    "checking",
    "Testing SQL injection",
    "test",
]

for text in test_texts:
    print(f"\nText: '{text}'")
    print(f"  Testing pattern: {_ANCHOR_TESTING_PATTERN.search(text)}")
    print(f"  General vuln: {_ANCHOR_KEYWORDS_PATTERN.search(text)}")
    print(f"  Confirm: {_ANCHOR_CONFIRM_PATTERN.search(text)}")