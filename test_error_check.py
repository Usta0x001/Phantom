import re
import os
os.environ["PHANTOM_LLM"] = "claude-3-haiku-20240307"

from phantom.llm.memory_compressor import (
    _ANCHOR_KEYWORDS_PATTERN,
    _ANCHOR_TESTING_PATTERN,
    _ANCHOR_CONFIRM_PATTERN,
)

text = "Error: website down"

print(f"Text: '{text}'")
print(f"")
print(f"Testing pattern match: {_ANCHOR_TESTING_PATTERN.search(text)}")
print(f"General vulns pattern match: {_ANCHOR_KEYWORDS_PATTERN.search(text)}")
print(f"Confirm pattern match: {_ANCHOR_CONFIRM_PATTERN.search(text)}")