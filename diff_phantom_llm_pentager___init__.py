diff --git a/phantom/llm/pentager/__init__.py b/phantom/llm/pentager/__init__.py
index 9f971b9..8f6ea55 100644
--- a/phantom/llm/pentager/__init__.py
+++ b/phantom/llm/pentager/__init__.py
@@ -2,32 +2,16 @@
 Pentager imports for Phantom v2.
 
 This module contains ports of Pentager's key efficiency features:
-- ChainAST summarization (threshold-based, no LLM calls)
-- Tool-based delegation patterns
 - Reflector pattern for empty responses
 
 Import from: Pentager's Go codebase
 """
-from phantom.llm.pentager.chain_summarizer import (
-    ChainAST,
-    ChainSummarizer,
-    ChainSection,
-    BodyPair,
-    SectionHeader,
-    create_chain_summarizer,
-)
 from phantom.llm.pentager.reflector import (
     Reflector,
     get_reflector,
 )
 
 __all__ = [
-    "ChainAST",
-    "ChainSummarizer",
-    "ChainSection",
-    "BodyPair",
-    "SectionHeader",
-    "create_chain_summarizer",
     "Reflector",
     "get_reflector",
 ]
