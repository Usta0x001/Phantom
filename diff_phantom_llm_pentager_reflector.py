diff --git a/phantom/llm/pentager/reflector.py b/phantom/llm/pentager/reflector.py
index 18e6908..6cf39cc 100644
--- a/phantom/llm/pentager/reflector.py
+++ b/phantom/llm/pentager/reflector.py
@@ -9,7 +9,7 @@ KEY DIFFERENCE from Phantom's corrective message:
 """
 import logging
 import re
-from typing import Any
+from typing import Optional
 
 from phantom.config.config import Config
 from phantom.llm.tracked_completion import tracked_acompletion
