diff --git a/phantom/tools/detection/detector.py b/phantom/tools/detection/detector.py
index 2b7f885..36e30ae 100644
--- a/phantom/tools/detection/detector.py
+++ b/phantom/tools/detection/detector.py
@@ -74,13 +74,24 @@ class VulnerabilityDetector:
     ]
 
     # Common XSS confirmation patterns
+    # FIX M4: Made more specific to avoid false positives on legitimate pages.
+    # The old <script>.*</script> matched every modern website.
     XSS_PATTERNS = [
-        r"<script[^>]*>.*</script>",
-        r"javascript:",
-        r"onerror\s*=",
-        r"onload\s*=",
-        r"onclick\s*=",
-        r"alert\(",
+        # Reflected script tags in response (not just any script)
+        r"<script[^>]*>\s*alert\s*\(",
+        r"<script[^>]*>\s*document\.cookie",
+        r"<script[^>]*>\s*eval\s*\(",
+        r"<script[^>]*>\s*location\.",
+        # Event handlers with suspicious payloads
+        r"on\w+\s*=\s*['\"]?\s*javascript:",
+        r"on\w+\s*=\s*['\"]?\s*alert\s*\(",
+        r"on\w+\s*=\s*['\"]?\s*eval\s*\(",
+        # JavaScript protocol in URLs
+        r"javascript:\s*alert\s*\(",
+        r"javascript:\s*eval\s*\(",
+        # Common XSS vectors
+        r"<img[^>]+onerror\s*=\s*['\"]?\s*alert\s*\(",
+        r"<svg[^>]+onload\s*=\s*['\"]?\s*alert\s*\(",
     ]
 
     # Command injection patterns
@@ -169,6 +180,8 @@ class VulnerabilityDetector:
             details={
                 "patterns_searched": len(search_patterns),
                 "patterns_matched": len(evidence),
+                "vuln_class": vuln_class or "unknown",
+                "surface": response_body[:500] if detected else "",
             },
         )
 
@@ -212,6 +225,7 @@ class VulnerabilityDetector:
             details={
                 "vuln_class": vuln_class,
                 "error_patterns_searched": len(patterns),
+                "surface": response_body[:500] if detected else "",
             },
         )
 
@@ -338,6 +352,7 @@ class VulnerabilityDetector:
                 "baseline_length": baseline_len,
                 "test_length": test_len,
                 "length_diff_ratio": len_ratio,
+                "surface": test_body[:500] if detected else "",
             },
         )
 
