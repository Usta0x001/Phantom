diff --git a/phantom/tools/browser/tab_manager.py b/phantom/tools/browser/tab_manager.py
index f037799..424e86b 100644
--- a/phantom/tools/browser/tab_manager.py
+++ b/phantom/tools/browser/tab_manager.py
@@ -39,6 +39,11 @@ class BrowserTabManager:
                 result = browser.launch(url)
                 self._browsers_by_agent[agent_id] = browser
                 result["message"] = "Browser launched successfully"
+            except TimeoutError as e:
+                raise RuntimeError(
+                    "Browser launch timed out. If this is the first run, "
+                    "Playwright may still be downloading Chromium. Try again shortly."
+                ) from e
             except (OSError, ValueError, RuntimeError) as e:
                 raise RuntimeError(f"Failed to launch browser: {e}") from e
             else:
