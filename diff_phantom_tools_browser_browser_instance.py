diff --git a/phantom/tools/browser/browser_instance.py b/phantom/tools/browser/browser_instance.py
index 0679fac..c73863d 100644
--- a/phantom/tools/browser/browser_instance.py
+++ b/phantom/tools/browser/browser_instance.py
@@ -8,6 +8,7 @@ from typing import Any, cast
 
 try:
     from playwright.async_api import Browser, BrowserContext, Page, Playwright, async_playwright
+
     _PLAYWRIGHT_AVAILABLE = True
 except ImportError:  # pragma: no cover - optional dependency guard
     Browser = BrowserContext = Page = Playwright = Any
@@ -61,23 +62,77 @@ async def _create_browser() -> Browser:
         return _state.browser
 
     if _state.browser is not None:
-        with contextlib.suppress(Exception):
-            await _state.browser.close()
+        try:
+            # Force-kill if close hangs (zombie browser from previous scan)
+            await asyncio.wait_for(_state.browser.close(), timeout=5)
+        except Exception:
+            # If close() hangs, try to kill the underlying process directly
+            try:
+                browser_proc = getattr(_state.browser, "process", None)
+                if browser_proc is not None:
+                    browser_proc.kill()
+                    await asyncio.wait_for(browser_proc.wait(), timeout=5)
+            except Exception:
+                pass
         _state.browser = None
     if _state.playwright is not None:
-        with contextlib.suppress(Exception):
-            await _state.playwright.stop()
+        try:
+            await asyncio.wait_for(_state.playwright.stop(), timeout=5)
+        except Exception:
+            pass
         _state.playwright = None
 
     _state.playwright = await async_playwright().start()
-    _state.browser = await _state.playwright.chromium.launch(
-        headless=True,
-        args=[
-            "--no-sandbox",
-            "--disable-dev-shm-usage",
-            "--disable-gpu",
-        ],
-    )
+    try:
+        _state.browser = await _state.playwright.chromium.launch(
+            headless=True,
+            args=[
+                "--no-sandbox",
+                "--disable-dev-shm-usage",
+                "--disable-gpu",
+            ],
+        )
+    except Exception as exc:
+        error_msg = str(exc)
+        # Auto-install Chromium if the browser binary is missing.
+        if "Executable doesn't exist" in error_msg or "download new browsers" in error_msg:
+            logger.warning("Playwright Chromium missing; attempting auto-install...")
+            import asyncio
+            import shutil
+            import sys
+
+            playwright_cmd = shutil.which("playwright")
+            if playwright_cmd is None:
+                # Fallback: try via python -m playwright
+                playwright_cmd = sys.executable
+                install_args = ["-m", "playwright", "install", "chromium"]
+            else:
+                install_args = ["install", "chromium"]
+
+            proc = await asyncio.create_subprocess_exec(
+                playwright_cmd,
+                *install_args,
+                stdout=asyncio.subprocess.PIPE,
+                stderr=asyncio.subprocess.PIPE,
+            )
+            stdout, stderr = await proc.communicate()
+            if proc.returncode != 0:
+                raise RuntimeError(
+                    f"Failed to auto-install Playwright Chromium: {stderr.decode().strip()}"
+                ) from exc
+            logger.info("Playwright Chromium auto-installed successfully.")
+
+            # Retry launch after installation.
+            _state.browser = await _state.playwright.chromium.launch(
+                headless=True,
+                args=[
+                    "--no-sandbox",
+                    "--disable-dev-shm-usage",
+                    "--disable-gpu",
+                ],
+            )
+        else:
+            raise
     return _state.browser
 
 
@@ -89,7 +144,14 @@ def _get_browser() -> tuple[asyncio.AbstractEventLoop, Browser]:
 
         if _state.browser is None or not _state.browser.is_connected():
             future = asyncio.run_coroutine_threadsafe(_create_browser(), _state.event_loop)
-            future.result(timeout=30)
+            try:
+                future.result(timeout=60)
+            except TimeoutError as exc:
+                raise RuntimeError(
+                    "Browser launch timed out after 60s. "
+                    "If this is the first run, Playwright may still be downloading Chromium. "
+                    "Try again in a moment or run 'playwright install chromium' manually."
+                ) from exc
 
         if _state.browser is None:
             raise RuntimeError("Failed to initialize browser instance")
@@ -174,8 +236,7 @@ class BrowserInstance:
 
         page = self.pages[tab_id]
 
-        await asyncio.sleep(2)
-
+        # Playwright already auto-waits for navigations/clicks; no need for extra sleep.
         screenshot_bytes = await page.screenshot(type="png", full_page=False)
         screenshot_b64 = base64.b64encode(screenshot_bytes).decode("utf-8")
 
@@ -610,14 +671,22 @@ class BrowserInstance:
             return state
 
     def wait_for_selector(
-        self, selector: str, tab_id: str | None = None, timeout: float = 10.0, state: str = "visible"
+        self,
+        selector: str,
+        tab_id: str | None = None,
+        timeout: float = 10.0,
+        state: str = "visible",
     ) -> dict[str, Any]:
         """Wait for an element matching selector to appear."""
         with self._execution_lock:
             return self._run_async(self._wait_for_selector(selector, tab_id, timeout, state))
 
     async def _wait_for_selector(
-        self, selector: str, tab_id: str | None = None, timeout: float = 10.0, state: str = "visible"
+        self,
+        selector: str,
+        tab_id: str | None = None,
+        timeout: float = 10.0,
+        state: str = "visible",
     ) -> dict[str, Any]:
         if not tab_id:
             tab_id = self.current_page_id
@@ -642,16 +711,12 @@ class BrowserInstance:
             page_state["wait_state"] = state
             return page_state
 
-    def query_selector_all(
-        self, selector: str, tab_id: str | None = None
-    ) -> dict[str, Any]:
+    def query_selector_all(self, selector: str, tab_id: str | None = None) -> dict[str, Any]:
         """Query all elements matching selector and return their info."""
         with self._execution_lock:
             return self._run_async(self._query_selector_all(selector, tab_id))
 
-    async def _query_selector_all(
-        self, selector: str, tab_id: str | None = None
-    ) -> dict[str, Any]:
+    async def _query_selector_all(self, selector: str, tab_id: str | None = None) -> dict[str, Any]:
         if not tab_id:
             tab_id = self.current_page_id
 
@@ -677,13 +742,15 @@ class BrowserInstance:
                         return attrs;
                     }""")
 
-                    element_info.append({
-                        "index": i,
-                        "tag": tag_name,
-                        "text": text_content.strip()[:100],
-                        "attributes": attrs,
-                        "bbox": bbox,
-                    })
+                    element_info.append(
+                        {
+                            "index": i,
+                            "tag": tag_name,
+                            "text": text_content.strip()[:100],
+                            "attributes": attrs,
+                            "bbox": bbox,
+                        }
+                    )
                 except Exception:  # noqa: BLE001
                     continue
 
