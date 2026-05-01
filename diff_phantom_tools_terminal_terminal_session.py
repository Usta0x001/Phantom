diff --git a/phantom/tools/terminal/terminal_session.py b/phantom/tools/terminal/terminal_session.py
index 1d3d2d8..73472e5 100644
--- a/phantom/tools/terminal/terminal_session.py
+++ b/phantom/tools/terminal/terminal_session.py
@@ -287,8 +287,21 @@ class TerminalSession:
         should_add_enter = not is_special_key and not no_enter
         self.pane.send_keys(command, enter=should_add_enter)
 
-        time.sleep(2)
+        # Poll for output instead of blind 2s sleep; cap at 2s for slow commands.
+        max_wait = 2.0
+        waited = 0.0
         cur_pane_output = self._get_pane_content()
+        while waited < max_wait:
+            time.sleep(self.POLL_INTERVAL)
+            waited += self.POLL_INTERVAL
+            new_output = self._get_pane_content()
+            if new_output != cur_pane_output:
+                cur_pane_output = new_output
+            else:
+                # Output stabilized; check if prompt is back.
+                if cur_pane_output.rstrip().endswith(self.PS1_END.rstrip()):
+                    break
+
         ps1_matches = self._matches_ps1_metadata(cur_pane_output)
         raw_command_output = self._combine_outputs_between_matches(cur_pane_output, ps1_matches)
         command_output = self._get_command_output(command, raw_command_output)
