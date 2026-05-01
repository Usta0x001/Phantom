diff --git a/phantom/core/diff_scanner.py b/phantom/core/diff_scanner.py
index 2a47623..99a84e5 100644
--- a/phantom/core/diff_scanner.py
+++ b/phantom/core/diff_scanner.py
@@ -28,8 +28,8 @@ def _load_vulns(run_dir: str | Path) -> list[dict[str, Any]]:
             vulns = data.get("vulnerability_reports", [])
             if isinstance(vulns, list):
                 return vulns
-        except Exception:
-            pass
+        except Exception as _e:
+            logger.warning("Failed to parse checkpoint %s: %s", cp_file, _e)
 
     # Fallback: scan any *.json file for a vulnerabilities / findings key
     for json_file in sorted(run_path.glob("*.json")):
@@ -38,8 +38,8 @@ def _load_vulns(run_dir: str | Path) -> list[dict[str, Any]]:
             for key in ("vulnerability_reports", "vulnerabilities", "findings"):
                 if isinstance(data.get(key), list):
                     return data[key]
-        except Exception:
-            continue
+        except Exception as _e:
+            logger.debug("Failed to parse fallback JSON %s: %s", json_file, _e)
 
     return []
 
@@ -48,12 +48,15 @@ def _vuln_key(v: dict[str, Any]) -> str:
     """Deterministic identity key for a vulnerability (used for diff matching)."""
     name = str(v.get("name", v.get("title", ""))).strip().lower()
     endpoint = str(v.get("endpoint", v.get("url", ""))).strip().lower()
-    sev = str(v.get("severity", "info")).strip().lower()
+    parameter = str(v.get("parameter", v.get("param", ""))).strip().lower()
     # Use id field if present (Phantom assigns stable UUIDs)
     vid = str(v.get("id", "")).strip()
     if vid:
         return vid
-    return f"{name}|{endpoint}|{sev}"
+    # FIX: Removed severity from the key. Changing severity between scans
+    # made the same vuln appear as both NEW and FIXED. Use name+endpoint+param
+    # for stable matching.
+    return f"{name}|{endpoint}|{parameter}"
 
 
 @dataclass
@@ -118,7 +121,7 @@ class DiffReport:
                 lines.append(self._vuln_summary(v))
             lines.append("")
 
-        if not any([self.new_vulns, self.fixed_vulns, self.persistent_vulns]):
+        if not any((self.new_vulns, self.fixed_vulns, self.persistent_vulns)):
             lines += ["_No differences found between the two runs._", ""]
 
         return "\n".join(lines)
