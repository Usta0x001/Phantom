diff --git a/phantom/tools/osint/__init__.py b/phantom/tools/osint/__init__.py
index bc91893..ebd9000 100644
--- a/phantom/tools/osint/__init__.py
+++ b/phantom/tools/osint/__init__.py
@@ -10,9 +10,6 @@ from phantom.tools.osint.osint_actions import (
 )
 
 from phantom.tools.osint.subdomain_bruteforce import (
-    bruteforce_subdomains,
-    smart_subdomain_gen,
-    run_subdomain_tools,
     comprehensive_subdomain_enum,
 )
 
@@ -22,8 +19,5 @@ __all__ = [
     "whois_lookup",
     "dns_enum",
     "github_dork",
-    "bruteforce_subdomains",
-    "smart_subdomain_gen",
-    "run_subdomain_tools",
     "comprehensive_subdomain_enum",
 ]
