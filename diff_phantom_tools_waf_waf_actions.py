diff --git a/phantom/tools/waf/waf_actions.py b/phantom/tools/waf/waf_actions.py
index dc641c3..cd537c5 100644
--- a/phantom/tools/waf/waf_actions.py
+++ b/phantom/tools/waf/waf_actions.py
@@ -918,7 +918,7 @@ async def detect_waf(
         # Build recommendations
         recommendations = []
         if primary_waf:
-            recommendations.append(f"Use get_waf_evasion_strategies('{primary_waf['waf_id']}') for bypass techniques")
+            recommendations.append("Use web_search for WAF bypass techniques and evasion strategies")
             recommendations.append("Consider searching for origin IP (DNS history, certificate search)")
             recommendations.append("Check if all subdomains use the same WAF")
         else:
@@ -978,112 +978,3 @@ async def detect_waf(
         }
 
 
-@register_tool(sandbox_execution=False)
-async def get_waf_evasion_strategies(
-    waf_id: str | None = None,
-    waf_name: str | None = None,
-    category: str | None = None,
-) -> dict[str, Any]:
-    """
-    Get WAF evasion strategies and bypass techniques for a specific WAF.
-    
-    This tool provides educational information about WAF bypass techniques.
-    Use this after detect_waf() identifies the target's WAF.
-    
-    Args:
-        waf_id: WAF identifier from detect_waf() (e.g., "cloudflare", "akamai")
-        waf_name: Alternative: search by WAF name (e.g., "Cloudflare")
-        category: Optional: filter strategies by category
-                 Options: "encoding", "origin", "browser", "protocol"
-    
-    Returns:
-        Dictionary containing:
-        - success: Whether lookup succeeded
-        - waf: WAF name and vendor information
-        - general_info: Overview of the WAF and its defenses
-        - strategies: List of evasion strategies with techniques
-        - limitations: Known limitations and caveats
-        - available_wafs: List of WAFs with available strategies
-        - message: Status message
-    
-    Supported WAFs:
-        cloudflare, akamai, aws_waf, imperva_incapsula, sucuri,
-        f5_big_ip, modsecurity, generic (universal techniques)
-    """
-    # Normalize inputs
-    if waf_name and not waf_id:
-        # Try to find waf_id from name
-        waf_name_lower = waf_name.lower()
-        for wid, strategies in WAF_EVASION_STRATEGIES.items():
-            if waf_name_lower in wid or waf_name_lower in strategies.get("general_info", "").lower():
-                waf_id = wid
-                break
-    
-    if not waf_id:
-        # List available WAFs
-        available = []
-        for wid in WAF_EVASION_STRATEGIES.keys():
-            if wid in WAF_SIGNATURES:
-                available.append({
-                    "id": wid,
-                    "name": WAF_SIGNATURES[wid].get("name", wid),
-                    "vendor": WAF_SIGNATURES[wid].get("vendor", "Unknown"),
-                })
-            else:
-                available.append({"id": wid, "name": wid.title(), "vendor": "N/A"})
-        
-        return {
-            "success": True,
-            "waf_id": None,
-            "message": "No WAF specified. Use waf_id parameter or run detect_waf() first.",
-            "available_wafs": available,
-            "suggestion": "Try get_waf_evasion_strategies(waf_id='cloudflare') or waf_id='generic' for universal techniques",
-        }
-    
-    waf_id = waf_id.lower().replace(" ", "_").replace("-", "_")
-    
-    # Check if we have strategies for this WAF
-    if waf_id not in WAF_EVASION_STRATEGIES:
-        # Try partial match
-        for wid in WAF_EVASION_STRATEGIES.keys():
-            if waf_id in wid or wid in waf_id:
-                waf_id = wid
-                break
-    
-    if waf_id not in WAF_EVASION_STRATEGIES:
-        return {
-            "success": False,
-            "error": f"No evasion strategies found for WAF: {waf_id}",
-            "suggestion": "Try waf_id='generic' for universal bypass techniques",
-            "available_wafs": list(WAF_EVASION_STRATEGIES.keys()),
-        }
-    
-    strategies_data = WAF_EVASION_STRATEGIES[waf_id]
-    
-    # Get WAF info from signatures if available
-    waf_info = {
-        "id": waf_id,
-        "name": WAF_SIGNATURES.get(waf_id, {}).get("name", waf_id.title()),
-        "vendor": WAF_SIGNATURES.get(waf_id, {}).get("vendor", "Unknown"),
-    }
-    
-    # Filter strategies by category if specified
-    strategies = strategies_data.get("strategies", [])
-    if category:
-        category_lower = category.lower()
-        strategies = [
-            s for s in strategies
-            if category_lower in s.get("name", "").lower()
-            or category_lower in s.get("description", "").lower()
-            or any(category_lower in t.lower() for t in s.get("techniques", []))
-        ]
-    
-    return {
-        "success": True,
-        "waf": waf_info,
-        "general_info": strategies_data.get("general_info", ""),
-        "strategies": strategies,
-        "limitations": strategies_data.get("limitations", []),
-        "note": "These techniques are for authorized security testing only",
-        "message": f"Found {len(strategies)} evasion strategies for {waf_info['name']}",
-    }
