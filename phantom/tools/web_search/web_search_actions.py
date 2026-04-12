import asyncio
import os
import re
from typing import Any

import httpx

from phantom.tools.registry import register_tool

# Try to import DuckDuckGo for fallback
_DDG_AVAILABLE = False
try:
    from ddgs import DDGS
    _DDG_AVAILABLE = True
except ImportError:
    pass  # DuckDuckGo not installed, will use Perplexity only


SYSTEM_PROMPT = """You are assisting a cybersecurity agent specialized in vulnerability scanning
and security assessment running on Kali Linux. When responding to search queries:

1. Prioritize cybersecurity-relevant information including:
   - Vulnerability details (CVEs, CVSS scores, impact)
   - Security tools, techniques, and methodologies
   - Exploit information and proof-of-concepts
   - Security best practices and mitigations
   - Penetration testing approaches
   - Web application security findings

2. Provide technical depth appropriate for security professionals
3. Include specific versions, configurations, and technical details when available
4. Focus on actionable intelligence for security assessment
5. Cite reliable security sources (NIST, OWASP, CVE databases, security vendors)
6. When providing commands or installation instructions, prioritize Kali Linux compatibility
   and use apt package manager or tools pre-installed in Kali
7. Be detailed and specific - avoid general answers. Always include concrete code examples,
   command-line instructions, configuration snippets, or practical implementation steps
   when applicable

Structure your response to be comprehensive yet concise, emphasizing the most critical
security implications and details."""


def _duckduckgo_search_fallback(query: str, max_results: int = 5) -> dict[str, Any]:
    """
    Fallback search using DuckDuckGo when Perplexity API key is not available.
    This is FREE and requires no API key.
    """
    if not _DDG_AVAILABLE:
        return {
            "success": False,
            "message": "DuckDuckGo not installed. Install with: pip install duckduckgo-search",
            "results": [],
        }
    
    try:
        results_text = ""
        with DDGS() as ddgs:
            results = list(ddgs.text(query, max_results=max_results))
        
        if not results:
            return {
                "success": True,
                "query": query,
                "content": "No search results found.",
                "message": "Search completed but no results found",
                "results": [],
            }
        
        # Format results for LLM
        results_text = f"[WEB SEARCH RESULTS FOR: {query}]\n"
        results_text += "=" * 50 + "\n\n"
        for i, r in enumerate(results, 1):
            results_text += f"[{i}] {r.get('title', 'N/A')}\n"
            results_text += f"    URL     : {r.get('href', 'N/A')}\n"
            results_text += f"    Snippet : {r.get('body', 'N/A')}\n\n"
        
        return {
            "success": True,
            "query": query,
            "content": results_text,
            "message": f"Found {len(results)} results via DuckDuckGo (free fallback)",
            "results": results,
        }
        
    except Exception as e:
        return {
            "success": False,
            "message": f"DuckDuckGo search failed: {e}",
            "results": [],
        }


def _search_cve_fallback(cve_id: str) -> dict[str, Any]:
    """
    Fallback CVE lookup using DuckDuckGo + MITRE when NVD API is not available.
    """
    if not _DDG_AVAILABLE:
        return {
            "success": False,
            "message": "DuckDuckGo not installed. Install with: pip install duckduckgo-search",
            "content": "",
        }
    
    try:
        results_text = f"[CVE LOOKUP: {cve_id}]\n"
        results_text += "=" * 50 + "\n\n"
        
        # Search for CVE details
        with DDGS() as ddgs:
            results = list(ddgs.text(f"{cve_id} vulnerability CVE details", max_results=3))
        
        if results:
            results_text += "[Search Results]\n"
            for r in results:
                results_text += f"- {r.get('title', 'N/A')}\n"
                results_text += f"  {r.get('href', 'N/A')}\n\n"
        
        # Try to fetch MITRE page
        try:
            import requests
            mitre_url = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
            resp = requests.get(mitre_url, timeout=10)
            if resp.status_code == 200:
                results_text += f"\n[MITRE Reference]\n{mitre_url}\n"
        except Exception:
            pass  # MITRE fetch optional
        
        return {
            "success": True,
            "content": results_text,
            "message": f"CVE lookup completed for {cve_id}",
        }
        
    except Exception as e:
        return {
            "success": False,
            "message": f"CVE search failed: {e}",
            "content": "",
        }


def _smart_search_router(query: str) -> dict[str, Any]:
    """
    Automatically detect query type and route to appropriate search:
    - CVE pattern (CVE-YYYY-NNNNN) → CVE lookup
    - Exploit/poc keywords → Exploit search  
    - Fix/patch/mitigate keywords → Fix search
    - Default → General web search
    """
    query_lower = query.lower()
    
    # CVE pattern detection
    cve_pattern = re.compile(r'cve-\d{4}-\d{4,7}', re.IGNORECASE)
    cve_match = cve_pattern.search(query)
    if cve_match:
        cve_id = cve_match.group().upper()
        return {
            "search_type": "cve",
            "query": cve_id,
            "result": _search_cve_fallback(cve_id),
        }
    
    # Exploit keywords
    exploit_keywords = ["exploit", "poc", "payload", "rce", "lfi", "sqli", "xss", "injection"]
    if any(word in query_lower for word in exploit_keywords):
        ddg_result = _duckduckgo_search_fallback(query + " exploit github", max_results=5)
        return {
            "search_type": "exploit",
            "query": query,
            "result": ddg_result,
        }
    
    # Fix/patch keywords
    fix_keywords = ["fix", "patch", "mitigate", "harden", "secure", "remediation"]
    if any(word in query_lower for word in fix_keywords):
        ddg_result = _duckduckgo_search_fallback(query + " security fix mitigation", max_results=5)
        return {
            "search_type": "fix",
            "query": query,
            "result": ddg_result,
        }
    
    # Default: general search
    ddg_result = _duckduckgo_search_fallback(query, max_results=5)
    return {
        "search_type": "general",
        "query": query,
        "result": ddg_result,
    }


@register_tool(sandbox_execution=False)
async def web_search(query: str, use_smart_router: bool = False) -> dict[str, Any]:
    token = os.getenv("PERPLEXITY_API_KEY")
    
    # Smart router: auto-detect CVE/exploit/fix queries
    if use_smart_router:
        router_result = _smart_search_router(query)
        result = router_result["result"]
        result["search_type"] = router_result["search_type"]
        return result
    
    # Try Perplexity first if API key is available
    if token:
        try:
            url = "https://api.perplexity.ai/chat/completions"
            bearer_token = f"Bearer {token}"
            headers = {"Authorization": bearer_token, "Content-Type": "application/json"}

            payload = {
                "model": "sonar-reasoning",
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": query},
                ],
            }

            async with httpx.AsyncClient(trust_env=False, timeout=300) as client:
                response = await client.post(url, headers=headers, json=payload)
                response.raise_for_status()
                response_data = response.json()
                content = response_data["choices"][0]["message"]["content"]

            return {
                "success": True,
                "query": query,
                "content": content,
                "message": "Web search completed successfully",
            }

        except httpx.TimeoutException:
            # Fall through to DuckDuckGo fallback
            pass
        except httpx.HTTPStatusError:
            # Fall through to DuckDuckGo fallback
            pass
        except httpx.RequestError:
            # Fall through to DuckDuckGo fallback
            pass
        except Exception:  # noqa: BLE001
            # Fall through to DuckDuckGo fallback
            pass
    
    # Fallback to DuckDuckGo if Perplexity failed or not available
    if _DDG_AVAILABLE:
        ddg_result = _duckduckgo_search_fallback(query, max_results=5)
        ddg_result["fallback_used"] = "duckduckgo"
        return ddg_result
    
    return {
        "success": False,
        "message": "PERPLEXITY_API_KEY not set and DuckDuckGo not installed. Install duckduckgo-search or set PERPLEXITY_API_KEY",
        "results": [],
    }
