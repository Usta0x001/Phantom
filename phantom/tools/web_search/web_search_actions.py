import html
import logging
import os
import re
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote_plus
from urllib.request import Request, urlopen

import requests

from phantom.tools.registry import register_tool


logger = logging.getLogger(__name__)


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


# ── DuckDuckGo HTML fallback ─────────────────────────────────────────
_DDG_URL = "https://html.duckduckgo.com/html/"
_DDG_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
    ),
    "Accept": "text/html,application/xhtml+xml",
    "Accept-Language": "en-US,en;q=0.9",
}

# Regex patterns for parsing DuckDuckGo HTML results
_RESULT_PATTERN = re.compile(
    r'class="result__a"[^>]*href="([^"]*)"[^>]*>(.*?)</a>',
    re.DOTALL,
)
_SNIPPET_PATTERN = re.compile(
    r'class="result__snippet"[^>]*>(.*?)</(?:a|td|div)',
    re.DOTALL,
)


def _strip_html(text: str) -> str:
    """Remove HTML tags and decode entities."""
    text = re.sub(r"<[^>]+>", "", text)
    return html.unescape(text).strip()


def _duckduckgo_search(query: str, max_results: int = 8) -> dict[str, Any]:
    """Perform a DuckDuckGo HTML search (no API key required).

    Returns a dict compatible with the web_search return format.
    """
    try:
        encoded_query = quote_plus(query)
        data = f"q={encoded_query}&b=&kl=".encode()
        req = Request(_DDG_URL, data=data, headers=_DDG_HEADERS, method="POST")  # noqa: S310

        with urlopen(req, timeout=20) as resp:  # noqa: S310  # nosec B310
            body = resp.read().decode("utf-8", errors="replace")

        # Extract titles + URLs
        titles_urls = _RESULT_PATTERN.findall(body)
        snippets = _SNIPPET_PATTERN.findall(body)

        results: list[dict[str, str]] = []
        for i, (url, raw_title) in enumerate(titles_urls[:max_results]):
            title = _strip_html(raw_title)
            snippet = _strip_html(snippets[i]) if i < len(snippets) else ""
            if title or snippet:
                results.append({"title": title, "url": url, "snippet": snippet})

        if not results:
            return {
                "success": False,
                "message": "DuckDuckGo returned no results for this query",
                "results": [],
            }

        # Build a readable text block for the agent
        lines = [f"Web search results for: {query}\n"]
        for idx, r in enumerate(results, 1):
            lines.append(f"{idx}. {r['title']}")
            lines.append(f"   URL: {r['url']}")
            if r["snippet"]:
                lines.append(f"   {r['snippet']}")
            lines.append("")

        content = "\n".join(lines)
        return {
            "success": True,
            "query": query,
            "content": content,
            "results": results,
            "source": "duckduckgo",
            "message": f"DuckDuckGo search returned {len(results)} results",
        }

    except (HTTPError, URLError) as e:
        logger.warning("DuckDuckGo search failed: %s", e)
        return {"success": False, "message": f"DuckDuckGo search failed: {e!s}", "results": []}
    except Exception as e:  # noqa: BLE001
        logger.warning("DuckDuckGo search error: %s", e)
        return {"success": False, "message": f"Web search failed: {e!s}", "results": []}


# ── Main web_search tool ─────────────────────────────────────────────


@register_tool(sandbox_execution=False)
def web_search(query: str) -> dict[str, Any]:
    """Search the web for cybersecurity information.

    Uses Perplexity AI when PERPLEXITY_API_KEY is available, otherwise
    falls back to DuckDuckGo HTML search (no key required).
    """
    # Try Perplexity first if key is available
    api_key = os.getenv("PERPLEXITY_API_KEY")
    if api_key:
        try:
            url = "https://api.perplexity.ai/chat/completions"
            headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

            payload = {
                "model": "sonar-reasoning",
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": query},
                ],
            }

            response = requests.post(url, headers=headers, json=payload, timeout=300)
            response.raise_for_status()

            response_data = response.json()
            content = response_data["choices"][0]["message"]["content"]

            return {
                "success": True,
                "query": query,
                "content": content,
                "source": "perplexity",
                "message": "Web search completed successfully",
            }
        except Exception as e:  # noqa: BLE001
            logger.warning("Perplexity search failed, falling back to DuckDuckGo: %s", e)

    # Fallback: DuckDuckGo HTML search (always available)
    return _duckduckgo_search(query)
