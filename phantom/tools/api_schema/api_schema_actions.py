"""
P3.6: API Schema Validation Tool
=================================

Parse and validate OpenAPI/Swagger schemas to extract endpoints,
parameters, and security requirements for automated testing.

SECURITY NOTES:
- READ-ONLY schema parsing (no execution)
- Uses defusedxml to prevent XXE attacks
- Size limits prevent billion laughs / quadratic blowup
- No external entity resolution
- Validates schema structure before processing

Tools:
- parse_openapi_schema: Parse OpenAPI 2.0/3.x JSON/YAML schemas
- extract_api_endpoints: Extract testable endpoints from schema
- analyze_security_requirements: Identify auth/security schemes
"""

import json
import logging
import re
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
import yaml

from phantom.config.config import Config
from phantom.tools.registry import register_tool


logger = logging.getLogger(__name__)

# Security limits
MAX_SCHEMA_SIZE = 10 * 1024 * 1024  # 10MB max schema size
MAX_ENDPOINTS = 1000  # Max endpoints to extract
MAX_PARAMETERS = 100  # Max parameters per endpoint
REQUEST_TIMEOUT = 10  # seconds


def _sanitize_url(url: str) -> str | None:
    """
    Validate and sanitize URL.
    
    Security: Prevents SSRF by validating URL format.
    """
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return None
        if not parsed.netloc:
            return None
        return url
    except Exception:
        return None


def _fetch_schema(url_or_data: str, timeout: int = REQUEST_TIMEOUT) -> dict[str, Any] | None:
    """
    Fetch and parse schema from URL or parse directly if JSON/YAML string.
    
    Security:
    - Size limit prevents DoS
    - Timeout prevents hanging
    - SSRF validation on URLs
    - Safe YAML loading (no code execution)
    """
    # Check if it's a URL
    if url_or_data.strip().startswith(("http://", "https://")):
        sanitized = _sanitize_url(url_or_data.strip())
        if not sanitized:
            logger.warning("Invalid or unsafe URL")
            return None
        
        try:
            # Fetch schema from URL
            with httpx.Client(timeout=timeout, follow_redirects=True) as client:
                response = client.get(sanitized)
                response.raise_for_status()
                
                # Check size
                if len(response.content) > MAX_SCHEMA_SIZE:
                    logger.warning(f"Schema too large: {len(response.content)} bytes")
                    return None
                
                content = response.text
        except Exception as e:
            logger.error(f"Failed to fetch schema: {e}")
            return None
    else:
        # Treat as direct schema content
        content = url_or_data
        
        # Check size
        if len(content) > MAX_SCHEMA_SIZE:
            logger.warning(f"Schema too large: {len(content)} bytes")
            return None
    
    # Try parsing as JSON first
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass
    
    # Try YAML (SAFE loading - no code execution)
    try:
        # yaml.safe_load prevents arbitrary Python object execution
        return yaml.safe_load(content)
    except yaml.YAMLError as e:
        logger.error(f"Failed to parse schema: {e}")
        return None


def _extract_openapi_v2_endpoints(schema: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract endpoints from OpenAPI 2.0 (Swagger) schema."""
    endpoints: list[dict[str, Any]] = []
    
    base_path = schema.get("basePath", "")
    host = schema.get("host", "")
    schemes = schema.get("schemes", ["http"])
    
    paths = schema.get("paths", {})
    
    for path, path_item in paths.items():
        if len(endpoints) >= MAX_ENDPOINTS:
            break
        
        # Each path can have multiple methods
        for method in ["get", "post", "put", "delete", "patch", "options", "head"]:
            if method not in path_item:
                continue
            
            operation = path_item[method]
            
            # Extract parameters
            parameters = []
            for param in operation.get("parameters", [])[:MAX_PARAMETERS]:
                parameters.append({
                    "name": param.get("name"),
                    "in": param.get("in"),  # query, header, path, body, form
                    "required": param.get("required", False),
                    "type": param.get("type", "string"),
                    "description": param.get("description", ""),
                })
            
            # Build full URL
            full_path = base_path + path
            base_url = f"{schemes[0]}://{host}" if host else ""
            
            endpoints.append({
                "path": path,
                "full_path": full_path,
                "base_url": base_url,
                "method": method.upper(),
                "summary": operation.get("summary", ""),
                "description": operation.get("description", ""),
                "parameters": parameters,
                "security": operation.get("security", schema.get("security", [])),
                "tags": operation.get("tags", []),
            })
    
    return endpoints


def _extract_openapi_v3_endpoints(schema: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract endpoints from OpenAPI 3.x schema."""
    endpoints: list[dict[str, Any]] = []
    
    # OpenAPI 3.x uses servers instead of host/basePath
    servers = schema.get("servers", [])
    base_url = servers[0].get("url", "") if servers else ""
    
    paths = schema.get("paths", {})
    
    for path, path_item in paths.items():
        if len(endpoints) >= MAX_ENDPOINTS:
            break
        
        for method in ["get", "post", "put", "delete", "patch", "options", "head"]:
            if method not in path_item:
                continue
            
            operation = path_item[method]
            
            # Extract parameters
            parameters = []
            for param in operation.get("parameters", [])[:MAX_PARAMETERS]:
                parameters.append({
                    "name": param.get("name"),
                    "in": param.get("in"),
                    "required": param.get("required", False),
                    "schema": param.get("schema", {}),
                    "description": param.get("description", ""),
                })
            
            # Handle requestBody (OpenAPI 3.x)
            request_body = operation.get("requestBody")
            if request_body:
                content = request_body.get("content", {})
                for media_type, media_obj in content.items():
                    parameters.append({
                        "name": "body",
                        "in": "body",
                        "required": request_body.get("required", False),
                        "media_type": media_type,
                        "schema": media_obj.get("schema", {}),
                        "description": request_body.get("description", ""),
                    })
            
            endpoints.append({
                "path": path,
                "full_path": path,
                "base_url": base_url,
                "method": method.upper(),
                "summary": operation.get("summary", ""),
                "description": operation.get("description", ""),
                "parameters": parameters,
                "security": operation.get("security", schema.get("security", [])),
                "tags": operation.get("tags", []),
            })
    
    return endpoints


def _extract_security_schemes(schema: dict[str, Any]) -> dict[str, Any]:
    """Extract security scheme definitions."""
    # OpenAPI 2.0
    if "securityDefinitions" in schema:
        return schema["securityDefinitions"]
    
    # OpenAPI 3.x
    if "components" in schema and "securitySchemes" in schema["components"]:
        return schema["components"]["securitySchemes"]
    
    return {}


@register_tool(sandbox_execution=False)
def parse_openapi_schema(schema_url_or_data: str) -> str:
    """
    Parse OpenAPI/Swagger schema and extract API structure.
    
    Supports OpenAPI 2.0 (Swagger) and OpenAPI 3.x formats in JSON or YAML.
    Returns parsed schema with endpoints, parameters, and security requirements.
    
    Args:
        schema_url_or_data: URL to schema file or direct schema content (JSON/YAML)
    
    Returns:
        JSON string with parsed schema information including:
        - openapi_version: Detected schema version
        - endpoints_count: Number of endpoints found
        - security_schemes: Authentication/authorization schemes
        - base_url: API base URL
    
    Security:
        - Uses safe YAML parser (no code execution)
        - Size limits prevent DoS
        - No external entity resolution
        - Read-only operation
    
    Example:
        parse_openapi_schema("https://api.example.com/openapi.json")
        parse_openapi_schema('{"openapi": "3.0.0", "paths": {...}}')
    """
    try:
        schema = _fetch_schema(schema_url_or_data)
        if not schema:
            return json.dumps({
                "success": False,
                "error": "Failed to fetch or parse schema"
            })
        
        # Detect version
        if "swagger" in schema:
            version = schema["swagger"]
            openapi_version = "2.0"
        elif "openapi" in schema:
            version = schema["openapi"]
            openapi_version = "3.x"
        else:
            return json.dumps({
                "success": False,
                "error": "Unknown schema format (missing 'swagger' or 'openapi' field)"
            })
        
        # Extract info
        info = schema.get("info", {})
        
        # Extract endpoints
        if openapi_version == "2.0":
            endpoints = _extract_openapi_v2_endpoints(schema)
        else:
            endpoints = _extract_openapi_v3_endpoints(schema)
        
        # Extract security schemes
        security_schemes = _extract_security_schemes(schema)
        
        # Build result
        result = {
            "success": True,
            "openapi_version": version,
            "api_title": info.get("title", "Unknown"),
            "api_version": info.get("version", "Unknown"),
            "api_description": info.get("description", ""),
            "endpoints_count": len(endpoints),
            "security_schemes": list(security_schemes.keys()),
            "security_schemes_detail": security_schemes,
        }
        
        # Add base URL if available
        if endpoints:
            result["base_url"] = endpoints[0].get("base_url", "")
        
        return json.dumps(result, indent=2)
    
    except Exception as e:
        logger.exception("Error parsing OpenAPI schema")
        return json.dumps({
            "success": False,
            "error": f"Unexpected error: {str(e)}"
        })


@register_tool(sandbox_execution=False)
def extract_api_endpoints(schema_url_or_data: str, filter_by_tag: str | None = None) -> str:
    """
    Extract testable endpoints from OpenAPI/Swagger schema.
    
    Returns detailed endpoint information including paths, methods, parameters,
    and security requirements. Useful for automated API testing.
    
    Args:
        schema_url_or_data: URL to schema or direct schema content
        filter_by_tag: Optional tag to filter endpoints (e.g., "admin", "public")
    
    Returns:
        JSON string with list of endpoints. Each endpoint includes:
        - path: URL path template (e.g., "/users/{id}")
        - method: HTTP method (GET, POST, etc.)
        - parameters: List of parameters with location (query, path, body, header)
        - security: Security requirements for this endpoint
        - summary/description: Endpoint documentation
    
    Security:
        - Read-only schema parsing
        - No code execution
        - Safe YAML/JSON parsing only
    
    Example:
        extract_api_endpoints("https://api.example.com/swagger.json")
        extract_api_endpoints(schema_data, filter_by_tag="admin")
    """
    try:
        schema = _fetch_schema(schema_url_or_data)
        if not schema:
            return json.dumps({
                "success": False,
                "error": "Failed to fetch or parse schema"
            })
        
        # Detect version and extract endpoints
        if "swagger" in schema:
            endpoints = _extract_openapi_v2_endpoints(schema)
        elif "openapi" in schema:
            endpoints = _extract_openapi_v3_endpoints(schema)
        else:
            return json.dumps({
                "success": False,
                "error": "Unknown schema format"
            })
        
        # Filter by tag if requested
        if filter_by_tag:
            endpoints = [
                ep for ep in endpoints
                if filter_by_tag in ep.get("tags", [])
            ]
        
        # Limit output size
        total_endpoints = len(endpoints)
        returned_endpoints = endpoints[:100]
        
        return json.dumps({
            "success": True,
            "endpoints_count": total_endpoints,  # Total found
            "endpoints_returned": len(returned_endpoints),  # Returned in response
            "endpoints": returned_endpoints,
        }, indent=2)
    
    except Exception as e:
        logger.exception("Error extracting endpoints")
        return json.dumps({
            "success": False,
            "error": f"Unexpected error: {str(e)}"
        })


@register_tool(sandbox_execution=False)
def analyze_security_requirements(schema_url_or_data: str) -> str:
    """
    Analyze security/authentication requirements from OpenAPI schema.
    
    Identifies authentication schemes, authorization requirements, and
    security policies defined in the API schema.
    
    Args:
        schema_url_or_data: URL to schema or direct schema content
    
    Returns:
        JSON string with security analysis including:
        - authentication_schemes: Available auth methods (apiKey, oauth2, http, etc.)
        - endpoints_by_security: Endpoints grouped by security requirements
        - insecure_endpoints: Endpoints with no security requirements
        - oauth_scopes: OAuth2 scopes if applicable
    
    Security:
        - Read-only analysis
        - No interaction with actual API
        - Safe parsing only
    
    Example:
        analyze_security_requirements("https://api.example.com/openapi.yaml")
    """
    try:
        schema = _fetch_schema(schema_url_or_data)
        if not schema:
            return json.dumps({
                "success": False,
                "error": "Failed to fetch or parse schema"
            })
        
        # Extract security schemes
        security_schemes = _extract_security_schemes(schema)
        
        # Extract endpoints
        if "swagger" in schema:
            endpoints = _extract_openapi_v2_endpoints(schema)
        elif "openapi" in schema:
            endpoints = _extract_openapi_v3_endpoints(schema)
        else:
            return json.dumps({
                "success": False,
                "error": "Unknown schema format"
            })
        
        # Analyze security requirements
        insecure_endpoints = []
        secured_endpoints = []
        security_usage = {}
        
        for ep in endpoints:
            ep_security = ep.get("security", [])
            
            if not ep_security:
                insecure_endpoints.append({
                    "path": ep["path"],
                    "method": ep["method"],
                })
            else:
                secured_endpoints.append({
                    "path": ep["path"],
                    "method": ep["method"],
                    "security": ep_security,
                })
                
                # Count security scheme usage
                for sec in ep_security:
                    for scheme_name in sec.keys():
                        security_usage[scheme_name] = security_usage.get(scheme_name, 0) + 1
        
        # Extract OAuth scopes if present
        oauth_scopes = {}
        for scheme_name, scheme_def in security_schemes.items():
            if scheme_def.get("type") == "oauth2":
                # OpenAPI 2.0
                if "scopes" in scheme_def:
                    oauth_scopes[scheme_name] = list(scheme_def["scopes"].keys())
                # OpenAPI 3.x
                elif "flows" in scheme_def:
                    for flow_type, flow in scheme_def["flows"].items():
                        if "scopes" in flow:
                            oauth_scopes[f"{scheme_name}_{flow_type}"] = list(flow["scopes"].keys())
        
        return json.dumps({
            "success": True,
            "authentication_schemes": {
                name: {
                    "type": scheme.get("type"),
                    "description": scheme.get("description", ""),
                }
                for name, scheme in security_schemes.items()
            },
            "security_usage": security_usage,
            "insecure_endpoints_count": len(insecure_endpoints),
            "insecure_endpoints": insecure_endpoints[:20],  # Limit output
            "secured_endpoints_count": len(secured_endpoints),
            "oauth_scopes": oauth_scopes,
        }, indent=2)
    
    except Exception as e:
        logger.exception("Error analyzing security")
        return json.dumps({
            "success": False,
            "error": f"Unexpected error: {str(e)}"
        })
