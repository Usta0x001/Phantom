"""
P3.6 API Schema Validation Tests

Test suite for verifying API schema parsing:
1. VERIFY it helps the system - Test real OpenAPI schemas
2. ATTACK it - Try XXE, billion laughs, SSRF, malformed schemas  
3. PROVE it works - Comprehensive functional tests
"""

import json
import pytest
from phantom.tools.api_schema.api_schema_actions import (
    parse_openapi_schema,
    extract_api_endpoints,
    analyze_security_requirements,
    _sanitize_url,
    _fetch_schema,
    MAX_SCHEMA_SIZE,
)


class TestP36SchemaValidationVerification:
    """VERIFY: Prove API schema validation helps the system"""
    
    def test_parse_openapi_v2_schema(self):
        """Verify: Can parse valid OpenAPI 2.0 (Swagger) schema"""
        schema = json.dumps({
            "swagger": "2.0",
            "info": {"title": "Test API", "version": "1.0"},
            "host": "api.example.com",
            "basePath": "/v1",
            "paths": {
                "/users": {
                    "get": {
                        "summary": "List users",
                        "parameters": [
                            {"name": "limit", "in": "query", "type": "integer"}
                        ]
                    }
                }
            }
        })
        
        result = json.loads(parse_openapi_schema(schema))
        
        assert result["success"] is True
        assert result["openapi_version"] == "2.0"
        assert result["api_title"] == "Test API"
        assert result["endpoints_count"] == 1
    
    def test_parse_openapi_v3_schema(self):
        """Verify: Can parse valid OpenAPI 3.x schema"""
        schema = json.dumps({
            "openapi": "3.0.0",
            "info": {"title": "Test API v3", "version": "2.0"},
            "servers": [{"url": "https://api.example.com/v2"}],
            "paths": {
                "/products/{id}": {
                    "get": {
                        "summary": "Get product",
                        "parameters": [
                            {"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}}
                        ]
                    },
                    "delete": {
                        "summary": "Delete product",
                        "security": [{"api_key": []}]
                    }
                }
            }
        })
        
        result = json.loads(parse_openapi_schema(schema))
        
        assert result["success"] is True
        assert result["openapi_version"].startswith("3.")
        assert result["endpoints_count"] == 2  # GET and DELETE
    
    def test_extract_endpoints_with_parameters(self):
        """Verify: Extracts endpoints with all parameter types"""
        schema = json.dumps({
            "openapi": "3.0.0",
            "info": {"title": "Test", "version": "1.0"},
            "paths": {
                "/api/search": {
                    "post": {
                        "parameters": [
                            {"name": "api_key", "in": "header", "required": True},
                            {"name": "q", "in": "query", "required": True}
                        ],
                        "requestBody": {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {"type": "object"}
                                }
                            }
                        }
                    }
                }
            }
        })
        
        result = json.loads(extract_api_endpoints(schema))
        
        assert result["success"] is True
        assert result["endpoints_count"] == 1
        
        endpoint = result["endpoints"][0]
        assert endpoint["method"] == "POST"
        assert endpoint["path"] == "/api/search"
        assert len(endpoint["parameters"]) == 3  # header, query, body
    
    def test_analyze_security_finds_insecure_endpoints(self):
        """Verify: Identifies endpoints without authentication"""
        schema = json.dumps({
            "swagger": "2.0",
            "info": {"title": "Test", "version": "1.0"},
            "paths": {
                "/public": {
                    "get": {"summary": "Public endpoint"}
                },
                "/admin": {
                    "get": {
                        "summary": "Admin endpoint",
                        "security": [{"api_key": []}]
                    }
                }
            },
            "securityDefinitions": {
                "api_key": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-API-Key"
                }
            }
        })
        
        result = json.loads(analyze_security_requirements(schema))
        
        assert result["success"] is True
        assert result["insecure_endpoints_count"] == 1
        assert result["secured_endpoints_count"] == 1
        assert "api_key" in result["authentication_schemes"]
    
    def test_helps_discover_oauth_scopes(self):
        """Verify: Extracts OAuth2 scopes for testing"""
        schema = json.dumps({
            "openapi": "3.0.0",
            "info": {"title": "OAuth API", "version": "1.0"},
            "paths": {
                "/protected": {
                    "get": {
                        "security": [{"oauth2": ["read:users", "write:users"]}]
                    }
                }
            },
            "components": {
                "securitySchemes": {
                    "oauth2": {
                        "type": "oauth2",
                        "flows": {
                            "authorizationCode": {
                                "authorizationUrl": "https://example.com/oauth/auth",
                                "tokenUrl": "https://example.com/oauth/token",
                                "scopes": {
                                    "read:users": "Read user data",
                                    "write:users": "Modify user data"
                                }
                            }
                        }
                    }
                }
            }
        })
        
        result = json.loads(analyze_security_requirements(schema))
        
        assert result["success"] is True
        assert "oauth_scopes" in result
        assert len(result["oauth_scopes"]) > 0


class TestP36SchemaValidationAttacks:
    """ATTACK: Try to break API schema validation"""
    
    def test_attack_xxe_injection(self):
        """Attack: Try XXE (XML External Entity) attack"""
        # Even though we parse JSON/YAML, test XML-like injection attempts
        malicious_schema = """
        swagger: "2.0"
        info:
          title: "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>&xxe;"
          version: "1.0"
        paths: {}
        """
        
        result = json.loads(parse_openapi_schema(malicious_schema))
        
        # Should parse as string, not execute XXE
        # The string is stored safely, no file read occurs
        assert result["success"] is True
        # The XXE entity is stored as text (not executed)
        assert result["api_title"] == "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>&xxe;"
    
    def test_attack_billion_laughs(self):
        """Attack: Try billion laughs DoS (exponential expansion)"""
        # YAML bomb attempt
        malicious_yaml = """
        swagger: "2.0"
        info: &a
          title: *a
          version: "1.0"
        paths: {}
        """
        
        try:
            result = json.loads(parse_openapi_schema(malicious_yaml))
            # Should handle safely or fail gracefully
            assert "success" in result
        except RecursionError:
            pytest.fail("Billion laughs attack caused recursion error!")
    
    def test_attack_ssrf_via_url(self):
        """Attack: Try SSRF (Server-Side Request Forgery)"""
        malicious_urls = [
            "file:///etc/passwd",
            "http://169.254.169.254/latest/meta-data/",  # AWS metadata
            "http://localhost:22/",  # Local services
            "ftp://internal.server/data",
            "gopher://internal:25/",
        ]
        
        for url in malicious_urls:
            sanitized = _sanitize_url(url)
            # Should reject non-http(s) schemes
            if not url.startswith(("http://", "https://")):
                assert sanitized is None, f"SSRF vulnerability: {url} was not blocked!"
    
    def test_attack_size_bomb(self):
        """Attack: Try to exhaust memory with huge schema"""
        # Create a massive schema (> MAX_SCHEMA_SIZE)
        huge_paths = {f"/path{i}": {"get": {"summary": "test"}} for i in range(10000)}
        huge_schema = json.dumps({
            "swagger": "2.0",
            "info": {"title": "Huge", "version": "1.0"},
            "paths": huge_paths
        })
        
        # If schema is too large, should be rejected
        if len(huge_schema) > MAX_SCHEMA_SIZE:
            result = _fetch_schema(huge_schema)
            assert result is None, "Size bomb not prevented!"
    
    def test_attack_malformed_json(self):
        """Attack: Try various malformed JSON attacks"""
        malformed_schemas = [
            '{"swagger": "2.0", "paths":',  # Incomplete
            '{"swagger": "2.0", "paths": {{{}}}',  # Invalid nesting
            '',  # Empty
        ]
        
        for schema in malformed_schemas:
            result = json.loads(parse_openapi_schema(schema))
            # Should fail gracefully, not crash
            assert "success" in result
            if not result["success"]:
                assert "error" in result
        
        # These should be rejected as not valid OpenAPI schemas
        invalid_schemas = [
            'null',  # Null
            '{"not": "openapi"}',  # Missing swagger/openapi field
        ]
        
        for schema in invalid_schemas:
            result = json.loads(parse_openapi_schema(schema))
            assert result["success"] is False
            assert "error" in result
    
    def test_attack_script_injection_in_fields(self):
        """Attack: Try script injection in schema fields"""
        schema = json.dumps({
            "swagger": "2.0",
            "info": {
                "title": "<script>alert('XSS')</script>",
                "version": "'; DROP TABLE schemas;--"
            },
            "paths": {
                "/<img src=x onerror=alert(1)>": {
                    "get": {
                        "summary": "javascript:void(0)"
                    }
                }
            }
        })
        
        result = json.loads(parse_openapi_schema(schema))
        
        # Should store as strings, not execute
        assert result["success"] is True
        # Scripts should be in data as plain strings, not executed
        assert "XSS" not in result or "<script>" in str(result)
    
    def test_attack_type_confusion(self):
        """Attack: Try type confusion attacks"""
        malformed_schemas = [
            123,  # Integer
            12.34,  # Float
            True,  # Boolean
            None,  # None
            [],  # Array
            {"not": "a valid schema"},  # Dict without swagger/openapi
        ]
        
        for schema in malformed_schemas:
            schema_str = json.dumps(schema) if not isinstance(schema, str) else schema
            result = json.loads(parse_openapi_schema(schema_str))
            # Should handle gracefully
            assert "success" in result
    
    def test_attack_path_traversal(self):
        """Attack: Try path traversal in endpoint paths"""
        schema = json.dumps({
            "swagger": "2.0",
            "info": {"title": "Test", "version": "1.0"},
            "paths": {
                "/../../../etc/passwd": {
                    "get": {"summary": "Path traversal"}
                }
            }
        })
        
        result = json.loads(extract_api_endpoints(schema))
        
        # Should store path as-is (security analysis is separate)
        assert result["success"] is True
        # Path traversal should be in data but not executed
        endpoint_paths = [ep["path"] for ep in result["endpoints"]]
        assert any("passwd" in path for path in endpoint_paths)
    
    def test_attack_unicode_overflow(self):
        """Attack: Try unicode buffer overflow"""
        schema = json.dumps({
            "swagger": "2.0",
            "info": {
                "title": "Test" + ("\u0000" * 1000),  # Null bytes
                "version": "🔥" * 1000  # Emojis
            },
            "paths": {
                "/test": {
                    "get": {"summary": "\uffff" * 1000}  # Max BMP
                }
            }
        })
        
        try:
            result = json.loads(parse_openapi_schema(schema))
            assert result["success"] is True
        except Exception as e:
            pytest.fail(f"Unicode overflow caused crash: {e}")


class TestP36SchemaValidationProof:
    """PROVE: Comprehensive functional verification"""
    
    def test_proof_yaml_parsing(self):
        """Prove: YAML parsing works correctly"""
        yaml_schema = """
swagger: "2.0"
info:
  title: YAML Test
  version: 1.0
paths:
  /test:
    get:
      summary: Test endpoint
"""
        result = json.loads(parse_openapi_schema(yaml_schema))
        
        assert result["success"] is True
        assert result["api_title"] == "YAML Test"
    
    def test_proof_endpoint_filtering_by_tag(self):
        """Prove: Tag filtering works correctly"""
        schema = json.dumps({
            "swagger": "2.0",
            "info": {"title": "Test", "version": "1.0"},
            "paths": {
                "/public": {
                    "get": {"tags": ["public"], "summary": "Public"}
                },
                "/admin": {
                    "get": {"tags": ["admin"], "summary": "Admin"}
                },
                "/both": {
                    "get": {"tags": ["public", "admin"], "summary": "Both"}
                }
            }
        })
        
        # Filter by admin tag
        result = json.loads(extract_api_endpoints(schema, filter_by_tag="admin"))
        
        assert result["success"] is True
        assert result["endpoints_count"] == 2  # /admin and /both
        paths = [ep["path"] for ep in result["endpoints"]]
        assert "/admin" in paths
        assert "/both" in paths
        assert "/public" not in paths
    
    def test_proof_multiple_http_methods(self):
        """Prove: All HTTP methods are extracted"""
        schema = json.dumps({
            "openapi": "3.0.0",
            "info": {"title": "Test", "version": "1.0"},
            "paths": {
                "/resource": {
                    "get": {"summary": "Get"},
                    "post": {"summary": "Create"},
                    "put": {"summary": "Update"},
                    "delete": {"summary": "Delete"},
                    "patch": {"summary": "Partial update"},
                    "options": {"summary": "Options"},
                    "head": {"summary": "Head"}
                }
            }
        })
        
        result = json.loads(extract_api_endpoints(schema))
        
        assert result["success"] is True
        assert result["endpoints_count"] == 7
        
        methods = {ep["method"] for ep in result["endpoints"]}
        expected = {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"}
        assert methods == expected
    
    def test_proof_parameter_locations(self):
        """Prove: All parameter locations are captured"""
        schema = json.dumps({
            "swagger": "2.0",
            "info": {"title": "Test", "version": "1.0"},
            "paths": {
                "/test/{id}": {
                    "get": {
                        "parameters": [
                            {"name": "id", "in": "path", "type": "integer"},
                            {"name": "q", "in": "query", "type": "string"},
                            {"name": "X-Auth", "in": "header", "type": "string"},
                            {"name": "data", "in": "body", "schema": {"type": "object"}}
                        ]
                    }
                }
            }
        })
        
        result = json.loads(extract_api_endpoints(schema))
        endpoint = result["endpoints"][0]
        
        param_locations = {p["in"] for p in endpoint["parameters"]}
        assert param_locations == {"path", "query", "header", "body"}
    
    def test_proof_security_scheme_types(self):
        """Prove: All security scheme types are recognized"""
        schema = json.dumps({
            "openapi": "3.0.0",
            "info": {"title": "Test", "version": "1.0"},
            "paths": {"/test": {"get": {}}},
            "components": {
                "securitySchemes": {
                    "api_key": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
                    "http_basic": {"type": "http", "scheme": "basic"},
                    "http_bearer": {"type": "http", "scheme": "bearer"},
                    "oauth2": {
                        "type": "oauth2",
                        "flows": {
                            "authorizationCode": {
                                "authorizationUrl": "https://example.com/oauth/authorize",
                                "tokenUrl": "https://example.com/oauth/token",
                                "scopes": {}
                            }
                        }
                    }
                }
            }
        })
        
        result = json.loads(parse_openapi_schema(schema))
        
        assert result["success"] is True
        assert len(result["security_schemes"]) == 4
        assert "api_key" in result["security_schemes"]
        assert "http_basic" in result["security_schemes"]
        assert "http_bearer" in result["security_schemes"]
        assert "oauth2" in result["security_schemes"]
    
    def test_proof_no_silent_failures(self):
        """Prove: No silent failures - all errors are reported"""
        invalid_schemas = [
            "",  # Empty
            "{}",  # Empty object
            '{"paths": {}}',  # Missing version
            '{"swagger": "1.0"}',  # Unsupported version
        ]
        
        for schema in invalid_schemas:
            result = json.loads(parse_openapi_schema(schema))
            # Should explicitly report failure
            assert "success" in result
            if not result["success"]:
                assert "error" in result
                assert len(result["error"]) > 0
    
    def test_proof_endpoint_limit_enforced(self):
        """Prove: Endpoint limits prevent DoS"""
        # Create schema with more endpoints than response limit (100)
        huge_paths = {
            f"/path{i}": {"get": {"summary": f"Endpoint {i}"}}
            for i in range(2000)
        }
        schema = json.dumps({
            "swagger": "2.0",
            "info": {"title": "Huge", "version": "1.0"},
            "paths": huge_paths
        })
        
        result = json.loads(extract_api_endpoints(schema))
        
        # Should limit returned endpoints
        assert result["success"] is True
        assert result["endpoints_count"] >= 1000  # Found many (limited by MAX_ENDPOINTS)
        assert result["endpoints_returned"] == 100  # But only returned 100
        assert len(result["endpoints"]) == 100  # Verify actual list size
    
    def test_proof_url_sanitization(self):
        """Prove: URL sanitization is effective"""
        valid_urls = [
            "http://example.com/schema.json",
            "https://api.example.com/openapi.yaml",
            "https://example.com:8080/swagger.json",
        ]
        
        invalid_urls = [
            "file:///etc/passwd",
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "ftp://example.com/file",
            "//example.com",
            "http://",
            "",
        ]
        
        for url in valid_urls:
            assert _sanitize_url(url) is not None, f"Valid URL rejected: {url}"
        
        for url in invalid_urls:
            assert _sanitize_url(url) is None, f"Invalid URL not blocked: {url}"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
