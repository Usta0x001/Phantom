import base64
import ipaddress
import logging
import os
import re
import socket
import time
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests
try:
    from gql import Client, gql
    from gql.transport.exceptions import TransportQueryError
    from gql.transport.requests import RequestsHTTPTransport
except ImportError:
    # gql is only available inside Docker sandbox; these are not needed on host
    Client = None  # type: ignore[assignment,misc]
    gql = None  # type: ignore[assignment]
    TransportQueryError = Exception  # type: ignore[assignment,misc]
    RequestsHTTPTransport = None  # type: ignore[assignment]
from requests.exceptions import ProxyError, RequestException, Timeout

_logger = logging.getLogger(__name__)

# PHT-010 FIX: Configurable TLS verification instead of hardcoded verify=False
# In proxy mode, TLS verification is disabled because Caido proxy handles
# TLS interception. In direct mode, honour the environment setting.
_PROXY_TLS_VERIFY: bool = False  # proxy always needs verify=False for interception
_DIRECT_TLS_VERIFY: bool = os.environ.get("PHANTOM_TLS_VERIFY", "0").lower() in ("1", "true", "yes")

# Explicitly allowed hostnames (populated from scan targets).
# Requests to these hosts bypass the private-IP SSRF check because
# they ARE the scan target — blocking them would break the scan.
_ALLOWED_SSRF_HOSTS: set[str] = set()

# ---- Session / Auth Token Store ----
# Automatically captures auth tokens from login responses and carries them
# across subsequent send_request calls so subagents don't need to re-login.
# Thread-safe: uses a simple dict guarded by the GIL for reads/writes.
_auth_token_store: dict[str, str] = {}  # header_name -> header_value


def get_auth_token_store() -> dict[str, str]:
    """Return the current auth token store (for injection into scanner tools)."""
    return dict(_auth_token_store)


def set_auth_token(header_name: str, header_value: str) -> None:
    """Manually register an auth token for auto-injection."""
    _auth_token_store[header_name] = header_value


def _capture_auth_from_response(response_headers: dict, response_body: str) -> None:
    """Auto-capture auth tokens from login-like responses.

    Detects JWT tokens in response JSON and Set-Cookie headers,
    stores them for auto-injection into subsequent requests.
    """
    import json as _json

    # Capture Set-Cookie headers
    set_cookie = response_headers.get("set-cookie", "") or response_headers.get("Set-Cookie", "")
    if set_cookie:
        # Store the cookie for future requests
        _auth_token_store["Cookie"] = set_cookie.split(";")[0]  # first cookie value

    # Capture JWT from JSON response body (common in REST APIs like Juice Shop)
    if response_body:
        try:
            data = _json.loads(response_body[:5000])  # limit parsing
            if isinstance(data, dict):
                # Look for token fields in response
                for key in ("token", "access_token", "accessToken", "jwt", "auth_token",
                            "authentication", "id_token"):
                    val = data.get(key)
                    if not val:
                        # Check nested: data.authentication.token
                        auth_obj = data.get("authentication", {})
                        if isinstance(auth_obj, dict):
                            val = auth_obj.get("token") or auth_obj.get("access_token")
                    if val and isinstance(val, str) and len(val) > 20:
                        _auth_token_store["Authorization"] = f"Bearer {val}"
                        _logger.info("Auto-captured auth token from response (field: %s)", key)
                        break
        except (_json.JSONDecodeError, ValueError, TypeError):
            pass


def allow_ssrf_host(hostname: str) -> None:
    """Register a hostname as safe for SSRF checks (scan target)."""
    _ALLOWED_SSRF_HOSTS.add(hostname.lower().strip())


def _is_ssrf_safe(url: str) -> bool:
    """Block requests to private/loopback IPs.

    PHT-003 FIX: Resolves DNS BEFORE checking IP addresses to prevent
    DNS rebinding attacks where a hostname initially resolves to a public
    IP during the check but is later re-resolved to a private IP.
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return False
        # Block file:// and other dangerous schemes
        if parsed.scheme not in ("http", "https"):
            return False

        # Block known dangerous hostnames
        if hostname.lower() in ("localhost", "0.0.0.0"):
            return False

        # Allow explicitly registered scan targets even if they resolve to
        # private IPs (e.g. host.docker.internal → 192.168.x.x).
        if hostname.lower() in _ALLOWED_SSRF_HOSTS:
            return True

        # PHT-003 FIX: Resolve DNS first, then check ALL resolved IPs
        try:
            addrinfos = socket.getaddrinfo(
                hostname, parsed.port or (443 if parsed.scheme == "https" else 80),
                proto=socket.IPPROTO_TCP,
            )
        except socket.gaierror:
            return False  # Can't resolve = not safe

        for family, type_, proto, canonname, sockaddr in addrinfos:
            resolved_ip = sockaddr[0]
            try:
                addr = ipaddress.ip_address(resolved_ip)
            except ValueError:
                return False
            # Allow 127.0.0.1 since requests go through local Caido proxy
            if str(addr) == "127.0.0.1":
                continue
            if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
                _logger.warning(
                    "SSRF blocked: %s resolved to private IP %s", hostname, resolved_ip
                )
                return False

        return True
    except Exception:
        return False


if TYPE_CHECKING:
    from collections.abc import Callable


CAIDO_PORT = 48080  # Fixed port inside container


class ProxyManager:
    def __init__(self, auth_token: str | None = None):
        host = "127.0.0.1"
        self.base_url = f"http://{host}:{CAIDO_PORT}/graphql"
        self.proxies = {
            "http": f"http://{host}:{CAIDO_PORT}",
            "https": f"http://{host}:{CAIDO_PORT}",
        }
        self.auth_token = auth_token or os.getenv("CAIDO_API_TOKEN")

    def _get_client(self) -> Client:
        transport = RequestsHTTPTransport(
            url=self.base_url, headers={"Authorization": f"Bearer {self.auth_token}"}
        )
        return Client(transport=transport, fetch_schema_from_transport=False)

    def list_requests(
        self,
        httpql_filter: str | None = None,
        start_page: int = 1,
        end_page: int = 1,
        page_size: int = 50,
        sort_by: str = "timestamp",
        sort_order: str = "desc",
        scope_id: str | None = None,
    ) -> dict[str, Any]:
        offset = (start_page - 1) * page_size
        limit = (end_page - start_page + 1) * page_size

        sort_mapping = {
            "timestamp": "CREATED_AT",
            "host": "HOST",
            "method": "METHOD",
            "path": "PATH",
            "status_code": "RESP_STATUS_CODE",
            "response_time": "RESP_ROUNDTRIP_TIME",
            "response_size": "RESP_LENGTH",
            "source": "SOURCE",
        }

        query = gql("""
            query GetRequests(
                $limit: Int, $offset: Int, $filter: HTTPQL,
                $order: RequestResponseOrderInput, $scopeId: ID
            ) {
                requestsByOffset(
                    limit: $limit, offset: $offset, filter: $filter,
                    order: $order, scopeId: $scopeId
                ) {
                    edges {
                        node {
                            id method host path query createdAt length isTls port
                            source alteration fileExtension
                            response { id statusCode length roundtripTime createdAt }
                        }
                    }
                    count { value }
                }
            }
        """)

        variables = {
            "limit": limit,
            "offset": offset,
            "filter": httpql_filter,
            "order": {
                "by": sort_mapping.get(sort_by, "CREATED_AT"),
                "ordering": sort_order.upper(),
            },
            "scopeId": scope_id,
        }

        try:
            result = self._get_client().execute(query, variable_values=variables)
            data = result.get("requestsByOffset", {})
            nodes = [edge["node"] for edge in data.get("edges", [])]

            count_data = data.get("count") or {}
            return {
                "requests": nodes,
                "total_count": count_data.get("value", 0),
                "start_page": start_page,
                "end_page": end_page,
                "page_size": page_size,
                "offset": offset,
                "returned_count": len(nodes),
                "sort_by": sort_by,
                "sort_order": sort_order,
            }
        except (TransportQueryError, ValueError, KeyError) as e:
            return {"requests": [], "total_count": 0, "error": f"Error fetching requests: {e}"}

    def view_request(
        self,
        request_id: str,
        part: str = "request",
        search_pattern: str | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> dict[str, Any]:
        queries = {
            "request": """query GetRequest($id: ID!) {
                request(id: $id) {
                    id method host path query createdAt length isTls port
                    source alteration edited raw
                }
            }""",
            "response": """query GetRequest($id: ID!) {
                request(id: $id) {
                    id response {
                        id statusCode length roundtripTime createdAt raw
                    }
                }
            }""",
        }

        if part not in queries:
            return {"error": f"Invalid part '{part}'. Use 'request' or 'response'"}

        try:
            result = self._get_client().execute(
                gql(queries[part]), variable_values={"id": request_id}
            )
            request_data = result.get("request", {})

            if not request_data:
                return {"error": f"Request {request_id} not found"}

            if part == "request":
                raw_content = request_data.get("raw")
            else:
                response_data = request_data.get("response") or {}
                raw_content = response_data.get("raw")

            if not raw_content:
                return {"error": "No content available"}

            content = base64.b64decode(raw_content).decode("utf-8", errors="replace")

            if part == "response":
                request_data["response"]["raw"] = content
            else:
                request_data["raw"] = content

            return (
                self._search_content(request_data, content, search_pattern)
                if search_pattern
                else self._paginate_content(request_data, content, page, page_size)
            )

        except (TransportQueryError, ValueError, KeyError, UnicodeDecodeError) as e:
            return {"error": f"Failed to view request: {e}"}

    def _search_content(
        self, request_data: dict[str, Any], content: str, pattern: str
    ) -> dict[str, Any]:
        # Limit pattern length to mitigate ReDoS
        if len(pattern) > 500:
            return {"error": "Search pattern too long (max 500 chars)"}
        try:
            regex = re.compile(pattern, re.IGNORECASE | re.MULTILINE | re.DOTALL)
            matches = []

            for match in regex.finditer(content):
                start, end = match.start(), match.end()
                context_size = 120

                before = re.sub(r"\s+", " ", content[max(0, start - context_size) : start].strip())[
                    -100:
                ]
                after = re.sub(r"\s+", " ", content[end : end + context_size].strip())[:100]

                matches.append(
                    {"match": match.group(), "before": before, "after": after, "position": start}
                )

                if len(matches) >= 20:
                    break

            return {
                "id": request_data.get("id"),
                "matches": matches,
                "total_matches": len(matches),
                "search_pattern": pattern,
                "truncated": len(matches) >= 20,
            }
        except re.error as e:
            return {"error": f"Invalid regex: {e}"}

    def _paginate_content(
        self, request_data: dict[str, Any], content: str, page: int, page_size: int
    ) -> dict[str, Any]:
        display_lines = []
        for line in content.split("\n"):
            if len(line) <= 80:
                display_lines.append(line)
            else:
                display_lines.extend(
                    [
                        line[i : i + 80] + (" \\" if i + 80 < len(line) else "")
                        for i in range(0, len(line), 80)
                    ]
                )

        total_lines = len(display_lines)
        total_pages = (total_lines + page_size - 1) // page_size
        page = max(1, min(page, total_pages))

        start_line = (page - 1) * page_size
        end_line = min(total_lines, start_line + page_size)

        return {
            "id": request_data.get("id"),
            "content": "\n".join(display_lines[start_line:end_line]),
            "page": page,
            "total_pages": total_pages,
            "showing_lines": f"{start_line + 1}-{end_line} of {total_lines}",
            "has_more": page < total_pages,
        }

    def send_simple_request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        body: str = "",
        timeout: int = 30,
        follow_redirects: bool = True,
    ) -> dict[str, Any]:
        if headers is None:
            headers = {}

        # Auto-inject stored auth tokens (from previous login responses)
        # Only inject if the caller hasn't already set the header.
        for hdr_name, hdr_value in _auth_token_store.items():
            if hdr_name not in headers and hdr_name.lower() not in {k.lower() for k in headers}:
                headers[hdr_name] = hdr_value

        if not _is_ssrf_safe(url):
            return {"error": "Blocked: URL targets a private/internal address", "url": url}

        # Try through proxy first, fall back to direct on 502/proxy failures
        for attempt, use_proxy in enumerate([(True, "proxy"), (False, "direct")]):
            proxy_mode = use_proxy[1]
            current_proxies = self.proxies if use_proxy[0] else None
            try:
                start_time = time.time()
                # PHT-010 FIX: Use configurable TLS verification
                tls_verify = _PROXY_TLS_VERIFY if use_proxy[0] else _DIRECT_TLS_VERIFY
                response = requests.request(
                    method=method,
                    url=url,
                    headers=headers,
                    data=body or None,
                    proxies=current_proxies,
                    timeout=timeout,
                    verify=tls_verify,
                    allow_redirects=follow_redirects,
                )
                response_time = int((time.time() - start_time) * 1000)

                # If proxy returns 502, retry without proxy
                if response.status_code == 502 and proxy_mode == "proxy":
                    _logger.warning("Proxy returned 502 for %s, retrying direct", url)
                    continue

                body_content = response.text

                # Auto-capture auth tokens from successful login-like responses
                if response.status_code in (200, 201) and method.upper() in ("POST", "PUT"):
                    _capture_auth_from_response(dict(response.headers), body_content)

                # Raise body truncation limit from 10K to 30K for richer context
                if len(body_content) > 30000:
                    body_content = body_content[:30000] + "\n... [truncated]"

                msg = (
                    "Request sent through proxy - check list_requests() for captured traffic"
                    if proxy_mode == "proxy"
                    else "Request sent directly (proxy unavailable)"
                )
                result = {
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "body": body_content,
                    "response_time_ms": response_time,
                    "url": response.url,
                    "message": msg,
                }
                # Show stored auth info to help the agent
                if _auth_token_store:
                    result["auto_auth_applied"] = list(_auth_token_store.keys())
                return result
            except (ProxyError, ConnectionError) as e:
                if proxy_mode == "proxy":
                    _logger.warning("Proxy error for %s (%s), retrying direct", url, e)
                    continue
                return {"error": f"Request failed: {type(e).__name__}", "details": str(e), "url": url}
            except (RequestException, Timeout) as e:
                return {"error": f"Request failed: {type(e).__name__}", "details": str(e), "url": url}

        # Should not reach here, but just in case
        return {"error": "Request failed after proxy and direct attempts", "url": url}

    def repeat_request(
        self, request_id: str, modifications: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        if modifications is None:
            modifications = {}

        original = self.view_request(request_id, "request")
        if "error" in original:
            return {"error": f"Could not retrieve original request: {original['error']}"}

        raw_content = original.get("content", "")
        if not raw_content:
            return {"error": "No raw request content found"}

        request_components = self._parse_http_request(raw_content)
        if "error" in request_components:
            return request_components

        full_url = self._build_full_url(request_components, modifications)
        if "error" in full_url:
            return full_url

        modified_request = self._apply_modifications(
            request_components, modifications, full_url["url"]
        )

        return self._send_modified_request(modified_request, request_id, modifications)

    def _parse_http_request(self, raw_content: str) -> dict[str, Any]:
        lines = raw_content.split("\n")
        request_line = lines[0].strip().split(" ")
        if len(request_line) < 2:
            return {"error": "Invalid request line format"}

        method, url_path = request_line[0], request_line[1]

        headers = {}
        body_start = 0
        for i, line in enumerate(lines[1:], 1):
            if line.strip() == "":
                body_start = i + 1
                break
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip()] = value.strip()

        body = "\n".join(lines[body_start:]).strip() if body_start < len(lines) else ""

        return {"method": method, "url_path": url_path, "headers": headers, "body": body}

    def _build_full_url(
        self, components: dict[str, Any], modifications: dict[str, Any]
    ) -> dict[str, Any]:
        headers = components["headers"]
        host = headers.get("Host", "")
        if not host:
            return {"error": "No Host header found"}

        protocol = (
            "https" if ":443" in host or "https" in headers.get("Referer", "").lower() else "http"
        )
        full_url = f"{protocol}://{host}{components['url_path']}"

        if "url" in modifications:
            full_url = modifications["url"]

        return {"url": full_url}

    def _apply_modifications(
        self, components: dict[str, Any], modifications: dict[str, Any], full_url: str
    ) -> dict[str, Any]:
        headers = components["headers"].copy()
        body = components["body"]
        final_url = full_url

        if "params" in modifications:
            parsed = urlparse(final_url)
            params = {k: v[0] if v else "" for k, v in parse_qs(parsed.query).items()}
            params.update(modifications["params"])
            final_url = urlunparse(parsed._replace(query=urlencode(params)))

        if "headers" in modifications:
            headers.update(modifications["headers"])

        if "body" in modifications:
            body = modifications["body"]

        if "cookies" in modifications:
            cookies = {}
            if headers.get("Cookie"):
                for cookie in headers["Cookie"].split(";"):
                    if "=" in cookie:
                        k, v = cookie.split("=", 1)
                        cookies[k.strip()] = v.strip()
            cookies.update(modifications["cookies"])
            headers["Cookie"] = "; ".join([f"{k}={v}" for k, v in cookies.items()])

        return {
            "method": components["method"],
            "url": final_url,
            "headers": headers,
            "body": body,
        }

    def _send_modified_request(
        self, request_data: dict[str, Any], request_id: str, modifications: dict[str, Any]
    ) -> dict[str, Any]:
        # SSRF check: validate modified URL before sending
        if not _is_ssrf_safe(request_data["url"]):
            return {"error": "Blocked: modified URL targets a private/internal address", "url": request_data["url"]}

        # Try through proxy first, fall back to direct on 502/proxy failures
        for use_proxy, proxy_label in [(True, "proxy"), (False, "direct")]:
            current_proxies = self.proxies if use_proxy else None
            try:
                start_time = time.time()
                # PHT-010 FIX: Use configurable TLS verification
                tls_verify = _PROXY_TLS_VERIFY if use_proxy else _DIRECT_TLS_VERIFY
                response = requests.request(
                    method=request_data["method"],
                    url=request_data["url"],
                    headers=request_data["headers"],
                    data=request_data["body"] or None,
                    proxies=current_proxies,
                    timeout=30,
                    verify=tls_verify,
                )
                response_time = int((time.time() - start_time) * 1000)

                # If proxy returns 502, retry without proxy
                if response.status_code == 502 and proxy_label == "proxy":
                    _logger.warning("Proxy returned 502 for modified request, retrying direct")
                    continue

                response_body = response.text
                # Balanced body cap for repeat_request (less than send_request's 30K)
                truncated = len(response_body) > 15000
                if truncated:
                    response_body = response_body[:15000] + "\n... [truncated]"

                return {
                    "status_code": response.status_code,
                    "status_text": response.reason,
                    "headers": {
                        k: v
                        for k, v in response.headers.items()
                        if k.lower()
                        in ["content-type", "content-length", "server", "set-cookie", "location"]
                    },
                    "body": response_body,
                    "body_truncated": truncated,
                    "body_size": len(response.content),
                    "response_time_ms": response_time,
                    "url": response.url,
                    "original_request_id": request_id,
                    "modifications_applied": modifications,
                    "request": {
                        "method": request_data["method"],
                        "url": request_data["url"],
                        "headers": request_data["headers"],
                        "has_body": bool(request_data["body"]),
                    },
                }
            except (ProxyError, ConnectionError) as e:
                if proxy_label == "proxy":
                    _logger.warning("Proxy error for modified request (%s), retrying direct", e)
                    continue
                return {
                    "error": "Proxy connection failed - is Caido running?",
                    "details": str(e),
                    "original_request_id": request_id,
                }
            except (RequestException, Timeout) as e:
                return {
                    "error": f"Failed to repeat request: {type(e).__name__}",
                    "details": str(e),
                    "original_request_id": request_id,
                }

        return {"error": "Request failed after proxy and direct attempts", "original_request_id": request_id}

    def _handle_scope_list(self) -> dict[str, Any]:
        result = self._get_client().execute(
            gql("query { scopes { id name allowlist denylist indexed } }")
        )
        scopes = result.get("scopes", [])
        return {"scopes": scopes, "count": len(scopes)}

    def _handle_scope_get(self, scope_id: str | None) -> dict[str, Any]:
        if not scope_id:
            return self._handle_scope_list()

        result = self._get_client().execute(
            gql(
                "query GetScope($id: ID!) { scope(id: $id) { id name allowlist denylist indexed } }"
            ),
            variable_values={"id": scope_id},
        )
        scope = result.get("scope")
        if not scope:
            return {"error": f"Scope {scope_id} not found"}
        return {"scope": scope}

    def _handle_scope_create(
        self, scope_name: str, allowlist: list[str] | None, denylist: list[str] | None
    ) -> dict[str, Any]:
        if not scope_name:
            return {"error": "scope_name required for create"}

        mutation = gql("""
            mutation CreateScope($input: CreateScopeInput!) {
                createScope(input: $input) {
                    scope { id name allowlist denylist indexed }
                    error {
                        ... on InvalidGlobTermsUserError { code terms }
                        ... on OtherUserError { code }
                    }
                }
            }
        """)

        result = self._get_client().execute(
            mutation,
            variable_values={
                "input": {
                    "name": scope_name,
                    "allowlist": allowlist or [],
                    "denylist": denylist or [],
                }
            },
        )

        payload = result.get("createScope", {})
        if payload.get("error"):
            error = payload["error"]
            return {"error": f"Invalid glob patterns: {error.get('terms', error.get('code'))}"}

        return {"scope": payload.get("scope"), "message": "Scope created successfully"}

    def _handle_scope_update(
        self,
        scope_id: str,
        scope_name: str,
        allowlist: list[str] | None,
        denylist: list[str] | None,
    ) -> dict[str, Any]:
        if not scope_id or not scope_name:
            return {"error": "scope_id and scope_name required"}

        mutation = gql("""
            mutation UpdateScope($id: ID!, $input: UpdateScopeInput!) {
                updateScope(id: $id, input: $input) {
                    scope { id name allowlist denylist indexed }
                    error {
                        ... on InvalidGlobTermsUserError { code terms }
                        ... on OtherUserError { code }
                    }
                }
            }
        """)

        result = self._get_client().execute(
            mutation,
            variable_values={
                "id": scope_id,
                "input": {
                    "name": scope_name,
                    "allowlist": allowlist or [],
                    "denylist": denylist or [],
                },
            },
        )

        payload = result.get("updateScope", {})
        if payload.get("error"):
            error = payload["error"]
            return {"error": f"Invalid glob patterns: {error.get('terms', error.get('code'))}"}

        return {"scope": payload.get("scope"), "message": "Scope updated successfully"}

    def _handle_scope_delete(self, scope_id: str) -> dict[str, Any]:
        if not scope_id:
            return {"error": "scope_id required for delete"}

        result = self._get_client().execute(
            gql("mutation DeleteScope($id: ID!) { deleteScope(id: $id) { deletedId } }"),
            variable_values={"id": scope_id},
        )

        payload = result.get("deleteScope", {})
        if not payload.get("deletedId"):
            return {"error": f"Failed to delete scope {scope_id}"}
        return {"message": f"Scope {scope_id} deleted", "deletedId": payload["deletedId"]}

    def scope_rules(
        self,
        action: str,
        allowlist: list[str] | None = None,
        denylist: list[str] | None = None,
        scope_id: str | None = None,
        scope_name: str | None = None,
    ) -> dict[str, Any]:
        handlers: dict[str, Callable[[], dict[str, Any]]] = {
            "list": self._handle_scope_list,
            "get": lambda: self._handle_scope_get(scope_id),
            "create": lambda: (
                {"error": "scope_name required for create"}
                if not scope_name
                else self._handle_scope_create(scope_name, allowlist, denylist)
            ),
            "update": lambda: (
                {"error": "scope_id and scope_name required"}
                if not scope_id or not scope_name
                else self._handle_scope_update(scope_id, scope_name, allowlist, denylist)
            ),
            "delete": lambda: (
                {"error": "scope_id required for delete"}
                if not scope_id
                else self._handle_scope_delete(scope_id)
            ),
        }

        handler = handlers.get(action)
        if not handler:
            return {
                "error": f"Unsupported action: {action}. Use 'get', 'list', 'create', "
                f"'update', or 'delete'"
            }

        try:
            result = handler()
        except (TransportQueryError, ValueError, KeyError) as e:
            return {"error": f"Scope operation failed: {e}"}
        else:
            return result

    def list_sitemap(
        self,
        scope_id: str | None = None,
        parent_id: str | None = None,
        depth: str = "DIRECT",
        page: int = 1,
        page_size: int = 30,
    ) -> dict[str, Any]:
        try:
            skip_count = (page - 1) * page_size

            if parent_id:
                query = gql("""
                    query GetSitemapDescendants($parentId: ID!, $depth: SitemapDescendantsDepth!) {
                        sitemapDescendantEntries(parentId: $parentId, depth: $depth) {
                            edges {
                                node {
                                    id kind label hasDescendants
                                    request { method path response { statusCode } }
                                }
                            }
                            count { value }
                        }
                    }
                """)
                result = self._get_client().execute(
                    query, variable_values={"parentId": parent_id, "depth": depth}
                )
                data = result.get("sitemapDescendantEntries", {})
            else:
                query = gql("""
                    query GetSitemapRoots($scopeId: ID) {
                        sitemapRootEntries(scopeId: $scopeId) {
                            edges { node {
                                id kind label hasDescendants
                                metadata { ... on SitemapEntryMetadataDomain { isTls port } }
                                request { method path response { statusCode } }
                            } }
                            count { value }
                        }
                    }
                """)
                result = self._get_client().execute(query, variable_values={"scopeId": scope_id})
                data = result.get("sitemapRootEntries", {})

            all_nodes = [edge["node"] for edge in data.get("edges", [])]
            count_data = data.get("count") or {}
            total_count = count_data.get("value", 0)

            paginated_nodes = all_nodes[skip_count : skip_count + page_size]
            cleaned_nodes = []

            for node in paginated_nodes:
                cleaned = {
                    "id": node["id"],
                    "kind": node["kind"],
                    "label": node["label"],
                    "hasDescendants": node["hasDescendants"],
                }

                if node.get("metadata") and (
                    node["metadata"].get("isTls") is not None or node["metadata"].get("port")
                ):
                    cleaned["metadata"] = node["metadata"]

                if node.get("request"):
                    req = node["request"]
                    cleaned_req = {}
                    if req.get("method"):
                        cleaned_req["method"] = req["method"]
                    if req.get("path"):
                        cleaned_req["path"] = req["path"]
                    response_data = req.get("response") or {}
                    if response_data.get("statusCode"):
                        cleaned_req["status"] = response_data["statusCode"]
                    if cleaned_req:
                        cleaned["request"] = cleaned_req

                cleaned_nodes.append(cleaned)

            total_pages = (total_count + page_size - 1) // page_size

            return {
                "entries": cleaned_nodes,
                "page": page,
                "page_size": page_size,
                "total_pages": total_pages,
                "total_count": total_count,
                "has_more": page < total_pages,
                "showing": (
                    f"{skip_count + 1}-{min(skip_count + page_size, total_count)} of {total_count}"
                ),
            }

        except (TransportQueryError, ValueError, KeyError) as e:
            return {"error": f"Failed to fetch sitemap: {e}"}

    def _process_sitemap_metadata(self, node: dict[str, Any]) -> dict[str, Any]:
        cleaned = {
            "id": node["id"],
            "kind": node["kind"],
            "label": node["label"],
            "hasDescendants": node["hasDescendants"],
        }

        if node.get("metadata") and (
            node["metadata"].get("isTls") is not None or node["metadata"].get("port")
        ):
            cleaned["metadata"] = node["metadata"]

        return cleaned

    def _process_sitemap_request(self, req: dict[str, Any]) -> dict[str, Any] | None:
        cleaned_req = {}
        if req.get("method"):
            cleaned_req["method"] = req["method"]
        if req.get("path"):
            cleaned_req["path"] = req["path"]
        response_data = req.get("response") or {}
        if response_data.get("statusCode"):
            cleaned_req["status"] = response_data["statusCode"]
        return cleaned_req if cleaned_req else None

    def _process_sitemap_response(self, resp: dict[str, Any]) -> dict[str, Any]:
        cleaned_resp = {}
        if resp.get("statusCode"):
            cleaned_resp["status"] = resp["statusCode"]
        if resp.get("length"):
            cleaned_resp["size"] = resp["length"]
        if resp.get("roundtripTime"):
            cleaned_resp["time_ms"] = resp["roundtripTime"]
        return cleaned_resp

    def view_sitemap_entry(self, entry_id: str) -> dict[str, Any]:
        try:
            query = gql("""
                query GetSitemapEntry($id: ID!) {
                    sitemapEntry(id: $id) {
                        id kind label hasDescendants
                        metadata { ... on SitemapEntryMetadataDomain { isTls port } }
                        request { method path response { statusCode length roundtripTime } }
                        requests(first: 30, order: {by: CREATED_AT, ordering: DESC}) {
                            edges { node { method path response { statusCode length } } }
                            count { value }
                        }
                    }
                }
            """)

            result = self._get_client().execute(query, variable_values={"id": entry_id})
            entry = result.get("sitemapEntry")

            if not entry:
                return {"error": f"Sitemap entry {entry_id} not found"}

            cleaned = self._process_sitemap_metadata(entry)

            if entry.get("request"):
                req = entry["request"]
                cleaned_req = {}
                if req.get("method"):
                    cleaned_req["method"] = req["method"]
                if req.get("path"):
                    cleaned_req["path"] = req["path"]
                if req.get("response"):
                    cleaned_req["response"] = self._process_sitemap_response(req["response"])
                if cleaned_req:
                    cleaned["request"] = cleaned_req

            requests_data = entry.get("requests", {})
            request_nodes = [edge["node"] for edge in requests_data.get("edges", [])]

            cleaned_requests = [
                req
                for req in (self._process_sitemap_request(node) for node in request_nodes)
                if req is not None
            ]

            count_data = requests_data.get("count") or {}
            cleaned["related_requests"] = {
                "requests": cleaned_requests,
                "total_count": count_data.get("value", 0),
                "showing": f"Latest {len(cleaned_requests)} requests",
            }

            return {"entry": cleaned} if cleaned else {"error": "Failed to process sitemap entry"}  # noqa: TRY300

        except (TransportQueryError, ValueError, KeyError) as e:
            return {"error": f"Failed to fetch sitemap entry: {e}"}

    def close(self) -> None:
        pass


import threading

_PROXY_MANAGER: ProxyManager | None = None
_proxy_manager_lock = threading.Lock()


def get_proxy_manager() -> ProxyManager:
    global _PROXY_MANAGER  # noqa: PLW0603
    with _proxy_manager_lock:
        if _PROXY_MANAGER is None:
            _PROXY_MANAGER = ProxyManager()
        return _PROXY_MANAGER
