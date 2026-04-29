"""Category 13: API Security — unauthenticated endpoints, GraphQL, rate limiting."""
import re
import json
import pytest

from tests.active.helpers import safe_get, safe_post, safe_request, url_join
from tests.active.config import TARGET_URL

API_PREFIXES = ["/api", "/api/v1", "/api/v2", "/api/v3",
                "/rest", "/v1", "/v2", "/service"]

API_RESOURCE_PATHS = [
    "/users", "/user", "/accounts", "/admin", "/config",
    "/settings", "/keys", "/tokens", "/credentials",
    "/data", "/export", "/logs", "/metrics",
]

GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/gql", "/query",
                 "/api/gql", "/graphiql"]

OLD_API_PATHS = [
    "/api/v0/", "/api/v1/", "/api/v2/",
    "/v1/", "/v2/", "/api/1.0/", "/api/2.0/",
]


class TestUnauthenticatedApiEndpoints:
    def test_api_endpoints_require_auth(self):
        exposed = []
        for prefix in API_PREFIXES[:3]:
            for resource in API_RESOURCE_PATHS[:5]:
                path = prefix + resource
                r = safe_get(url_join(path), allow_redirects=False)
                if r and r.status_code == 200:
                    try:
                        data = r.json()
                        if isinstance(data, (list, dict)) and len(str(data)) > 50:
                            exposed.append(path)
                    except Exception:
                        pass
        assert not exposed, (
            f"API endpoints returning data without authentication: {exposed}"
        )


class TestApiKeyInUrl:
    def test_api_key_not_in_url_params(self, base_response):
        if base_response is None:
            pytest.skip("target unreachable")
        import urllib.parse
        parsed = urllib.parse.urlparse(base_response.url)
        qs = urllib.parse.parse_qs(parsed.query)
        key_params = [k for k in qs if any(
            w in k.lower() for w in ["apikey", "api_key", "key", "token", "secret", "auth"]
        )]
        assert not key_params, (
            f"API key/token in URL query string: {key_params} at {base_response.url}"
        )

    def test_api_calls_use_headers_not_url(self, base_html):
        # Check if JS source constructs API calls with tokens in query strings
        token_in_url = re.compile(
            r'["\']https?://[^"\']*[?&](?:api_?key|token|auth)[=][^&"\']+',
            re.IGNORECASE
        )
        found = token_in_url.findall(base_html)
        assert not found, (
            f"JS source constructs API URLs with keys/tokens in query string: {found[:3]}"
        )


class TestExcessiveDataExposure:
    def test_api_no_sensitive_fields_in_list(self):
        sensitive_fields = ["password", "passwd", "secret", "credit_card",
                            "ssn", "social_security", "private_key", "api_key"]
        for prefix in API_PREFIXES[:2]:
            r = safe_get(url_join(prefix + "/users"))
            if r is None or r.status_code != 200:
                continue
            try:
                data = r.json()
                text = json.dumps(data).lower()
                found = [f for f in sensitive_fields if f in text]
                if found:
                    pytest.fail(
                        f"API {prefix}/users response contains sensitive fields: {found}"
                    )
            except Exception:
                pass


class TestRateLimiting:
    def test_api_rate_limiting_headers_present(self):
        rate_limit_headers = [
            "X-RateLimit-Limit", "X-Rate-Limit-Limit",
            "RateLimit-Limit", "X-RateLimit-Remaining",
            "Retry-After",
        ]
        r = safe_get(url_join("/api"))
        if r is None:
            r = safe_get(TARGET_URL)
        if r is None:
            pytest.skip("target unreachable")
        found = [h for h in rate_limit_headers if h in r.headers]
        if not found:
            pytest.skip(
                "No rate-limit headers found — rate limiting may exist but not be advertised. "
                "Run destructive tests to verify enforcement."
            )

    def test_api_rate_limiting_on_login(self):
        r = safe_post(url_join("/api/login"),
                      json={"username": "test", "password": "test"})
        if r is None:
            pytest.skip("no API login endpoint")
        rate_headers = ["X-RateLimit-Limit", "X-Rate-Limit-Limit", "Retry-After"]
        found = [h for h in rate_headers if h in r.headers]
        if not found:
            pytest.skip(
                "Login endpoint has no rate-limit headers — verify enforcement manually"
            )


class TestOldApiVersions:
    def test_old_api_versions_disabled(self):
        accessible = []
        for path in OLD_API_PATHS:
            r = safe_get(url_join(path), allow_redirects=False)
            if r and r.status_code == 200:
                accessible.append(path)
        assert not accessible, (
            f"Old API version paths are accessible: {accessible}"
        )


class TestGraphQlSecurity:
    def test_graphql_introspection_disabled_in_production(self):
        introspection_query = '{"query":"{__schema{types{name}}}"}'
        for path in GRAPHQL_PATHS:
            r = safe_post(url_join(path),
                          data=introspection_query,
                          headers={"Content-Type": "application/json"})
            if r and r.status_code == 200:
                try:
                    data = r.json()
                    if "data" in data and "__schema" in str(data.get("data", "")):
                        pytest.fail(
                            f"GraphQL introspection enabled at {path} — "
                            "full schema is publicly queryable"
                        )
                except Exception:
                    pass

    def test_graphql_field_suggestions_disabled(self):
        # GraphQL field suggestions reveal schema info even without introspection
        query = '{"query":"{__typenameXXX}"}'
        for path in GRAPHQL_PATHS:
            r = safe_post(url_join(path),
                          data=query,
                          headers={"Content-Type": "application/json"})
            if r and "Did you mean" in r.text:
                pytest.fail(
                    f"GraphQL field suggestions enabled at {path} — schema info leaks via errors"
                )


class TestApiErrorVerbosity:
    def test_api_errors_not_verbose(self):
        for prefix in API_PREFIXES[:2]:
            r = safe_get(url_join(prefix + "/nonexistent_wc_probe_9z7x"))
            if r is None:
                continue
            verbose_indicators = [
                "stack trace", "exception", "at line", "traceback",
                "sql syntax", "database error",
            ]
            for ind in verbose_indicators:
                if ind in r.text.lower():
                    pytest.fail(
                        f"Verbose error in API {prefix} response: found {ind!r}"
                    )


class TestApiInputValidation:
    def test_api_rejects_invalid_content_type(self):
        for prefix in API_PREFIXES[:2]:
            r = safe_post(url_join(prefix + "/users"),
                          data="<script>xss</script>",
                          headers={"Content-Type": "text/plain"})
            if r is None:
                continue
            # Should reject or return 400, not process arbitrary text
            assert r.status_code not in (200,) or "script" not in r.text.lower(), (
                f"API accepted and reflected plain-text with script tag at {prefix}/users"
            )

    def test_api_accepts_json_content_type(self):
        for prefix in API_PREFIXES[:2]:
            r = safe_get(url_join(prefix),
                         headers={"Accept": "application/json"})
            if r is None or r.status_code == 404:
                continue
            ct = r.headers.get("Content-Type", "")
            if r.status_code == 200:
                pytest.skip(
                    f"{prefix} returns 200 — verify response Content-Type is application/json: {ct!r}"
                )


# Tests requiring authenticated sessions
class TestApiSecuritySkipped:
    def test_bola_idor_requires_auth(self):
        pytest.skip(
            "BOLA/IDOR requires an authenticated session to compare object access. "
            "Configure AUTH_TOKEN in config.py."
        )

    def test_broken_function_level_auth_requires_auth(self):
        pytest.skip("Broken function-level authorization requires auth context.")

    def test_websocket_auth_requires_ws_endpoint(self):
        pytest.skip("WebSocket auth test requires a known WebSocket endpoint.")
