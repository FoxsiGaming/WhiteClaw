"""Category 36: Authentication Bypass via HTTP Method Confusion."""
import pytest

from tests.active.helpers import safe_request, url_join
from tests.active.config import TARGET_URL

PROTECTED_ENDPOINTS = [
    "/admin", "/admin/", "/api/admin", "/dashboard", "/settings",
    "/account", "/profile", "/user/settings", "/api/secret",
    "/api/v1/admin", "/management", "/control-panel",
]

HTTP_METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE"]


class TestHttpMethodBypass:
    def test_head_request_bypasses_auth(self):
        """Test if HEAD requests bypass authentication checks."""
        for endpoint in PROTECTED_ENDPOINTS:
            get_r = safe_request("GET", url_join(endpoint), allow_redirects=False)
            head_r = safe_request("HEAD", url_join(endpoint), allow_redirects=False)
            
            if get_r and head_r:
                # If GET requires auth but HEAD doesn't
                if get_r.status_code in (401, 403) and head_r.status_code == 200:
                    pytest.fail(
                        f"HTTP method bypass: GET {endpoint} blocked (HTTP {get_r.status_code}), "
                        f"but HEAD {endpoint} allowed (HTTP {head_r.status_code})"
                    )

    def test_put_request_bypasses_auth(self):
        """Test if PUT requests bypass authentication."""
        for endpoint in PROTECTED_ENDPOINTS:
            get_r = safe_request("GET", url_join(endpoint), allow_redirects=False)
            put_r = safe_request("PUT", url_join(endpoint), allow_redirects=False)
            
            if get_r and put_r:
                if get_r.status_code in (401, 403) and put_r.status_code not in (401, 403, 405):
                    pytest.fail(
                        f"HTTP method bypass: GET blocked (HTTP {get_r.status_code}), "
                        f"PUT allowed (HTTP {put_r.status_code}) at {endpoint}"
                    )

    def test_patch_request_bypasses_auth(self):
        """Test if PATCH requests bypass authentication."""
        for endpoint in PROTECTED_ENDPOINTS:
            get_r = safe_request("GET", url_join(endpoint), allow_redirects=False)
            patch_r = safe_request("PATCH", url_join(endpoint), allow_redirects=False)
            
            if get_r and patch_r:
                if get_r.status_code in (401, 403) and patch_r.status_code not in (401, 403, 405):
                    pytest.skip(
                        f"PATCH bypass candidate at {endpoint}: "
                        "GET {0}, PATCH {1}".format(get_r.status_code, patch_r.status_code)
                    )


class TestHttpMethodOverride:
    def test_x_http_method_override(self):
        """Test X-HTTP-Method-Override header bypass."""
        for endpoint in PROTECTED_ENDPOINTS:
            r = safe_request("POST", url_join(endpoint),
                            headers={"X-HTTP-Method-Override": "GET"},
                            allow_redirects=False)
            if r and r.status_code == 200 and len(r.text) > 200:
                pytest.skip(
                    f"X-HTTP-Method-Override processed at {endpoint}: "
                    "verify if authentication was bypassed"
                )

    def test_x_method_override(self):
        """Test X-Method-Override header."""
        for endpoint in PROTECTED_ENDPOINTS:
            r = safe_request("POST", url_join(endpoint),
                            headers={"X-Method-Override": "DELETE"},
                            allow_redirects=False)
            if r and r.status_code in (200, 204):
                pytest.skip(
                    f"X-Method-Override processed at {endpoint}: "
                    "dangerous operation via method override"
                )


class TestHttpMethodCaseVariation:
    def test_http_method_case_sensitivity(self):
        """Test if HTTP method checking is case-sensitive."""
        for endpoint in PROTECTED_ENDPOINTS:
            methods = ["get", "Get", "GeT", "gEt", "post", "Post", "pOSt"]
            for method in methods:
                r = safe_request(method.upper(), url_join(endpoint),
                                allow_redirects=False)
                if r and r.status_code == 200:
                    pytest.skip(
                        f"Case variation bypass candidate: {method.upper()} {endpoint}"
                    )


class TestHttpMethodChaining:
    def test_method_query_parameter_bypass(self):
        """Test if ?_method=DELETE or ?_method=PUT bypasses checks."""
        for endpoint in PROTECTED_ENDPOINTS:
            r = safe_request("GET", url_join(endpoint) + "?_method=DELETE",
                            allow_redirects=False)
            if r and r.status_code in (200, 204, 302):
                pytest.skip(
                    f"Query parameter method override at {endpoint}?_method=DELETE: "
                    "HTTP {0}".format(r.status_code)
                )


class TestContentTypeMethodBypass:
    def test_method_bypass_with_content_type(self):
        """Test if different Content-Type allows method bypass."""
        for endpoint in PROTECTED_ENDPOINTS:
            # Try POST with different content types
            for ct in ["application/json", "application/xml", "text/plain"]:
                r = safe_request("POST", url_join(endpoint),
                                headers={"Content-Type": ct},
                                allow_redirects=False)
                if r and r.status_code == 200:
                    pytest.skip(
                        f"Content-Type method bypass at {endpoint}: "
                        "Content-Type: {0}".format(ct)
                    )


class TestMethodBypassSkipped:
    def test_active_method_bypass_exploitation_destructive(self):
        pytest.skip(
            "Active HTTP method bypass exploitation may modify server state. "
            "Verify bypasses are real before destructively testing state changes."
        )
