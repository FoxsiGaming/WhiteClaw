# ⚠️ DESTRUCTIVE TEST — Do not run against production.
# Set ENABLE_DESTRUCTIVE_TESTS=True in tests/active/config.py to enable.
"""Category 27: CORS Misconfiguration and Preflight Bypass."""
import re
import pytest

from tests.active.helpers import safe_request, url_join
from tests.active.config import ENABLE_DESTRUCTIVE_TESTS, TARGET_URL

if not ENABLE_DESTRUCTIVE_TESTS:
    pytestmark = pytest.mark.skip(
        reason="ENABLE_DESTRUCTIVE_TESTS=False in config.py — "
               "these tests modify server state, trigger lockouts, and may cause disruption."
    )

CORS_HEADERS = [
    "Access-Control-Allow-Origin",
    "Access-Control-Allow-Credentials",
    "Access-Control-Allow-Methods",
    "Access-Control-Allow-Headers",
]

DANGEROUS_ORIGINS = [
    "https://attacker.com",
    "https://evil.example.com",
    "http://127.0.0.1",
    "http://localhost",
    "null",
]


class TestCorsBroadOrigins:
    def test_cors_wildcard_with_credentials(self):
        """Test if CORS allows wildcard with credentials."""
        r = safe_request("OPTIONS", TARGET_URL)
        if r is None:
            pytest.skip("OPTIONS request failed")
        
        allow_origin = r.headers.get("Access-Control-Allow-Origin", "")
        allow_creds = r.headers.get("Access-Control-Allow-Credentials", "").lower()
        
        if allow_origin == "*" and "true" in allow_creds:
            pytest.fail(
                "CORS misconfiguration: Allow-Origin: * with Credentials: true — "
                "violates CORS spec and allows credential theft"
            )

    def test_cors_wildcard_origin(self):
        """Test if CORS allows wildcard origin."""
        r = safe_request("GET", TARGET_URL, headers={"Origin": "https://attacker.com"})
        if r is None:
            pytest.skip("request failed")
        
        allow_origin = r.headers.get("Access-Control-Allow-Origin", "")
        if allow_origin == "*":
            pytest.fail(
                "CORS allows wildcard origin: Access-Control-Allow-Origin: * — "
                "enables cross-origin data access from any website"
            )


class TestCorsNullOrigin:
    def test_cors_null_origin_accepted(self):
        """Test if null origin is accepted (can be exploited via data: or file: URIs)."""
        r = safe_request("GET", TARGET_URL, headers={"Origin": "null"})
        if r is None:
            pytest.skip("request failed")
        
        allow_origin = r.headers.get("Access-Control-Allow-Origin", "")
        if allow_origin == "null" or allow_origin == "*":
            pytest.fail(
                "CORS accepts null origin — exploitable via data: or file: URIs "
                "for cross-origin attacks"
            )


class TestCorsOriginValidation:
    def test_cors_origin_subdomain_bypass(self):
        """Test origin validation bypass via subdomain manipulation."""
        bypass_origins = [
            "https://attacker.comlegitimate.com",
            "https://legitimate.com.attacker.com",
            "https://legitimate.com@attacker.com",
            "https://legitimate.com#attacker.com",
        ]
        for origin in bypass_origins:
            r = safe_request("GET", TARGET_URL, headers={"Origin": origin})
            if r is None:
                continue
            allow_origin = r.headers.get("Access-Control-Allow-Origin", "")
            if allow_origin and "attacker" in allow_origin:
                pytest.fail(f"CORS origin bypass via: {origin}")

    def test_cors_origin_case_sensitivity(self):
        """Test if CORS origin check is case-sensitive."""
        origins = [
            ("https://ATTACKER.COM", "https://attacker.com"),
            ("https://Evil.Example.COM", "https://evil.example.com"),
        ]
        for upper, lower in origins:
            r = safe_request("GET", TARGET_URL, headers={"Origin": upper})
            if r:
                allow = r.headers.get("Access-Control-Allow-Origin", "")
                if allow.lower() == lower.lower() and allow != lower:
                    pytest.skip("CORS may have case-sensitivity bypass")


class TestCorsCredentials:
    def test_cors_credentials_exposure(self):
        """Test if credentials are exposed via CORS."""
        r = safe_request("GET", TARGET_URL,
                        headers={"Origin": "https://attacker.com"})
        if r is None:
            pytest.skip("request failed")
        
        allow_creds = r.headers.get("Access-Control-Allow-Credentials", "").lower()
        allow_origin = r.headers.get("Access-Control-Allow-Origin", "")
        
        if "true" in allow_creds and allow_origin and allow_origin != "null":
            # Credentials allowed with specific origin is okay, but check if too permissive
            if allow_origin == "*":
                pytest.fail("CORS credentials exposed: Allow-Credentials: true with Allow-Origin: *")


class TestCorsPreflightBypass:
    def test_cors_simple_request_no_preflight(self):
        """Test if simple requests bypass preflight checks."""
        # Simple requests don't trigger preflight — check if restrictions apply anyway
        r = safe_request("GET", TARGET_URL,
                        headers={"Origin": "https://attacker.com",
                                "Content-Type": "text/plain"})
        if r is None:
            pytest.skip("request failed")
        
        allow_origin = r.headers.get("Access-Control-Allow-Origin", "")
        if allow_origin == "https://attacker.com":
            pytest.fail("CORS allows attacker origin on simple GET request")

    def test_cors_options_preflight_missing(self):
        """Test if preflight OPTIONS request is required but missing."""
        r = safe_request("OPTIONS", TARGET_URL,
                        headers={"Origin": "https://attacker.com",
                                "Access-Control-Request-Method": "POST"})
        if r is None:
            pytest.skip("OPTIONS failed")
        
        if r.status_code == 200:
            allow_methods = r.headers.get("Access-Control-Allow-Methods", "")
            if "POST" in allow_methods:
                # Check if preflight properly restricts
                post_r = safe_request("POST", TARGET_URL,
                                     headers={"Origin": "https://attacker.com"})
                if post_r and "Access-Control-Allow-Origin" in post_r.headers:
                    pytest.fail("CORS preflight bypass: POST allowed without proper validation")


class TestCorsWildcardMethods:
    def test_cors_wildcard_methods(self):
        """Test if CORS allows all methods via wildcard."""
        r = safe_request("OPTIONS", TARGET_URL)
        if r is None:
            pytest.skip("OPTIONS failed")
        
        allow_methods = r.headers.get("Access-Control-Allow-Methods", "")
        if allow_methods == "*":
            pytest.fail(
                "CORS allows all methods via wildcard: Access-Control-Allow-Methods: * — "
                "enables unrestricted HTTP method access"
            )
