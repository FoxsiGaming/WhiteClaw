"""Category 18: DoS & Rate Limiting — passive header checks and ReDoS source analysis."""
import re
import pytest

from tests.active.helpers import safe_get, safe_post, url_join
from tests.active.config import TARGET_URL

RATE_LIMIT_HEADERS = [
    "X-RateLimit-Limit", "X-Rate-Limit-Limit", "RateLimit-Limit",
    "X-RateLimit-Remaining", "X-Rate-Limit-Remaining", "Retry-After",
]

REDOS_CATASTROPHIC = [
    re.compile(r"\(a\+\)\+b"),
    re.compile(r"\(\w\+\)\+"),
    re.compile(r"\(\.?\.\*\)\+"),
    re.compile(r"\([^)]+\?\+[^)]+\)\{"),
    re.compile(r"\([^)]+\+[^)]+\)\+"),
    re.compile(r"\([^)]+\)\{[0-9]+,\}[^)]+\)\+"),
]


class TestRateLimitingPassive:
    def _has_rate_headers(self, r):
        if r is None:
            return False
        return any(h in r.headers for h in RATE_LIMIT_HEADERS)

    def test_login_endpoint_has_rate_limit_headers(self):
        for path in ["/login", "/signin", "/auth", "/api/login"]:
            r = safe_post(url_join(path),
                          data={"username": "test", "password": "test"})
            if r is None or r.status_code == 404:
                continue
            if not self._has_rate_headers(r):
                pytest.skip(
                    f"Login endpoint {path} has no rate-limit headers — "
                    "enforcement may still exist at infrastructure level. "
                    "Run destructive brute-force tests to verify."
                )
            return
        pytest.skip("No login endpoint found at common paths")

    def test_password_reset_has_rate_limit_headers(self):
        for path in ["/forgot-password", "/reset-password", "/password/reset"]:
            r = safe_post(url_join(path), data={"email": "test@example.com"})
            if r is None or r.status_code == 404:
                continue
            if not self._has_rate_headers(r):
                pytest.skip(
                    f"Password reset {path} has no rate-limit headers — verify manually"
                )
            return
        pytest.skip("No password reset endpoint found")

    def test_api_root_has_rate_limit_headers(self):
        for path in ["/api", "/api/v1", "/api/v2"]:
            r = safe_get(url_join(path))
            if r is None or r.status_code == 404:
                continue
            if not self._has_rate_headers(r):
                pytest.skip(
                    f"API endpoint {path} has no rate-limit headers — "
                    "verify enforcement with load testing"
                )
            return
        pytest.skip("No API endpoint found")

    def test_otp_endpoint_has_rate_limit(self):
        for path in ["/auth/otp", "/api/otp", "/2fa/verify", "/otp/verify",
                     "/auth/mfa", "/verify"]:
            r = safe_post(url_join(path), json={"code": "123456"})
            if r is None or r.status_code == 404:
                continue
            if not self._has_rate_headers(r):
                pytest.skip(
                    f"OTP/2FA endpoint {path} has no rate-limit headers — "
                    "enforcement may exist but is not advertised"
                )
            return
        pytest.skip("No OTP/2FA endpoint found at common paths")


class TestReDosPatterns:
    def test_no_redos_patterns_in_html_source(self, base_html):
        hits = []
        for pat in REDOS_CATASTROPHIC:
            found = pat.findall(base_html)
            if found:
                hits.append(pat.pattern)
        assert not hits, (
            f"Potential catastrophic regex (ReDoS) patterns in page source: {hits}"
        )

    def test_no_redos_in_inline_scripts(self, base_soup):
        for tag in base_soup.find_all("script"):
            if not tag.string:
                continue
            for pat in REDOS_CATASTROPHIC:
                if pat.search(tag.string):
                    pytest.fail(
                        f"Potential ReDoS regex in inline script: {pat.pattern!r}"
                    )


# Destructive tests — gated
class TestDosDestructiveSkipped:
    def test_xml_bomb_is_destructive(self):
        pytest.skip(
            "XML bomb (billion laughs) is DESTRUCTIVE — may crash the server. "
            "Set ENABLE_DESTRUCTIVE_TESTS=True in config.py and run tests/destructive/test_dos.py."
        )

    def test_graphql_complexity_dos_is_destructive(self):
        pytest.skip(
            "GraphQL complexity DoS is DESTRUCTIVE. Run tests/destructive/test_dos.py."
        )

    def test_slowloris_is_destructive(self):
        pytest.skip(
            "Slowloris attack is DESTRUCTIVE — it will deny service. "
            "Run tests/destructive/test_dos.py with ENABLE_DESTRUCTIVE_TESTS=True."
        )

    def test_large_payload_dos_is_destructive(self):
        pytest.skip(
            "Large payload DoS is DESTRUCTIVE. Run tests/destructive/test_dos.py."
        )

    def test_account_lockout_dos_is_destructive(self):
        pytest.skip(
            "Account lockout DoS (locking other users) is DESTRUCTIVE. "
            "Only run on isolated test accounts."
        )
