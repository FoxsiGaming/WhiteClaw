# ⚠️ DESTRUCTIVE TEST — Do not run against production.
# Set ENABLE_DESTRUCTIVE_TESTS=True in tests/active/config.py to enable.
"""Category 21: LDAP Injection — LDAP filter manipulation in auth and directory search."""
import re
import pytest

from tests.active.helpers import safe_get, safe_post, url_join
from tests.active.config import ENABLE_DESTRUCTIVE_TESTS, TARGET_URL

if not ENABLE_DESTRUCTIVE_TESTS:
    pytestmark = pytest.mark.skip(
        reason="ENABLE_DESTRUCTIVE_TESTS=False in config.py — "
               "these tests modify server state, trigger lockouts, and may cause disruption."
    )

LOGIN_PATHS = ["/login", "/signin", "/auth", "/user/login", "/account/login"]
SEARCH_PATHS = ["/search/users", "/api/directory", "/api/v1/search", "/users/search"]

LDAP_INJECTION_PAYLOADS = [
    "*",
    "admin*",
    "*))(&(uid=*",
    "*))(&(mail=*",
    "admin*))(|(&(uid=*",
    "*)(objectClass=*",
    "*)(|(uid=*",
    "admin*))%00",
]

LDAP_ERROR_PATTERNS = re.compile(
    r"LDAP|ldap|error in search filter|Invalid filter|filter syntax|"
    r"Potential search filter error|Unable to parse|Search filter invalid",
    re.IGNORECASE,
)


class TestLdapInjectionInLogin:
    def test_ldap_injection_basic_asterisk(self):
        for path in LOGIN_PATHS:
            r = safe_post(url_join(path),
                          data={"username": "*", "password": "*"},
                          allow_redirects=False)
            if r is None or r.status_code == 404:
                continue
            # Successful login with wildcard = LDAP injection vulnerability
            if r.status_code == 302 or (r.status_code == 200 and "dashboard" in r.text.lower()):
                pytest.fail(f"LDAP injection in {path}: wildcard username accepted as valid auth")

    def test_ldap_injection_filter_bypass(self):
        for path in LOGIN_PATHS:
            r = safe_post(url_join(path),
                          data={"username": "admin*", "password": "*"},
                          allow_redirects=False)
            if r is None or r.status_code == 404:
                continue
            # admin* should match 'admin' LDAP entry without correct password
            if r.status_code == 302 or (r.status_code == 200 and "welcome" in r.text.lower()):
                pytest.fail(f"LDAP injection via wildcard prefix in {path}: admin account accessed")

    def test_ldap_injection_or_condition(self):
        for path in LOGIN_PATHS:
            r = safe_post(url_join(path),
                          data={"username": "admin*))(|(&(uid=*", "password": "anything"},
                          allow_redirects=False)
            if r is None or r.status_code == 404:
                continue
            if r.status_code in (302, 200) and "login" not in r.text.lower():
                pytest.fail(
                    f"LDAP injection via OR condition in {path}: "
                    "LDAP filter manipulation successful"
                )

    def test_ldap_injection_error_based(self):
        for path in LOGIN_PATHS:
            r = safe_post(url_join(path),
                          data={"username": "*", "password": "test"},
                          allow_redirects=False)
            if r and LDAP_ERROR_PATTERNS.search(r.text):
                pytest.fail(f"LDAP error message leaked in {path}: {r.text[:100]}")


class TestLdapInjectionInSearch:
    def test_ldap_search_wildcard_enumeration(self):
        for path in SEARCH_PATHS:
            r = safe_get(f"{url_join(path)}?query=*")
            if r is None or r.status_code == 404:
                continue
            # If * returns all entries, LDAP injection is possible
            if r.status_code == 200 and (len(r.text) > 500 or "uid=" in r.text.lower()):
                pytest.fail(
                    f"LDAP wildcard enumeration in {path}: * returned large result set"
                )

    def test_ldap_search_filter_injection(self):
        for path in SEARCH_PATHS:
            payload = "*))(&(uid=*"
            r = safe_get(f"{url_join(path)}?q={payload}")
            if r and r.status_code == 200 and len(r.text) > 300:
                pytest.fail(
                    f"LDAP filter injection in {path}: injected filter pattern processed"
                )

    def test_ldap_search_blind_injection(self):
        # Test boolean-based blind LDAP injection via response comparison
        base_r = safe_get(url_join(SEARCH_PATHS[0] if SEARCH_PATHS else "/search") + "?q=a")
        true_r = safe_get(url_join(SEARCH_PATHS[0] if SEARCH_PATHS else "/search") + "?q=*)(uid=*")
        if base_r and true_r:
            if abs(len(base_r.text) - len(true_r.text)) > 200:
                pytest.fail(
                    "LDAP blind injection detected: different response sizes for true/false conditions"
                )


class TestLdapNullByteBypass:
    def test_ldap_null_byte_injection(self):
        for path in LOGIN_PATHS:
            r = safe_post(url_join(path),
                          data={"username": "admin%00", "password": "anything"},
                          allow_redirects=False)
            if r is None or r.status_code == 404:
                continue
            # Null byte may terminate LDAP filter early
            if r.status_code in (302, 200) and "login" not in r.text.lower():
                pytest.fail(f"LDAP null byte bypass in {path}: authentication succeeded")


class TestLdapTimeBasedBlind:
    def test_ldap_injection_sleep_detection(self):
        # Time-based LDAP injection is difficult to detect passively
        # This test documents the attack surface
        pytest.skip(
            "Time-based LDAP injection detection requires destructive testing. "
            "See tests/destructive/ for active probing with time measurements."
        )
