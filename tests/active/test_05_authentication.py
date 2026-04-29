"""Category 5: Authentication & Session Management."""
import re
import urllib.parse
import pytest

from tests.active.helpers import safe_get, safe_post, url_join, get_soup
from tests.active.config import TARGET_URL


LOGIN_PATHS = ["/login", "/signin", "/auth", "/account/login", "/user/login",
               "/wp-login.php", "/admin/login"]
FORGOT_PATHS = ["/forgot-password", "/reset-password", "/password/reset",
                "/account/forgot", "/auth/forgot"]


def _find_login_url():
    for path in LOGIN_PATHS:
        r = safe_get(url_join(path))
        if r and r.status_code == 200:
            return url_join(path), r
    return None, None


class TestUsernameEnumeration:
    def test_login_no_username_enumeration(self):
        login_url, r = _find_login_url()
        if login_url is None:
            pytest.skip("no login endpoint found at common paths")

        existing_resp = safe_post(login_url,
                                  data={"username": "admin", "password": "INVALID_WC_TEST"},
                                  allow_redirects=False)
        nonexist_resp = safe_post(login_url,
                                  data={"username": "wc_nonexistent_9z7x", "password": "INVALID_WC_TEST"},
                                  allow_redirects=False)
        if existing_resp is None or nonexist_resp is None:
            pytest.skip("login POST failed")

        # Different status codes for valid vs invalid usernames = enumeration
        if existing_resp.status_code != nonexist_resp.status_code:
            pytest.fail(
                f"Username enumeration via login: different HTTP status codes "
                f"for existing ({existing_resp.status_code}) vs non-existing ({nonexist_resp.status_code}) usernames"
            )

        # Different error message text
        if existing_resp.text != nonexist_resp.text:
            # Quick heuristic — long diff suggests different pages, not just timing
            diff_len = abs(len(existing_resp.text) - len(nonexist_resp.text))
            if diff_len > 50:
                pytest.fail(
                    "Username enumeration via login: different response bodies for "
                    "existing vs non-existing usernames (response length differs by "
                    f"{diff_len} bytes)"
                )

    def test_forgot_password_no_username_enumeration(self):
        for path in FORGOT_PATHS:
            r = safe_get(url_join(path))
            if r is None or r.status_code != 200:
                continue
            exist = safe_post(url_join(path),
                              data={"email": "admin@example.com"},
                              allow_redirects=False)
            nonexist = safe_post(url_join(path),
                                 data={"email": "wc_ghost_9z7x@example.com"},
                                 allow_redirects=False)
            if exist is None or nonexist is None:
                continue
            if exist.status_code != nonexist.status_code:
                pytest.fail(
                    f"Username enumeration via forgot-password ({path}): different status "
                    f"codes for registered ({exist.status_code}) vs unregistered ({nonexist.status_code})"
                )
            return
        pytest.skip("no forgot-password endpoint found at common paths")


class TestAccountLockoutPassive:
    def test_lockout_policy_mentioned_in_login_page(self):
        _, r = _find_login_url()
        if r is None:
            pytest.skip("no login page found")
        # This is a passive hint — not a definitive check
        lockout_hints = ["locked", "too many", "attempts", "temporarily"]
        found = any(h in r.text.lower() for h in lockout_hints)
        # Not failing — just note if there's no mention. Real lockout needs destructive test.
        if not found:
            pytest.skip(
                "No lockout policy message found in login page — "
                "run destructive brute-force test to verify actual enforcement"
            )


class TestDefaultCredentials:
    def test_default_creds_passive_hint(self):
        _, r = _find_login_url()
        if r is None:
            pytest.skip("no login page found")
        # Check page source for hints suggesting default creds (e.g. 'admin/admin' in comments)
        indicators = ["admin/admin", "admin:admin", "default password", "default credentials"]
        found = [i for i in indicators if i in r.text.lower()]
        assert not found, (
            f"Login page source contains default credential hints: {found}"
        )


class TestCookieSecurity:
    def test_session_cookie_httponly(self, base_cookies, base_response):
        if base_response is None:
            pytest.skip("target unreachable")
        session_names = ["session", "sessionid", "sid", "PHPSESSID", "JSESSIONID",
                         "ASP.NET_SessionId", "connect.sid", "token", "auth"]
        for cookie in base_response.cookies:
            if any(n.lower() in cookie.name.lower() for n in session_names):
                assert cookie.has_nonstandard_attr("HttpOnly") or "httponly" in str(cookie).lower(), (
                    f"Session cookie '{cookie.name}' is missing the HttpOnly flag"
                )

    def test_session_cookie_secure_on_https(self, base_response):
        if base_response is None:
            pytest.skip("target unreachable")
        if not TARGET_URL.startswith("https"):
            pytest.skip("target is not HTTPS — Secure flag check not applicable")
        session_names = ["session", "sessionid", "sid", "PHPSESSID", "JSESSIONID",
                         "ASP.NET_SessionId", "connect.sid", "token", "auth"]
        for cookie in base_response.cookies:
            if any(n.lower() in cookie.name.lower() for n in session_names):
                assert cookie.secure, (
                    f"Session cookie '{cookie.name}' is missing the Secure flag on an HTTPS site"
                )

    def test_cookie_samesite_attribute(self, base_response):
        if base_response is None:
            pytest.skip("target unreachable")
        missing = []
        for cookie in base_response.cookies:
            samesite = cookie._rest.get("SameSite", "").lower() if hasattr(cookie, "_rest") else ""
            if not samesite:
                # Check Set-Cookie header directly
                for hdr in base_response.headers.get("Set-Cookie", "").split("\n"):
                    if cookie.name in hdr and "samesite" not in hdr.lower():
                        missing.append(cookie.name)
        # Report, don't hard-fail — SameSite has legitimate None values for cross-site cookies
        if missing:
            pytest.skip(
                f"Cookies without SameSite attribute: {missing} — "
                "verify these are not session/auth cookies"
            )

    def test_cookie_expiry_reasonable(self, base_response):
        if base_response is None:
            pytest.skip("target unreachable")
        for cookie in base_response.cookies:
            if cookie.expires:
                import time
                days = (cookie.expires - time.time()) / 86400
                if days > 365:
                    pytest.fail(
                        f"Cookie '{cookie.name}' expires in {days:.0f} days — "
                        "long-lived session cookies increase hijacking window"
                    )


class TestHttpsEnforcement:
    def test_https_only_login(self):
        _, r = _find_login_url()
        if r is None:
            pytest.skip("no login endpoint found")
        assert r.url.startswith("https://"), (
            f"Login page is served over HTTP, not HTTPS: {r.url}"
        )

    def test_http_redirects_to_https(self):
        if not TARGET_URL.startswith("https"):
            pytest.skip("TARGET_URL is not HTTPS — redirect test not applicable")
        http_url = TARGET_URL.replace("https://", "http://", 1)
        r = safe_get(http_url, allow_redirects=True)
        if r is None:
            pytest.skip("HTTP request failed (could be port-blocked)")
        assert r.url.startswith("https://"), (
            f"HTTP does not redirect to HTTPS — last URL: {r.url}"
        )


class TestPasswordResetSecurity:
    def test_reset_token_not_in_url_query_string(self):
        # If the app returns a reset confirmation page that shows the token in URL, flag it
        for path in FORGOT_PATHS:
            r = safe_get(url_join(path))
            if r is None or r.status_code != 200:
                continue
            submit = safe_post(url_join(path),
                               data={"email": "test@example.com"},
                               allow_redirects=True)
            if submit is None:
                continue
            parsed = urllib.parse.urlparse(submit.url)
            qs = urllib.parse.parse_qs(parsed.query)
            token_params = [k for k in qs if "token" in k.lower() or "reset" in k.lower()]
            assert not token_params, (
                f"Password reset token exposed in URL query string: {submit.url}"
            )
            return
        pytest.skip("no forgot-password endpoint found")


class TestOAuthSecurity:
    def test_oauth_no_open_redirect_in_callback(self):
        for path in ["/auth/callback", "/oauth/callback", "/callback",
                     "/oauth2/callback", "/auth/google/callback"]:
            r = safe_get(url_join(path) + "?code=test&state=test&redirect_uri=https://evil.com",
                         allow_redirects=False)
            if r is None:
                continue
            if r.status_code in (301, 302, 303, 307, 308):
                loc = r.headers.get("Location", "")
                if "evil.com" in loc:
                    pytest.fail(
                        f"Open redirect in OAuth callback {path}: "
                        f"redirect_uri=evil.com accepted, Location: {loc}"
                    )


# Tests requiring auth or specific application context
class TestAuthRequiredSkips:
    def test_mfa_check_requires_auth(self):
        pytest.skip("MFA enforcement requires an authenticated session — configure AUTH_TOKEN.")

    def test_session_token_entropy_requires_auth(self):
        pytest.skip("Session entropy analysis requires multiple authenticated login sessions.")

    def test_session_invalidation_logout_requires_auth(self):
        pytest.skip("Session invalidation requires active session — configure auth in config.py.")

    def test_jwt_algorithm_none_requires_jwt(self):
        pytest.skip("JWT algorithm confusion requires a valid JWT — set AUTH_TOKEN in config.py.")

    def test_jwt_expiration_requires_jwt(self):
        pytest.skip("JWT expiration test requires a valid JWT token.")

    def test_weak_password_policy_requires_signup(self):
        pytest.skip("Password policy test requires access to an account creation endpoint.")
