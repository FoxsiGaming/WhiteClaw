"""Category 11: CSRF & Business Logic — token checks, state-change probes."""
import re
import pytest

from tests.active.helpers import safe_get, safe_post, safe_request, url_join, get_soup
from tests.active.config import TARGET_URL

STATE_CHANGING_PATHS = [
    "/login", "/logout", "/register", "/signup",
    "/account/update", "/profile/update", "/password/change",
    "/settings", "/subscribe", "/unsubscribe",
    "/checkout", "/order", "/cart/add",
]

CSRF_TOKEN_NAMES = [
    "csrf_token", "csrftoken", "csrf", "_token", "__csrf",
    "x-csrf-token", "authenticity_token", "xsrf-token", "_csrf",
]


def _find_csrf_token(html):
    soup = get_soup(None)
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(html, "html.parser")
    # Look in hidden inputs
    for inp in soup.find_all("input", type="hidden"):
        name = (inp.get("name") or "").lower()
        if any(t in name for t in CSRF_TOKEN_NAMES):
            return inp.get("value", "")
    # Look in meta tags
    for meta in soup.find_all("meta"):
        name = (meta.get("name") or "").lower()
        if any(t in name for t in CSRF_TOKEN_NAMES):
            return meta.get("content", "")
    return None


class TestCsrfTokenPresence:
    def test_state_changing_forms_have_csrf_tokens(self):
        missing = []
        for path in STATE_CHANGING_PATHS:
            r = safe_get(url_join(path))
            if r is None or r.status_code != 200:
                continue
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(r.text, "html.parser")
            forms = soup.find_all("form")
            for form in forms:
                method = (form.get("method") or "get").upper()
                if method == "POST":
                    token = _find_csrf_token(str(form))
                    if token is None:
                        # Also check for meta CSRF token (SPA pattern)
                        meta_token = _find_csrf_token(r.text)
                        if meta_token is None:
                            missing.append(path)
                            break
        assert not missing, (
            f"POST forms without detectable CSRF token: {missing}"
        )

    def test_csrf_token_not_in_url(self):
        for path in STATE_CHANGING_PATHS:
            r = safe_get(url_join(path))
            if r is None:
                continue
            import urllib.parse
            parsed = urllib.parse.urlparse(r.url)
            qs = urllib.parse.parse_qs(parsed.query)
            exposed = [k for k in qs if any(t in k.lower() for t in CSRF_TOKEN_NAMES)]
            if exposed:
                pytest.fail(
                    f"CSRF token appears in URL query string at {r.url} — "
                    "tokens in URLs may be logged in server logs or leaked via Referer"
                )


class TestCsrfViaJson:
    def test_json_post_without_csrf_token(self):
        # Many CSRF defenses check Content-Type but fail to validate token for JSON requests.
        for path in ["/api/update", "/api/settings", "/api/account", "/account/update"]:
            r = safe_post(url_join(path),
                          json={"test": "csrf_probe"},
                          headers={"Content-Type": "application/json"})
            if r is None:
                continue
            # If the endpoint returns 200 with no CSRF validation on a JSON body, it may be vulnerable
            # We can only flag if we get a non-4xx response suggesting the request was processed
            if r.status_code == 200:
                pytest.skip(
                    f"JSON POST to {path} returned 200 without CSRF token — "
                    "verify if CSRF protection applies to JSON content type"
                )


class TestCsrfViaGet:
    def test_state_changes_not_on_get(self):
        state_get_paths = [
            "/logout?confirmed=true",
            "/delete?id=1",
            "/account/delete",
            "/user/delete",
        ]
        issues = []
        for path in state_get_paths:
            r = safe_get(url_join(path), allow_redirects=False)
            if r and r.status_code == 200:
                # If action actually executed (body suggests deletion/logout happened)
                action_keywords = ["deleted", "removed", "logged out", "success"]
                if any(k in r.text.lower() for k in action_keywords):
                    issues.append(path)
        assert not issues, (
            f"State-changing actions appear possible via GET: {issues}"
        )


class TestWeakCsrfToken:
    def test_csrf_token_not_trivially_predictable(self):
        tokens = []
        for _ in range(3):
            r = safe_get(url_join("/login"))
            if r is None or r.status_code != 200:
                continue
            t = _find_csrf_token(r.text)
            if t:
                tokens.append(t)
        if len(tokens) < 2:
            pytest.skip("Could not collect multiple CSRF tokens for comparison")
        # All tokens should be unique
        assert len(set(tokens)) == len(tokens), (
            f"CSRF tokens are not unique across requests: {tokens}"
        )
        # Tokens should have sufficient entropy (at least 16 chars)
        for t in tokens:
            assert len(t) >= 16, (
                f"CSRF token is suspiciously short ({len(t)} chars): {t!r}"
            )


class TestBusinessLogic:
    def test_negative_price_rejected(self):
        for path in ["/cart/add", "/order", "/checkout"]:
            r = safe_post(url_join(path),
                          data={"price": "-100", "quantity": "1", "product_id": "1"})
            if r is None or r.status_code == 404:
                continue
            assert r.status_code not in (200,) or "success" not in r.text.lower(), (
                f"Negative price accepted at {path} — business logic bypass possible"
            )

    def test_negative_quantity_rejected(self):
        for path in ["/cart/add", "/order"]:
            r = safe_post(url_join(path),
                          data={"quantity": "-1", "product_id": "1"})
            if r is None or r.status_code == 404:
                continue
            assert r.status_code != 200 or "error" in r.text.lower() or "invalid" in r.text.lower(), (
                f"Negative quantity not rejected at {path}"
            )

    def test_workflow_step_bypass(self):
        # Try to access step 3 of a checkout without step 1
        for path in ["/checkout/payment", "/checkout/step3", "/order/confirm",
                     "/checkout/confirm", "/payment"]:
            r = safe_get(url_join(path), allow_redirects=False)
            if r is None or r.status_code == 404:
                continue
            # A 200 without prior steps could indicate workflow bypass
            if r.status_code == 200:
                pytest.skip(
                    f"{path} returns 200 without prior checkout steps — "
                    "verify manually whether cart/session is required"
                )


# Requires auth or specific context
class TestCsrfSkipped:
    def test_race_condition_double_spend_destructive(self):
        pytest.skip(
            "Race condition / double-spend tests are DESTRUCTIVE — "
            "they submit real transactions. Move to tests/destructive/ and set ENABLE_DESTRUCTIVE_TESTS=True."
        )
