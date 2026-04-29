"""Category 15: Client-Side — open redirects, sensitive source analysis, tabnapping."""
import re
import pytest

from tests.active.helpers import safe_get, url_join, get_soup
from tests.active.config import TARGET_URL

REDIRECT_PARAMS = ["redirect", "next", "url", "return", "returnUrl", "returnTo",
                   "goto", "dest", "destination", "continue", "forward", "target",
                   "redir", "r", "back", "callback"]

SENSITIVE_FORM_FIELDS = ["password", "passwd", "credit_card", "card_number",
                          "cvv", "cvc", "ssn", "social_security", "pin", "secret"]


class TestOpenRedirects:
    def test_no_open_redirect_to_external(self):
        ext_url = "https://evil.attacker.com/phishing"
        for param in REDIRECT_PARAMS:
            r = safe_get(f"{TARGET_URL}?{param}={ext_url}", allow_redirects=False)
            if r is None:
                continue
            if r.status_code in (301, 302, 303, 307, 308):
                loc = r.headers.get("Location", "")
                if "evil.attacker.com" in loc:
                    pytest.fail(
                        f"Open redirect via ?{param}: Location: {loc}"
                    )

    def test_no_open_redirect_via_double_slash(self):
        for param in REDIRECT_PARAMS:
            r = safe_get(f"{TARGET_URL}?{param}=//evil.attacker.com/",
                         allow_redirects=False)
            if r is None:
                continue
            if r.status_code in (301, 302, 303, 307, 308):
                loc = r.headers.get("Location", "")
                if "evil.attacker.com" in loc:
                    pytest.fail(
                        f"Open redirect via ?{param}=//evil.attacker.com"
                    )


class TestSensitiveSourceComments:
    def test_no_sensitive_comments_in_html(self, base_soup):
        from bs4 import Comment
        sensitive_kws = ["password", "passwd", "secret", "api_key", "todo: remove",
                         "debug", "test credentials", "admin", "hack", "internal"]
        bad_comments = []
        for comment in base_soup.find_all(string=lambda t: isinstance(t, Comment)):
            text = str(comment).lower()
            for kw in sensitive_kws:
                if kw in text:
                    bad_comments.append(str(comment)[:80])
                    break
        assert not bad_comments, (
            f"Sensitive HTML comments found: {bad_comments[:3]}"
        )


class TestPostMessageSecurity:
    def test_postmessage_origin_check_in_js(self, base_soup):
        js_with_postmessage = []
        for tag in base_soup.find_all("script"):
            if tag.string and "postMessage" in tag.string:
                if "addEventListener" in tag.string and "message" in tag.string:
                    # Check if origin is validated
                    if "event.origin" not in tag.string and "origin ==" not in tag.string:
                        js_with_postmessage.append(str(tag.string)[:100])
        assert not js_with_postmessage, (
            f"addEventListener for 'message' without origin check: {js_with_postmessage[:2]}"
        )


class TestUnsafeDomOperations:
    def test_no_eval_with_location_hash(self, base_soup):
        unsafe_pattern = re.compile(
            r"eval\s*\(\s*(?:location\.hash|window\.location\.hash|decodeURIComponent)",
            re.IGNORECASE
        )
        for tag in base_soup.find_all("script"):
            if tag.string and unsafe_pattern.search(tag.string):
                pytest.fail(
                    "eval() with location.hash in inline script — DOM XSS risk"
                )

    def test_no_innerhtml_with_location_params(self, base_soup):
        unsafe_pattern = re.compile(
            r'\.innerHTML\s*=\s*.*(?:location\.|URLSearchParams|getParameter)',
            re.IGNORECASE
        )
        for tag in base_soup.find_all("script"):
            if tag.string and unsafe_pattern.search(tag.string):
                pytest.fail(
                    "innerHTML assignment using URL parameters in inline script — DOM XSS risk"
                )


class TestApiKeysInJs:
    def test_no_api_keys_in_inline_scripts(self, base_soup):
        secret_patterns = [
            re.compile(r'AKIA[0-9A-Z]{16}'),
            re.compile(r'ghp_[A-Za-z0-9]{36}'),
            re.compile(r'sk-[A-Za-z0-9]{48}'),
            re.compile(r'(?i)api[_-]?key\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']'),
        ]
        for tag in base_soup.find_all("script"):
            if not tag.string:
                continue
            for pat in secret_patterns:
                m = pat.search(tag.string)
                if m:
                    pytest.fail(
                        f"Potential API key/secret in inline script: {m.group(0)[:50]}"
                    )


class TestAutocompleteOnSensitiveForms:
    def test_password_fields_have_autocomplete_off(self, base_soup):
        for inp in base_soup.find_all("input"):
            inp_type = (inp.get("type") or "").lower()
            inp_name = (inp.get("name") or "").lower()
            if inp_type == "password" or "password" in inp_name:
                autocomplete = (inp.get("autocomplete") or "").lower()
                if autocomplete not in ("off", "new-password", "current-password"):
                    pytest.fail(
                        f"Password field without autocomplete='off': "
                        f"<input type={inp_type!r} name={inp_name!r} autocomplete={autocomplete!r}>"
                    )

    def test_credit_card_fields_have_autocomplete_off(self, base_soup):
        cc_names = ["card", "cc", "credit", "cvv", "cvc", "expiry", "exp_"]
        for inp in base_soup.find_all("input"):
            name = (inp.get("name") or inp.get("id") or "").lower()
            if any(cc in name for cc in cc_names):
                autocomplete = (inp.get("autocomplete") or "").lower()
                if autocomplete not in ("off", "cc-number", "cc-csc", "cc-exp"):
                    pytest.fail(
                        f"Payment field without appropriate autocomplete: name={name!r}"
                    )


class TestTabnapping:
    def test_no_target_blank_without_noopener(self, base_soup):
        vulnerable = []
        for tag in base_soup.find_all("a", target="_blank"):
            rel = (tag.get("rel") or [])
            if isinstance(rel, str):
                rel = rel.split()
            rel_lower = [r.lower() for r in rel]
            if "noopener" not in rel_lower:
                href = tag.get("href", "")[:60]
                vulnerable.append(href)
        assert not vulnerable, (
            f"<a target='_blank'> without rel='noopener' — reverse tabnapping risk: {vulnerable[:5]}"
        )


class TestJsonpInjection:
    def test_jsonp_callback_not_injectable(self):
        for param in ["callback", "jsonp", "cb", "json_callback"]:
            r = safe_get(f"{TARGET_URL}?{param}=evil_function")
            if r is None:
                continue
            if r.status_code == 200 and "evil_function(" in r.text:
                pytest.fail(
                    f"JSONP callback injection: ?{param}=evil_function reflected as function call"
                )


class TestClientSideAuthChecks:
    def test_no_client_side_only_auth_in_js(self, base_soup):
        # Look for auth checks done purely in JS (easily bypassed)
        bypass_patterns = [
            re.compile(r'if\s*\(\s*isAdmin\s*\)', re.IGNORECASE),
            re.compile(r'if\s*\(\s*user\.role\s*===?\s*["\']admin["\']', re.IGNORECASE),
            re.compile(r'if\s*\(\s*localStorage\.getItem\(["\']role["\']\)', re.IGNORECASE),
        ]
        for tag in base_soup.find_all("script"):
            if not tag.string:
                continue
            for pat in bypass_patterns:
                if pat.search(tag.string):
                    pytest.fail(
                        f"Client-side-only authorization check found in JS: {pat.pattern!r} — "
                        "trivially bypassable in browser developer tools"
                    )


class TestPrototypePollutionInJs:
    def test_no_prototype_pollution_sinks_inline(self, base_soup):
        pollution_re = re.compile(
            r'__proto__|Object\.prototype\.\w+\s*=', re.IGNORECASE
        )
        for tag in base_soup.find_all("script"):
            if tag.string and pollution_re.search(tag.string):
                pytest.fail(
                    f"Potential prototype pollution sink in inline JS: "
                    f"{pollution_re.search(tag.string).group(0)}"
                )


# Browser-only tests
class TestClientSideSkipped:
    def test_localstorage_sensitive_data_browser_only(self):
        pytest.skip(
            "localStorage content can only be inspected in a browser context. "
            "Use Playwright or browser DevTools."
        )

    def test_sessionstorage_browser_only(self):
        pytest.skip("sessionStorage inspection requires a browser context.")
