"""Category 4: Cross-Site Scripting (XSS) — reflected, DOM-based, header-based probes."""
import re
import pytest

from tests.active.helpers import safe_get, safe_post, url_join, get_soup
from tests.active.config import TARGET_URL

XSS_MARKER = "xss_wc_7z9q"
XSS_PAYLOAD = f"<script>{XSS_MARKER}</script>"
XSS_IMG_PAYLOAD = f'<img src=x onerror="{XSS_MARKER}">'
XSS_POLY = f"'\"--><svg/onload='{XSS_MARKER}'>"

ENCODED_PAYLOAD = "%3Cscript%3E" + XSS_MARKER + "%3C%2Fscript%3E"

WAF_EVASION_PAYLOADS = [
    f"<ScRiPt>{XSS_MARKER}</ScRiPt>",
    f"<script >  {XSS_MARKER}  </script>",
    f"<img src=x OnErRoR={XSS_MARKER}>",
    f"<svg><animate onbegin={XSS_MARKER}>",
    f"&lt;script&gt;{XSS_MARKER}&lt;/script&gt;",  # this one should be safe (already encoded)
]

SEARCH_PARAMS = ["q", "search", "query", "term", "keyword", "s", "find",
                 "msg", "message", "text", "name", "input"]


def _reflected(r, marker=XSS_MARKER):
    """True if marker appears unencoded in response."""
    if r is None:
        return False
    return marker in r.text and "&lt;" not in r.text.split(marker)[0][-30:]


class TestReflectedXss:
    def test_reflected_xss_script_tag(self):
        for param in SEARCH_PARAMS:
            r = safe_get(f"{TARGET_URL}?{param}={XSS_PAYLOAD}")
            if _reflected(r):
                pytest.fail(
                    f"Reflected XSS: <script> tag unencoded in response for ?{param}"
                )

    def test_reflected_xss_img_onerror(self):
        for param in SEARCH_PARAMS[:4]:
            r = safe_get(f"{TARGET_URL}?{param}={XSS_IMG_PAYLOAD}")
            if _reflected(r):
                pytest.fail(
                    f"Reflected XSS via <img onerror> in ?{param}"
                )

    def test_reflected_xss_polyglot(self):
        for param in SEARCH_PARAMS[:4]:
            r = safe_get(f"{TARGET_URL}?{param}={XSS_POLY}")
            if _reflected(r):
                pytest.fail(f"Reflected XSS via polyglot payload in ?{param}")

    def test_reflected_xss_url_encoded(self):
        for param in SEARCH_PARAMS[:4]:
            r = safe_get(f"{TARGET_URL}?{param}={ENCODED_PAYLOAD}")
            if _reflected(r):
                pytest.fail(
                    f"Reflected XSS via URL-encoded payload in ?{param} — server decoded and reflected"
                )

    def test_xss_in_error_messages(self):
        r = safe_get(f"{TARGET_URL}?notexist={XSS_PAYLOAD}")
        if r and _reflected(r):
            pytest.fail("XSS in error message: <script> reflected from unknown param in 404/error page")


class TestCspEffectiveness:
    def test_csp_header_present(self, base_headers):
        csp = base_headers.get("Content-Security-Policy", "")
        assert csp, "Content-Security-Policy header is missing — XSS is fully unmitigated by CSP"

    def test_csp_no_unsafe_inline(self, base_headers):
        csp = base_headers.get("Content-Security-Policy", "")
        if not csp:
            pytest.skip("CSP not present (covered by test_csp_header_present)")
        assert "'unsafe-inline'" not in csp, (
            f"CSP contains 'unsafe-inline' — inline scripts are permitted: {csp}"
        )

    def test_csp_no_unsafe_eval(self, base_headers):
        csp = base_headers.get("Content-Security-Policy", "")
        if not csp:
            pytest.skip("CSP not present")
        assert "'unsafe-eval'" not in csp, (
            f"CSP contains 'unsafe-eval' — eval() is permitted: {csp}"
        )

    def test_csp_no_wildcard_script_src(self, base_headers):
        csp = base_headers.get("Content-Security-Policy", "")
        if not csp:
            pytest.skip("CSP not present")
        assert "script-src *" not in csp and "script-src '*'" not in csp, (
            "CSP uses wildcard for script-src — any origin can load scripts"
        )


class TestXssViaHeaders:
    def test_xss_via_user_agent(self):
        r = safe_get(TARGET_URL, headers={"User-Agent": XSS_PAYLOAD})
        if r and _reflected(r):
            pytest.fail("XSS via User-Agent: payload reflected unencoded in response")

    def test_xss_via_referer(self):
        r = safe_get(TARGET_URL, headers={"Referer": f"https://attacker.com/{XSS_PAYLOAD}"})
        if r and _reflected(r):
            pytest.fail("XSS via Referer header: payload reflected unencoded in response")

    def test_xss_via_accept_language(self):
        r = safe_get(TARGET_URL, headers={"Accept-Language": XSS_PAYLOAD})
        if r and _reflected(r):
            pytest.fail("XSS via Accept-Language header reflected in response")


class TestXssInJsonResponse:
    def test_json_response_xss_reflection(self):
        for param in SEARCH_PARAMS[:4]:
            r = safe_get(f"{TARGET_URL}?{param}={XSS_PAYLOAD}",
                         headers={"Accept": "application/json"})
            if r and _reflected(r) and "application/json" in r.headers.get("Content-Type", ""):
                pytest.fail(
                    f"XSS in JSON response: <script> unencoded in JSON body for ?{param}"
                )


class TestWafEvasion:
    def test_mixed_case_xss(self):
        for param in SEARCH_PARAMS[:3]:
            r = safe_get(f"{TARGET_URL}?{param}={WAF_EVASION_PAYLOADS[0]}")
            if _reflected(r):
                pytest.fail(f"XSS WAF bypass (mixed case <ScRiPt>) via ?{param}")

    def test_svg_onload_xss(self):
        for param in SEARCH_PARAMS[:3]:
            r = safe_get(f"{TARGET_URL}?{param}={WAF_EVASION_PAYLOADS[3]}")
            if _reflected(r):
                pytest.fail(f"XSS via <svg onbegin> reflected in ?{param}")


class TestMutationXss:
    def test_mutation_xss_probe(self):
        # mXSS: browser DOM mutation can change safe-looking HTML into executable script.
        # We check if the application uses innerHTML to insert user-supplied content.
        payload = "<!--<img src=--><img src=x onerror=" + XSS_MARKER + ">"
        for param in SEARCH_PARAMS[:3]:
            r = safe_get(f"{TARGET_URL}?{param}={payload}")
            if r and XSS_MARKER in r.text:
                pytest.fail(
                    f"Potential mXSS: marker present in response for ?{param} — review DOM insertion logic"
                )


# Browser-based and context-specific skips
class TestBrowserBasedSkipped:
    def test_dom_xss_fragment_browser_only(self):
        pytest.skip(
            "DOM-based XSS via URL fragment (#) cannot be tested via HTTP requests — "
            "the fragment is never sent to the server. Use a headless browser (Playwright/Selenium)."
        )

    def test_stored_xss_requires_auth(self):
        pytest.skip(
            "Stored XSS requires write access (auth) and a read-back endpoint. "
            "Configure AUTH_TOKEN in config.py and add a stored XSS scenario."
        )

    def test_xss_via_file_upload_svg_requires_upload(self):
        pytest.skip("SVG XSS requires a file upload endpoint — test manually.")

    def test_xss_via_postmessage_browser_only(self):
        pytest.skip("PostMessage XSS requires a browser context — use Playwright.")

    def test_xss_in_websockets_browser_only(self):
        pytest.skip("WebSocket XSS requires a browser — use Playwright or wscat.")

    def test_mutation_xss_browser_dom_only(self):
        pytest.skip("Full mXSS verification requires DOM rendering in a real browser.")

    def test_xss_in_pdf_rendering_requires_endpoint(self):
        pytest.skip("PDF XSS requires a known PDF-generation endpoint — test manually.")
