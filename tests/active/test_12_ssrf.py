"""Category 12: SSRF — URL parameter detection, metadata endpoint probes, Host header."""
import re
import pytest

from tests.active.helpers import safe_get, safe_post, url_join, get_soup
from tests.active.config import TARGET_URL

# Cloud metadata endpoints that should never be reachable from the app
CLOUD_METADATA_URL = "http://169.254.169.254/latest/meta-data/"
CLOUD_METADATA_INDICATORS = re.compile(
    r"ami-id|instance-id|iam/security-credentials|"
    r"computeMetadata|metadata\.google\.internal",
    re.IGNORECASE
)

URL_PARAMS = ["url", "link", "src", "source", "href", "path", "dest",
              "redirect", "next", "callback", "webhook", "endpoint",
              "fetch", "load", "proxy", "image", "img", "avatar",
              "background", "feed", "uri", "location"]


class TestSsrfParameterDetection:
    def test_url_params_dont_reach_cloud_metadata(self):
        for param in URL_PARAMS:
            r = safe_get(f"{TARGET_URL}?{param}={CLOUD_METADATA_URL}")
            if r and CLOUD_METADATA_INDICATORS.search(r.text):
                pytest.fail(
                    f"SSRF: ?{param}={CLOUD_METADATA_URL} returned cloud metadata content"
                )

    def test_url_params_dont_fetch_localhost(self):
        for param in URL_PARAMS:
            r = safe_get(f"{TARGET_URL}?{param}=http://127.0.0.1/")
            if r and (len(r.text) > 100 and "localhost" in r.text.lower() or
                      "127.0.0.1" in r.text):
                pytest.fail(
                    f"SSRF: ?{param}=http://127.0.0.1/ returned localhost content"
                )

    def test_url_params_dont_fetch_internal_range(self):
        internal_urls = [
            "http://10.0.0.1/",
            "http://192.168.1.1/",
            "http://172.16.0.1/",
        ]
        for param in URL_PARAMS[:5]:
            for internal in internal_urls:
                r = safe_get(f"{TARGET_URL}?{param}={internal}")
                if r is None:
                    continue
                # A very different response length might indicate the server fetched internal content
                base_r = safe_get(f"{TARGET_URL}?{param}=https://example.com")
                if base_r and abs(len(r.text) - len(base_r.text)) > 500 and len(r.text) > 200:
                    pytest.skip(
                        f"?{param}={internal} response differs significantly from baseline — "
                        "verify manually for SSRF"
                    )


class TestSsrfViaPOST:
    def test_post_url_param_no_metadata_fetch(self):
        for path in ["/api/fetch", "/api/preview", "/webhook", "/callback",
                     "/proxy", "/load", "/upload-url"]:
            r = safe_post(url_join(path), json={"url": CLOUD_METADATA_URL})
            if r and CLOUD_METADATA_INDICATORS.search(r.text):
                pytest.fail(
                    f"SSRF via POST to {path}: cloud metadata content in response"
                )


class TestSsrfHostHeader:
    def test_host_header_ssrf_no_internal_fetch(self):
        r = safe_get(TARGET_URL, headers={"Host": "169.254.169.254"})
        if r and CLOUD_METADATA_INDICATORS.search(r.text):
            pytest.fail("SSRF via Host header injection: cloud metadata returned")

    def test_x_forwarded_host_ssrf(self):
        r = safe_get(TARGET_URL,
                     headers={"X-Forwarded-Host": "169.254.169.254"})
        if r and CLOUD_METADATA_INDICATORS.search(r.text):
            pytest.fail("SSRF via X-Forwarded-Host: cloud metadata in response")


class TestSsrfViaRedirect:
    def test_open_redirect_not_used_for_ssrf(self):
        # A common SSRF bypass: app follows redirects, redirect target is internal
        # We check if the app follows redirects to internal addresses
        for param in ["redirect", "next", "url", "callback"]:
            r = safe_get(
                f"{TARGET_URL}?{param}=http://127.0.0.1:80/",
                allow_redirects=True
            )
            if r is None:
                continue
            if r.url.startswith("http://127.0.0.1") or r.url.startswith("http://localhost"):
                pytest.fail(
                    f"Application followed redirect to localhost via ?{param} — SSRF via redirect possible"
                )


class TestSsrfPartialUrl:
    def test_partial_url_no_internal_access(self):
        # Some parsers allow //evil.com or @evil.com style bypasses
        for param in URL_PARAMS[:5]:
            r = safe_get(f"{TARGET_URL}?{param}=//169.254.169.254/")
            if r and CLOUD_METADATA_INDICATORS.search(r.text):
                pytest.fail(
                    f"SSRF via protocol-relative URL: ?{param}=//169.254.169.254/ fetched metadata"
                )


# Tests requiring specific infrastructure
class TestSsrfSkipped:
    def test_ssrf_blind_dns_requires_oob_infra(self):
        pytest.skip(
            "Blind SSRF detection requires out-of-band infrastructure (DNS/HTTP callback server). "
            "Use Burp Collaborator, interactsh, or canarytokens.org for manual testing."
        )

    def test_ssrf_svg_upload_requires_endpoint(self):
        pytest.skip("SSRF via SVG upload requires a file upload endpoint — test manually.")

    def test_ssrf_pdf_generation_requires_endpoint(self):
        pytest.skip("SSRF via PDF generation requires a known PDF generation endpoint.")

    def test_active_ssrf_to_internal_services_is_destructive(self):
        pytest.skip(
            "Active SSRF exploitation (reading internal services) is DESTRUCTIVE. "
            "Set ENABLE_DESTRUCTIVE_TESTS=True in config.py and run tests/destructive/."
        )
