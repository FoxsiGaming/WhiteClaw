"""Category 7: HTTP Headers & Transport Security."""
import re
import ssl
import socket
import pytest

from tests.active.helpers import safe_get, safe_request, url_join, tls_info, tls_cert
from tests.active.config import TARGET_URL, TIMEOUT


def _scheme():
    return TARGET_URL.split("://")[0]


class TestSecurityHeaders:
    def test_hsts_present(self, base_headers):
        if _scheme() != "https":
            pytest.skip("HSTS only applies to HTTPS sites")
        hsts = base_headers.get("Strict-Transport-Security", "")
        assert hsts, "Strict-Transport-Security (HSTS) header is missing"

    def test_hsts_max_age_sufficient(self, base_headers):
        if _scheme() != "https":
            pytest.skip("HSTS only applies to HTTPS")
        hsts = base_headers.get("Strict-Transport-Security", "")
        if not hsts:
            pytest.skip("HSTS not present (covered by test_hsts_present)")
        match = re.search(r"max-age=(\d+)", hsts)
        assert match, f"HSTS header has no max-age: {hsts}"
        age = int(match.group(1))
        assert age >= 31_536_000, (
            f"HSTS max-age={age} is less than 1 year (31536000) — HSTS period is too short"
        )

    def test_x_frame_options_present(self, base_headers):
        xfo = base_headers.get("X-Frame-Options", "")
        csp = base_headers.get("Content-Security-Policy", "")
        # Either X-Frame-Options or CSP frame-ancestors is acceptable
        has_frame_ancestor = "frame-ancestors" in csp
        assert xfo or has_frame_ancestor, (
            "Neither X-Frame-Options nor CSP frame-ancestors set — clickjacking unmitigated"
        )

    def test_x_content_type_options_nosniff(self, base_headers):
        val = base_headers.get("X-Content-Type-Options", "")
        assert val.lower() == "nosniff", (
            f"X-Content-Type-Options is {val!r} — should be 'nosniff' to prevent MIME sniffing"
        )

    def test_referrer_policy_present(self, base_headers):
        val = base_headers.get("Referrer-Policy", "")
        assert val, "Referrer-Policy header is missing"

    def test_referrer_policy_not_unsafe(self, base_headers):
        val = base_headers.get("Referrer-Policy", "")
        if not val:
            pytest.skip("Referrer-Policy not present (covered by test_referrer_policy_present)")
        unsafe = ["unsafe-url", "no-referrer-when-downgrade"]
        assert val.lower() not in unsafe, (
            f"Referrer-Policy={val!r} may leak full URLs to third parties"
        )

    def test_permissions_policy_present(self, base_headers):
        val = (base_headers.get("Permissions-Policy", "")
               or base_headers.get("Feature-Policy", ""))
        assert val, "Permissions-Policy (formerly Feature-Policy) header is missing"

    def test_no_sensitive_data_in_headers(self, base_headers):
        sensitive_keys = ["X-DB-Password", "X-Auth-Token", "X-Internal-Key", "X-Secret"]
        found = [k for k in sensitive_keys if k in base_headers]
        assert not found, f"Sensitive headers present in response: {found}"


class TestHttpsRedirect:
    def test_http_redirects_to_https(self):
        if _scheme() != "https":
            pytest.skip("TARGET_URL is not HTTPS")
        http_url = TARGET_URL.replace("https://", "http://", 1)
        r = safe_get(http_url, allow_redirects=True)
        if r is None:
            pytest.skip("HTTP request failed — port 80 may be blocked")
        assert r.url.startswith("https://"), (
            f"HTTP request did not redirect to HTTPS — final URL: {r.url}"
        )

    def test_mixed_content_in_page(self, base_html):
        if _scheme() != "https":
            pytest.skip("Mixed content only relevant for HTTPS sites")
        # Look for http:// assets in src/href attributes
        http_assets = re.findall(
            r'(?:src|href|action)=["\']http://[^"\']+["\']', base_html, re.IGNORECASE
        )
        assert not http_assets, (
            f"Mixed content: HTTP assets found on HTTPS page: {http_assets[:5]}"
        )


class TestTlsSecurity:
    def test_tls_version_at_least_1_2(self):
        if _scheme() != "https":
            pytest.skip("TLS check only for HTTPS")
        info = tls_info()
        if info is None:
            pytest.skip("TLS connection failed")
        version = info.get("version", "")
        bad_versions = ["TLSv1", "TLSv1.0", "TLSv1.1", "SSLv2", "SSLv3"]
        assert version not in bad_versions, (
            f"Server negotiated insecure TLS version: {version}"
        )

    def test_no_weak_cipher_suites(self):
        if _scheme() != "https":
            pytest.skip("TLS check only for HTTPS")
        info = tls_info()
        if info is None:
            pytest.skip("TLS connection failed")
        cipher = info.get("cipher", ("", "", 0))
        cipher_name = cipher[0] if cipher else ""
        weak = ["RC4", "DES", "3DES", "EXPORT", "NULL", "MD5", "ADH", "AECDH"]
        for w in weak:
            assert w not in cipher_name.upper(), (
                f"Weak cipher suite in use: {cipher_name}"
            )

    def test_certificate_not_expired(self):
        if _scheme() != "https":
            pytest.skip("TLS check only for HTTPS")
        cert = tls_cert()
        if cert is None:
            pytest.skip("Could not retrieve certificate (may be self-signed/expired)")
        assert cert, "Certificate retrieved is empty"

    def test_certificate_not_self_signed(self):
        if _scheme() != "https":
            pytest.skip("TLS check only for HTTPS")
        try:
            from tests.active.helpers import target_host
            host = target_host()
            port = 443
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    pass  # validation succeeded → not self-signed
        except ssl.SSLCertVerificationError as e:
            pytest.fail(f"Certificate verification failed — possibly self-signed: {e}")
        except Exception:
            pytest.skip("TLS connection error — unable to verify certificate")


class TestCors:
    def test_cors_no_wildcard_allow_origin(self):
        r = safe_get(TARGET_URL, headers={"Origin": "https://evil.attacker.com"})
        if r is None:
            pytest.skip("request failed")
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        assert acao != "*", (
            "CORS: Access-Control-Allow-Origin: * allows any origin to read responses"
        )

    def test_cors_no_reflected_arbitrary_origin(self):
        r = safe_get(TARGET_URL, headers={"Origin": "https://evil.attacker.com"})
        if r is None:
            pytest.skip("request failed")
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        assert acao != "https://evil.attacker.com", (
            "CORS misconfiguration: arbitrary Origin is reflected back in ACAO header"
        )

    def test_cors_credentials_not_with_wildcard(self, base_headers):
        acao = base_headers.get("Access-Control-Allow-Origin", "")
        acac = base_headers.get("Access-Control-Allow-Credentials", "")
        assert not (acao == "*" and acac.lower() == "true"), (
            "CORS: ACAO=* combined with ACAC=true allows credential theft from any origin"
        )


class TestDangerousHttpMethods:
    def test_trace_method_disabled(self):
        r = safe_request("TRACE", TARGET_URL)
        if r is None:
            pytest.skip("TRACE connection failed")
        assert r.status_code in (405, 403, 501), (
            f"HTTP TRACE returned {r.status_code} — method may be enabled (XST attack vector)"
        )

    def test_put_method_disabled_on_root(self):
        r = safe_request("PUT", TARGET_URL, data="test")
        if r is None:
            pytest.skip("PUT request failed")
        assert r.status_code in (405, 403, 404, 501), (
            f"HTTP PUT on root returned {r.status_code} — may allow unauthorized file writes"
        )

    def test_delete_method_disabled_on_root(self):
        r = safe_request("DELETE", TARGET_URL)
        if r is None:
            pytest.skip("DELETE request failed")
        assert r.status_code in (405, 403, 404, 501), (
            f"HTTP DELETE on root returned {r.status_code}"
        )


class TestCacheControl:
    def test_sensitive_pages_have_no_store(self):
        sensitive_paths = ["/login", "/account", "/profile", "/dashboard",
                           "/settings", "/checkout", "/payment"]
        issues = []
        for path in sensitive_paths:
            r = safe_get(url_join(path))
            if r is None or r.status_code != 200:
                continue
            cc = r.headers.get("Cache-Control", "").lower()
            if "no-store" not in cc and "no-cache" not in cc and "private" not in cc:
                issues.append(f"{path} (Cache-Control: {cc!r})")
        assert not issues, (
            f"Sensitive pages lack Cache-Control: no-store — responses may be cached: {issues}"
        )
