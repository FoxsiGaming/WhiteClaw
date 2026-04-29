"""Category 20: Modern Attack Surfaces — smuggling, cache poisoning, host header, etc."""
import re
import socket
import urllib.parse
import pytest

from tests.active.helpers import (
    safe_get, safe_post, safe_request, url_join,
    target_host, parsed_target, SECRET_PATTERNS
)
from tests.active.config import TARGET_URL, TIMEOUT


class TestHttpRequestSmuggling:
    def test_cl_te_smuggling_probe(self):
        """
        CL.TE: send Content-Length and Transfer-Encoding, see if server desync occurs.
        We send a smuggled prefix 'G' to the backend; if the next request gets a 405/weird
        response, smuggling is likely.
        """
        host = target_host()
        port = parsed_target().port or (443 if TARGET_URL.startswith("https") else 80)
        try:
            raw = (
                b"POST / HTTP/1.1\r\n"
                b"Host: " + host.encode() + b"\r\n"
                b"Content-Length: 6\r\n"
                b"Transfer-Encoding: chunked\r\n"
                b"Connection: keep-alive\r\n"
                b"\r\n"
                b"0\r\n"
                b"\r\n"
                b"G"
            )
            import ssl as _ssl
            if TARGET_URL.startswith("https"):
                ctx = _ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = _ssl.CERT_NONE
                with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                        ssock.sendall(raw)
                        resp = ssock.recv(4096)
            else:
                with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
                    sock.sendall(raw)
                    resp = sock.recv(4096)

            resp_str = resp.decode("utf-8", errors="replace")
            # A 400 or 501 response to the CL.TE probe is the normal safe outcome
            # A 200 or 405 may indicate the smuggled prefix was processed
            if "405" in resp_str[:20] or "GPOST" in resp_str:
                pytest.fail(
                    "HTTP request smuggling (CL.TE) probe suggests possible desync: "
                    f"response starts with: {resp_str[:80]!r}"
                )
        except Exception:
            pytest.skip("Raw TCP connection failed — smuggling probe not possible")


class TestCachePoisoning:
    def test_host_header_cache_poisoning(self):
        # Inject a custom Host header and check if the response contains our injected host
        r = safe_get(TARGET_URL, headers={
            "Host": "evil.attacker.com",
            "X-Forwarded-Host": "evil.attacker.com",
        })
        if r is None:
            pytest.skip("request failed")
        assert "evil.attacker.com" not in r.text, (
            "Host header value reflected in response body — cache poisoning vector"
        )

    def test_x_forwarded_host_not_reflected(self):
        r = safe_get(TARGET_URL, headers={"X-Forwarded-Host": "evil.poisoned.com"})
        if r is None:
            pytest.skip("request failed")
        assert "evil.poisoned.com" not in r.text, (
            "X-Forwarded-Host reflected in response — possible cache poisoning"
        )

    def test_cache_control_no_private_user_data_cached(self):
        r = safe_get(TARGET_URL)
        if r is None:
            pytest.skip("request failed")
        cc = r.headers.get("Cache-Control", "").lower()
        vary = r.headers.get("Vary", "").lower()
        # Public-cacheable responses shouldn't vary on Cookie without proper Vary header
        if "public" in cc and "cookie" not in vary:
            pytest.fail(
                "Response is publicly cacheable (Cache-Control: public) but "
                "Vary: Cookie is missing — cached pages may leak user-specific data"
            )


class TestWebCacheDeception:
    def test_cache_deception_static_suffix(self):
        # Appending a static extension may trick CDN into caching authenticated response
        deception_urls = [
            url_join("/account/profile.css"),
            url_join("/dashboard/data.jpg"),
            url_join("/settings/config.js"),
        ]
        for url in deception_urls:
            r = safe_get(url, allow_redirects=False)
            if r is None or r.status_code == 404:
                continue
            if r.status_code == 200:
                cc = r.headers.get("Cache-Control", "").lower()
                # If response is cacheable and contains sensitive data, flag it
                if "no-store" not in cc and "private" not in cc:
                    pytest.fail(
                        f"Web cache deception candidate: {url} returns 200 with "
                        f"Cache-Control: {cc!r} — may cache authenticated content"
                    )


class TestSsiInjection:
    def test_ssi_probe_not_executed(self):
        ssi_payload = "<!--#exec cmd='id'-->"
        for param in ["q", "name", "msg", "search"]:
            r = safe_get(f"{TARGET_URL}?{param}={ssi_payload}")
            if r and re.search(r"uid=\d+", r.text):
                pytest.fail(f"SSI injection via ?{param}: command output in response")


class TestHostHeaderAttacks:
    def test_password_reset_not_poisonable_via_host(self):
        for path in ["/forgot-password", "/reset-password", "/password/reset"]:
            r = safe_post(
                url_join(path),
                data={"email": "wc_audit@example.com"},
                headers={"Host": "evil.attacker.com"},
            )
            if r is None or r.status_code == 404:
                continue
            # If the response or any subsequent email would contain the poisoned host,
            # we flag it. Here we just check for reflection in the response.
            if "evil.attacker.com" in r.text:
                pytest.fail(
                    f"Password reset at {path} reflects injected Host header in response — "
                    "reset link poisoning possible"
                )
            return
        pytest.skip("No password reset endpoint found")

    def test_host_header_routing_attack(self):
        r = safe_get(url_join("/admin"),
                     headers={"Host": "localhost"},
                     allow_redirects=False)
        if r and r.status_code == 200:
            pytest.fail(
                "Host: localhost bypasses access control to /admin — "
                "routing-based SSRF / authentication bypass"
            )


class TestRefererAccessControl:
    def test_no_referer_based_access_control(self):
        for path in ["/admin", "/dashboard", "/settings"]:
            r = safe_get(url_join(path),
                         headers={"Referer": f"{TARGET_URL}/admin"},
                         allow_redirects=False)
            if r and r.status_code == 200:
                base_r = safe_get(url_join(path), allow_redirects=False)
                if base_r and base_r.status_code != 200:
                    pytest.fail(
                        f"Referer-based access control bypass: {path} is accessible "
                        "only when Referer matches an internal URL"
                    )


class TestReverseTabnapping:
    def test_external_links_have_noopener(self, base_soup):
        vulnerable = []
        for tag in base_soup.find_all("a", target="_blank"):
            rel = tag.get("rel") or []
            if isinstance(rel, str):
                rel = rel.split()
            if "noopener" not in [r.lower() for r in rel]:
                href = tag.get("href", "")[:60]
                if href.startswith("http") or href.startswith("//"):
                    vulnerable.append(href)
        assert not vulnerable, (
            f"External links with target='_blank' missing rel='noopener': {vulnerable[:5]}"
        )


class TestPiiInErrors:
    def test_no_pii_in_500_error(self):
        r = safe_get(f"{TARGET_URL}?crash='+OR+1=1")
        if r is None or r.status_code != 500:
            pytest.skip("no 500 response triggered")
        pii_patterns = [
            re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),  # email
            re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),  # SSN
            re.compile(r"\b4[0-9]{12}(?:[0-9]{3})?\b"),  # Visa card number
        ]
        for pat in pii_patterns:
            found = pat.findall(r.text)
            if found:
                pytest.fail(
                    f"PII ({pat.pattern[:30]}) found in error response: {found[:2]}"
                )


class TestOAuthSecurity:
    def test_oauth_state_parameter_present(self, base_soup):
        for tag in base_soup.find_all("a", href=True):
            href = tag["href"]
            if any(p in href for p in ["/oauth", "/auth/google", "/auth/github",
                                        "/login/oauth", "/connect/"]):
                parsed = urllib.parse.urlparse(href)
                qs = urllib.parse.parse_qs(parsed.query)
                if "state" not in qs:
                    pytest.fail(
                        f"OAuth authorization URL missing 'state' parameter (CSRF risk): {href[:100]}"
                    )


class TestUserControlledRedirect:
    def test_redirect_params_limited_to_same_origin(self):
        redirect_params = ["next", "redirect", "url", "return", "returnTo", "goto"]
        external_url = "https://evil.attacker.com/"
        for param in redirect_params:
            r = safe_get(f"{TARGET_URL}?{param}={external_url}",
                         allow_redirects=False)
            if r and r.status_code in (301, 302, 303, 307, 308):
                loc = r.headers.get("Location", "")
                if "evil.attacker.com" in loc:
                    pytest.fail(
                        f"Open redirect: ?{param}={external_url} → Location: {loc}"
                    )


class TestSubdomainTakeoverPassive:
    def test_no_dangling_cname_records(self):
        import socket
        host = target_host()
        parts = host.split(".")
        if len(parts) < 2:
            pytest.skip("can't check subdomains")
        base = ".".join(parts[-2:])
        # Common dangling CNAME targets
        cloud_services = [
            f"staging.{base}", f"dev.{base}", f"beta.{base}",
            f"assets.{base}", f"cdn.{base}",
        ]
        dangling = []
        for sub in cloud_services:
            try:
                # If CNAME resolves but HTTP fails, it may be takeable
                addr = socket.gethostbyname(sub)
                r = safe_get(f"https://{sub}/")
                if r is None:
                    dangling.append(sub)
            except socket.gaierror:
                pass
        if dangling:
            pytest.fail(
                f"Possible dangling DNS (CNAME resolves but HTTP fails) — "
                f"subdomain takeover risk: {dangling}"
            )


class TestInsecureDeserializationMarkers:
    def test_no_java_serialization_magic_bytes_in_response(self, base_response):
        if base_response is None:
            pytest.skip("target unreachable")
        # Java serialized objects start with 0xACED0005
        content = base_response.content
        if content[:2] == b'\xac\xed':
            pytest.fail(
                "Response starts with Java serialization magic bytes (0xACED) — "
                "server may be deserializing untrusted data"
            )

    def test_no_php_serialized_in_cookies(self, base_response):
        if base_response is None:
            pytest.skip("target unreachable")
        for cookie in base_response.cookies:
            val = cookie.value
            if re.match(r'^(?:a|O|s|i|b|d):\d+:', val):
                pytest.fail(
                    f"Cookie '{cookie.name}' appears to contain raw PHP serialized data — "
                    "insecure deserialization risk"
                )


# Tests requiring very specific conditions
class TestModernAttacksSkipped:
    def test_jwt_kid_header_injection_needs_jwt(self):
        pytest.skip("JWT kid injection requires a valid JWT — set AUTH_TOKEN in config.py.")

    def test_saml_signature_wrapping_needs_saml(self):
        pytest.skip("SAML signature wrapping is SAML-specific — test manually if target uses SAML SSO.")

    def test_dns_rebinding_requires_browser(self):
        pytest.skip("DNS rebinding requires a browser context.")

    def test_timing_attack_on_auth_requires_precision(self):
        pytest.skip(
            "Timing attacks on auth comparisons require microsecond-precision measurement "
            "over many samples — use timeit with a dedicated timing harness, not HTTP tests."
        )

    def test_account_merge_vulnerabilities_needs_auth(self):
        pytest.skip("Account merge/linking vulnerabilities require multiple auth sessions.")

    def test_2fa_recovery_code_brute_force_is_destructive(self):
        pytest.skip("Brute-forcing 2FA recovery codes is DESTRUCTIVE — run tests/destructive/.")
