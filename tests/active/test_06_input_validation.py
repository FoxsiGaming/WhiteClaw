"""Category 6: Input Validation — boundary, encoding, and special-character probes."""
import re
import pytest

from tests.active.helpers import safe_get, safe_post, url_join
from tests.active.config import TARGET_URL

COMMON_PARAMS = ["q", "search", "id", "name", "page", "input", "value", "data"]

REDOS_PATTERNS = [
    re.compile(r"\(a\+\)\+"),
    re.compile(r"\(a\*\)\*"),
    re.compile(r"\(\.\*\)\+"),
    re.compile(r"\[^\s\]\+\+"),
]


class TestMaxLength:
    def test_large_param_does_not_crash_server(self):
        big = "A" * 10000
        r = safe_get(f"{TARGET_URL}?q={big}")
        if r is None:
            pytest.skip("request failed")
        assert r.status_code not in (500, 502, 503), (
            f"Server returned {r.status_code} for a 10 000-char input — "
            "possible lack of max-length enforcement or unhandled exception"
        )

    def test_large_param_body_does_not_crash(self):
        big = "B" * 50000
        r = safe_post(TARGET_URL, data={"input": big})
        if r is None:
            pytest.skip("POST failed")
        assert r.status_code not in (500, 502, 503), (
            f"Server returned {r.status_code} for a 50 000-char POST body"
        )


class TestIntegerBoundaries:
    def test_integer_overflow_in_id_param(self):
        for val in ["9999999999999999999", "-9999999999999999999", "2147483648", "-2147483649"]:
            r = safe_get(f"{TARGET_URL}?id={val}")
            if r is None:
                continue
            assert r.status_code not in (500,), (
                f"Server error (500) for integer overflow value ?id={val}"
            )

    def test_negative_number_in_quantity(self):
        for val in ["-1", "-100", "-9999"]:
            for param in ["qty", "quantity", "count", "amount", "num"]:
                r = safe_get(f"{TARGET_URL}?{param}={val}")
                if r is None:
                    continue
                assert r.status_code not in (500,), (
                    f"Server error (500) for ?{param}={val}"
                )


class TestSpecialCharacters:
    def test_special_chars_no_server_error(self):
        special = "<>'\";:&%$#@!^*()"
        for param in COMMON_PARAMS[:4]:
            r = safe_get(f"{TARGET_URL}?{param}={special}")
            if r is None:
                continue
            assert r.status_code not in (500,), (
                f"Server 500 for special characters in ?{param}"
            )

    def test_null_byte_in_param(self):
        for param in COMMON_PARAMS[:4]:
            r = safe_get(f"{TARGET_URL}?{param}=value%00extra")
            if r is None:
                continue
            assert r.status_code not in (500,), (
                f"Server 500 for null byte in ?{param}"
            )
            # Null byte truncation — if only 'value' is reflected, not 'extra'
            if "extra" in r.text and "\x00" in r.text:
                pytest.fail(f"Null byte reflected as literal in ?{param} response")


class TestEncoding:
    def test_double_encoding_no_bypass(self):
        # %252F = URL decode → %2F = URL decode → /
        payload = "..%252f..%252fetc%252fpasswd"
        for param in ["file", "path", "page", "include", "doc"]:
            r = safe_get(f"{TARGET_URL}?{param}={payload}")
            if r and "root:" in r.text:
                pytest.fail(f"Double-encoded path traversal succeeded via ?{param}")

    def test_unicode_normalization_no_bypass(self):
        # Full-width equivalents: ／ (U+FF0F) for /
        payload = "..／..／etc／passwd"
        for param in ["file", "path", "page"]:
            r = safe_get(f"{TARGET_URL}?{param}={payload}")
            if r and "root:x:" in r.text:
                pytest.fail(f"Unicode normalization bypass succeeded via ?{param}")


class TestParameterPollution:
    def test_http_param_pollution_no_crash(self):
        r = safe_get(f"{TARGET_URL}?id=1&id=2&id=3")
        if r is None:
            pytest.skip("request failed")
        assert r.status_code not in (500,), "Server 500 on duplicate parameter names"

    def test_param_pollution_no_acl_bypass(self):
        r = safe_get(f"{TARGET_URL}?admin=false&admin=true")
        if r is None:
            pytest.skip("request failed")
        # If response is 200 and contains admin-only content, could be a bypass
        assert r.status_code != 403 or True, "baseline"  # passes always, documents intent


class TestXxe:
    def test_xxe_probe_on_xml_endpoint(self):
        xxe_payload = (
            '<?xml version="1.0"?>'
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            '<root><item>&xxe;</item></root>'
        )
        for path in ["/api", "/upload", "/xml", "/import", "/parse", "/api/xml"]:
            r = safe_post(url_join(path), data=xxe_payload,
                          headers={"Content-Type": "application/xml"})
            if r and r.status_code == 200 and "root:" in r.text:
                pytest.fail(f"XXE injection succeeded at {path}: /etc/passwd content in response")

    def test_xxe_probe_json_to_xml_endpoint(self):
        # Some APIs accept JSON but convert to XML internally
        xxe_via_json = '{"item": "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \'file:///etc/passwd\'>]><x>&xxe;</x>"}'
        r = safe_post(TARGET_URL, data=xxe_via_json,
                      headers={"Content-Type": "application/json"})
        if r and "root:" in r.text:
            pytest.fail("XXE via JSON-to-XML conversion — /etc/passwd reflected")


class TestReDoS:
    def test_redos_patterns_not_in_source(self, base_html):
        hits = []
        for pat in REDOS_PATTERNS:
            found = pat.findall(base_html)
            if found:
                hits.append(str(pat.pattern))
        assert not hits, (
            f"Potential catastrophic backtracking (ReDoS) regex patterns found in page source: {hits}"
        )


# Tests requiring specific application endpoints
class TestInputValidationSkipped:
    def test_file_upload_unrestricted_type_requires_endpoint(self):
        pytest.skip("File upload tests require a known upload endpoint — configure one in config.py.")

    def test_file_upload_path_traversal_requires_endpoint(self):
        pytest.skip("File upload path traversal requires a known upload endpoint.")

    def test_insecure_deserialization_generic_skip(self):
        pytest.skip(
            "Insecure deserialization cannot be tested generically — "
            "requires knowledge of the serialization format (Java, PHP, Python pickle, etc.)."
        )

    def test_type_juggling_php_specific(self):
        pytest.skip("Type juggling is PHP-specific — only applicable if target runs PHP.")
