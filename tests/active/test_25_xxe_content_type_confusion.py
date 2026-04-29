"""Category 25: XXE via Content-Type Header Confusion."""
import re
import pytest

from tests.active.helpers import safe_get, safe_post, url_join
from tests.active.config import TARGET_URL

XXE_PAYLOAD_BASE = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><data>&xxe;</data></root>'

XXE_ENDPOINTS = [
    "/api/import", "/api/xml", "/parse", "/upload", "/api/v1/import",
    "/webhook", "/callback", "/process", "/api/data", "/xml/parse",
]

UNIX_PASSWD_INDICATOR = re.compile(r"root:[x*]:\d+:\d+")
WINDOWS_INDICATOR = re.compile(r"\[boot loader\]|\[operating systems\]")


class TestXxeJsonContentType:
    def test_xxe_in_json_body(self):
        """Test XXE in JSON body with JSON Content-Type."""
        for endpoint in XXE_ENDPOINTS:
            xxe_json = '{"data": "' + XXE_PAYLOAD_BASE.replace('"', '\\"') + '"}'
            r = safe_post(url_join(endpoint),
                          data=xxe_json,
                          headers={"Content-Type": "application/json"})
            if r and (UNIX_PASSWD_INDICATOR.search(r.text) or WINDOWS_INDICATOR.search(r.text)):
                pytest.fail(f"XXE in JSON body at {endpoint}: file disclosure")

    def test_xxe_embedded_in_json_value(self):
        """Test XXE embedded in JSON value that gets parsed."""
        for endpoint in XXE_ENDPOINTS:
            payload = {"content": XXE_PAYLOAD_BASE}
            r = safe_post(url_join(endpoint),
                          json=payload)
            if r and UNIX_PASSWD_INDICATOR.search(r.text):
                pytest.fail(f"XXE via JSON value at {endpoint}")


class TestXxeFormData:
    def test_xxe_in_form_field(self):
        """Test XXE in form-data field."""
        for endpoint in XXE_ENDPOINTS:
            r = safe_post(url_join(endpoint),
                          data={"file": XXE_PAYLOAD_BASE},
                          headers={"Content-Type": "application/x-www-form-urlencoded"})
            if r and UNIX_PASSWD_INDICATOR.search(r.text):
                pytest.fail(f"XXE via form-data at {endpoint}")

    def test_xxe_multipart_boundary_confusion(self):
        """Test XXE in multipart form boundary areas."""
        for endpoint in XXE_ENDPOINTS:
            # Malformed multipart that may be parsed as XML
            multipart = (
                f"--boundary\r\n"
                f"Content-Disposition: form-data; name=\"data\"\r\n\r\n"
                f"{XXE_PAYLOAD_BASE}\r\n"
                f"--boundary--"
            )
            r = safe_post(url_join(endpoint),
                          data=multipart,
                          headers={"Content-Type": "multipart/form-data; boundary=boundary"})
            if r and UNIX_PASSWD_INDICATOR.search(r.text):
                pytest.fail(f"XXE in multipart at {endpoint}")


class TestXxeContentTypeBypass:
    def test_xxe_with_wrong_content_type(self):
        """Test XXE with incorrect Content-Type (XML in JSON content-type)."""
        for endpoint in XXE_ENDPOINTS:
            r = safe_post(url_join(endpoint),
                          data=XXE_PAYLOAD_BASE,
                          headers={"Content-Type": "application/json"})
            if r and UNIX_PASSWD_INDICATOR.search(r.text):
                pytest.fail(
                    f"XXE processed despite JSON Content-Type at {endpoint}: "
                    "server parsed XML anyway"
                )

    def test_xxe_charset_bypass(self):
        """Test XXE with charset encoding bypass."""
        for endpoint in XXE_ENDPOINTS:
            r = safe_post(url_join(endpoint),
                          data=XXE_PAYLOAD_BASE,
                          headers={"Content-Type": "application/xml; charset=utf-16"})
            if r and UNIX_PASSWD_INDICATOR.search(r.text):
                pytest.fail(f"XXE with charset bypass at {endpoint}")


class TestXxeBase64Encoding:
    def test_xxe_base64_encoded_payload(self):
        """Test XXE in base64-encoded form."""
        import base64
        for endpoint in XXE_ENDPOINTS:
            xxe_b64 = base64.b64encode(XXE_PAYLOAD_BASE.encode()).decode()
            r = safe_post(url_join(endpoint),
                          json={"data": xxe_b64},
                          headers={"Content-Type": "application/json"})
            if r and UNIX_PASSWD_INDICATOR.search(r.text):
                pytest.fail(f"Base64-encoded XXE processed at {endpoint}")


class TestXxeNoExtraction:
    def test_xxe_via_blind_callback_not_passive(self):
        pytest.skip(
            "Blind XXE detection (out-of-band) requires callback infrastructure. "
            "Use Burp Collaborator or interactsh in destructive tests."
        )

    def test_xxe_billion_laughs_denial_is_destructive(self):
        pytest.skip(
            "XXE Billion Laughs attack is DESTRUCTIVE (DoS). "
            "Only test on isolated test environments with ENABLE_DESTRUCTIVE_TESTS."
        )
