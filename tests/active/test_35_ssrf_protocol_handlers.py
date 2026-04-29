"""Category 35: SSRF via Protocol Handlers — file://, dict://, gopher://, etc."""
import re
import pytest

from tests.active.helpers import safe_get, safe_post, url_join
from tests.active.config import TARGET_URL

SSRF_PARAMS = ["url", "link", "src", "image", "fetch", "proxy", "endpoint"]

UNIX_PASSWD_INDICATOR = re.compile(r"root:[x*]:\d+:\d+")
WINDOWS_SYSTEM_INDICATOR = re.compile(r"\[boot loader\]|\[operating systems\]|WINNT")


class TestSsrfFileProtocol:
    def test_ssrf_file_protocol_unix(self):
        """Test SSRF via file:// protocol on Unix systems."""
        for param in SSRF_PARAMS:
            r = safe_get(f"{TARGET_URL}?{param}=file:///etc/passwd")
            if r and UNIX_PASSWD_INDICATOR.search(r.text):
                pytest.fail(f"SSRF file:// protocol at ?{param}: /etc/passwd disclosed")

    def test_ssrf_file_protocol_windows(self):
        """Test SSRF via file:// protocol on Windows."""
        for param in SSRF_PARAMS:
            r = safe_get(f"{TARGET_URL}?{param}=file:///c:/windows/win.ini")
            if r and WINDOWS_SYSTEM_INDICATOR.search(r.text):
                pytest.fail(f"SSRF file:// protocol at ?{param}: Windows system file disclosed")


class TestSsrfDataUri:
    def test_ssrf_data_uri_base64(self):
        """Test SSRF via data: URI with base64 encoding."""
        import base64
        payload = base64.b64encode(b"test_data").decode()
        
        for param in SSRF_PARAMS:
            r = safe_get(f"{TARGET_URL}?{param}=data:text/plain;base64,{payload}")
            if r and "test_data" in r.text:
                pytest.fail(f"SSRF data: URI at ?{param}: base64 decoded and processed")


class TestSsrfDictProtocol:
    def test_ssrf_dict_protocol_redis(self):
        """Test SSRF via dict:// protocol for Redis probing."""
        # dict://localhost:6379/INFO
        for param in SSRF_PARAMS:
            r = safe_get(f"{TARGET_URL}?{param}=dict://127.0.0.1:6379/INFO")
            if r and ("redis_version" in r.text or "REDIS" in r.text):
                pytest.fail(f"SSRF dict:// protocol at ?{param}: Redis accessed")


class TestSsrfGopherProtocol:
    def test_ssrf_gopher_protocol(self):
        """Test SSRF via gopher:// protocol."""
        # gopher://127.0.0.1:25 for SMTP probing
        pytest.skip(
            "Gopher protocol SSRF requires legacy/specialized infrastructure. "
            "Test in destructive suite if target environment supports gopher://"
        )


class TestSsrfLdapProtocol:
    def test_ssrf_ldap_protocol(self):
        """Test SSRF via ldap:// protocol."""
        for param in SSRF_PARAMS:
            r = safe_get(f"{TARGET_URL}?{param}=ldap://127.0.0.1:389/")
            if r and r.status_code == 200 and len(r.text) > 100:
                pytest.skip(
                    f"LDAP protocol response at ?{param}: "
                    "verify if this is actual LDAP response or error"
                )


class TestSsrfUncPath:
    def test_ssrf_unc_path_windows(self):
        """Test SSRF via UNC path on Windows."""
        # \\127.0.0.1\c$\windows\win.ini
        for param in SSRF_PARAMS:
            r = safe_get(f"{TARGET_URL}?{param}=\\\\127.0.0.1\\c$\\windows\\win.ini")
            if r and WINDOWS_SYSTEM_INDICATOR.search(r.text):
                pytest.fail(f"SSRF UNC path at ?{param}: Windows file disclosed")


class TestSsrfProtocolConfusion:
    def test_ssrf_mixed_protocol_bypass(self):
        """Test SSRF via mixed protocol confusion."""
        # file://\localhost\etc\passwd
        for param in SSRF_PARAMS:
            r = safe_get(f"{TARGET_URL}?{param}=file://\\\\127.0.0.1\\etc\\passwd")
            if r and UNIX_PASSWD_INDICATOR.search(r.text):
                pytest.fail(f"SSRF mixed protocol at ?{param}")


class TestSsrfFragmentBypass:
    def test_ssrf_fragment_bypass(self):
        """Test SSRF via URL fragment bypass."""
        # http://127.0.0.1#@legitimate.com
        for param in SSRF_PARAMS:
            r = safe_get(f"{TARGET_URL}?{param}=http://127.0.0.1%23@legitimate.com")
            if r and r.status_code == 200 and len(r.text) > 200:
                pytest.skip(
                    f"Fragment bypass candidate at ?{param}: "
                    "verify if internal IP response received"
                )


class TestSsrfPostRequest:
    def test_ssrf_via_post_body(self):
        """Test SSRF in POST request body."""
        for param in SSRF_PARAMS:
            r = safe_post(url_join("/api"),
                          json={param: "file:///etc/passwd"},
                          allow_redirects=False)
            if r and UNIX_PASSWD_INDICATOR.search(r.text):
                pytest.fail(f"SSRF via POST body {param}: file disclosure")


class TestSsrfOobDetection:
    def test_ssrf_blind_detection_requires_oob(self):
        pytest.skip(
            "Blind SSRF detection requires out-of-band callback infrastructure "
            "(Burp Collaborator, interactsh, canarytokens). "
            "See destructive tests for OOB SSRF exploitation."
        )
