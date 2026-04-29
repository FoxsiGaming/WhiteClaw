"""Category 30: SSTI — Comprehensive Server-Side Template Injection across engines."""
import re
import pytest

from tests.active.helpers import safe_get, safe_post, url_join
from tests.active.config import TARGET_URL

SSTI_TEST_ENDPOINTS = [
    "/search", "/report", "/email", "/template", "/api/render",
    "/personalize", "/greet", "/message", "/generate",
]

SSTI_MARKERS = {
    "jinja2": "49",      # {{7*7}}
    "erb": "49",         # <%= 7*7 %>
    "freemarker": "49",  # ${7*7}
    "velocity": "49",    # #set($x=7*7)$x
}

SSTI_PAYLOADS = {
    "jinja2": [
        "{{7*7}}",
        "{{config.items()}}",
        "{{self}}",
        "{{request.application}}",
    ],
    "erb": [
        "<%= 7*7 %>",
        "<%= system('id') %>",
        "<%= ENV['HOME'] %>",
    ],
    "freemarker": [
        "<#assign value='freemarker.template.utility.ObjectConstructor'?new()>"
        "${value('java.lang.ProcessBuilder','id').start()}",
    ],
    "velocity": [
        "#set($x='')#set($rt=$x.getClass().forName('java.lang.Runtime'))"
        "#set($ex=$rt.getRuntime().exec('id'))$ex",
    ],
}


class TestSstiJinja2:
    def test_ssti_jinja2_basic_math(self):
        """Test Jinja2 SSTI with basic math expression."""
        for param in ["q", "search", "template", "input", "msg"]:
            for endpoint in SSTI_TEST_ENDPOINTS:
                r = safe_get(f"{url_join(endpoint)}?{param}={{{{7*7}}}}")
                if r and "49" in r.text and "{{" not in r.text:
                    pytest.fail(f"Jinja2 SSTI at {endpoint}?{param}: math expression evaluated")

    def test_ssti_jinja2_config_access(self):
        """Test Jinja2 SSTI via config object access."""
        for endpoint in SSTI_TEST_ENDPOINTS:
            r = safe_post(url_join(endpoint),
                          data={"input": "{{config.items()}}"},
                          allow_redirects=False)
            if r and ("DEBUG" in r.text or "SECRET" in r.text):
                pytest.fail(f"Jinja2 SSTI config access at {endpoint}")


class TestSstiErb:
    def test_ssti_erb_basic(self):
        """Test ERB SSTI."""
        for endpoint in SSTI_TEST_ENDPOINTS:
            r = safe_post(url_join(endpoint),
                          data={"content": "<%= 7*7 %>"},
                          allow_redirects=False)
            if r and "49" in r.text and "<%=" not in r.text:
                pytest.fail(f"ERB SSTI at {endpoint}: math evaluated")

    def test_ssti_erb_env_access(self):
        """Test ERB SSTI for environment variable access."""
        for endpoint in SSTI_TEST_ENDPOINTS:
            r = safe_post(url_join(endpoint),
                          data={"template": "<%= ENV['PATH'] %>"},
                          allow_redirects=False)
            if r and ("/bin" in r.text or "/usr" in r.text):
                pytest.fail(f"ERB SSTI environment access at {endpoint}")


class TestSstiFreeMarker:
    def test_ssti_freemarker_basic(self):
        """Test FreeMarker SSTI."""
        for endpoint in SSTI_TEST_ENDPOINTS:
            r = safe_post(url_join(endpoint),
                          data={"template": "${7*7}"},
                          allow_redirects=False)
            if r and "49" in r.text and "${" not in r.text:
                pytest.fail(f"FreeMarker SSTI at {endpoint}")


class TestSstiVelocity:
    def test_ssti_velocity_basic(self):
        """Test Velocity SSTI."""
        payload = "#set($x=7*7)$x"
        for endpoint in SSTI_TEST_ENDPOINTS:
            r = safe_post(url_join(endpoint),
                          data={"input": payload},
                          allow_redirects=False)
            if r and "49" in r.text and "#set" not in r.text:
                pytest.fail(f"Velocity SSTI at {endpoint}")


class TestSstiThymeleaf:
    def test_ssti_thymeleaf_basic(self):
        """Test Thymeleaf SSTI."""
        for endpoint in SSTI_TEST_ENDPOINTS:
            r = safe_post(url_join(endpoint),
                          data={"template": "[[${7*7}]]"},
                          allow_redirects=False)
            if r and "49" in r.text:
                pytest.fail(f"Thymeleaf SSTI at {endpoint}")


class TestSstiBlindTimeBased:
    def test_ssti_time_based_blind(self):
        """Test blind SSTI via time-based detection."""
        pytest.skip(
            "Time-based SSTI detection requires measuring response delays. "
            "Implement in destructive tests with timing measurements."
        )


class TestSstiRce:
    def test_ssti_command_execution_destructive(self):
        pytest.skip(
            "SSTI Remote Code Execution is DESTRUCTIVE. "
            "Only test with full authorization on isolated environments. "
            "Use tools like tplmap in destructive suite."
        )
