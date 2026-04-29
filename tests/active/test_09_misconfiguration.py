"""Category 9: Security Misconfiguration — exposed files, verbose errors, debug mode."""
import re
import pytest

from tests.active.helpers import safe_get, safe_post, url_join
from tests.active.config import TARGET_URL

STACK_TRACE_PATTERNS = re.compile(
    r"Traceback \(most recent call last\)|"
    r"at \w+\.\w+\([\w.]+:\d+\)|"          # Java/Kotlin stack trace
    r"Stack trace:|"
    r"Fatal error:|"                          # PHP
    r"in [\w/\\]+\.php on line \d+|"
    r"Microsoft\.AspNetCore\.|"               # ASP.NET
    r"System\.Web\.|"
    r"NullPointerException|"
    r"ActiveRecord::|"                        # Rails
    r"ActionController::",
    re.IGNORECASE,
)

DEBUG_INDICATORS = re.compile(
    r"DEBUG\s*=\s*True|"
    r"APP_ENV\s*=\s*development|"
    r"NODE_ENV\s*=\s*development|"
    r"Whoops!|"                               # PHP Whoops error handler
    r"Error\s+in\s+application|"
    r"application\.debug|"
    r"werkzeug debugger|"                     # Flask dev server
    r"Django debug toolbar",
    re.IGNORECASE,
)

INTERNAL_IP_PATTERN = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3}|"
    r"127\.0\.0\.\d+)\b"
)

ACTUATOR_PATHS = [
    "/actuator", "/actuator/env", "/actuator/health", "/actuator/info",
    "/actuator/beans", "/actuator/mappings", "/actuator/metrics",
    "/actuator/threaddump", "/actuator/heapdump",
]

SWAGGER_PATHS = [
    "/swagger-ui.html", "/swagger-ui/", "/swagger",
    "/api-docs", "/api/docs", "/v2/api-docs", "/v3/api-docs",
    "/openapi.json", "/api/swagger-ui.html",
]


class TestVerboseErrors:
    def test_404_no_stack_trace(self):
        r = safe_get(url_join("/wc_nonexistent_path_9z7x"))
        if r is None:
            pytest.skip("request failed")
        assert not STACK_TRACE_PATTERNS.search(r.text), (
            "Stack trace or framework error details leaked in 404 response"
        )

    def test_500_no_stack_trace_on_bad_input(self):
        r = safe_get(f"{TARGET_URL}?id='+OR+1=1--")
        if r is None:
            pytest.skip("request failed")
        if r.status_code == 500:
            assert not STACK_TRACE_PATTERNS.search(r.text), (
                "Stack trace leaked in 500 error response"
            )

    def test_error_page_no_server_path_disclosure(self):
        r = safe_get(url_join("/wc_404_test"))
        if r is None:
            pytest.skip("request failed")
        # Look for absolute server paths like /var/www/html, /home/ubuntu/app, C:\inetpub
        path_pat = re.compile(r"(/var/www|/home/\w+|/opt/\w+|C:\\inetpub|C:\\Users)", re.IGNORECASE)
        assert not path_pat.search(r.text), (
            "Absolute server file paths disclosed in error response"
        )


class TestDebugMode:
    def test_no_debug_mode_indicators(self, base_html):
        assert not DEBUG_INDICATORS.search(base_html), (
            "Debug/development mode indicators found in page source"
        )

    def test_werkzeug_debugger_not_accessible(self):
        r = safe_get(url_join("/console"))
        if r and r.status_code == 200 and "werkzeug" in r.text.lower():
            pytest.fail("Werkzeug interactive debugger/console is publicly accessible")

    def test_django_debug_toolbar_not_in_production(self, base_html):
        assert "djdt" not in base_html and "djDebugToolbar" not in base_html, (
            "Django Debug Toolbar appears to be enabled"
        )


class TestExposedSensitiveFiles:
    def test_git_not_accessible(self):
        r = safe_get(url_join("/.git/HEAD"), allow_redirects=False)
        if r is None:
            pytest.skip("network error")
        assert r.status_code != 200 or "ref:" not in r.text, (
            "/.git/HEAD accessible — git repository may be downloadable"
        )

    def test_env_file_not_accessible(self):
        for path in ["/.env", "/.env.local", "/.env.production", "/.env.staging"]:
            r = safe_get(url_join(path), allow_redirects=False)
            if r and r.status_code == 200 and "=" in r.text:
                pytest.fail(f"{path} is publicly accessible and contains key=value data")

    def test_docker_compose_not_accessible(self):
        for path in ["/docker-compose.yml", "/docker-compose.yaml"]:
            r = safe_get(url_join(path), allow_redirects=False)
            if r and r.status_code == 200:
                pytest.fail(f"{path} is publicly accessible")

    def test_config_files_not_accessible(self):
        for path in ["/config.php", "/config.py", "/config.rb", "/settings.py",
                     "/application.properties", "/web.config"]:
            r = safe_get(url_join(path), allow_redirects=False)
            if r and r.status_code == 200:
                pytest.fail(f"Config file {path} is publicly accessible")


class TestActuatorEndpoints:
    def test_no_spring_actuator_exposed(self):
        for path in ACTUATOR_PATHS:
            r = safe_get(url_join(path), allow_redirects=False)
            if r and r.status_code == 200:
                pytest.fail(
                    f"Spring Boot Actuator endpoint {path} exposed — "
                    "may leak environment variables, config, heap dumps, etc."
                )


class TestSwaggerExposure:
    def test_api_docs_not_publicly_exposed(self):
        found = []
        for path in SWAGGER_PATHS:
            r = safe_get(url_join(path), allow_redirects=False)
            if r and r.status_code == 200:
                found.append(path)
        assert not found, (
            f"API documentation (Swagger/OpenAPI) is publicly accessible: {found}"
        )


class TestDirectoryListing:
    def test_no_directory_listing(self):
        dirs = ["/", "/static/", "/assets/", "/uploads/", "/files/", "/images/"]
        for d in dirs:
            r = safe_get(url_join(d))
            if r is None:
                continue
            for ind in ["Index of /", "Directory listing for", "Parent Directory"]:
                if ind in r.text:
                    pytest.fail(f"Directory listing enabled at {d}: found {ind!r}")


class TestInternalIpDisclosure:
    def test_no_internal_ips_in_response(self, base_html):
        found = INTERNAL_IP_PATTERN.findall(base_html)
        assert not found, (
            f"Internal IP addresses found in response: {list(set(found))[:5]}"
        )

    def test_no_internal_ips_in_headers(self, base_headers):
        all_vals = " ".join(base_headers.values())
        found = INTERNAL_IP_PATTERN.findall(all_vals)
        assert not found, (
            f"Internal IP addresses in response headers: {list(set(found))}"
        )
