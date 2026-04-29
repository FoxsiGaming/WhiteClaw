"""Category 1: Reconnaissance — passive fingerprinting and exposure checks."""
import re
import pytest

from tests.active.helpers import safe_get, safe_request, url_join, get_soup, VERSION_PATTERN
from tests.active.config import TARGET_URL

ADMIN_PATHS = ["/admin", "/admin/", "/administrator", "/admin/login",
               "/admin/dashboard", "/wp-admin", "/wp-admin/", "/cpanel",
               "/manager", "/management", "/backend"]

DEBUG_PATHS = ["/debug", "/test", "/info", "/phpinfo.php", "/server-status",
               "/server-info", "/_debug", "/diagnostic", "/status"]

HIDDEN_DIRS = ["/backup", "/old", "/temp", "/tmp", "/test", "/dev",
               "/staging", "/private", "/secret", "/uploads", "/files",
               "/data", "/logs", "/config", "/src", "/deploy", "/release"]


class TestServerFingerprint:
    def test_server_header_no_version(self, base_headers):
        server = base_headers.get("Server", "")
        assert not VERSION_PATTERN.search(server), (
            f"Server header discloses version: {server!r}"
        )

    def test_x_powered_by_absent(self, base_headers):
        val = base_headers.get("X-Powered-By", "")
        assert not val, f"X-Powered-By discloses tech stack: {val!r}"

    def test_x_aspnet_version_absent(self, base_headers):
        val = base_headers.get("X-AspNet-Version", "")
        assert not val, f"X-AspNet-Version header leaks .NET version: {val!r}"

    def test_x_generator_absent(self, base_headers):
        val = base_headers.get("X-Generator", "")
        assert not val, f"X-Generator header leaks CMS info: {val!r}"


class TestRobotsTxt:
    def test_robots_txt_no_sensitive_paths(self):
        r = safe_get(url_join("/robots.txt"))
        if r is None or r.status_code == 404:
            pytest.skip("robots.txt not found")
        sensitive_kws = ["admin", "backup", "config", "db", "secret",
                         "api", "internal", "private", "staging", "dev"]
        found = []
        for line in r.text.splitlines():
            if line.strip().lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip().lower()
                for kw in sensitive_kws:
                    if kw in path:
                        found.append(path)
        assert not found, f"robots.txt Disallow entries expose sensitive paths: {found}"


class TestHttpMethods:
    def test_options_no_dangerous_methods(self):
        r = safe_request("OPTIONS", TARGET_URL)
        if r is None:
            pytest.skip("OPTIONS request failed")
        allow = r.headers.get("Allow", "") + r.headers.get("Access-Control-Allow-Methods", "")
        dangerous = [m for m in ["TRACE", "TRACK"] if m in allow.upper()]
        assert not dangerous, f"Dangerous HTTP methods reported in Allow: {dangerous}"

    def test_trace_method_disabled(self):
        r = safe_request("TRACE", TARGET_URL)
        if r is None:
            pytest.skip("TRACE request failed (could be blocked at TCP level)")
        assert r.status_code in (405, 403, 501), (
            f"TRACE method returned {r.status_code} — may be enabled (XST risk)"
        )


class TestSensitiveFileExposure:
    def test_ds_store_not_accessible(self):
        r = safe_get(url_join("/.DS_Store"), allow_redirects=False)
        if r is None:
            pytest.skip("network error")
        assert r.status_code != 200, "/.DS_Store is publicly accessible"

    def test_git_head_not_accessible(self):
        r = safe_get(url_join("/.git/HEAD"), allow_redirects=False)
        if r is None:
            pytest.skip("network error")
        exposed = r.status_code == 200 and "ref:" in r.text
        assert not exposed, "/.git/HEAD exposed — full git repository may be downloadable"

    def test_git_dir_not_browseable(self):
        r = safe_get(url_join("/.git/"), allow_redirects=False)
        if r is None:
            pytest.skip("network error")
        assert r.status_code not in (200, 403), (
            f"/.git/ directory exists (HTTP {r.status_code}) — repository may be accessible"
        )

    def test_env_file_not_accessible(self):
        r = safe_get(url_join("/.env"), allow_redirects=False)
        if r is None:
            pytest.skip("network error")
        if r.status_code == 200:
            assert "=" not in r.text, "/.env file is publicly accessible and contains key=value pairs"

    def test_htaccess_not_accessible(self):
        r = safe_get(url_join("/.htaccess"), allow_redirects=False)
        if r is None:
            pytest.skip("network error")
        assert r.status_code != 200, "/.htaccess is publicly accessible"


class TestAdminPanelExposure:
    def test_no_admin_panels_open(self):
        found = []
        for path in ADMIN_PATHS:
            r = safe_get(url_join(path), allow_redirects=False)
            if r and r.status_code == 200:
                found.append(path)
        assert not found, f"Admin panels accessible without auth: {found}"

    def test_debug_endpoints_not_exposed(self):
        found = []
        for path in DEBUG_PATHS:
            r = safe_get(url_join(path), allow_redirects=False)
            if r and r.status_code == 200:
                found.append(f"{path}")
        assert not found, f"Debug/test endpoints exposed: {found}"


class TestHiddenDirectories:
    def test_no_sensitive_dirs_open(self):
        found = []
        for d in HIDDEN_DIRS:
            r = safe_get(url_join(d), allow_redirects=False)
            if r and r.status_code == 200:
                found.append(d)
        assert not found, f"Sensitive directories accessible without auth: {found}"


class TestCloudStorage:
    def test_no_cloud_bucket_urls_in_html(self, base_html):
        s3_pat = re.compile(
            r'https?://[a-z0-9._-]+\.s3(?:-[a-z0-9-]+)?\.amazonaws\.com', re.I)
        gcs_pat = re.compile(
            r'https?://storage\.googleapis\.com/[a-z0-9._/-]+', re.I)
        found = list(set(s3_pat.findall(base_html) + gcs_pat.findall(base_html)))
        assert not found, (
            f"Cloud storage bucket URLs found in HTML — verify public access: {found[:5]}"
        )
