"""Category 10: Vulnerable & Outdated Components — library version detection."""
import re
import pytest

from tests.active.helpers import safe_get, url_join, get_soup
from tests.active.config import TARGET_URL

# Known vulnerable version thresholds (minimum SAFE version)
JQUERY_MIN_SAFE = (3, 5, 0)
ANGULAR_MIN_SAFE = (1, 8, 0)   # AngularJS 1.x
BOOTSTRAP_MIN_SAFE = (4, 3, 1)
LODASH_MIN_SAFE = (4, 17, 21)
MOMENT_MIN_SAFE = (2, 29, 2)


def _parse_version(v_str):
    m = re.search(r"(\d+)\.(\d+)\.?(\d*)", v_str)
    if not m:
        return (0, 0, 0)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))


def _version_lt(a, b):
    return a < b


def _scan_page_for_lib(html, pattern):
    m = re.search(pattern, html, re.IGNORECASE)
    return m.group(1) if m else None


class TestJqueryVersion:
    def test_jquery_not_vulnerable(self, base_html, base_soup):
        # Check inline version comment
        jquery_ver = _scan_page_for_lib(
            base_html, r"jQuery\s+JavaScript\s+Library\s+v([\d.]+)"
        )
        # Check script src
        if jquery_ver is None:
            for tag in base_soup.find_all("script", src=True):
                m = re.search(r"jquery[.-]([\d.]+)(?:\.min)?\.js", tag["src"], re.IGNORECASE)
                if m:
                    jquery_ver = m.group(1)
                    break
        if jquery_ver is None:
            pytest.skip("jQuery version not detectable from page source")
        ver = _parse_version(jquery_ver)
        assert not _version_lt(ver, JQUERY_MIN_SAFE), (
            f"jQuery {jquery_ver} is below safe minimum {'.'.join(map(str, JQUERY_MIN_SAFE))} — "
            "known XSS and prototype pollution vulnerabilities"
        )


class TestAngularVersion:
    def test_angular_not_vulnerable(self, base_html, base_soup):
        ng_ver = _scan_page_for_lib(base_html, r"AngularJS\s+v([\d.]+)")
        if ng_ver is None:
            for tag in base_soup.find_all("script", src=True):
                m = re.search(r"angular[.-]([\d.]+)(?:\.min)?\.js", tag["src"], re.IGNORECASE)
                if m:
                    ng_ver = m.group(1)
                    break
        if ng_ver is None:
            pytest.skip("AngularJS version not detectable")
        ver = _parse_version(ng_ver)
        assert not _version_lt(ver, ANGULAR_MIN_SAFE), (
            f"AngularJS {ng_ver} may have known vulnerabilities — update to latest"
        )


class TestBootstrapVersion:
    def test_bootstrap_not_vulnerable(self, base_html, base_soup):
        bs_ver = None
        for tag in base_soup.find_all(["script", "link"]):
            src = tag.get("src", "") or tag.get("href", "")
            m = re.search(r"bootstrap[.-]([\d.]+)(?:\.min)?\.(?:js|css)", src, re.IGNORECASE)
            if m:
                bs_ver = m.group(1)
                break
        if bs_ver is None:
            pytest.skip("Bootstrap version not detectable from page source")
        ver = _parse_version(bs_ver)
        assert not _version_lt(ver, BOOTSTRAP_MIN_SAFE), (
            f"Bootstrap {bs_ver} is below safe minimum {'.'.join(map(str, BOOTSTRAP_MIN_SAFE))} — "
            "known XSS vulnerability in tooltip/popover"
        )


class TestCmsVersionDetection:
    def test_wordpress_version_not_disclosed(self, base_html, base_headers):
        wp_ver = re.search(r"WordPress\s+([\d.]+)", base_html)
        meta_gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s+([\d.]+)', base_html, re.IGNORECASE)
        found = wp_ver or meta_gen
        if found:
            pytest.fail(f"WordPress version disclosed: {found.group(0)[:80]}")

    def test_drupal_version_not_disclosed(self, base_html):
        drupal_ver = re.search(r"Drupal\s+([\d.]+)", base_html)
        if drupal_ver:
            pytest.fail(f"Drupal version disclosed in page source: {drupal_ver.group(0)}")

    def test_joomla_version_not_disclosed(self, base_html):
        joomla_ver = re.search(r'content=["\']Joomla!\s+([\d.]+)', base_html, re.IGNORECASE)
        if joomla_ver:
            pytest.fail(f"Joomla version disclosed: {joomla_ver.group(0)}")


class TestServerVersionInHeaders:
    def test_nginx_version_not_disclosed(self, base_headers):
        server = base_headers.get("Server", "")
        if "nginx" in server.lower():
            ver_match = re.search(r"nginx/([\d.]+)", server, re.IGNORECASE)
            if ver_match:
                pytest.fail(f"Nginx version disclosed in Server header: {server!r}")

    def test_apache_version_not_disclosed(self, base_headers):
        server = base_headers.get("Server", "")
        if "apache" in server.lower():
            ver_match = re.search(r"Apache/([\d.]+)", server, re.IGNORECASE)
            if ver_match:
                pytest.fail(f"Apache version disclosed in Server header: {server!r}")

    def test_iis_version_not_disclosed(self, base_headers):
        server = base_headers.get("Server", "")
        if "iis" in server.lower() or "microsoft-iis" in server.lower():
            ver_match = re.search(r"IIS/([\d.]+)", server, re.IGNORECASE)
            if ver_match:
                pytest.fail(f"IIS version disclosed in Server header: {server!r}")


class TestPrototypePollutionIndicators:
    def test_no_obvious_prototype_pollution_sink_in_js(self, base_soup):
        pollution_patterns = [
            re.compile(r"__proto__\s*\["),
            re.compile(r"constructor\s*\["),
            re.compile(r'jQuery\.extend\s*\(\s*true'),
            re.compile(r'_\.merge\s*\('),
            re.compile(r'Object\.assign\s*\(\s*\{\s*\}'),
        ]
        js_urls = []
        for tag in base_soup.find_all("script", src=True):
            src = tag["src"]
            if src.startswith("/"):
                js_urls.append(url_join(src))
        for js_url in js_urls[:5]:
            r = safe_get(js_url)
            if r is None:
                continue
            for pat in pollution_patterns:
                if pat.search(r.text):
                    pytest.fail(
                        f"Potential prototype pollution sink in {js_url}: "
                        f"pattern {pat.pattern!r} found"
                    )


class TestLodashVersion:
    def test_lodash_not_vulnerable(self, base_html, base_soup):
        lodash_ver = None
        for tag in base_soup.find_all("script", src=True):
            m = re.search(r"lodash[.-]([\d.]+)(?:\.min)?\.js", tag["src"], re.IGNORECASE)
            if m:
                lodash_ver = m.group(1)
                break
        if lodash_ver is None:
            pytest.skip("Lodash version not detectable")
        ver = _parse_version(lodash_ver)
        assert not _version_lt(ver, LODASH_MIN_SAFE), (
            f"Lodash {lodash_ver} is below safe minimum "
            f"{'.'.join(map(str, LODASH_MIN_SAFE))} — prototype pollution CVE"
        )
