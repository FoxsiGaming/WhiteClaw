"""Category 19: Supply Chain & Third-Party — SRI checks, external script origins."""
import re
import pytest

from tests.active.helpers import safe_get, get_soup
from tests.active.config import TARGET_URL

KNOWN_CDN_DOMAINS = {
    "cdnjs.cloudflare.com", "cdn.jsdelivr.net", "code.jquery.com",
    "cdn.jsdelivr.net", "stackpath.bootstrapcdn.com", "maxcdn.bootstrapcdn.com",
    "unpkg.com", "cdn.polyfill.io", "ajax.googleapis.com",
    "fonts.googleapis.com", "fonts.gstatic.com",
    "static.cloudflareinsights.com", "www.google-analytics.com",
    "www.googletagmanager.com", "connect.facebook.net",
}

SUSPICIOUS_CDN_ORIGINS = {
    "cdn.polyfill.io",  # compromised in 2024
}


def _collect_external_scripts(soup):
    external = []
    for tag in soup.find_all("script", src=True):
        src = tag.get("src", "")
        if src.startswith("http") or src.startswith("//"):
            external.append((src, tag))
    return external


def _collect_external_links(soup):
    external = []
    for tag in soup.find_all("link", rel=True, href=True):
        rel = tag.get("rel", [])
        if isinstance(rel, str):
            rel = [rel]
        href = tag.get("href", "")
        if "stylesheet" in rel and (href.startswith("http") or href.startswith("//")):
            external.append((href, tag))
    return external


class TestSubresourceIntegrity:
    def test_cdn_scripts_have_integrity_attribute(self, base_soup):
        external_scripts = _collect_external_scripts(base_soup)
        if not external_scripts:
            pytest.skip("No external scripts found on page")
        missing_sri = []
        for src, tag in external_scripts:
            if not tag.get("integrity"):
                missing_sri.append(src[:80])
        assert not missing_sri, (
            f"External scripts without SRI integrity attribute: {missing_sri}"
        )

    def test_cdn_stylesheets_have_integrity_attribute(self, base_soup):
        external_css = _collect_external_links(base_soup)
        if not external_css:
            pytest.skip("No external stylesheets found on page")
        missing = []
        for href, tag in external_css:
            if not tag.get("integrity"):
                missing.append(href[:80])
        assert not missing, (
            f"External stylesheets without SRI integrity: {missing}"
        )

    def test_integrity_hashes_use_sha256_or_stronger(self, base_soup):
        for tag in base_soup.find_all(["script", "link"]):
            integrity = tag.get("integrity", "")
            if not integrity:
                continue
            # sha384 and sha512 are acceptable; sha1 and md5 are not
            if integrity.startswith("sha1-") or integrity.startswith("md5-"):
                pytest.fail(
                    f"Weak SRI hash algorithm in integrity attribute: {integrity[:50]}"
                )


class TestThirdPartyScriptOrigins:
    def test_no_compromised_cdn_origins(self, base_soup):
        external_scripts = _collect_external_scripts(base_soup)
        found = []
        for src, _ in external_scripts:
            for suspect in SUSPICIOUS_CDN_ORIGINS:
                if suspect in src:
                    found.append(src[:80])
        assert not found, (
            f"Scripts loaded from known-compromised CDN origins: {found}"
        )

    def test_external_script_origins_are_known(self, base_soup):
        external_scripts = _collect_external_scripts(base_soup)
        unknown = []
        for src, _ in external_scripts:
            # Extract hostname
            m = re.search(r"https?://([^/]+)", src)
            if not m:
                m = re.search(r"//([^/]+)", src)
            if not m:
                continue
            origin = m.group(1).lower()
            if origin not in KNOWN_CDN_DOMAINS:
                unknown.append(src[:80])
        if unknown:
            # Warn but don't fail — unknown origins may be legitimate (custom CDN)
            pytest.skip(
                f"External scripts from unrecognized origins (verify these are legitimate): {unknown}"
            )


class TestDependencyVersionDisclosure:
    def test_no_library_version_in_asset_urls(self, base_soup):
        version_in_url = re.compile(r"@([\d.]+)/|[.-]([\d]+\.[\d]+\.[\d]+)(?:\.min)?\.")
        for tag in base_soup.find_all(["script", "link"]):
            src = tag.get("src", "") or tag.get("href", "")
            if version_in_url.search(src):
                # This is not always a failure — just informational in many cases.
                # Fail only if it's a known vulnerable version pattern + no SRI
                if not tag.get("integrity"):
                    m = version_in_url.search(src)
                    # Only flag if a version is visible AND there's no SRI to prevent tampering
                    pytest.skip(
                        f"Library version visible in asset URL without SRI: {src[:80]} — "
                        "version disclosure + no integrity check"
                    )


class TestCrossOriginResourcePolicy:
    def test_scripts_have_crossorigin_attribute(self, base_soup):
        external = _collect_external_scripts(base_soup)
        missing = []
        for src, tag in external:
            if tag.get("integrity") and not tag.get("crossorigin"):
                missing.append(src[:60])
        assert not missing, (
            f"Scripts with integrity attribute but missing crossorigin='anonymous': {missing}\n"
            "Without crossorigin, CORS errors will prevent SRI validation."
        )
