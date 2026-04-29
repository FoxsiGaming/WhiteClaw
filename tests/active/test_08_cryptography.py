"""Category 8: Cryptography — secrets in source, cleartext data, TLS coverage."""
import re
import pytest

from tests.active.helpers import safe_get, url_join, SECRET_PATTERNS
from tests.active.config import TARGET_URL

JS_PATHS_TO_SCAN = ["/static/js/main.js", "/js/app.js", "/assets/js/bundle.js",
                    "/app.js", "/bundle.js", "/main.js", "/dist/bundle.js"]


def _collect_js_urls(base_soup):
    """Extract JS file URLs from page source."""
    urls = []
    for tag in base_soup.find_all("script", src=True):
        src = tag["src"]
        if src.startswith("http"):
            urls.append(src)
        elif src.startswith("/"):
            urls.append(url_join(src))
        elif src:
            urls.append(url_join("/" + src))
    return urls[:10]  # limit to first 10 JS files


def _scan_for_secrets(text):
    """Return list of (pattern_name, match) tuples found in text."""
    hits = []
    for pat_str, name in SECRET_PATTERNS:
        matches = re.findall(pat_str, text)
        for m in matches:
            val = m if isinstance(m, str) else m[-1]
            if len(val) >= 8:  # ignore short false positives
                hits.append((name, val[:40]))
    return hits


class TestSecretsInSource:
    def test_no_secrets_in_html_source(self, base_html):
        hits = _scan_for_secrets(base_html)
        assert not hits, (
            f"Potential secrets found in HTML source: {hits[:5]}"
        )

    def test_no_secrets_in_html_comments(self, base_soup):
        from bs4 import Comment
        comments = base_soup.find_all(string=lambda t: isinstance(t, Comment))
        for comment in comments:
            hits = _scan_for_secrets(str(comment))
            if hits:
                pytest.fail(f"Secrets in HTML comment: {hits[:3]}")

    def test_no_secrets_in_linked_js_files(self, base_soup):
        js_urls = _collect_js_urls(base_soup)
        for path in JS_PATHS_TO_SCAN:
            js_urls.append(url_join(path))
        for js_url in js_urls:
            r = safe_get(js_url)
            if r is None or r.status_code != 200:
                continue
            hits = _scan_for_secrets(r.text)
            if hits:
                pytest.fail(f"Secrets found in {js_url}: {hits[:3]}")

    def test_no_aws_access_keys_in_source(self, base_html):
        aws_pattern = re.compile(r"AKIA[0-9A-Z]{16}")
        found = aws_pattern.findall(base_html)
        assert not found, f"AWS Access Key ID found in HTML source: {found}"

    def test_no_github_tokens_in_source(self, base_html):
        gh_pattern = re.compile(r"ghp_[A-Za-z0-9]{36}")
        found = gh_pattern.findall(base_html)
        assert not found, f"GitHub personal access token found in HTML source: {found}"

    def test_no_openai_keys_in_source(self, base_html):
        oai_pattern = re.compile(r"sk-[A-Za-z0-9]{48}")
        found = oai_pattern.findall(base_html)
        assert not found, f"OpenAI API key found in HTML source: {found}"


class TestSensitiveDataInTransit:
    def test_no_tokens_in_url_query_string(self, base_response):
        if base_response is None:
            pytest.skip("target unreachable")
        import urllib.parse
        parsed = urllib.parse.urlparse(base_response.url)
        qs = urllib.parse.parse_qs(parsed.query)
        sensitive_params = [k for k in qs
                            if any(w in k.lower() for w in
                                   ["token", "secret", "key", "password", "passwd", "auth"])]
        assert not sensitive_params, (
            f"Sensitive parameters in URL query string: {sensitive_params} — "
            f"URL: {base_response.url}"
        )

    def test_no_plaintext_passwords_in_response(self, base_html):
        password_pat = re.compile(
            r'(?i)"password"\s*:\s*"[^"]{4,}"', )
        found = password_pat.findall(base_html)
        assert not found, f"Plaintext password fields in response: {found[:3]}"

    def test_tls_used_for_login(self):
        from tests.active.helpers import url_join as uj
        from tests.active.config import TARGET_URL as TU
        for path in ["/login", "/signin", "/auth"]:
            r = safe_get(uj(path))
            if r is None or r.status_code != 200:
                continue
            assert r.url.startswith("https://"), (
                f"Login page {path} served over non-HTTPS: {r.url}"
            )
            return
        pytest.skip("no login page found")


class TestCacheLeakage:
    def test_no_store_on_sensitive_cached_pages(self):
        sensitive = ["/account", "/profile", "/dashboard", "/orders",
                     "/payment", "/checkout", "/my-account"]
        leaking = []
        for path in sensitive:
            r = safe_get(url_join(path))
            if r is None or r.status_code != 200:
                continue
            cc = r.headers.get("Cache-Control", "").lower()
            pragma = r.headers.get("Pragma", "").lower()
            if "no-store" not in cc and "no-cache" not in cc and "no-cache" not in pragma:
                leaking.append(f"{path} ({cc!r})")
        assert not leaking, (
            f"Sensitive pages may be cached by browsers/proxies (no Cache-Control: no-store): {leaking}"
        )


class TestInsecureRandomMarkers:
    def test_no_math_random_for_security_in_js(self, base_soup):
        from tests.active.helpers import _collect_js_urls  # noqa: reuse local fn
        # Check for Math.random() used near security-sensitive naming
        pattern = re.compile(r"Math\.random\(\)\s*\*\s*\d+.*(?:token|csrf|nonce|secret|key)", re.IGNORECASE)
        js_urls = _collect_js_urls(base_soup)
        for js_url in js_urls:
            r = safe_get(js_url)
            if r and pattern.search(r.text):
                pytest.fail(
                    f"Math.random() used near security-sensitive token generation in {js_url}"
                )


def _collect_js_urls(soup):
    """Module-level alias so test class can import it."""
    from tests.active.helpers import url_join
    urls = []
    for tag in soup.find_all("script", src=True):
        src = tag["src"]
        if src.startswith("http"):
            urls.append(src)
        elif src.startswith("/"):
            urls.append(url_join(src))
    return urls[:10]
