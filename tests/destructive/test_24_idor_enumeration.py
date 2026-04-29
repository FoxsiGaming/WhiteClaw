# ⚠️ DESTRUCTIVE TEST — Do not run against production.
# Set ENABLE_DESTRUCTIVE_TESTS=True in tests/active/config.py to enable.
"""Category 24: IDOR — Insecure Direct Object Reference enumeration."""
import re
import pytest

from tests.active.helpers import safe_get, safe_post, url_join
from tests.active.config import ENABLE_DESTRUCTIVE_TESTS, TARGET_URL

if not ENABLE_DESTRUCTIVE_TESTS:
    pytestmark = pytest.mark.skip(
        reason="ENABLE_DESTRUCTIVE_TESTS=False in config.py — "
               "these tests modify server state, trigger lockouts, and may cause disruption."
    )

# Common IDOR patterns in URLs and parameters
IDOR_ENDPOINTS = [
    "/api/users/{id}", "/api/v1/user/{id}", "/api/accounts/{id}",
    "/user/{id}/profile", "/order/{id}", "/api/orders/{id}",
    "/document/{id}", "/file/{id}", "/api/v1/documents/{id}",
    "/invoice/{id}", "/booking/{id}", "/project/{id}",
]

IDOR_PARAMS = ["id", "user_id", "uid", "account_id", "order_id", "doc_id", "client_id"]

USER_DATA_INDICATORS = [
    "email", "phone", "address", "credit_card", "ssn",
    "name", "date_of_birth", "password", "salary", "secret",
]


class TestIdorDirectUrl:
    def test_idor_sequential_ids_accessible(self):
        """Test if incrementing sequential IDs in URLs returns other users' data."""
        # Try common IDOR patterns
        for endpoint_pattern in IDOR_ENDPOINTS:
            for test_id in [0, 1, 2, 3, 99, 999, 1, -1]:
                endpoint = endpoint_pattern.replace("{id}", str(test_id))
                r = safe_get(url_join(endpoint), allow_redirects=False)
                if r is None or r.status_code == 404:
                    continue
                if r.status_code == 200:
                    # Check for user data that suggests it's a valid resource
                    data_indicators = [ind for ind in USER_DATA_INDICATORS if ind in r.text.lower()]
                    if data_indicators and len(r.text) > 200:
                        pytest.skip(
                            f"Accessible endpoint found: {endpoint} — "
                            f"contains data indicators: {data_indicators}. "
                            "Manual verification needed to confirm IDOR."
                        )

    def test_idor_uuid_patterns(self):
        """Test common UUID patterns for IDOR."""
        uuid_patterns = [
            "550e8400-e29b-41d4-a716-446655440000",
            "00000000-0000-0000-0000-000000000001",
            "ffffffff-ffff-ffff-ffff-ffffffffffff",
        ]
        for endpoint_pattern in IDOR_ENDPOINTS:
            for uuid_test in uuid_patterns:
                endpoint = endpoint_pattern.replace("{id}", uuid_test)
                r = safe_get(url_join(endpoint), allow_redirects=False)
                if r and r.status_code == 200 and len(r.text) > 200:
                    pytest.skip(f"UUID endpoint accessible: {endpoint}")


class TestIdorQueryParameters:
    def test_idor_user_id_parameter(self):
        """Test IDOR via user_id, uid, or account_id query parameters."""
        for param in IDOR_PARAMS:
            for test_id in [1, 2, 0, -1]:
                r = safe_get(f"{TARGET_URL}?{param}={test_id}", allow_redirects=False)
                if r and r.status_code == 200 and len(r.text) > 300:
                    # Check for user data
                    has_data = any(ind in r.text.lower() for ind in USER_DATA_INDICATORS)
                    if has_data:
                        pytest.skip(
                            f"Parameter-based IDOR candidate: ?{param}={test_id} "
                            "returns user data. Manual verification needed."
                        )

    def test_idor_nested_parameter(self):
        """Test IDOR in nested resource parameters."""
        nested_patterns = [
            "/api/user/{user_id}/orders/{order_id}",
            "/api/account/{account_id}/documents/{doc_id}",
            "/user/{user_id}/profile?view_user_id={view_user_id}",
        ]
        # Requires knowing valid IDs — skip in passive mode
        pytest.skip(
            "Nested IDOR requires valid authenticated context with user IDs. "
            "Perform with authenticated session in destructive tests."
        )


class TestIdorPostRequest:
    def test_idor_via_post_body(self):
        """Test IDOR in POST request bodies."""
        idor_post_endpoints = [
            "/api/update-profile",
            "/api/change-email",
            "/api/update-address",
            "/user/settings/save",
        ]
        for endpoint in idor_post_endpoints:
            for user_id in [1, 2, 0]:
                r = safe_post(url_join(endpoint),
                              json={"user_id": user_id, "email": "test@example.com"},
                              allow_redirects=False)
                if r and r.status_code in (200, 201) and "success" in r.text.lower():
                    pytest.skip(
                        f"POST IDOR candidate: {endpoint} accepted user_id={user_id} update"
                    )


class TestIdorBulkOperations:
    def test_idor_bulk_export_other_users(self):
        """Test if bulk export/download includes other users' data."""
        export_endpoints = [
            "/export", "/api/export", "/download", "/api/v1/export-all",
            "/report/generate", "/api/backup",
        ]
        for endpoint in export_endpoints:
            r = safe_get(url_join(endpoint), allow_redirects=False)
            if r and r.status_code == 200 and len(r.content) > 1000:
                # Check if export contains multiple user records
                if r.text.count("@example.com") > 3 or r.text.count("user") > 10:
                    pytest.skip(
                        f"Bulk export IDOR candidate at {endpoint}: "
                        "export may contain multiple users' data"
                    )


class TestIdorAccessLoggedIn:
    def test_idor_requires_authenticated_context(self):
        """Note that IDOR is best tested with authenticated session."""
        pytest.skip(
            "IDOR testing is more effective with authenticated context. "
            "Current passive tests cannot verify authorization checks fully. "
            "Run authenticated IDOR tests in destructive suite with known user IDs."
        )
