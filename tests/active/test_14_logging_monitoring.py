"""Category 14: Security Logging & Monitoring — passive checks for log injection and info leakage."""
import pytest

from tests.active.helpers import safe_get, safe_post, url_join
from tests.active.config import TARGET_URL

LOGIN_PATHS = ["/login", "/signin", "/auth", "/user/login", "/account/login"]


class TestSecurityEventsLogged:
    def test_failed_login_returns_generic_message(self):
        for path in LOGIN_PATHS:
            r = safe_post(url_join(path),
                          data={"username": "wc_audit_user", "password": "wc_invalid_pass"},
                          allow_redirects=False)
            if r is None or r.status_code == 404:
                continue
            # Good: generic message. Bad: "User not found" or "Wrong password" (enumeration risk)
            enumeration_hints = [
                "user not found", "no account with", "email not registered",
                "password is incorrect", "wrong password",
            ]
            found = [h for h in enumeration_hints if h in r.text.lower()]
            if found:
                pytest.fail(
                    f"Login failure message reveals specific reason at {path}: {found} — "
                    "this enables username enumeration and leaks into logs"
                )
            return
        pytest.skip("no login endpoint found at common paths")


class TestLogInjection:
    def test_user_agent_log_injection_not_reflected(self):
        payload = "LegitAgent\r\nINFO: admin logged in as root"
        r = safe_get(TARGET_URL, headers={"User-Agent": payload})
        if r is None:
            pytest.skip("request failed")
        assert "INJECTED" not in r.text and "admin logged in" not in r.text, (
            "Log injection payload reflected in response — CRLF in User-Agent leaks into page"
        )

    def test_referer_log_injection_not_reflected(self):
        payload = "https://example.com/\r\nCRITICAL: system compromised"
        r = safe_get(TARGET_URL, headers={"Referer": payload})
        if r is None:
            pytest.skip("request failed")
        assert "CRITICAL: system compromised" not in r.text, (
            "Referer log injection payload appeared in response body"
        )

    def test_x_forwarded_for_injection_not_stored(self):
        marker = "127.0.0.1, INJECTED_LOG_ENTRY_WC"
        r = safe_get(TARGET_URL, headers={"X-Forwarded-For": marker})
        if r is None:
            pytest.skip("request failed")
        assert "INJECTED_LOG_ENTRY_WC" not in r.text, (
            "X-Forwarded-For injection reflected in response — may also write into logs"
        )


class TestSensitiveDataInErrors:
    def test_404_no_sensitive_data(self):
        r = safe_get(url_join("/wc_audit_nonexistent_9z7x"))
        if r is None:
            pytest.skip("request failed")
        sensitive_patterns = [
            "password", "secret", "api_key", "access_token",
            "private_key", "database", "connection string",
        ]
        for pat in sensitive_patterns:
            if pat in r.text.lower():
                pytest.fail(
                    f"Sensitive keyword {pat!r} found in 404 error response"
                )

    def test_error_page_no_user_data_leakage(self):
        r = safe_get(f"{TARGET_URL}?id='; DROP TABLE users --")
        if r is None:
            pytest.skip("request failed")
        if r.status_code == 500:
            user_data_patterns = ["email", "@example.com", "user_id", "account"]
            for pat in user_data_patterns:
                if pat in r.text.lower():
                    pytest.fail(
                        f"User data {pat!r} leaked in 500 error response to SQL injection probe"
                    )


# Tests requiring server-side log access
class TestLoggingSkipped:
    def test_logs_no_sensitive_data_server_side(self):
        pytest.skip(
            "Cannot verify server-side log content without log file access — "
            "review log configuration manually and ensure PII is not logged."
        )

    def test_audit_trail_on_sensitive_actions_requires_auth(self):
        pytest.skip(
            "Audit trail verification requires authenticated actions and log inspection — "
            "test manually with auth context."
        )
