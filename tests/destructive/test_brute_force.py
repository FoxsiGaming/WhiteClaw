# ⚠️ DESTRUCTIVE TEST — Do not run against production.
# Set ENABLE_DESTRUCTIVE_TESTS=True in tests/active/config.py to enable.
"""Destructive: brute-force, credential stuffing, OTP enumeration."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import time
import pytest

from tests.active.config import ENABLE_DESTRUCTIVE_TESTS, TARGET_URL
from tests.active.helpers import safe_post, url_join

if not ENABLE_DESTRUCTIVE_TESTS:
    pytestmark = pytest.mark.skip(
        reason="ENABLE_DESTRUCTIVE_TESTS=False in config.py — "
               "these tests modify server state, trigger lockouts, and may cause disruption."
    )

# Common password lists for brute-force simulation
TOP_PASSWORDS = [
    "password", "123456", "password1", "admin", "letmein",
    "qwerty", "abc123", "monkey", "1234567890", "welcome",
    "login", "master", "dragon", "test", "secret",
]

TOP_USERNAMES = ["admin", "administrator", "root", "user", "test",
                 "guest", "support", "info", "webmaster", "demo"]

TOP_OTP_CODES = [str(i).zfill(6) for i in range(0, 20)] + ["123456", "000000", "111111", "999999"]


class TestBruteForceLogin:
    def test_brute_force_login_endpoint(self):
        """Try common username/password combinations against the login endpoint."""
        for path in ["/login", "/signin", "/auth", "/api/login"]:
            r = safe_post(url_join(path),
                          data={"username": "admin", "password": "test"},
                          allow_redirects=False)
            if r is None or r.status_code == 404:
                continue
            successes = []
            for username in TOP_USERNAMES[:5]:
                for password in TOP_PASSWORDS[:10]:
                    r = safe_post(url_join(path),
                                  data={"username": username, "password": password},
                                  allow_redirects=False)
                    if r and r.status_code in (200, 302):
                        if "logout" in r.text.lower() or "dashboard" in r.text.lower():
                            successes.append(f"{username}:{password}")
                    time.sleep(0.1)  # respect the server
            if successes:
                pytest.fail(f"Default credentials accepted at {path}: {successes}")
            return
        pytest.skip("No login endpoint found")

    def test_account_lockout_triggered_after_failures(self):
        """Verify the server locks out after N consecutive failures."""
        for path in ["/login", "/signin", "/api/login"]:
            locked = False
            for i in range(20):
                r = safe_post(url_join(path),
                              data={"username": "admin", "password": f"wrong_pass_{i}"},
                              allow_redirects=False)
                if r and r.status_code in (429, 423):
                    locked = True
                    break
                if r and ("locked" in r.text.lower() or "too many" in r.text.lower()):
                    locked = True
                    break
                time.sleep(0.2)
            if not locked:
                pytest.fail(
                    f"No lockout or rate-limit after 20 failed logins at {path}"
                )
            return
        pytest.skip("No login endpoint found")


class TestCredentialStuffing:
    def test_credential_stuffing_blocked(self):
        """Simulate credential stuffing with different IPs via X-Forwarded-For spoofing."""
        for path in ["/login", "/signin"]:
            r = safe_post(url_join(path),
                          data={"username": "admin", "password": "test"},
                          allow_redirects=False)
            if r is None or r.status_code == 404:
                continue
            blocked_count = 0
            for i in range(10):
                spoofed_ip = f"1.2.3.{i+1}"
                r = safe_post(url_join(path),
                              data={"username": f"user{i}", "password": "Password1!"},
                              headers={"X-Forwarded-For": spoofed_ip},
                              allow_redirects=False)
                if r and r.status_code == 429:
                    blocked_count += 1
                time.sleep(0.1)
            if blocked_count == 0:
                pytest.fail(
                    f"Credential stuffing via X-Forwarded-For spoofing not blocked at {path}"
                )
            return
        pytest.skip("No login endpoint found")


class TestOtpBruteForce:
    def test_otp_brute_force_locked_out(self):
        """Verify OTP endpoint rate-limits or locks after rapid guessing."""
        for path in ["/auth/otp", "/2fa/verify", "/otp/verify", "/verify"]:
            r = safe_post(url_join(path), json={"code": "000000"})
            if r is None or r.status_code == 404:
                continue
            locked = False
            for code in TOP_OTP_CODES:
                r = safe_post(url_join(path), json={"code": code})
                if r and r.status_code in (429, 423):
                    locked = True
                    break
                time.sleep(0.1)
            if not locked:
                pytest.fail(
                    f"OTP endpoint {path} does not rate-limit or lock after rapid code guessing"
                )
            return
        pytest.skip("No OTP/2FA endpoint found")


class TestPasswordResetBruteForce:
    def test_reset_token_brute_force_blocked(self):
        """Verify that password reset tokens cannot be brute-forced."""
        # Submit a reset request first
        for path in ["/forgot-password", "/reset-password"]:
            r = safe_post(url_join(path),
                          data={"email": "wc_brutetest@example.com"})
            if r is None or r.status_code == 404:
                continue
            # Try short numeric tokens
            blocked = False
            for token in [str(i).zfill(6) for i in range(30)]:
                r = safe_get_compat(url_join(f"/reset-password?token={token}"))
                if r and r.status_code == 429:
                    blocked = True
                    break
                time.sleep(0.05)
            if not blocked:
                pytest.fail(
                    f"Password reset token at {path} not rate-limited — "
                    "short/numeric tokens may be brute-forceable"
                )
            return
        pytest.skip("No password reset endpoint found")


def safe_get_compat(url, **kwargs):
    from tests.active.helpers import safe_get
    return safe_get(url, **kwargs)
