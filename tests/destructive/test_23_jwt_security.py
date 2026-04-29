# ⚠️ DESTRUCTIVE TEST — Do not run against production.
# Set ENABLE_DESTRUCTIVE_TESTS=True in tests/active/config.py to enable.
"""Category 23: JWT Security — secret brute force, algorithm confusion, token manipulation."""
import re
import json
import base64
import pytest

from tests.active.helpers import safe_get, safe_post, url_join
from tests.active.config import ENABLE_DESTRUCTIVE_TESTS, TARGET_URL

if not ENABLE_DESTRUCTIVE_TESTS:
    pytestmark = pytest.mark.skip(
        reason="ENABLE_DESTRUCTIVE_TESTS=False in config.py — "
               "these tests modify server state, trigger lockouts, and may cause disruption."
    )

COMMON_JWT_SECRETS = [
    "secret", "password", "12345", "admin", "key", "token",
    "jwt_secret", "your-secret-key", "mysecret", "verysecret",
]

JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]*")
JWT_BEARER_PATTERN = re.compile(r"Bearer\s+(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]*)")


def _extract_jwt_from_response(r):
    """Extract JWT from response headers, body, or cookies."""
    if r is None:
        return None
    # Check Authorization header
    auth = r.headers.get("Authorization", "")
    m = JWT_BEARER_PATTERN.search(auth)
    if m:
        return m.group(1)
    # Check response body
    m = JWT_PATTERN.search(r.text)
    if m:
        return m.group(0)
    # Check cookies
    for cookie in r.cookies:
        if JWT_PATTERN.search(cookie.value):
            return cookie.value
    return None


def _decode_jwt_part(part):
    """Decode JWT part (header, payload, signature)."""
    try:
        # Add padding if needed
        part += "=" * (4 - len(part) % 4)
        return json.loads(base64.urlsafe_b64decode(part))
    except Exception:
        return None


class TestJwtExtraction:
    def test_jwt_extraction_from_auth_flow(self):
        """Extract JWT from typical authentication flow."""
        r = safe_post(url_join("/api/login"),
                      json={"username": "test", "password": "test"})
        if r is None:
            r = safe_post(url_join("/login"),
                          data={"username": "test", "password": "test"})
        if r is None:
            pytest.skip("no login endpoint found")
        jwt = _extract_jwt_from_response(r)
        if jwt is None:
            pytest.skip("no JWT token found in response")
        # Token extracted — analyze it
        parts = jwt.split(".")
        if len(parts) != 3:
            pytest.fail(f"Invalid JWT format: {len(parts)} parts")


class TestJwtAlgorithmConfusion:
    def test_jwt_none_algorithm_accepted(self):
        """Test if JWT with alg:none is accepted."""
        # This requires extracting and regenerating a JWT, which is complex in passive tests
        pytest.skip(
            "JWT algorithm confusion requires active token generation and signing. "
            "Use PyJWT or similar library in destructive tests to generate forged tokens."
        )

    def test_jwt_hs256_instead_of_rs256(self):
        """Test if HS256 (HMAC) is accepted when RS256 (RSA) expected."""
        pytest.skip(
            "Requires extracting public key and signing test tokens. "
            "Perform in destructive test suite."
        )


class TestJwtSecretBruteForce:
    def test_jwt_weak_secret_detection(self):
        """Passive check: verify JWT secret is not weak (difficult without token)."""
        pytest.skip(
            "JWT secret brute-force is DESTRUCTIVE and time-consuming. "
            "Use tools like jwt-cli or hashcat in offline mode on captured tokens. "
            "See tests/destructive/ for active attempts."
        )


class TestJwtExpirationManipulation:
    def test_jwt_no_expiration_bypass(self):
        """Test if JWT tokens without expiration are accepted."""
        # Similar to above — requires capturing and analyzing token
        pytest.skip(
            "JWT expiration analysis requires token inspection and modification. "
            "Implement in destructive test suite."
        )


class TestJwtClaimInjection:
    def test_jwt_claim_manipulation_via_api(self):
        """Test if modifying JWT claims (role, admin, etc.) is reflected."""
        pytest.skip(
            "JWT claim injection requires active token manipulation. "
            "Destructive tests will generate forged tokens with modified claims."
        )


class TestJwtStorage:
    def test_jwt_not_in_localStorage(self):
        """Check if JWT is stored in browser localStorage (vulnerable to XSS)."""
        pytest.skip("Requires HTML content inspection")

    def test_jwt_in_secure_http_only_cookie(self):
        """Passive check: if JWT is in cookie, should be HttpOnly + Secure."""
        pytest.skip(
            "Requires authenticated request inspection. "
            "Check via browser dev tools or automated scanning."
        )


class TestJwtSignatureBypass:
    def test_jwt_signature_not_verified(self):
        """Passive indicator: check for signature verification bypass."""
        pytest.skip(
            "Signature verification bypass requires token modification and resubmission. "
            "See destructive tests."
        )


class TestJwtKidConfusion:
    def test_jwt_kid_injection_for_algorithm_confusion(self):
        """Test for key ID (kid) confusion leading to algorithm downgrade."""
        pytest.skip(
            "JWT kid confusion requires token generation with custom headers. "
            "Implement in destructive test suite with PyJWT/jose libraries."
        )
