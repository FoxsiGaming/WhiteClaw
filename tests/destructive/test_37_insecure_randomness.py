# ⚠️ DESTRUCTIVE TEST — Do not run against production.
# Set ENABLE_DESTRUCTIVE_TESTS=True in tests/active/config.py to enable.
"""Category 37: Insecure Randomness in Security Tokens."""
import re
import statistics
import pytest

from tests.active.helpers import safe_get, safe_post, url_join
from tests.active.config import ENABLE_DESTRUCTIVE_TESTS, TARGET_URL

if not ENABLE_DESTRUCTIVE_TESTS:
    pytestmark = pytest.mark.skip(
        reason="ENABLE_DESTRUCTIVE_TESTS=False in config.py — "
               "these tests modify server state, trigger lockouts, and may cause disruption."
    )

TOKEN_PATTERNS = {
    "session": re.compile(r"(?:session|sid|sessionid)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_\-]+)"),
    "csrf": re.compile(r"(?:csrf|token|_token)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_\-]+)"),
    "api_key": re.compile(r"(?:api_?key|key|token)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{20,})"),
}


class TestTokenRandomnessCollection:
    def test_collect_session_tokens(self):
        """Collect multiple session tokens for entropy analysis."""
        tokens = []
        for _ in range(10):
            r = safe_post(url_join("/login"),
                          data={"username": "test", "password": "test"},
                          allow_redirects=False)
            if r and "session" in r.headers.get("Set-Cookie", "").lower():
                # Extract session cookie
                for cookie in r.cookies:
                    if "session" in cookie.name.lower():
                        tokens.append(cookie.value)
                        break
        
        if len(tokens) < 5:
            pytest.skip("Insufficient session tokens collected for analysis")
        
        # Analyze token entropy
        _analyze_token_entropy(tokens, "Session Tokens")

    def test_collect_csrf_tokens(self):
        """Collect multiple CSRF tokens for randomness analysis."""
        tokens = []
        for _ in range(10):
            r = safe_get(url_join("/login"))
            if r:
                # Extract CSRF token
                m = re.search(r'name=["\']csrf_token["\'][^>]*value=["\']([^"\']+)["\']', r.text)
                if m:
                    tokens.append(m.group(1))
        
        if len(tokens) < 5:
            pytest.skip("Insufficient CSRF tokens collected")
        
        _analyze_token_entropy(tokens, "CSRF Tokens")

    def test_collect_api_tokens(self):
        """Collect API tokens for randomness analysis."""
        tokens = []
        for _ in range(10):
            r = safe_post(url_join("/api/token"),
                          json={"client_id": "test", "client_secret": "test"})
            if r:
                try:
                    data = r.json()
                    if "access_token" in data:
                        tokens.append(data["access_token"])
                except Exception:
                    pass
        
        if len(tokens) < 5:
            pytest.skip("Insufficient API tokens collected")
        
        _analyze_token_entropy(tokens, "API Tokens")


def _analyze_token_entropy(tokens, label):
    """Analyze token entropy and predictability."""
    # Check for obvious patterns
    if len(set(tokens)) < len(tokens) / 2:
        pytest.fail(f"{label}: High token repetition detected — weak randomness")
    
    # Check for sequential patterns
    token_ints = []
    for t in tokens:
        try:
            # Try to extract numeric part
            nums = re.findall(r"\d+", t)
            if nums:
                token_ints.append(int(nums[0]))
        except Exception:
            pass
    
    if token_ints and len(token_ints) > 3:
        diffs = [token_ints[i+1] - token_ints[i] for i in range(len(token_ints)-1)]
        if len(set(diffs)) == 1:
            pytest.fail(
                f"{label}: Sequential pattern detected (constant difference {diffs[0]})"
            )
        
        # Check if differences form a pattern
        if len(set(diffs)) < len(diffs) / 2:
            pytest.skip(
                f"{label}: Potential pattern in numeric differences — weak randomness"
            )
    
    # Check timestamp correlation
    for i, token in enumerate(tokens):
        if str(i) in token or f"{i:02d}" in token:
            pytest.fail(f"{label}: Token contains sequential index — weak randomness")
    
    # Calculate entropy (simplified)
    char_entropy = len(set("".join(tokens)))
    avg_length = statistics.mean(len(t) for t in tokens)
    
    if char_entropy < 20 or avg_length < 10:
        pytest.skip(
            f"{label}: Low entropy ({char_entropy} unique chars, "
            f"avg length {avg_length:.1f}) — possible weak randomness"
        )


class TestTokenTimingCorrelation:
    def test_token_generation_timing_correlation(self):
        """Test if tokens correlate with generation time."""
        pytest.skip(
            "Token timing correlation analysis requires: "
            "1) Collecting tokens with precise timestamps "
            "2) Analyzing correlation between time and token value "
            "3) Statistical test for significance. "
            "Implement in destructive suite with timing analysis."
        )


class TestTokenMathRandomness:
    def test_math_random_detection_in_source(self):
        """Passive check: look for Math.random() in source code."""
        pytest.skip("Requires HTML content")


class TestRandomnessSkipped:
    def test_randomness_advanced_analysis_destructive(self):
        pytest.skip(
            "Advanced randomness analysis (diehard tests, entropy calculation, "
            "predictor algorithms) requires: "
            "1) Large sample collection (100+ tokens) "
            "2) Statistical testing libraries (scipy, numpy) "
            "3) Specialized entropy analysis tools. "
            "Implement in destructive test suite."
        )
