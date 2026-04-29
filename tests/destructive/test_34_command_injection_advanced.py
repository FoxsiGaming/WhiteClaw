# ⚠️ DESTRUCTIVE TEST — Do not run against production.
# Set ENABLE_DESTRUCTIVE_TESTS=True in tests/active/config.py to enable.
"""Category 34: Command Injection via Non-Standard Vectors."""
import re
import pytest

from tests.active.helpers import safe_get, safe_post, url_join
from tests.active.config import ENABLE_DESTRUCTIVE_TESTS, TARGET_URL

if not ENABLE_DESTRUCTIVE_TESTS:
    pytestmark = pytest.mark.skip(
        reason="ENABLE_DESTRUCTIVE_TESTS=False in config.py — "
               "these tests modify server state, trigger lockouts, and may cause disruption."
    )

COMMAND_EXECUTION_INDICATORS = re.compile(
    r"\buid=\d+\(\w+\)|root|command not found|syntax error|"
    r"cannot execute|no such file|permission denied",
    re.IGNORECASE,
)

COMMAND_PARAMS = ["cmd", "command", "exec", "execute", "run", "query"]


class TestCommandInjectionBackgrounding:
    def test_command_backgrounding_bypass(self):
        """Test command injection via backgrounding operators."""
        for param in COMMAND_PARAMS:
            for endpoint in [TARGET_URL, url_join("/search"), url_join("/api")]:
                # Try backgrounding: command & sleep 1
                r = safe_get(f"{endpoint}?{param}=test%20%26%20id%20%26")
                if r and COMMAND_EXECUTION_INDICATORS.search(r.text):
                    pytest.fail(f"Command injection via backgrounding at ?{param}")


class TestCommandInjectionProcessSubstitution:
    def test_command_process_substitution(self):
        """Test command injection via process substitution."""
        for param in COMMAND_PARAMS:
            # Try process substitution: <(command)
            r = safe_get(f"{TARGET_URL}?{param}=test%20%3C%28id%29")
            if r and COMMAND_EXECUTION_INDICATORS.search(r.text):
                pytest.fail(f"Command injection via process substitution at ?{param}")


class TestCommandInjectionHistoryExpansion:
    def test_command_history_expansion(self):
        """Test command injection via shell history expansion."""
        # History expansion like !-1, !!, !$ depends on shell context
        pytest.skip(
            "History expansion is context-dependent (shell type, history settings). "
            "Test in destructive suite with shell-based environments."
        )


class TestCommandInjectionCommentBypass:
    def test_command_injection_comment_bypass(self):
        """Test command injection via comment injection."""
        for param in COMMAND_PARAMS:
            # Try comment bypass: command; #comment
            r = safe_get(f"{TARGET_URL}?{param}=echo%20test%3B%20%23%20id")
            if r and r.status_code == 200:
                pytest.skip(
                    f"Comment bypass candidate at ?{param}: "
                    "verify if semicolon and comment are processed"
                )


class TestCommandInjectionEnvironmentVar:
    def test_command_injection_env_variable_expansion(self):
        """Test command injection via environment variable expansion."""
        # Try: $(HOME)/injection or ${PATH}/injection
        r = safe_get(f"{TARGET_URL}?cmd=%24%28HOME%29/injection")
        if r and "/injection" in r.text:
            pytest.skip(
                "Environment variable expansion candidate: $() syntax processed"
            )


class TestCommandInjectionNewlineBypass:
    def test_command_newline_injection(self):
        """Test command injection via newline characters."""
        for param in COMMAND_PARAMS:
            # Try newline: command%0Aid
            r = safe_get(f"{TARGET_URL}?{param}=echo%20test%0Aid")
            if r and COMMAND_EXECUTION_INDICATORS.search(r.text):
                pytest.fail(f"Command injection via newline at ?{param}")


class TestCommandInjectionQuoteBypass:
    def test_command_single_quote_bypass(self):
        """Test command injection via single quote escaping."""
        for param in COMMAND_PARAMS:
            # Try: test'$(id)'
            r = safe_get(f"{TARGET_URL}?{param}=test%27%24%28id%29%27")
            if r and COMMAND_EXECUTION_INDICATORS.search(r.text):
                pytest.fail(f"Command injection via quote escape at ?{param}")

    def test_command_double_quote_bypass(self):
        """Test command injection via double quote escaping."""
        for param in COMMAND_PARAMS:
            # Try: test"$(id)"
            r = safe_get(f"{TARGET_URL}?{param}=test%22%24%28id%29%22")
            if r and COMMAND_EXECUTION_INDICATORS.search(r.text):
                pytest.fail(f"Command injection via double quote at ?{param}")


class TestCommandInjectionOperatorChaining:
    def test_command_pipe_operator(self):
        """Test command injection via pipe operator."""
        for param in COMMAND_PARAMS:
            # Try: test | id
            r = safe_get(f"{TARGET_URL}?{param}=test%20%7C%20id")
            if r and COMMAND_EXECUTION_INDICATORS.search(r.text):
                pytest.fail(f"Command injection via pipe at ?{param}")


class TestCommandInjectionSkipped:
    def test_command_injection_destructive_execution(self):
        pytest.skip(
            "Active command injection exploitation is DESTRUCTIVE. "
            "See tests/destructive/test_active/ for authorized testing."
        )
