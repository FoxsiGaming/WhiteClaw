TARGET_URL = "https://example.com"  # <-- replace with your authorized target

TIMEOUT = 10  # seconds per request

# Set True only after obtaining written authorization for the target.
# Destructive tests modify data, trigger lockouts, or generate significant load.
ENABLE_DESTRUCTIVE_TESTS = False

# Optional bearer token / session cookie for auth-required tests.
# Leave empty to skip auth-dependent checks.
AUTH_TOKEN = ""
AUTH_COOKIE_NAME = "session"
AUTH_COOKIE_VALUE = ""

# User-Agent sent with every request.
USER_AGENT = "WhiteClaw-SecurityAudit/1.0 (authorized pentest)"
