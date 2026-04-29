"""Shared HTTP helpers for active security tests."""
import re
import ssl
import socket
import urllib.parse
import warnings

import requests
import urllib3
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

from tests.active.config import TARGET_URL, TIMEOUT, USER_AGENT, AUTH_TOKEN, AUTH_COOKIE_NAME, AUTH_COOKIE_VALUE

SESSION = requests.Session()
SESSION.headers["User-Agent"] = USER_AGENT
if AUTH_TOKEN:
    SESSION.headers["Authorization"] = f"Bearer {AUTH_TOKEN}"
if AUTH_COOKIE_VALUE:
    SESSION.cookies.set(AUTH_COOKIE_NAME, AUTH_COOKIE_VALUE)


def safe_get(url, **kwargs):
    kwargs.setdefault("timeout", TIMEOUT)
    kwargs.setdefault("verify", False)
    try:
        return SESSION.get(url, **kwargs)
    except Exception:
        return None


def safe_post(url, **kwargs):
    kwargs.setdefault("timeout", TIMEOUT)
    kwargs.setdefault("verify", False)
    try:
        return SESSION.post(url, **kwargs)
    except Exception:
        return None


def safe_request(method, url, **kwargs):
    kwargs.setdefault("timeout", TIMEOUT)
    kwargs.setdefault("verify", False)
    try:
        return SESSION.request(method, url, **kwargs)
    except Exception:
        return None


def url_join(*paths):
    base = TARGET_URL.rstrip("/")
    for p in paths:
        base = base + "/" + p.lstrip("/")
    return base


def parsed_target():
    return urllib.parse.urlparse(TARGET_URL)


def target_host():
    return parsed_target().hostname


def target_scheme():
    return parsed_target().scheme


def get_soup(r):
    if r is None:
        return BeautifulSoup("", "html.parser")
    try:
        return BeautifulSoup(r.text, "html.parser")
    except Exception:
        return BeautifulSoup("", "html.parser")


def tls_info():
    """Return raw SSL connection metadata dict or None on error."""
    host = target_host()
    port = parsed_target().port or 443
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return {
                    "version": ssock.version(),
                    "cipher": ssock.cipher(),
                    "cert": ssock.getpeercert(binary_form=False),
                }
    except Exception:
        return None


def tls_cert():
    """Return the peer certificate dict or None."""
    host = target_host()
    port = parsed_target().port or 443
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return ssock.getpeercert()
    except Exception:
        return None


def has_auth():
    return bool(AUTH_TOKEN or AUTH_COOKIE_VALUE)


# Common secret patterns for JS/HTML scanning
SECRET_PATTERNS = [
    (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})', "API key"),
    (r'(?i)(secret[_-]?key|secret)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})', "secret key"),
    (r'(?i)(access[_-]?token|auth[_-]?token)\s*[=:]\s*["\']?([A-Za-z0-9_\-\.]{20,})', "access token"),
    (r'(?i)(aws[_-]?secret|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*["\']?([A-Za-z0-9/+=]{30,})', "AWS secret"),
    (r'AKIA[0-9A-Z]{16}', "AWS access key"),
    (r'(?i)password\s*[=:]\s*["\']([^"\']{6,})["\']', "hardcoded password"),
    (r'(?i)private[_-]?key\s*[=:]\s*["\']([^"\']{20,})["\']', "private key"),
    (r'ghp_[A-Za-z0-9]{36}', "GitHub token"),
    (r'sk-[A-Za-z0-9]{48}', "OpenAI key"),
]

VERSION_PATTERN = re.compile(r"\d+\.\d+(\.\d+)?")
