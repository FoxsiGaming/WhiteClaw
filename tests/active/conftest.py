"""Session-scoped fixtures shared across all active security tests."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import pytest
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from tests.active.helpers import safe_get, get_soup
from tests.active.config import TARGET_URL


@pytest.fixture(scope="session")
def base_response():
    return safe_get(TARGET_URL)


@pytest.fixture(scope="session")
def base_html(base_response):
    if base_response is None:
        return ""
    return base_response.text


@pytest.fixture(scope="session")
def base_soup(base_html):
    from bs4 import BeautifulSoup
    return BeautifulSoup(base_html, "html.parser")


@pytest.fixture(scope="session")
def base_headers(base_response):
    if base_response is None:
        return {}
    return dict(base_response.headers)


@pytest.fixture(scope="session")
def base_cookies(base_response):
    if base_response is None:
        return {}
    return dict(base_response.cookies)
