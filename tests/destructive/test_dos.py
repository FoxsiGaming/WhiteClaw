# ⚠️ DESTRUCTIVE TEST — Do not run against production.
# Set ENABLE_DESTRUCTIVE_TESTS=True in tests/active/config.py to enable.
"""Destructive: DoS via large payloads, XML bomb, GraphQL complexity, slow HTTP."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import socket
import time
import threading
import pytest

from tests.active.config import ENABLE_DESTRUCTIVE_TESTS, TARGET_URL, TIMEOUT
from tests.active.helpers import safe_post, url_join, target_host, parsed_target

if not ENABLE_DESTRUCTIVE_TESTS:
    pytestmark = pytest.mark.skip(
        reason="ENABLE_DESTRUCTIVE_TESTS=False in config.py — "
               "these tests may cause service disruption."
    )


class TestLargePayloadDos:
    def test_large_json_body_rejected(self):
        """Server should reject extremely large JSON payloads (e.g. >10MB)."""
        big_payload = {"data": "A" * (10 * 1024 * 1024)}  # 10 MB string
        r = safe_post(TARGET_URL, json=big_payload)
        if r is None:
            pytest.skip("request failed or timed out")
        assert r.status_code in (400, 413, 414, 431), (
            f"Server accepted a 10 MB payload (status {r.status_code}) — "
            "no max body size enforcement"
        )

    def test_large_url_rejected(self):
        """Server should reject URLs exceeding common length limits."""
        big_url = TARGET_URL + "?" + "a=" + "B" * 65536
        r = safe_post(big_url, data="")
        if r is None:
            pytest.skip("request failed")
        assert r.status_code in (400, 414), (
            f"Server accepted a 65 KB URL (status {r.status_code}) — "
            "no URL length enforcement"
        )

    def test_many_headers_rejected(self):
        """Server should handle or reject requests with many custom headers."""
        headers = {f"X-Custom-Header-{i}": f"value{i}" for i in range(500)}
        r = safe_post(TARGET_URL, data="test", headers=headers)
        if r is None:
            pytest.skip("request failed")
        assert r.status_code in (200, 400, 431), (
            f"Unexpected status code {r.status_code} for 500 custom headers"
        )


class TestXmlBomb:
    def test_xml_bomb_rejected(self):
        """Server must not process the billion laughs XML expansion attack."""
        xml_bomb = """<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
]>
<root>&lol6;</root>"""
        import requests
        try:
            r = requests.post(
                TARGET_URL,
                data=xml_bomb,
                headers={"Content-Type": "application/xml"},
                timeout=5,
                verify=False,
            )
            assert r.status_code in (400, 403, 413, 422, 503), (
                f"XML bomb not rejected — server returned {r.status_code} "
                "(may have attempted expansion)"
            )
        except requests.Timeout:
            pytest.fail(
                "XML bomb caused server timeout — server attempted to expand the entity bomb"
            )
        except Exception:
            pytest.skip("XML POST request failed")


class TestGraphQlDoS:
    def test_graphql_deeply_nested_query_rejected(self):
        """Deeply nested GraphQL queries can cause exponential resolver execution."""
        nested = "{ user" + "{ friends" * 15 + " { id }" + " }" * 15 + " }"
        query = '{"query":"' + nested.replace('"', '\\"') + '"}'
        for path in ["/graphql", "/api/graphql", "/gql"]:
            r = safe_post(url_join(path), data=query,
                          headers={"Content-Type": "application/json"})
            if r is None or r.status_code == 404:
                continue
            if r.status_code == 200:
                pytest.fail(
                    f"GraphQL at {path} accepted a deeply-nested (15-level) query — "
                    "complexity limiting not enforced"
                )
            return
        pytest.skip("No GraphQL endpoint found")

    def test_graphql_query_batching_limited(self):
        """GraphQL query batching without limit enables DoS via many operations."""
        single_query = '{"query":"{__typename}"}'
        batch = "[" + ",".join([single_query] * 100) + "]"
        for path in ["/graphql", "/api/graphql"]:
            r = safe_post(url_join(path), data=batch,
                          headers={"Content-Type": "application/json"})
            if r is None or r.status_code == 404:
                continue
            if r.status_code == 200:
                try:
                    data = r.json()
                    if isinstance(data, list) and len(data) == 100:
                        pytest.fail(
                            f"GraphQL at {path} processed 100 batched operations — "
                            "batch size limiting not enforced"
                        )
                except Exception:
                    pass
            return
        pytest.skip("No GraphQL endpoint found")


class TestSlowloris:
    def test_slow_http_attack_resilience(self):
        """
        Send partial HTTP headers very slowly and verify the server closes the connection
        before the attack can establish a hold.
        """
        host = target_host()
        port = parsed_target().port or 80
        connections = []
        try:
            # Open 10 slow connections
            for _ in range(10):
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(TIMEOUT)
                    s.connect((host, port))
                    s.send(b"GET / HTTP/1.1\r\n")
                    s.send(f"Host: {host}\r\n".encode())
                    connections.append(s)
                except Exception:
                    break

            if not connections:
                pytest.skip("Could not establish TCP connections")

            # Keep alive with partial headers for 5 seconds
            time.sleep(5)

            # A robust server should have closed the connections by now
            alive = 0
            for s in connections:
                try:
                    s.send(b"X-Keep-Alive: 1\r\n")
                    alive += 1
                except Exception:
                    pass

            if alive == len(connections):
                pytest.fail(
                    f"All {alive} slow-HTTP connections remain open after 5s — "
                    "server may be vulnerable to Slowloris attack"
                )
        finally:
            for s in connections:
                try:
                    s.close()
                except Exception:
                    pass
