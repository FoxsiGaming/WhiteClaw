"""Category 3: Injection — SQL, NoSQL, OS command, SSTI, CRLF, header injection."""
import re
import pytest

from tests.active.helpers import safe_get, safe_post, url_join
from tests.active.config import TARGET_URL

SQL_ERROR_PATTERNS = re.compile(
    r"you have an error in your sql syntax|warning: mysql|mysql_fetch|"
    r"pg_query|pg_exec|column not found|table or view not found|"
    r"sqlite3|microsoft sql server|unclosed quotation|"
    r"ora-\d{4}|sqlstate|sql syntax|division by zero",
    re.IGNORECASE,
)

SSTI_INDICATORS = ["49", "7777777"]  # 7*7=49, {{7*7}} or ${7*7}

COMMON_PARAMS = ["id", "q", "search", "query", "user", "name", "page",
                 "item", "product", "category", "sort", "order", "filter"]

SQLI_PAYLOADS = ["'", '"', "' OR '1'='1", "1' AND SLEEP(0)--",
                 "1; SELECT 1--", "' UNION SELECT NULL--"]

NOSQL_PAYLOADS = [
    '{"$gt": ""}',
    '{"$where": "1==1"}',
    '{"$regex": ".*"}',
]

OS_CMD_PAYLOADS = [";id", "&&id", "|id", "`id`", ";sleep 0"]
OS_CMD_INDICATORS = re.compile(r"\buid=\d+\(\w+\)\s+gid=\d+", re.IGNORECASE)

SSTI_PAYLOADS = ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "{{7*'7'}}"]

CRLF_PAYLOAD = "value%0d%0aX-Injected-Header:injected"


class TestSqlInjection:
    def _probe_params(self, payload):
        """Try payload on each common param and return any URL that triggers an SQL error."""
        hits = []
        for param in COMMON_PARAMS[:6]:
            r = safe_get(f"{TARGET_URL}?{param}={payload}")
            if r and SQL_ERROR_PATTERNS.search(r.text):
                hits.append(param)
        return hits

    def test_sqli_error_based_single_quote(self):
        hits = self._probe_params("'")
        assert not hits, f"SQL error returned for ?{hits[0]}=' — possible error-based SQLi"

    def test_sqli_error_based_double_quote(self):
        hits = self._probe_params('"')
        assert not hits, f"SQL error returned for ?{hits[0]}=\" — possible error-based SQLi"

    def test_sqli_or_condition(self):
        hits = self._probe_params("' OR '1'='1")
        assert not hits, f"SQL error returned with OR payload on ?{hits[0]}"

    def test_sqli_boolean_blind(self):
        # Boolean blind: compare response lengths for true/false conditions
        base = safe_get(f"{TARGET_URL}?id=1")
        true_r = safe_get(f"{TARGET_URL}?id=1 AND 1=1")
        false_r = safe_get(f"{TARGET_URL}?id=1 AND 1=2")
        if base is None or true_r is None or false_r is None:
            pytest.skip("one or more requests failed")
        base_len = len(base.text)
        true_len = len(true_r.text)
        false_len = len(false_r.text)
        # If true == base but false differs significantly → boolean blind
        significant_diff = abs(true_len - false_len) > 100
        true_matches_base = abs(true_len - base_len) < 50
        assert not (significant_diff and true_matches_base), (
            f"Boolean blind SQLi detected: id=1 AND 1=1 ({true_len}b) vs "
            f"id=1 AND 1=2 ({false_len}b) differ significantly"
        )

    def test_sqli_union_probe(self):
        hits = self._probe_params("1 UNION SELECT NULL--")
        assert not hits, f"SQL error on UNION probe via ?{hits[0]}"


class TestNoSqlInjection:
    def test_nosql_gt_operator(self):
        r = safe_post(url_join("/api/login"),
                      json={"username": {"$gt": ""}, "password": {"$gt": ""}})
        if r is None:
            pytest.skip("no API login endpoint found")
        # Successful login without real credentials indicates NoSQL injection
        assert r.status_code not in (200,) or "token" not in r.text.lower(), (
            "Possible NoSQL injection: $gt operator returned apparent success on login"
        )

    def test_nosql_regex_operator(self):
        r = safe_get(f"{TARGET_URL}?username[$regex]=.*")
        if r is None:
            pytest.skip("request failed")
        assert not SQL_ERROR_PATTERNS.search(r.text), "NoSQL error pattern in response"


class TestHtmlInjection:
    def test_html_injection_in_params(self):
        payload = "<h1>injected</h1>"
        for param in ["q", "search", "name", "msg"]:
            r = safe_get(f"{TARGET_URL}?{param}={payload}")
            if r and payload in r.text:
                pytest.fail(
                    f"HTML injection in ?{param}: payload reflected unencoded in response"
                )


class TestOsCommandInjection:
    def test_cmd_injection_no_uid_output(self):
        for param in COMMON_PARAMS[:4]:
            for payload in OS_CMD_PAYLOADS:
                r = safe_get(f"{TARGET_URL}?{param}=test{payload}")
                if r and OS_CMD_INDICATORS.search(r.text):
                    pytest.fail(
                        f"OS command injection: ?{param}=test{payload} returned uid/gid output"
                    )


class TestSsti:
    def test_ssti_numeric_evaluation(self):
        for param in ["template", "name", "msg", "greeting", "q"]:
            for payload in SSTI_PAYLOADS:
                r = safe_get(f"{TARGET_URL}?{param}={payload}")
                if r and any(ind in r.text for ind in SSTI_INDICATORS):
                    pytest.fail(
                        f"SSTI detected: ?{param}={payload!r} evaluates to arithmetic result"
                    )


class TestHeaderInjection:
    def test_host_header_injection(self):
        r = safe_get(TARGET_URL, headers={"Host": "evil.attacker.com"})
        if r is None:
            pytest.skip("request failed")
        # If the response body reflects the injected host without sanitization → vuln
        assert "evil.attacker.com" not in r.text, (
            "Host header injection: injected hostname reflected in response body"
        )

    def test_x_forwarded_for_injection(self):
        r = safe_get(TARGET_URL, headers={"X-Forwarded-For": "<script>xss</script>"})
        if r is None:
            pytest.skip("request failed")
        assert "<script>xss</script>" not in r.text, (
            "X-Forwarded-For header value reflected unencoded in response"
        )


class TestCrlfInjection:
    def test_crlf_in_param(self):
        r = safe_get(f"{TARGET_URL}?redirect={CRLF_PAYLOAD}", allow_redirects=False)
        if r is None:
            pytest.skip("request failed")
        assert "X-Injected-Header" not in r.headers, (
            "CRLF injection: injected header appears in HTTP response headers"
        )

    def test_crlf_in_location_header(self):
        r = safe_get(f"{TARGET_URL}?url=https://example.com%0d%0aX-Injected:evil",
                     allow_redirects=False)
        if r is None:
            pytest.skip("request failed")
        assert "X-Injected" not in r.headers, (
            "CRLF injection via url parameter reflected into response headers"
        )


class TestXpathInjection:
    def test_xpath_probe(self):
        payload = "' or '1'='1"
        for param in ["user", "username", "login", "name"]:
            r = safe_get(f"{TARGET_URL}?{param}={payload}")
            if r and any(e in r.text.lower() for e in
                         ["xpath", "xmlpath", "invalid expression", "xpathexception"]):
                pytest.fail(f"XPath error returned for ?{param}={payload!r}")


class TestGraphQlInjection:
    def test_graphql_introspection_enabled(self):
        query = '{"query":"{__schema{types{name}}}"}'
        for path in ["/graphql", "/api/graphql", "/gql"]:
            r = safe_post(url_join(path), data=query,
                          headers={"Content-Type": "application/json"})
            if r and r.status_code == 200 and "__schema" in r.text:
                pytest.fail(
                    f"GraphQL introspection enabled at {path} — schema exposed"
                )


class TestLogInjection:
    def test_log_injection_via_user_agent(self):
        # We can't read server logs, but we can check if the payload is reflected
        payload = "WhiteClaw-Audit\r\nINJECTED LOG LINE"
        r = safe_get(TARGET_URL, headers={"User-Agent": payload})
        if r is None:
            pytest.skip("request failed")
        assert "INJECTED LOG LINE" not in r.text, (
            "Log injection payload reflected in response body"
        )


# Tests requiring specific application context
class TestSkipped:
    def test_second_order_sqli_requires_stored_context(self):
        pytest.skip("Second-order SQLi requires stored input and a retrieval endpoint — test manually")

    def test_email_header_injection_requires_email_flow(self):
        pytest.skip("Email header injection requires an application email-sending feature")

    def test_csv_injection_requires_auth_export(self):
        pytest.skip("CSV injection requires authenticated access to data export functionality")

    def test_ldap_injection_no_generic_probe(self):
        pytest.skip("LDAP injection requires knowledge of the LDAP filter structure — test manually")

    def test_sqli_time_based_skipped(self):
        pytest.skip(
            "Time-based blind SQLi would cause deliberate server-side delays — "
            "classified as semi-destructive; test manually with sqlmap against an authorized target"
        )
