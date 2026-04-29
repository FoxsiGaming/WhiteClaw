"""
50 database security tests for scanner/scanner.py.

These tests verify that the scanner correctly detects database exposures on
target web pages — SQL injection errors, exposed admin panels, leaked
credentials in JavaScript, and exposed dump files — without making any real
network requests.

Run: pytest tests/test_database_security.py -v
"""
import sys
import os
import json
import io
from unittest.mock import patch, call

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import scanner.scanner as sc

# ---------------------------------------------------------------------------
# Shared helpers (same pattern as test_scanner_logic.py)
# ---------------------------------------------------------------------------

def _resp(status: int, headers: dict = None, body: bytes = b""):
    return (status, headers or {}, body)

def _cfg(**overrides) -> dict:
    base = {
        "url":      "http://target.example.com?id=1",
        "base_url": "http://target.example.com",
        "params":   ["id"],
        "js_urls":  [],
        "workers":  4,
        "timeout":  5,
    }
    base.update(overrides)
    return base

def capture_findings(fn, *args):
    buf = io.StringIO()
    with patch("scanner.scanner.sys.stdout", buf):
        fn(*args)
    lines = [l for l in buf.getvalue().splitlines() if l.strip()]
    return [json.loads(l) for l in lines]

def only_findings(events):
    return [e for e in events if e.get("type") == "finding"]

def panel_side_effect(trigger_path: str, status_code: int):
    """Returns a mock side_effect that responds with status_code for one path
    and 404 for every other DB panel path."""
    def _side_effect(url, **kwargs):
        if trigger_path in url:
            return _resp(status_code, {}, b"Database admin panel")
        return _resp(404, {}, b"Not Found")
    return _side_effect


# ===========================================================================
# A. SQL Injection — error-signature detection (16 tests)
# ===========================================================================

class TestSqliErrorSignatures:
    """Each _SQL_ERRORS string must trigger a CRITICAL finding when it appears
    in the response body of an injected parameter request."""

    def _sqli_hit(self, error_text: bytes):
        with patch("scanner.scanner._req", return_value=_resp(200, {}, error_text)):
            return only_findings(capture_findings(sc.check_sqli, _cfg()))

    # ── MySQL ─────────────────────────────────────────────────────────────────

    def test_mysql_syntax_error_detected(self):
        findings = self._sqli_hit(b"You have an error in your SQL syntax near '1'")
        assert findings and findings[0]["severity"] == "CRITICAL"

    def test_mysql_warning_detected(self):
        findings = self._sqli_hit(b"Warning: mysql_connect() failed to connect")
        assert findings and findings[0]["severity"] == "CRITICAL"

    def test_mysql_fetch_function_error_detected(self):
        findings = self._sqli_hit(b"supplied argument is not a valid MySQL result resource in mysql_fetch_array()")
        assert findings and findings[0]["severity"] == "CRITICAL"

    def test_mysql_uppercase_error_is_case_insensitive(self):
        # Error messages from real MySQL are often mixed/upper case
        findings = self._sqli_hit(b"YOU HAVE AN ERROR IN YOUR SQL SYNTAX")
        assert findings and findings[0]["severity"] == "CRITICAL"

    # ── PostgreSQL ────────────────────────────────────────────────────────────

    def test_postgresql_pg_query_error_detected(self):
        findings = self._sqli_hit(b"pg_query(): Query failed: ERROR: syntax error at or near")
        assert findings

    def test_postgresql_pg_exec_error_detected(self):
        findings = self._sqli_hit(b"pg_exec() [function.pg-exec]: Query failed")
        assert findings

    def test_postgresql_column_not_found_detected(self):
        findings = self._sqli_hit(b"column not found: ERROR: column \"users\" does not exist")
        assert findings

    def test_postgresql_table_not_found_detected(self):
        findings = self._sqli_hit(b"table or view not found in schema")
        assert findings

    # ── SQLite ────────────────────────────────────────────────────────────────

    def test_sqlite_error_detected(self):
        findings = self._sqli_hit(b"sqlite3.OperationalError: near \"'\": syntax error")
        assert findings

    # ── MSSQL / SQL Server ────────────────────────────────────────────────────

    def test_mssql_server_error_detected(self):
        findings = self._sqli_hit(b"Microsoft SQL Server error '80040e14'")
        assert findings

    def test_mssql_unclosed_quotation_detected(self):
        findings = self._sqli_hit(b"Unclosed quotation mark after the character string '1'")
        assert findings

    def test_mssql_division_by_zero_detected(self):
        findings = self._sqli_hit(b"division by zero error in SQL statement")
        assert findings

    # ── Oracle ────────────────────────────────────────────────────────────────

    def test_oracle_ora_error_detected(self):
        findings = self._sqli_hit(b"ORA-01756: quoted string not properly terminated")
        assert findings

    # ── Generic SQL ──────────────────────────────────────────────────────────

    def test_sqlstate_error_detected(self):
        findings = self._sqli_hit(b"SQLSTATE[42000]: Syntax error or access violation")
        assert findings

    def test_sql_syntax_generic_error_detected(self):
        findings = self._sqli_hit(b"SQL syntax error near ORDER BY clause")
        assert findings

    def test_error_buried_in_large_html_response_still_detected(self):
        # Error is in the middle of a large HTML page
        prefix = b"<html>" + b"<p>Normal content</p>" * 500
        middle = b"pg_query(): Query failed"
        suffix = b"<p>Footer</p>" * 200 + b"</html>"
        findings = self._sqli_hit(prefix + middle + suffix)
        assert findings


# ===========================================================================
# B. SQL Injection — behavioral and edge cases (6 tests)
# ===========================================================================

class TestSqliBehavioral:

    def test_no_params_skips_sqli_check(self):
        events = capture_findings(sc.check_sqli, _cfg(params=[]))
        assert not only_findings(events)

    @patch("scanner.scanner._req", return_value=None)
    def test_request_failure_does_not_crash(self, _):
        events = capture_findings(sc.check_sqli, _cfg())
        assert not only_findings(events)

    @patch("scanner.scanner._req")
    def test_only_one_finding_emitted_per_vulnerable_param(self, mock_req):
        # Every request returns an error; only one finding per param
        mock_req.return_value = _resp(200, {}, b"sql syntax error in query")
        events = capture_findings(sc.check_sqli, _cfg(params=["id"]))
        assert len(only_findings(events)) == 1

    @patch("scanner.scanner._req")
    def test_multiple_vulnerable_params_each_get_finding(self, mock_req):
        mock_req.return_value = _resp(200, {}, b"you have an error in your sql syntax")
        events = capture_findings(sc.check_sqli, _cfg(params=["id", "name", "page"]))
        # One finding per param, so 3 total
        assert len(only_findings(events)) == 3

    @patch("scanner.scanner._req")
    def test_clean_response_produces_no_sqli_finding(self, mock_req):
        mock_req.return_value = _resp(200, {}, b"<html><body>Hello World</body></html>")
        events = capture_findings(sc.check_sqli, _cfg())
        assert not only_findings(events)

    @patch("scanner.scanner._req")
    def test_sql_error_in_json_api_response_detected(self, mock_req):
        # Some apps return JSON error messages that still contain DB error text
        body = b'{"error": "pg_query failed: syntax error at or near \'1\'"}'
        mock_req.return_value = _resp(200, {"Content-Type": "application/json"}, body)
        events = capture_findings(sc.check_sqli, _cfg())
        assert only_findings(events)


# ===========================================================================
# C. Database admin panels — HTTP 200 → CRITICAL (7 tests)
# ===========================================================================

class TestDbPanelsCritical:
    """A 200 response on any DB admin path means unauthenticated access — CRITICAL."""

    @patch("scanner.scanner._req")
    def test_phpmyadmin_root_path_open_is_critical(self, mock_req):
        mock_req.side_effect = panel_side_effect("/phpmyadmin", 200)
        findings = only_findings(capture_findings(sc.check_databases, _cfg()))
        assert any("phpMyAdmin" in f["title"] and f["severity"] == "CRITICAL" for f in findings)

    @patch("scanner.scanner._req")
    def test_pma_shortcut_open_is_critical(self, mock_req):
        mock_req.side_effect = panel_side_effect("/pma", 200)
        findings = only_findings(capture_findings(sc.check_databases, _cfg()))
        assert any("phpMyAdmin" in f["title"] and f["severity"] == "CRITICAL" for f in findings)

    @patch("scanner.scanner._req")
    def test_adminer_php_open_is_critical(self, mock_req):
        mock_req.side_effect = panel_side_effect("/adminer.php", 200)
        findings = only_findings(capture_findings(sc.check_databases, _cfg()))
        assert any("Adminer" in f["title"] and f["severity"] == "CRITICAL" for f in findings)

    @patch("scanner.scanner._req")
    def test_pgadmin_open_is_critical(self, mock_req):
        mock_req.side_effect = panel_side_effect("/pgadmin", 200)
        findings = only_findings(capture_findings(sc.check_databases, _cfg()))
        assert any("pgAdmin" in f["title"] and f["severity"] == "CRITICAL" for f in findings)

    @patch("scanner.scanner._req")
    def test_mongo_express_open_is_critical(self, mock_req):
        mock_req.side_effect = panel_side_effect("/mongo-express", 200)
        findings = only_findings(capture_findings(sc.check_databases, _cfg()))
        assert any("Mongo" in f["title"] and f["severity"] == "CRITICAL" for f in findings)

    @patch("scanner.scanner._req")
    def test_kibana_open_is_critical(self, mock_req):
        mock_req.side_effect = panel_side_effect("/kibana", 200)
        findings = only_findings(capture_findings(sc.check_databases, _cfg()))
        assert any("Kibana" in f["title"] and f["severity"] == "CRITICAL" for f in findings)

    @patch("scanner.scanner._req")
    def test_elasticsearch_cat_endpoint_open_is_critical(self, mock_req):
        mock_req.side_effect = panel_side_effect("/_cat", 200)
        findings = only_findings(capture_findings(sc.check_databases, _cfg()))
        assert any("Elasticsearch" in f["title"] and f["severity"] == "CRITICAL" for f in findings)


# ===========================================================================
# D. Database admin panels — HTTP 302/401/403 → HIGH (7 tests)
# ===========================================================================

class TestDbPanelsHigh:
    """302/401/403 means the panel exists but requires authentication — HIGH severity
    because it confirms the service is running and exposed to the network."""

    @patch("scanner.scanner._req")
    def test_phpmyadmin_trailing_slash_redirect_is_high(self, mock_req):
        mock_req.side_effect = panel_side_effect("/phpmyadmin/", 302)
        findings = only_findings(capture_findings(sc.check_databases, _cfg()))
        assert any("phpMyAdmin" in f["title"] and f["severity"] == "HIGH" for f in findings)

    @patch("scanner.scanner._req")
    def test_adminer_path_requires_auth_is_high(self, mock_req):
        mock_req.side_effect = panel_side_effect("/adminer", 401)
        findings = only_findings(capture_findings(sc.check_databases, _cfg()))
        assert any("Adminer" in f["title"] and f["severity"] == "HIGH" for f in findings)

    @patch("scanner.scanner._req")
    def test_pgadmin4_forbidden_is_high(self, mock_req):
        mock_req.side_effect = panel_side_effect("/pgadmin4", 403)
        findings = only_findings(capture_findings(sc.check_databases, _cfg()))
        assert any("pgAdmin" in f["title"] and f["severity"] == "HIGH" for f in findings)

    @patch("scanner.scanner._req")
    def test_mongoexpress_alternate_path_redirect_is_high(self, mock_req):
        mock_req.side_effect = panel_side_effect("/mongoexpress", 302)
        findings = only_findings(capture_findings(sc.check_databases, _cfg()))
        assert any("Mongo" in f["title"] and f["severity"] == "HIGH" for f in findings)

    @patch("scanner.scanner._req")
    def test_redis_ui_requires_login_is_high(self, mock_req):
        mock_req.side_effect = panel_side_effect("/redis", 401)
        findings = only_findings(capture_findings(sc.check_databases, _cfg()))
        assert any("Redis" in f["title"] and f["severity"] == "HIGH" for f in findings)

    @patch("scanner.scanner._req")
    def test_redisinsight_forbidden_is_high(self, mock_req):
        mock_req.side_effect = panel_side_effect("/redisinsight", 403)
        findings = only_findings(capture_findings(sc.check_databases, _cfg()))
        assert any("Redis" in f["title"] and f["severity"] == "HIGH" for f in findings)

    @patch("scanner.scanner._req")
    def test_couchdb_requires_auth_is_high(self, mock_req):
        mock_req.side_effect = panel_side_effect("/couchdb", 401)
        findings = only_findings(capture_findings(sc.check_databases, _cfg()))
        assert any("CouchDB" in f["title"] and f["severity"] == "HIGH" for f in findings)


# ===========================================================================
# E. Database admin panels — negative / edge cases (3 tests)
# ===========================================================================

class TestDbPanelsNegative:

    @patch("scanner.scanner._req", return_value=_resp(404, {}, b"Not Found"))
    def test_all_panels_return_404_produces_no_findings(self, _):
        findings = only_findings(capture_findings(sc.check_databases, _cfg()))
        assert not findings

    @patch("scanner.scanner._req", return_value=None)
    def test_request_failure_on_all_panels_does_not_crash(self, _):
        events = capture_findings(sc.check_databases, _cfg())
        assert not only_findings(events)

    @patch("scanner.scanner._req")
    def test_http_500_on_panel_path_does_not_trigger_finding(self, mock_req):
        # 500 is NOT in (200, 302, 401, 403) — must not create a finding
        mock_req.return_value = _resp(500, {}, b"Internal Server Error")
        findings = only_findings(capture_findings(sc.check_databases, _cfg()))
        assert not findings


# ===========================================================================
# F. Database credentials leaked in JavaScript files (11 tests)
# ===========================================================================

class TestDbCredentialsInJs:

    def _scan_js(self, js_body: bytes, js_url: str = "http://target.example.com/app.js"):
        cfg = _cfg(js_urls=[js_url])
        with patch("scanner.scanner._req", return_value=_resp(200, {}, js_body)):
            return only_findings(capture_findings(sc.check_js_secrets, cfg))

    def test_mongodb_uri_with_credentials_is_critical(self):
        findings = self._scan_js(b"const db = 'mongodb://admin:s3cr3t@prod-db.example.com:27017/myapp';")
        assert any("MongoDB" in f["title"] and f["severity"] == "CRITICAL" for f in findings)

    def test_mongodb_srv_atlas_uri_is_critical(self):
        # MongoDB Atlas uses the +srv scheme
        findings = self._scan_js(b"const uri = 'mongodb+srv://user:pass@cluster0.mongodb.net/prod';")
        assert any("MongoDB" in f["title"] and f["severity"] == "CRITICAL" for f in findings)

    def test_postgresql_uri_with_credentials_is_critical(self):
        findings = self._scan_js(b"const conn = 'postgresql://dbuser:dbpass@10.0.0.5:5432/mydb';")
        assert any("PostgreSQL" in f["title"] and f["severity"] == "CRITICAL" for f in findings)

    def test_postgres_shorthand_uri_is_critical(self):
        # Some apps use postgres:// (without ql)
        findings = self._scan_js(b"const pgUri = 'postgres://root:hunter2@localhost/shop';")
        assert any("PostgreSQL" in f["title"] and f["severity"] == "CRITICAL" for f in findings)

    def test_redis_uri_with_password_is_high(self):
        findings = self._scan_js(b"const cache = 'redis://:mysecretpassword@redis.internal:6379';")
        assert any("Redis" in f["title"] and f["severity"] == "HIGH" for f in findings)

    def test_hardcoded_db_password_field_is_high(self):
        findings = self._scan_js(b"var config = { password: 'Sup3rS3cr3t!Db', host: 'localhost' };")
        assert any("Password" in f["title"] and f["severity"] == "HIGH" for f in findings)

    def test_multiple_db_credentials_in_one_js_file_all_detected(self):
        js = (
            b"const mongo = 'mongodb://user:pass@db.example.com/prod';\n"
            b"const pg = 'postgresql://admin:secret@pg.example.com/app';\n"
        )
        findings = self._scan_js(js)
        titles = [f["title"] for f in findings]
        assert any("MongoDB" in t for t in titles)
        assert any("PostgreSQL" in t for t in titles)

    def test_clean_js_with_no_db_secrets_produces_no_findings(self):
        findings = self._scan_js(b"console.log('Hello, world!'); function add(a, b) { return a + b; }")
        assert not findings

    @patch("scanner.scanner._req")
    def test_db_uri_auto_discovered_from_html_script_tag(self, mock_req):
        # Page HTML contains a <script src="..."> — scanner fetches it automatically
        page_html = b'<html><body><script src="/js/config.js"></script></body></html>'
        js_body   = b"const db = 'mongodb://app:s3cr3t@db-host:27017/production';"

        def side_effect(url, **kwargs):
            if url.endswith(".js"):
                return _resp(200, {}, js_body)
            return _resp(200, {}, page_html)

        mock_req.side_effect = side_effect
        findings = only_findings(capture_findings(sc.check_js_secrets, _cfg(js_urls=[])))
        assert any("MongoDB" in f["title"] for f in findings)

    def test_mongodb_uri_in_multiline_js_detected(self):
        js = (
            b"// Database configuration\n"
            b"const options = {\n"
            b"  uri: 'mongodb://dbadmin:p@ssw0rd@mongo.example.com:27017/users',\n"
            b"  poolSize: 10\n"
            b"};\n"
        )
        findings = self._scan_js(js)
        assert any("MongoDB" in f["title"] for f in findings)

    def test_redis_uri_minimum_match_detected(self):
        # Minimum-length Redis URI (6 chars of path after redis://)
        findings = self._scan_js(b"var r='redis://localhost';")
        assert any("Redis" in f["title"] for f in findings)


# ===========================================================================
# G. Exposed database dump and backup files (7 tests)
# ===========================================================================

class TestExposedDatabaseFiles:
    """_SENSITIVE_PATHS includes SQL dumps and DB backup files.
    A 200 response on these paths must trigger a CRITICAL finding."""

    def _probe_path(self, path: str, status: int = 200):
        def side_effect(url, **kwargs):
            if path in url:
                return _resp(status, {}, b"database content")
            return _resp(404, {}, b"")
        with patch("scanner.scanner._req", side_effect=side_effect):
            return only_findings(capture_findings(sc.check_sensitive_files, _cfg()))

    def test_sql_backup_file_exposed_is_critical(self):
        findings = self._probe_path("/backup.sql")
        assert any("backup" in f["title"].lower() or "sql" in f["title"].lower()
                   for f in findings)
        assert any(f["severity"] == "CRITICAL" for f in findings)

    def test_database_sql_dump_exposed_is_critical(self):
        findings = self._probe_path("/database.sql")
        assert any(f["severity"] == "CRITICAL" for f in findings)

    def test_dump_sql_exposed_is_critical(self):
        findings = self._probe_path("/dump.sql")
        assert any(f["severity"] == "CRITICAL" for f in findings)

    def test_db_sql_shorthand_exposed_is_critical(self):
        findings = self._probe_path("/db.sql")
        assert any(f["severity"] == "CRITICAL" for f in findings)

    def test_rails_database_config_exposed_is_high(self):
        findings = self._probe_path("/config/database.yml")
        assert findings
        assert any(f["severity"] in ("HIGH", "CRITICAL") for f in findings)

    def test_env_file_with_db_credentials_is_critical(self):
        # .env almost certainly contains DATABASE_URL — CRITICAL severity
        findings = self._probe_path("/.env")
        assert any(f["severity"] == "CRITICAL" for f in findings)

    def test_sensitive_file_returning_404_produces_no_finding(self):
        findings = self._probe_path("/backup.sql", status=404)
        assert not findings
