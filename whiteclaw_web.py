#!/usr/bin/env python3
"""
WhiteClaw WEB — Web Security Scanner.
Authorized penetration testing and vulnerability discovery tool.
For use only on systems you own or have explicit written permission to test.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading
import json
import re
import os
import base64
import urllib.parse
import urllib3
import warnings
from datetime import datetime
from collections import defaultdict
import html as _html_mod
import random
from pathlib import Path

import requests
from bs4 import BeautifulSoup, Comment

try:
    import anthropic as _anthropic_sdk
except ImportError:
    _anthropic_sdk = None

try:
    import openai as _openai_sdk
except ImportError:
    _openai_sdk = None

try:
    from google import genai as _genai_sdk
except ImportError:
    _genai_sdk = None

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore")

# ─────────────────────────────────────────────────────────────────────────────
# Colour palette — green / security scanner
# ─────────────────────────────────────────────────────────────────────────────
BG       = "#0d1117"
BG2      = "#0b1a0d"
BG3      = "#112014"
BG4      = "#1a3020"
FG       = "#c9d1d9"
FG2      = "#8b949e"
GREEN    = "#39d353"
DARK_GRN = "#196127"
BLUE     = "#58a6ff"
YELLOW   = "#d29922"
RED      = "#f85149"
PURPLE   = "#8957e5"

SEV_COLOR = {
    "CRITICAL": RED,
    "HIGH":     YELLOW,
    "MEDIUM":   BLUE,
    "LOW":      GREEN,
    "INFO":     FG2,
}

# ─────────────────────────────────────────────────────────────────────────────
# Scanner constants
# ─────────────────────────────────────────────────────────────────────────────
COMMON_API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/graphql", "/graphiql", "/graphql/playground",
    "/rest", "/rest/v1", "/swagger", "/swagger.json", "/swagger.yaml",
    "/openapi.json", "/openapi.yaml", "/api-docs", "/docs/api",
    "/v1", "/v2", "/v3",
    "/.well-known/openid-configuration",
    "/wp-json", "/wp-json/wp/v2",
    "/admin/api", "/api/admin", "/internal/api",
]

SENSITIVE_PATHS = [
    ("/.env",                    "CRITICAL", "Environment file — may contain DB creds, API keys"),
    ("/.env.local",              "CRITICAL", "Local env file exposed"),
    ("/.env.production",         "CRITICAL", "Production env file exposed"),
    ("/.env.backup",             "CRITICAL", "Backup env file exposed"),
    ("/.env.staging",            "CRITICAL", "Staging env file exposed"),
    ("/.git/HEAD",               "CRITICAL", "Git repository exposed — full source leak possible"),
    ("/.git/config",             "CRITICAL", "Git config exposed"),
    ("/.git/COMMIT_EDITMSG",     "HIGH",     "Git commit message exposed"),
    ("/.git/index",              "CRITICAL", "Git index file exposed — full repo reconstructable"),
    ("/wp-config.php",           "CRITICAL", "WordPress config — DB credentials at risk"),
    ("/wp-config.php.bak",       "CRITICAL", "WordPress config backup exposed"),
    ("/backup.zip",              "CRITICAL", "Backup archive exposed"),
    ("/backup.tar.gz",           "CRITICAL", "Backup archive exposed"),
    ("/backup.sql",              "CRITICAL", "SQL backup exposed"),
    ("/dump.sql",                "CRITICAL", "Database dump exposed"),
    ("/database.sql",            "CRITICAL", "Database SQL exposed"),
    ("/db.sql",                  "CRITICAL", "Database SQL exposed"),
    ("/terraform.tfstate",       "CRITICAL", "Terraform state file — cloud credentials exposed"),
    ("/.vault-token",            "CRITICAL", "HashiCorp Vault token exposed"),
    ("/.ssh/id_rsa",             "CRITICAL", "SSH private key exposed"),
    ("/private-key.pem",         "CRITICAL", "PEM private key exposed"),
    ("/server.key",              "CRITICAL", "TLS server private key exposed"),
    ("/config.php",              "HIGH",     "PHP config file exposed"),
    ("/config.js",               "HIGH",     "JS config file exposed"),
    ("/config.json",             "HIGH",     "JSON config file exposed"),
    ("/config/database.yml",     "HIGH",     "Rails database config exposed"),
    ("/config/secrets.yml",      "HIGH",     "Rails secrets file exposed"),
    ("/settings.py",             "HIGH",     "Python settings file exposed"),
    ("/web.config",              "HIGH",     "IIS web.config exposed"),
    ("/phpinfo.php",             "HIGH",     "PHPInfo leaks server internals"),
    ("/info.php",                "HIGH",     "PHP info page exposed"),
    ("/phpmyadmin",              "HIGH",     "phpMyAdmin DB management panel"),
    ("/pma",                     "HIGH",     "phpMyAdmin short path"),
    ("/adminer.php",             "HIGH",     "Adminer DB tool exposed"),
    ("/_profiler",               "HIGH",     "Symfony profiler exposed"),
    ("/telescope",               "HIGH",     "Laravel Telescope debug dashboard exposed"),
    ("/horizon",                 "HIGH",     "Laravel Horizon queue monitor exposed"),
    ("/storage/logs/laravel.log","HIGH",     "Laravel log file exposed"),
    ("/error.log",               "HIGH",     "Error log exposed"),
    ("/.ssh/authorized_keys",    "HIGH",     "SSH authorized keys file exposed"),
    ("/test.php",                "MEDIUM",   "Test PHP file left on server"),
    ("/server-status",           "MEDIUM",   "Apache server-status exposed"),
    ("/server-info",             "MEDIUM",   "Apache server-info exposed"),
    ("/wp-login.php",            "MEDIUM",   "WordPress login page detected"),
    ("/wp-admin",                "MEDIUM",   "WordPress admin panel"),
    ("/.htaccess",               "MEDIUM",   "htaccess config exposed"),
    ("/access.log",              "MEDIUM",   "Access log exposed"),
    ("/.DS_Store",               "LOW",      "macOS metadata exposes directory structure"),
    ("/package.json",            "LOW",      "package.json reveals dependency versions"),
    ("/package-lock.json",       "LOW",      "package-lock.json reveals full dependency tree"),
    ("/composer.json",           "LOW",      "composer.json reveals PHP dependency versions"),
    ("/Gemfile",                 "LOW",      "Gemfile reveals Ruby dependency versions"),
    ("/yarn.lock",               "LOW",      "yarn.lock reveals full JS dependency tree"),
    ("/swagger-ui.html",         "INFO",     "Swagger UI — full API docs publicly visible"),
    ("/.well-known/security.txt","INFO",     "security.txt vulnerability disclosure policy"),
    ("/robots.txt",              "INFO",     "robots.txt (checked separately)"),
    ("/sitemap.xml",             "INFO",     "sitemap.xml reveals page structure"),
]

SQL_PAYLOADS = [
    "'", '"', "`", "\\", "''",
    "' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1'/*",
    "\" OR \"1\"=\"1", "\" OR \"1\"=\"1\"--",
    "1 OR 1=1", "' OR 1=1--", "admin'--", "' OR 'x'='x",
    "') OR ('1'='1", "') OR 1=1--",
    "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--", "1 UNION SELECT 1,2,3--",
    "0 UNION ALL SELECT NULL--",
    "' AND 1=1--", "' AND 1=2--", "1 AND 1=1--", "1 AND 1=2--",
    "' AND '1'='1", "' AND '1'='2",
    "1/0", "1 AND GTID_SUBSET(1,0)--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
    "1 AND SLEEP(1)--", "1 OR SLEEP(1)--",
    "'; WAITFOR DELAY '0:0:1'--",
    "1; SELECT pg_sleep(1)--",
    "1 AND BENCHMARK(2000000,MD5(1))--",
    "1; SELECT 1--",
    "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
    "' AND SUBSTRING(@@version,1,1)='5'--",
    "%27", "%22", "0x27", "0x22",
    "' OR 1=1%00", "' /*!OR*/ '1'='1", "' OR/**/'1'='1",
    "' HAVING 1=1--", "' GROUP BY 1--",
    "' ORDER BY 1--", "' ORDER BY 100--",
    "' || '1'='1", "1;return true",
    "';SELECT 1;--",
    "' AND EXISTS(SELECT 1 FROM users)--",
]

XSS_MARKER = "wh1t3cl4wXSS"

XSS_PAYLOADS = [
    f"<script>alert('{XSS_MARKER}')</script>",
    f"<img src=x onerror=alert('{XSS_MARKER}')>",
    f"<svg onload=alert('{XSS_MARKER}')>",
    f"<body onload=alert('{XSS_MARKER}')>",
    f"\"><script>alert('{XSS_MARKER}')</script>",
    f"'><script>alert('{XSS_MARKER}')</script>",
    f"</script><script>alert('{XSS_MARKER}')</script>",
    f"<img src=\"x\" onerror=\"alert('{XSS_MARKER}')\">",
    f"<input onfocus=alert('{XSS_MARKER}') autofocus>",
    f"<details open ontoggle=alert('{XSS_MARKER}')>",
    f"<svg/onload=alert('{XSS_MARKER}')>",
    f"<ScRiPt>alert('{XSS_MARKER}')</ScRiPt>",
    f"%3Cscript%3Ealert('{XSS_MARKER}')%3C%2Fscript%3E",
    f"&#60;script&#62;alert('{XSS_MARKER}')&#60;/script&#62;",
    f"\"-alert('{XSS_MARKER}')-\"",
    f"'-alert('{XSS_MARKER}')-'",
    f"<div style=\"width:expression(alert('{XSS_MARKER}'))\">",
    f"<!--<script>--><script>alert('{XSS_MARKER}')</script>",
    f"<script>/*</script><script>*/alert('{XSS_MARKER}')</script>",
    f"<img/src=\"x\"/onerror=alert('{XSS_MARKER}')>",
    f"<img src=x oNeRrOr=alert('{XSS_MARKER}')>",
    f"<select onfocus=alert('{XSS_MARKER}') autofocus>",
    f"<textarea onfocus=alert('{XSS_MARKER}') autofocus>",
    f"{XSS_MARKER}<script>alert(1)</script>",
    XSS_MARKER,
]

DATABASE_ENDPOINTS = [
    ("/phpmyadmin",  "phpMyAdmin"), ("/phpmyadmin/", "phpMyAdmin"),
    ("/pma",         "phpMyAdmin"), ("/adminer.php",  "Adminer"),
    ("/adminer",     "Adminer"),    ("/pgadmin",      "pgAdmin"),
    ("/pgadmin4",    "pgAdmin 4"),  ("/mongo-express","Mongo Express"),
    ("/redis",       "Redis Web"),  ("/redisinsight", "RedisInsight"),
    ("/kibana",      "Kibana"),     ("/_cat",         "Elasticsearch"),
    ("/couchdb",     "CouchDB"),    ("/influxdb",     "InfluxDB"),
]

DB_PORT_PATHS = [
    (":9200","Elasticsearch"),(":27017","MongoDB"),(":5432","PostgreSQL"),
    (":3306","MySQL"),(":6379","Redis"),(":5984","CouchDB"),(":8086","InfluxDB"),
]

JS_SECRET_PATTERNS = [
    (r'(?i)api[_\-]?key\s*[=:]\s*["\']([^"\']{8,})["\']',          "API Key"),
    (r'(?i)api[_\-]?secret\s*[=:]\s*["\']([^"\']{8,})["\']',       "API Secret"),
    (r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{4,})["\']',"Password"),
    (r'(?i)secret[_\-]?key\s*[=:]\s*["\']([^"\']{8,})["\']',       "Secret Key"),
    (r'(?i)(?:auth|access)[_\-]?token\s*[=:]\s*["\']([^"\']{8,})["\']',"Auth Token"),
    (r'AKIA[0-9A-Z]{16}',                                            "AWS Access Key ID"),
    (r'mongodb(?:\+srv)?://[^\s"\'<>]+',                             "MongoDB Connection String"),
    (r'postgres(?:ql)?://[^\s"\'<>]+',                               "PostgreSQL Connection String"),
    (r'redis://[^\s"\'<>]+',                                         "Redis Connection String"),
    (r'(?i)bearer\s+([A-Za-z0-9\-_]{20,})',                         "Bearer Token"),
    (r'ghp_[A-Za-z0-9]{36}',                                        "GitHub PAT"),
    (r'sk-[A-Za-z0-9]{48}',                                         "OpenAI API Key"),
    (r'xox[baprs]-[A-Za-z0-9\-]+',                                  "Slack Token"),
]

SQL_ERROR_STRINGS = [
    "you have an error in your sql", "warning: mysql", "mysql_fetch",
    "pg_query", "pg_exec", "sqlite3", "sqlstate", "ora-0",
    "microsoft sql server", "unclosed quotation",
    "syntax error", "sql syntax", "column not found",
    "table or view not found", "division by zero",
]

COVER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36 h1whiteclaw",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 Version/17.4 Safari/605.1.15 h1whiteclaw",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0 h1whiteclaw",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0 h1whiteclaw",
]

# ─────────────────────────────────────────────────────────────────────────────
# AI provider config
# ─────────────────────────────────────────────────────────────────────────────
PROVIDERS = {
    "Claude (Anthropic)": {
        "sdk":    "_anthropic_sdk",
        "models": ["claude-opus-4-5", "claude-sonnet-4-6", "claude-haiku-4-5-20251001"],
        "hint":   "sk-ant-…",
    },
    "GPT-4o (OpenAI)": {
        "sdk":    "_openai_sdk",
        "models": ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo"],
        "hint":   "sk-…",
    },
    "Gemini (Google)": {
        "sdk":    "_genai_sdk",
        "models": ["gemini-1.5-pro", "gemini-1.5-flash", "gemini-2.0-flash"],
        "hint":   "AIza…",
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# Scanner engine
# ─────────────────────────────────────────────────────────────────────────────
class WhiteClawScanner:
    def __init__(self, url: str, callback):
        self.url = url
        self.base_url = self._base(url)
        self.callback = callback
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "WhiteClaw/1.0 (Authorized Security Testing)",
            "Accept":     "text/html,application/xhtml+xml,application/json,*/*;q=0.9",
        })
        self.session.max_redirects = 5
        self.attack_session = self._make_attack_session()
        self.main_response = None
        self.main_soup = None
        self.findings: dict[str, list] = defaultdict(list)

    def _base(self, url: str) -> str:
        p = urllib.parse.urlparse(url)
        return f"{p.scheme}://{p.netloc}"

    def _get(self, url: str, timeout: int = 8, **kw) -> requests.Response | None:
        try:
            return self.session.get(url, timeout=timeout, verify=False,
                                    allow_redirects=kw.get("follow", True),
                                    **{k: v for k, v in kw.items() if k != "follow"})
        except Exception:
            return None

    def _log(self, category: str, severity: str, title: str,
             detail: str = "", fix: str = "") -> None:
        finding = {
            "category":  category, "severity": severity, "title": title,
            "detail":    detail,   "fix":      fix,
            "timestamp": datetime.now().isoformat(),
        }
        self.findings[category].append(finding)
        self.callback("finding", finding)

    def _status(self, msg: str) -> None:
        self.callback("status", msg)

    def _make_attack_session(self) -> requests.Session:
        s = requests.Session()
        s.headers.update({
            "User-Agent":               random.choice(COVER_AGENTS),
            "Accept":                   "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Language":          "en-US,en;q=0.9",
            "Accept-Encoding":          "gzip, deflate",
            "Connection":               "keep-alive",
            "Upgrade-Insecure-Requests":"1",
        })
        s.max_redirects = 3
        return s

    def _attack_get(self, url: str, timeout: int = 8, **kw) -> requests.Response | None:
        try:
            return self.attack_session.get(
                url, timeout=timeout, verify=False,
                allow_redirects=kw.get("follow", True),
                **{k: v for k, v in kw.items() if k != "follow"},
            )
        except Exception:
            return None

    def run(self) -> None:
        steps = [
            ("Fetching target page",               self._fetch_main),
            ("Analysing HTTP headers",              self._check_headers),
            ("Checking security headers",           self._check_security_headers),
            ("Analysing cookies",                   self._check_cookies),
            ("Testing CORS policy",                 self._check_cors),
            ("Discovering API endpoints",           self._discover_apis),
            ("Scanning JavaScript files",           self._scan_js),
            ("Probing sensitive files",             self._check_sensitive_files),
            ("Probing database interfaces",         self._probe_databases),
            ("Testing SQL injection (40 payloads)", self._test_sqli),
            ("Testing XSS reflection (25 payloads)",self._test_xss),
            ("Checking open redirect",              self._test_open_redirect),
            ("Testing HTTP methods",                self._test_http_methods),
            ("Testing path traversal",              self._test_path_traversal),
            ("Probing SSRF vectors",                self._test_ssrf),
            ("Inspecting forms",                    self._analyze_forms),
            ("Mining CTF / hidden artifacts",       self._mine_ctf),
            ("Reading robots.txt / sitemap",        self._check_robots_sitemap),
        ]
        total = len(steps)
        for i, (label, fn) in enumerate(steps, 1):
            self._status(f"[{i}/{total}] {label}…")
            try:
                fn()
            except Exception as exc:
                self.callback("error", f"{label} failed: {exc}")
        self.callback("done", dict(self.findings))

    def _fetch_main(self) -> None:
        resp = self._get(self.url)
        if resp is None:
            raise RuntimeError(f"Cannot reach {self.url}")
        self.main_response = resp
        self.main_soup = BeautifulSoup(resp.text, "html.parser")
        self._log("info", "INFO", "Target reachable",
                  f"Status {resp.status_code} · {len(resp.content):,} bytes · "
                  f"Content-Type: {resp.headers.get('Content-Type','?')}")

    def _check_headers(self) -> None:
        h = self.main_response.headers
        if "Server" in h:
            self._log("vulnerabilities", "MEDIUM", "Server header discloses version",
                      f"Server: {h['Server']}",
                      "Set ServerTokens Prod (Apache) or server_tokens off (Nginx).")
        if "X-Powered-By" in h:
            self._log("vulnerabilities", "MEDIUM", "Technology stack disclosed via X-Powered-By",
                      f"X-Powered-By: {h['X-Powered-By']}",
                      "Remove this header. Express.js: app.disable('x-powered-by').")
        if "X-Debug-Token" in h or "X-Debug-Token-Link" in h:
            self._log("vulnerabilities", "HIGH", "Symfony debug token exposed",
                      "Full request data accessible via profiler.",
                      "Disable the Symfony profiler in production (APP_ENV=prod).")

    def _check_security_headers(self) -> None:
        h  = self.main_response.headers
        hl = {k.lower(): v for k, v in h.items()}

        missing = [
            ("Strict-Transport-Security",   "HIGH",
             "HSTS missing — vulnerable to SSL stripping.",
             "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"),
            ("X-Frame-Options",             "HIGH",
             "Clickjacking protection missing.",
             "Add: X-Frame-Options: DENY"),
            ("X-Content-Type-Options",      "MEDIUM",
             "MIME-sniffing not disabled.",
             "Add: X-Content-Type-Options: nosniff"),
            ("Content-Security-Policy",     "HIGH",
             "No CSP — XSS has no browser-level mitigation.",
             "Add a strict Content-Security-Policy."),
            ("Referrer-Policy",             "MEDIUM",
             "No Referrer-Policy — full URL sent to third parties.",
             "Add: Referrer-Policy: strict-origin-when-cross-origin"),
            ("Permissions-Policy",          "LOW",
             "No Permissions-Policy — camera/mic/geolocation unrestricted.",
             "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()"),
            ("Cross-Origin-Opener-Policy",  "MEDIUM",
             "No COOP — cross-origin window attacks possible.",
             "Add: Cross-Origin-Opener-Policy: same-origin"),
        ]
        for header, sev, detail, fix in missing:
            if header not in h:
                self._log("vulnerabilities", sev, f"Missing header: {header}", detail, fix)

        csp = hl.get("content-security-policy", "")
        if csp:
            for bad, label in [("'unsafe-inline'", "unsafe-inline"),
                                ("'unsafe-eval'",   "unsafe-eval"),
                                ("*",               "wildcard source")]:
                if bad in csp:
                    self._log("vulnerabilities", "HIGH", f"Dangerous CSP directive: {label}",
                              f"CSP: {csp[:200]}",
                              f"Remove '{bad}' — it negates XSS protection.")

    def _check_cookies(self) -> None:
        for c in self.session.cookies:
            issues = []
            extra = {k.lower(): v for k, v in c._rest.items()} if hasattr(c, "_rest") else {}
            if "httponly" not in extra:
                issues.append("HttpOnly missing")
            if not c.secure:
                issues.append("Secure flag missing")
            if "samesite" not in extra:
                issues.append("SameSite not set")
            if issues:
                self._log("vulnerabilities", "MEDIUM", f"Insecure cookie: {c.name}",
                          " | ".join(issues),
                          "Set cookies with HttpOnly; Secure; SameSite=Strict.")

    def _check_cors(self) -> None:
        resp = self._get(self.url, headers={"Origin": "https://evil-attacker.com"})
        if resp is None:
            return
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
        if acao == "*":
            self._log("vulnerabilities", "HIGH", "CORS wildcard origin (*)",
                      "Any site can read API responses.",
                      "Replace * with an explicit allowlist of trusted origins.")
        elif "evil-attacker.com" in acao:
            sev = "CRITICAL" if acac == "true" else "HIGH"
            self._log("vulnerabilities", sev,
                      "CORS reflects arbitrary Origin" + (" with credentials!" if acac == "true" else ""),
                      f"ACAO: {acao}  ACAC: {acac}",
                      "Validate Origin against a hardcoded allowlist.")

    def _discover_apis(self) -> None:
        found: set[str] = set()
        soup = self.main_soup
        for script in soup.find_all("script"):
            if not script.string:
                continue
            for pat in [r'["\'](/api/[^"\'?\s]{1,120})["\']',
                        r'fetch\s*\(\s*["\']([^"\']+)["\']',
                        r'axios\.\w+\s*\(\s*["\']([^"\']+)["\']']:
                for m in re.findall(pat, script.string):
                    found.add(m)
        for form in soup.find_all("form"):
            action = form.get("action", "")
            if action and not action.startswith("#"):
                found.add(action)
        for ref in found:
            self._log("apis", "INFO", f"API reference in source: {ref}",
                      "Endpoint referenced in page HTML/JS.")
        for path in COMMON_API_PATHS:
            resp = self._get(self.base_url + path, follow=False, timeout=5)
            if resp and resp.status_code in (200, 201, 401, 403):
                ct = resp.headers.get("Content-Type", "")
                self._log("apis", "MEDIUM" if resp.status_code == 200 else "INFO",
                          f"API endpoint found: {path}",
                          f"Status {resp.status_code} · {len(resp.content):,} bytes · {ct}",
                          "Ensure the endpoint requires authentication and rate limiting.")

    def _scan_js(self) -> None:
        soup = self.main_soup
        js_urls: list[str] = []
        for tag in soup.find_all("script", src=True):
            src = tag["src"]
            if src.startswith("//"):
                src = "https:" + src
            elif not src.startswith("http"):
                src = self.base_url + ("" if src.startswith("/") else "/") + src
            js_urls.append(src)
        for url in js_urls[:15]:
            resp = self._get(url, timeout=10)
            if resp is None:
                continue
            for pattern, label in JS_SECRET_PATTERNS:
                for match in re.findall(pattern, resp.text):
                    val = match if isinstance(match, str) else match[0]
                    if len(val) < 6:
                        continue
                    self._log("vulnerabilities", "CRITICAL", f"Secret in JavaScript: {label}",
                              f"File: {url}\nValue (partial): {val[:60]}…",
                              "Move secrets server-side. Never expose them in client JavaScript.")

    def _check_sensitive_files(self) -> None:
        for path, sev, desc in SENSITIVE_PATHS:
            if path in ("/robots.txt", "/sitemap.xml"):
                continue
            resp = self._attack_get(self.base_url + path, follow=False, timeout=5)
            if resp and resp.status_code == 200 and len(resp.content) > 0:
                snippet = resp.text[:200].replace("\n", " ")
                self._log("vulnerabilities", sev, desc,
                          f"Accessible at {self.base_url + path} ({len(resp.content):,} bytes)\n"
                          f"Preview: {snippet}",
                          f"Block or remove `{path}` via server config.")

    def _probe_databases(self) -> None:
        parsed = urllib.parse.urlparse(self.url)
        hostname = parsed.hostname
        for path, name in DATABASE_ENDPOINTS:
            resp = self._get(self.base_url + path, follow=False, timeout=5)
            if resp and resp.status_code in (200, 401, 403):
                self._log("database", "CRITICAL", f"{name} interface accessible",
                          f"Endpoint: {self.base_url + path}  Status: {resp.status_code}",
                          f"Place {name} behind a VPN or firewall.")
        for port_suffix, name in DB_PORT_PATHS:
            url = f"{parsed.scheme}://{hostname}{port_suffix}"
            resp = self._get(url, timeout=4)
            if resp and resp.status_code < 500:
                self._log("database", "CRITICAL", f"{name} port exposed",
                          f"Responding at {url} (Status {resp.status_code})",
                          f"Block {port_suffix} in your firewall.")

    def _test_sqli(self) -> None:
        parsed = urllib.parse.urlparse(self.url)
        params = urllib.parse.parse_qs(parsed.query)
        if not params:
            return
        reported: set[str] = set()
        for param in list(params.keys())[:8]:
            for payload in SQL_PAYLOADS:
                tp = dict(params)
                tp[param] = [params[param][0] + payload]
                turl = parsed._replace(query=urllib.parse.urlencode(tp, doseq=True)).geturl()
                resp = self._attack_get(turl, timeout=7)
                if resp is None:
                    continue
                low = resp.text.lower()
                for err in SQL_ERROR_STRINGS:
                    if err in low and param not in reported:
                        reported.add(param)
                        self._log("vulnerabilities", "CRITICAL",
                                  f"SQL injection in parameter: `{param}`",
                                  f"Payload: {payload!r}\nError matched: «{err}»",
                                  "Use parameterised queries / prepared statements.")
                        break

    def _test_xss(self) -> None:
        parsed = urllib.parse.urlparse(self.url)
        params = urllib.parse.parse_qs(parsed.query)
        if not params:
            return
        reported: set[str] = set()
        for param in list(params.keys())[:8]:
            for payload in XSS_PAYLOADS:
                tp = dict(params)
                tp[param] = [payload]
                turl = parsed._replace(query=urllib.parse.urlencode(tp, doseq=True)).geturl()
                resp = self._attack_get(turl, timeout=7)
                if resp is None:
                    continue
                if "html" not in resp.headers.get("Content-Type", "").lower():
                    continue
                if XSS_MARKER in resp.text and param not in reported:
                    reported.add(param)
                    self._log("vulnerabilities", "HIGH",
                              f"Reflected XSS candidate: parameter `{param}`",
                              f"Payload: {payload[:120]}",
                              "HTML-encode all user input. Use CSP and auto-escaping templates.")

    def _test_open_redirect(self) -> None:
        parsed = urllib.parse.urlparse(self.url)
        params = urllib.parse.parse_qs(parsed.query)
        redirect_params = [p for p in params if any(
            k in p.lower() for k in ("redirect", "return", "next", "url", "goto", "dest")
        )]
        if not redirect_params:
            return
        evil = "https://evil-attacker.com"
        for param in redirect_params:
            tp = dict(params)
            tp[param] = [evil]
            turl = parsed._replace(query=urllib.parse.urlencode(tp, doseq=True)).geturl()
            resp = self._get(turl, follow=False, timeout=7)
            if resp and resp.status_code in (301, 302, 303, 307, 308):
                if "evil-attacker.com" in resp.headers.get("Location", ""):
                    self._log("vulnerabilities", "HIGH",
                              f"Open redirect in parameter: `{param}`",
                              f"Redirects to evil-attacker.com without validation.",
                              "Validate redirect targets against an allowlist.")

    def _test_http_methods(self) -> None:
        dangerous = ["TRACE", "TRACK", "PUT", "DELETE", "PATCH", "PROPFIND"]
        try:
            opts = self.attack_session.options(self.url, timeout=6, verify=False)
            allow = opts.headers.get("Allow", "")
            if allow:
                self._log("vulnerabilities", "INFO", "HTTP OPTIONS reveals allowed methods",
                          f"Allow: {allow}",
                          "Restrict allowed methods in server config.")
                found = [m for m in dangerous if m in allow.upper()]
                if found:
                    self._log("vulnerabilities", "HIGH",
                              f"Dangerous HTTP methods allowed: {', '.join(found)}",
                              f"Allow header: {allow}",
                              "Disable TRACE/TRACK (XST) and PUT/DELETE unless API-required.")
        except Exception:
            pass
        for method in ["TRACE", "TRACK"]:
            try:
                r = self.attack_session.request(method, self.url, timeout=6, verify=False)
                if r and r.status_code not in (400, 403, 404, 405, 501):
                    self._log("vulnerabilities", "HIGH", f"HTTP {method} enabled (XST risk)",
                              f"Status {r.status_code}",
                              f"Disable {method}: TraceEnable off (Apache).")
            except Exception:
                pass

    def _test_path_traversal(self) -> None:
        payloads = [
            "../etc/passwd", "../../etc/passwd", "../../../etc/passwd",
            "....//....//etc/passwd", "..%2F..%2Fetc%2Fpasswd",
            "%252e%252e%252fetc%252fpasswd", "..\\..\\windows\\win.ini",
            "/etc/passwd", "/proc/self/environ",
        ]
        parsed = urllib.parse.urlparse(self.url)
        params = urllib.parse.parse_qs(parsed.query)
        path_params = {k: v for k, v in params.items()
                       if any(x in k.lower() for x in
                              ("file", "path", "dir", "page", "include", "load", "doc", "src"))}
        targets = path_params if path_params else dict(list(params.items())[:3])
        signatures = ["root:x:", "root:0:", "/bin/bash", "[fonts]", "HOME=", "PATH="]
        for param in targets:
            for payload in payloads:
                tp = dict(params)
                tp[param] = [payload]
                turl = parsed._replace(query=urllib.parse.urlencode(tp, doseq=True)).geturl()
                resp = self._attack_get(turl, timeout=7)
                if resp is None:
                    continue
                for sig in signatures:
                    if sig in resp.text:
                        self._log("vulnerabilities", "CRITICAL",
                                  f"Path traversal / LFI in parameter `{param}`",
                                  f"Payload: {payload!r}\nSignature: {sig!r}",
                                  "Whitelist allowed file paths; never pass user input to FS calls.")
                        break

    def _test_ssrf(self) -> None:
        ssrf_payloads = [
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://localhost/", "http://127.0.0.1/",
            "file:///etc/passwd",
        ]
        cloud_sigs = ["ami-id", "instance-id", "computeMetadata", "root:x:", "[fonts]"]
        parsed = urllib.parse.urlparse(self.url)
        params = urllib.parse.parse_qs(parsed.query)
        url_params = {k: v for k, v in params.items()
                      if any(x in k.lower() for x in
                             ("url", "uri", "src", "dest", "redirect", "link", "href",
                              "host", "endpoint", "proxy", "fetch", "load"))}
        if not url_params:
            return
        for param in list(url_params.keys())[:5]:
            for payload in ssrf_payloads:
                tp = dict(params)
                tp[param] = [payload]
                turl = parsed._replace(query=urllib.parse.urlencode(tp, doseq=True)).geturl()
                resp = self._attack_get(turl, timeout=8)
                if resp is None:
                    continue
                for sig in cloud_sigs:
                    if sig in resp.text:
                        self._log("vulnerabilities", "CRITICAL",
                                  f"SSRF in parameter `{param}` — metadata accessible",
                                  f"Payload: {payload}\nSignature: {sig!r}",
                                  "Whitelist allowed URLs. Block IMDSv1. Enforce egress firewall.")
                        break

    def _analyze_forms(self) -> None:
        for form in self.main_soup.find_all("form"):
            method = form.get("method", "GET").upper()
            action = form.get("action", self.url) or self.url
            inputs = form.find_all("input")
            has_csrf = any(
                any(k in (inp.get("name", "") + inp.get("id", "")).lower()
                    for k in ("csrf", "_token", "authenticity_token", "nonce"))
                for inp in inputs
            )
            if method == "POST" and not has_csrf:
                self._log("vulnerabilities", "HIGH",
                          f"POST form without CSRF token (action: {action})",
                          "Form has no anti-CSRF token — susceptible to CSRF.",
                          "Add a per-session CSRF token field and validate server-side.")
            for inp in inputs:
                if inp.get("type", "").lower() == "password":
                    if inp.get("autocomplete", "on").lower() != "off":
                        self._log("vulnerabilities", "LOW",
                                  "Password field with autocomplete enabled",
                                  f"Form action: {action}",
                                  "Add autocomplete='off' to password inputs.")

    def _mine_ctf(self) -> None:
        soup = self.main_soup
        page_text = self.main_response.text
        for comment in soup.find_all(string=lambda t: isinstance(t, Comment)):
            text = str(comment).strip()
            if text:
                self._log("ctf", "MEDIUM", "HTML comment found", f"{text[:300]}",
                          "Strip all HTML comments before deploying to production.")
        for inp in soup.find_all("input", type="hidden"):
            name = inp.get("name", "?")
            value = inp.get("value", "")
            if value:
                self._log("ctf", "LOW", f"Hidden input field: `{name}`",
                          f"value={value[:120]}",
                          "Never trust hidden-field values for security decisions.")
        for m in re.findall(r'"([A-Za-z0-9+/]{24,}={0,2})"', page_text):
            try:
                decoded = base64.b64decode(m + "==").decode("utf-8", errors="ignore")
                if decoded.isprintable() and len(decoded) > 4:
                    self._log("ctf", "INFO", "Base64-encoded string detected",
                              f"Encoded: {m[:60]}…\nDecoded: {decoded[:120]}",
                              "Base64 is trivially reversible — do not use for sensitive data.")
            except Exception:
                pass
        jwt_pat = r'eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+'
        for jwt in re.findall(jwt_pat, page_text):
            parts = jwt.split(".")
            try:
                header  = json.loads(base64.b64decode(parts[0] + "=="))
                payload = json.loads(base64.b64decode(parts[1] + "=="))
                alg = header.get("alg", "?")
                sev = "CRITICAL" if alg.upper() == "NONE" else "HIGH"
                self._log("ctf", sev, f"JWT exposed in page (alg: {alg})",
                          f"Header: {json.dumps(header)}\nPayload: {json.dumps(payload)}",
                          "Store JWTs in HttpOnly cookies. Use RS256/ES256. Never allow alg:none.")
            except Exception:
                pass

    def _check_robots_sitemap(self) -> None:
        resp = self._get(self.base_url + "/robots.txt", timeout=5)
        if resp and resp.status_code == 200:
            self._log("ctf", "INFO", "robots.txt found", resp.text[:800])
            for path in re.findall(r"(?i)Disallow:\s*(\S+)", resp.text):
                if path != "/" and path:
                    self._log("ctf", "INFO", f"robots.txt discloses hidden path: {path}",
                              "Disallowed crawl target may reveal admin or sensitive areas.",
                              "Never use robots.txt to 'hide' sensitive paths — use proper auth.")
        resp = self._get(self.base_url + "/sitemap.xml", timeout=5)
        if resp and resp.status_code == 200:
            urls = re.findall(r"<loc>([^<]+)</loc>", resp.text)
            self._log("ctf", "INFO", f"sitemap.xml found ({len(urls)} URLs)",
                      "Full site URL structure exposed in sitemap.")


# ─────────────────────────────────────────────────────────────────────────────
# AI reporter
# ─────────────────────────────────────────────────────────────────────────────
class AIReporter:
    def __init__(self, provider: str, api_key: str, model: str):
        self.provider = provider
        self.api_key  = api_key
        self.model    = model

    def _build_prompt(self, url: str, findings: dict) -> str:
        flat: list = []
        for items in findings.values():
            flat.extend(items)
        counts: dict = defaultdict(int)
        for f in flat:
            counts[f.get("severity", "INFO")] += 1
        return f"""You are a senior penetration tester writing a professional security report.

Target URL  : {url}
Scan Date   : {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}
Tool        : WhiteClaw WEB v2.0

Severity counts:
  CRITICAL : {counts['CRITICAL']}
  HIGH     : {counts['HIGH']}
  MEDIUM   : {counts['MEDIUM']}
  LOW      : {counts['LOW']}
  INFO     : {counts['INFO']}

Raw findings JSON:
{json.dumps(flat, indent=2)}

Write a complete penetration test report (Markdown):
1. **Executive Summary** — 3-4 sentences for a non-technical audience.
2. **Risk Rating** — Overall rating with justification.
3. **Critical & High Findings** — title, impact, reproduction steps, remediation with code examples, CWE/OWASP.
4. **Medium & Low Findings** — Brief table: Finding | Severity | Quick Fix
5. **Attack Chains** — 1-3 realistic multi-step attack scenarios.
6. **Remediation Roadmap** — Prioritised P1/P2/P3 with estimated effort.
7. **Compliance Notes** — OWASP Top 10, CWE IDs, GDPR/PCI-DSS.

Be specific, technical, and actionable."""

    def generate(self, url: str, findings: dict) -> str:
        prompt = self._build_prompt(url, findings)
        if self.provider == "Claude (Anthropic)":
            if _anthropic_sdk is None:
                raise RuntimeError("anthropic package not installed.")
            client = _anthropic_sdk.Anthropic(api_key=self.api_key)
            msg = client.messages.create(model=self.model, max_tokens=8192,
                                         messages=[{"role": "user", "content": prompt}])
            return msg.content[0].text
        elif self.provider == "GPT-4o (OpenAI)":
            if _openai_sdk is None:
                raise RuntimeError("openai package not installed.")
            client = _openai_sdk.OpenAI(api_key=self.api_key)
            resp = client.chat.completions.create(model=self.model, max_tokens=8192,
                                                   messages=[{"role": "user", "content": prompt}])
            return resp.choices[0].message.content
        elif self.provider == "Gemini (Google)":
            if _genai_sdk is None:
                raise RuntimeError("google-genai package not installed.")
            client = _genai_sdk.Client(api_key=self.api_key)
            return client.models.generate_content(model=self.model, contents=prompt).text
        else:
            raise ValueError(f"Unknown provider: {self.provider}")


# ─────────────────────────────────────────────────────────────────────────────
# GUI
# ─────────────────────────────────────────────────────────────────────────────
class WhiteClawWebApp:
    TABS = [
        ("Vulnerabilities", "vulnerabilities"),
        ("APIs",            "apis"),
        ("Database",        "database"),
        ("CTF Artifacts",   "ctf"),
        ("General Info",    "info"),
        ("AI Report",       "report"),
        ("Scan Log",        "log"),
    ]

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("WhiteClaw WEB — Web Security Scanner")
        self.root.geometry("1280x820")
        self.root.minsize(900, 600)
        self.root.configure(bg=BG)

        self._findings: dict    = {}
        self._sev_counts: dict  = {s: 0 for s in SEV_COLOR}
        self._scan_url          = ""
        self._log_only_var      = tk.BooleanVar(value=False)

        self._build_styles()
        self._build_ui()

    def _build_styles(self) -> None:
        s = ttk.Style()
        s.theme_use("clam")
        s.configure("TFrame",  background=BG)
        s.configure("TLabel",  background=BG, foreground=FG)
        s.configure("TNotebook",     background=BG, borderwidth=0, tabmargins=0)
        s.configure("TNotebook.Tab", background=BG3, foreground=FG2,
                    padding=[14, 5], font=("Consolas", 15))
        s.map("TNotebook.Tab",
              background=[("selected", BG)],
              foreground=[("selected", GREEN)])
        s.configure("Horizontal.TProgressbar",
                    background=GREEN, troughcolor=BG3, borderwidth=0, thickness=4)

    def _build_ui(self) -> None:
        self._build_header()
        self._build_toolbar()
        self._build_status_bar()
        self._build_notebook()

    def _build_header(self) -> None:
        bar = tk.Frame(self.root, bg=BG2, pady=10, padx=20)
        bar.pack(fill="x")
        tk.Label(bar, text="⬡ WhiteClaw WEB",
                 font=("Consolas", 28, "bold"), fg=GREEN, bg=BG2).pack(side="left")
        tk.Label(bar, text="  Web Security Scanner",
                 font=("Consolas", 17), fg=FG2, bg=BG2).pack(side="left", pady=2)
        tk.Label(bar, text="[ Authorized use only ]",
                 font=("Consolas", 15), fg=RED, bg=BG2).pack(side="right")

    def _build_toolbar(self) -> None:
        row1 = tk.Frame(self.root, bg=BG2, padx=20, pady=6)
        row1.pack(fill="x")

        tk.Label(row1, text="URL:", font=("Consolas", 16),
                 fg=FG2, bg=BG2).pack(side="left")
        self._url_var = tk.StringVar()
        url_entry = tk.Entry(row1, textvariable=self._url_var, font=("Consolas", 17),
                             bg=BG3, fg=FG, insertbackground=GREEN,
                             relief="flat", bd=6, width=64)
        url_entry.pack(side="left", padx=8, ipady=3)
        url_entry.insert(0, "https://")
        url_entry.bind("<Return>", lambda _: self._start_scan())

        self._scan_btn = tk.Button(row1, text="  SCAN  ", font=("Consolas", 17, "bold"),
                                   bg=DARK_GRN, fg="white", activebackground="#2ea043",
                                   relief="flat", padx=12, pady=3,
                                   command=self._start_scan)
        self._scan_btn.pack(side="left", padx=4)

        self._export_btn = tk.Button(row1, text="Export Report",
                                     font=("Consolas", 15), bg=BG3, fg=FG2,
                                     activebackground=BG4, relief="flat",
                                     padx=10, pady=3, command=self._export_report,
                                     state="disabled")
        self._export_btn.pack(side="left", padx=4)

        self._export_all_btn = tk.Button(row1, text="Export All Findings",
                                         font=("Consolas", 15), bg=BG3, fg=FG2,
                                         activebackground=BG4, relief="flat",
                                         padx=10, pady=3, command=self._export_all_findings,
                                         state="disabled")
        self._export_all_btn.pack(side="left", padx=4)

        # Log-only checkbox
        tk.Checkbutton(
            row1, text="Log only (no report files)",
            variable=self._log_only_var,
            font=("Consolas", 14), fg=FG2, bg=BG2,
            selectcolor=BG3, activebackground=BG2, activeforeground=GREEN,
            relief="flat",
        ).pack(side="left", padx=12)

        # Row 2: AI settings
        row2 = tk.Frame(self.root, bg=BG2, padx=20, pady=4)
        row2.pack(fill="x")

        tk.Label(row2, text="AI Provider:", font=("Consolas", 16),
                 fg=FG2, bg=BG2).pack(side="left")
        self._provider_var = tk.StringVar(value=list(PROVIDERS.keys())[0])
        provider_cb = ttk.Combobox(row2, textvariable=self._provider_var,
                                   values=list(PROVIDERS.keys()),
                                   state="readonly", width=20, font=("Consolas", 16))
        provider_cb.pack(side="left", padx=8, ipady=2)
        provider_cb.bind("<<ComboboxSelected>>", self._on_provider_change)

        tk.Label(row2, text="Model:", font=("Consolas", 16),
                 fg=FG2, bg=BG2).pack(side="left", padx=(4, 0))
        self._model_var = tk.StringVar(value=PROVIDERS[list(PROVIDERS.keys())[0]]["models"][0])
        self._model_cb = ttk.Combobox(row2, textvariable=self._model_var,
                                      values=PROVIDERS[list(PROVIDERS.keys())[0]]["models"],
                                      state="readonly", width=26, font=("Consolas", 16))
        self._model_cb.pack(side="left", padx=8, ipady=2)

        tk.Label(row2, text="API Key:", font=("Consolas", 16),
                 fg=FG2, bg=BG2).pack(side="left", padx=(8, 0))
        self._key_var = tk.StringVar()
        self._key_hint_var = tk.StringVar(value=PROVIDERS[list(PROVIDERS.keys())[0]]["hint"])
        tk.Entry(row2, textvariable=self._key_var, font=("Consolas", 17),
                 bg=BG3, fg=FG, insertbackground=GREEN,
                 relief="flat", bd=6, show="•", width=36).pack(side="left", padx=8, ipady=3)
        tk.Label(row2, textvariable=self._key_hint_var,
                 font=("Consolas", 15), fg=BG4, bg=BG2).pack(side="left")

    def _on_provider_change(self, _event=None) -> None:
        provider = self._provider_var.get()
        info = PROVIDERS.get(provider, {})
        models = info.get("models", [])
        self._model_cb.config(values=models)
        self._model_var.set(models[0] if models else "")
        self._key_hint_var.set(info.get("hint", ""))

    def _build_status_bar(self) -> None:
        bar = tk.Frame(self.root, bg=BG, padx=20)
        bar.pack(fill="x")
        self._status_var = tk.StringVar(value="Ready — paste a URL and press SCAN.")
        tk.Label(bar, textvariable=self._status_var, font=("Consolas", 15),
                 fg=FG2, bg=BG).pack(side="left", pady=3)
        self._progress = ttk.Progressbar(bar, style="Horizontal.TProgressbar",
                                          mode="indeterminate", length=180)
        self._progress.pack(side="right", pady=3)

        counter_bar = tk.Frame(self.root, bg=BG, padx=20, pady=2)
        counter_bar.pack(fill="x")
        self._counter_labels: dict[str, tk.Label] = {}
        for sev, color in SEV_COLOR.items():
            lbl = tk.Label(counter_bar, text=f"{sev}: 0",
                           font=("Consolas", 15, "bold"), fg=color, bg=BG)
            lbl.pack(side="left", padx=10)
            self._counter_labels[sev] = lbl

    def _build_notebook(self) -> None:
        self._nb = ttk.Notebook(self.root)
        self._nb.pack(fill="both", expand=True, padx=8, pady=6)

        self._text_areas: dict[str, scrolledtext.ScrolledText] = {}

        for tab_name, key in self.TABS:
            frame = tk.Frame(self._nb, bg=BG)
            self._nb.add(frame, text=f"  {tab_name}  ")

            if key == "report":
                btn_bar = tk.Frame(frame, bg=BG)
                btn_bar.pack(fill="x", padx=8, pady=4)
                self._gen_btn = tk.Button(
                    btn_bar, text=">> Generate AI Report",
                    font=("Consolas", 16, "bold"),
                    bg=PURPLE, fg="white", activebackground="#6e40c9",
                    relief="flat", padx=14, pady=4,
                    command=self._generate_ai_report,
                )
                self._gen_btn.pack(side="left")
                tk.Label(btn_bar,
                         text="  Requires a valid AI API key and a completed scan.",
                         font=("Consolas", 15), fg=FG2, bg=BG).pack(side="left")

            ta = scrolledtext.ScrolledText(frame, bg=BG, fg=FG, font=("Consolas", 16),
                                           relief="flat", wrap="word",
                                           insertbackground="white", padx=6, pady=4)
            ta.pack(fill="both", expand=True, padx=4, pady=(0, 4))
            ta.config(state="disabled")
            self._text_areas[key] = ta

            ta.tag_configure("CRITICAL", foreground=RED,    font=("Consolas", 16, "bold"))
            ta.tag_configure("HIGH",     foreground=YELLOW, font=("Consolas", 16, "bold"))
            ta.tag_configure("MEDIUM",   foreground=BLUE)
            ta.tag_configure("LOW",      foreground=GREEN)
            ta.tag_configure("INFO",     foreground=FG2)
            ta.tag_configure("header",   foreground=FG,     font=("Consolas", 16, "bold"))
            ta.tag_configure("fix",      foreground=GREEN)
            ta.tag_configure("sep",      foreground=BG4)
            ta.tag_configure("detail",   foreground=FG2)

    # ── scanning ──────────────────────────────────────────────────────────────

    def _start_scan(self) -> None:
        url = self._url_var.get().strip()
        if not url or url in ("https://", "http://", ""):
            messagebox.showwarning("Input required", "Please enter a target URL.")
            return
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
            self._url_var.set(url)

        for ta in self._text_areas.values():
            ta.config(state="normal")
            ta.delete("1.0", "end")
            ta.config(state="disabled")

        self._findings = {}
        self._sev_counts = {s: 0 for s in SEV_COLOR}
        self._update_counters()
        self._export_btn.config(state="disabled")
        self._export_all_btn.config(state="disabled")
        self._scan_btn.config(state="disabled", text="SCANNING…")
        self._progress.start(12)
        self._scan_url = url

        self._log_to("log", "INFO",
                     f"WhiteClaw WEB scan started: {url}",
                     datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        threading.Thread(target=self._run_scan, args=(url,), daemon=True).start()

    def _run_scan(self, url: str) -> None:
        def cb(event_type: str, data):
            self.root.after(0, self._handle_event, event_type, data)
        WhiteClawScanner(url, cb).run()

    def _handle_event(self, event_type: str, data) -> None:
        if event_type == "status":
            self._status_var.set(data)
            self._log_to("log", "INFO", data)

        elif event_type == "finding":
            cat  = data.get("category", "info")
            sev  = data.get("severity",  "INFO")
            titl = data.get("title",     "")
            det  = data.get("detail",    "")
            fix  = data.get("fix",       "")
            tab = cat if cat in self._text_areas else "info"
            self._log_to(tab, sev, titl, det, fix)
            self._log_to("log", sev, f"[{cat.upper()}] {titl}")
            if sev in self._sev_counts:
                self._sev_counts[sev] += 1
                self._update_counters()

        elif event_type == "error":
            self._log_to("log", "HIGH", f"Error: {data}")

        elif event_type == "done":
            self._findings = data
            self._progress.stop()
            total = sum(self._sev_counts.values())
            self._scan_btn.config(state="normal", text="  SCAN  ")
            self._status_var.set(
                f"Scan complete — {total} finding(s)  "
                f"| CRIT {self._sev_counts['CRITICAL']} "
                f"| HIGH {self._sev_counts['HIGH']} "
                f"| MED {self._sev_counts['MEDIUM']}"
            )
            self._export_btn.config(state="normal")
            self._export_all_btn.config(state="normal")
            self._log_to("log", "INFO", "─" * 60)
            self._log_to("log", "INFO", "Scan complete. Switch to the AI Report tab to generate a report.")
            threading.Thread(
                target=self._save_reports,
                args=(self._scan_url, data),
                daemon=True,
            ).start()

    def _update_counters(self) -> None:
        for sev, lbl in self._counter_labels.items():
            lbl.config(text=f"{sev}: {self._sev_counts[sev]}")

    def _log_to(self, tab: str, sev: str, title: str,
                detail: str = "", fix: str = "") -> None:
        if tab not in self._text_areas:
            tab = "log"
        ta = self._text_areas[tab]
        ta.config(state="normal")
        ta.insert("end", "─" * 70 + "\n", "sep")
        ta.insert("end", f"[{sev}] {title}\n", sev)
        if detail:
            for line in detail.splitlines():
                ta.insert("end", f"  {line}\n", "detail")
        if fix:
            ta.insert("end", f"  ✔ FIX: {fix}\n", "fix")
        ta.insert("end", "\n")
        ta.see("end")
        ta.config(state="disabled")

    # ── AI report ─────────────────────────────────────────────────────────────

    def _generate_ai_report(self) -> None:
        key      = self._key_var.get().strip()
        provider = self._provider_var.get()
        model    = self._model_var.get()
        if not key:
            messagebox.showwarning("API Key required",
                                   f"Paste your {provider} API key in the toolbar.")
            return
        if not self._findings:
            messagebox.showinfo("No scan data", "Run a scan first.")
            return
        ta = self._text_areas["report"]
        ta.config(state="normal")
        ta.delete("1.0", "end")
        ta.insert("end", f"Generating report via {provider} ({model})…\n", "INFO")
        ta.config(state="disabled")
        self._gen_btn.config(state="disabled", text="Generating…")

        def _work():
            try:
                reporter = AIReporter(provider, key, model)
                text = reporter.generate(self._scan_url, self._findings)
                self.root.after(0, self._show_report, text)
            except Exception as exc:
                self.root.after(0, self._show_report, f"Error: {exc}")

        threading.Thread(target=_work, daemon=True).start()

    def _show_report(self, text: str) -> None:
        ta = self._text_areas["report"]
        ta.config(state="normal")
        ta.delete("1.0", "end")
        ta.insert("end", text)
        ta.config(state="disabled")
        self._gen_btn.config(state="normal", text=">> Generate AI Report")
        for idx, (_, key) in enumerate(self.TABS):
            if key == "report":
                self._nb.select(idx)
                break

    # ── report file saving ────────────────────────────────────────────────────

    @staticmethod
    def _provider_name(url: str) -> str:
        try:
            host = urllib.parse.urlparse(url).hostname or "unknown"
            host = re.sub(r'^www\.', '', host)
            name = host.split('.')[0]
            return re.sub(r'[^\w\-]', '_', name) or "unknown"
        except Exception:
            return "unknown"

    def _save_reports(self, url: str, findings: dict) -> None:
        provider = self._provider_name(url)
        here     = Path(os.path.abspath(__file__)).parent
        rdir     = here / "reports" / provider
        rdir.mkdir(parents=True, exist_ok=True)

        now      = datetime.now()
        ts_file  = now.strftime("%Y%m%d_%H%M%S")
        ts_human = now.strftime("%Y-%m-%d %H:%M:%S")

        flat: list[dict] = []
        for items in findings.values():
            flat.extend(items)

        log_only = self._log_only_var.get()

        if not log_only:
            # Write one .txt file per finding
            for idx, f in enumerate(flat, 1):
                sev   = f.get("severity", "INFO")
                title = re.sub(r'[^\w\s\-]', '', f.get("title", "finding"))
                title = re.sub(r'\s+', '_', title.strip())[:60]
                fname = f"{ts_file}_{idx:03d}_{sev}_{title}.txt"
                lines = [
                    "WhiteClaw WEB Finding Report",
                    "=" * 50,
                    f"Target   : {url}",
                    f"Date     : {ts_human}",
                    f"Severity : {sev}",
                    f"Category : {f.get('category', '?')}",
                    "",
                    f"Finding  : {f.get('title', '')}",
                    "",
                ]
                if f.get("detail"):
                    lines += ["Detail:", f.get("detail", ""), ""]
                if f.get("fix"):
                    lines += ["Remediation:", f.get("fix", ""), ""]
                (rdir / fname).write_text("\n".join(lines), encoding="utf-8")

        # Always write scan_log.txt
        sev_counts: dict[str, int] = {}
        for f in flat:
            s = f.get("severity", "INFO")
            sev_counts[s] = sev_counts.get(s, 0) + 1

        separator = "\n" + "=" * 60 + "\n"
        header = (
            f"SCAN SESSION — {ts_human}\n"
            f"Target : {url}\n"
            f"Mode   : {'Log only' if log_only else 'Full reports'}\n"
            f"Total  : {len(flat)} finding(s)  "
            + "  ".join(f"{s}:{n}" for s, n in sorted(sev_counts.items()))
            + "\n"
        )
        body = "\n".join(
            f"  [{f.get('severity','?'):8}] {f.get('title','')}"
            for f in flat
        )
        log_path = rdir / "scan_log.txt"
        with open(log_path, "a", encoding="utf-8") as lf:
            lf.write(separator + header + body + "\n")

        mode_str = "scan_log.txt only" if log_only else f"{len(flat)} files + scan_log.txt"
        self._log_to("log", "INFO",
                     f"Reports saved → reports/{provider}/  ({mode_str})")

    # ── export ────────────────────────────────────────────────────────────────

    def _export_report(self) -> None:
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text file", "*.txt"), ("All files", "*.*")],
            title="Save WhiteClaw WEB Report",
        )
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            f.write("WhiteClaw WEB — Security Report\n")
            f.write(f"Target : {self._scan_url}\n")
            f.write(f"Date   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 70 + "\n\n")
            for tab_name, key in self.TABS:
                content = self._text_areas[key].get("1.0", "end").strip()
                if content:
                    f.write(f"\n{'='*70}\n{tab_name.upper()}\n{'='*70}\n\n")
                    f.write(content + "\n")
        messagebox.showinfo("Exported", f"Report saved:\n{path}")

    def _export_all_findings(self) -> None:
        if not self._findings:
            messagebox.showinfo("No findings", "Run a scan first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text file", "*.txt"), ("All files", "*.*")],
            title="Save All Findings — WhiteClaw WEB",
        )
        if not path:
            return
        flat: list[dict] = []
        for items in self._findings.values():
            flat.extend(items)
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        flat.sort(key=lambda f: sev_order.get(f.get("severity", "INFO"), 5))
        sev_counts: dict[str, int] = {}
        for f in flat:
            s = f.get("severity", "INFO")
            sev_counts[s] = sev_counts.get(s, 0) + 1
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        lines = [
            "WhiteClaw WEB — All Findings Report",
            "=" * 70,
            f"Target : {self._scan_url}",
            f"Date   : {now}",
            f"Total  : {len(flat)} finding(s)",
            "  " + "  ".join(
                f"{s}: {sev_counts[s]}"
                for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
                if s in sev_counts
            ),
            "=" * 70, "",
        ]
        for idx, f in enumerate(flat, 1):
            lines += [
                f"Finding #{idx}", "-" * 50,
                f"Severity : {f.get('severity', '?')}",
                f"Category : {f.get('category', '?')}",
                f"Title    : {f.get('title', '')}",
                "",
            ]
            if f.get("detail"):
                lines += ["Detail:", f.get("detail", ""), ""]
            if f.get("fix"):
                lines += ["Remediation:", f.get("fix", ""), ""]
            lines.append("")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
        messagebox.showinfo("Exported", f"All {len(flat)} findings saved to:\n{path}")


def main() -> None:
    root = tk.Tk()
    WhiteClawWebApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
