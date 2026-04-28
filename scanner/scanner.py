#!/usr/bin/env python3
"""
WhiteClaw scanner — Python implementation of the Go scanner checks.
Reads a JSON ScanConfig from stdin, emits newline-delimited JSON findings
to stdout, and terminates with a {"type":"done"} line.
Same protocol as the compiled Go binary.
"""

import json
import re
import sys
import threading
import urllib.parse
import urllib.request
import urllib.error
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ── JSON output helpers ───────────────────────────────────────────────────────

_out_lock = threading.Lock()

def _emit(obj: dict) -> None:
    line = json.dumps(obj)
    with _out_lock:
        sys.stdout.write(line + "\n")
        sys.stdout.flush()

def status(msg: str) -> None:
    _emit({"type": "status", "message": msg})

def finding(severity: str, category: str, title: str, detail: str = "", fix: str = "") -> None:
    _emit({"type": "finding", "severity": severity, "category": category,
           "title": title, "detail": detail, "fix": fix})

def error(msg: str) -> None:
    _emit({"type": "error", "message": msg})

def done() -> None:
    _emit({"type": "done"})

# ── HTTP helpers ──────────────────────────────────────────────────────────────

_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
]
_ua_idx = 0
_ua_lock = threading.Lock()

def _ua() -> str:
    global _ua_idx
    with _ua_lock:
        ua = _USER_AGENTS[_ua_idx % len(_USER_AGENTS)]
        _ua_idx += 1
    return ua

def _req(url: str, method: str = "GET", headers: dict = None,
         max_bytes: int = 512 * 1024, timeout: int = 8,
         follow_redirects: bool = False):
    """Returns (status_code, headers_dict, body_bytes) or None on error."""
    try:
        h = {"User-Agent": _ua(), "Accept": "text/html,application/xhtml+xml,application/json,*/*;q=0.9"}
        if headers:
            h.update(headers)
        req = urllib.request.Request(url, headers=h, method=method)
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=_CTX),
            urllib.request.HTTPRedirectHandler() if follow_redirects
            else _NoRedirectHandler(),
        )
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(max_bytes)
            return resp.status, dict(resp.headers), body
    except urllib.error.HTTPError as e:
        try:
            body = e.read(max_bytes)
        except Exception:
            body = b""
        return e.code, dict(e.headers), body
    except Exception:
        return None

class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None
    def http_error_301(self, req, fp, code, msg, headers): return fp
    def http_error_302(self, req, fp, code, msg, headers): return fp
    def http_error_303(self, req, fp, code, msg, headers): return fp
    def http_error_307(self, req, fp, code, msg, headers): return fp
    def http_error_308(self, req, fp, code, msg, headers): return fp

def _inject_param(url: str, param: str, payload: str) -> str:
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    new_query = urllib.parse.urlencode(qs, doseq=True)
    return parsed._replace(query=new_query).geturl()

# ── Check: server disclosure headers ─────────────────────────────────────────

def check_headers(cfg: dict) -> None:
    status("Checking server disclosure headers...")
    r = _req(cfg["url"], timeout=cfg["timeout"])
    if r is None:
        return
    _, hdrs, _ = r
    disclose = [
        ("Server",              "Set ServerTokens Prod (Apache) or server_tokens off (Nginx)."),
        ("X-Powered-By",        "Remove via app config. Express: app.disable('x-powered-by')."),
        ("X-AspNet-Version",    "Remove in web.config: <httpRuntime enableVersionHeader=\"false\">."),
        ("X-AspNetMvc-Version", "Remove in Application_Start: MvcHandler.DisableMvcResponseHeader = true;"),
        ("X-Generator",         "Remove the generator meta-tag and response header."),
        ("X-Debug-Token",       "Disable the Symfony profiler in production (APP_ENV=prod)."),
        ("X-Debug-Token-Link",  "Disable the Symfony profiler in production (APP_ENV=prod)."),
    ]
    for name, fix in disclose:
        v = hdrs.get(name, "")
        if v:
            finding("LOW", "vulnerabilities",
                    f"Server disclosure: {name}",
                    f"Header {name!r} reveals: {v!r}", fix)

# ── Check: security headers ───────────────────────────────────────────────────

def check_security_headers(cfg: dict) -> None:
    status("Checking security headers...")
    r = _req(cfg["url"], timeout=cfg["timeout"])
    if r is None:
        return
    _, hdrs, _ = r
    rules = [
        ("Strict-Transport-Security",  "HIGH",   "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"),
        ("Content-Security-Policy",    "HIGH",   "Implement a Content-Security-Policy restricting script/style sources."),
        ("X-Frame-Options",            "HIGH",   "Add: X-Frame-Options: DENY"),
        ("X-Content-Type-Options",     "MEDIUM", "Add: X-Content-Type-Options: nosniff"),
        ("Referrer-Policy",            "MEDIUM", "Add: Referrer-Policy: strict-origin-when-cross-origin"),
        ("Permissions-Policy",         "LOW",    "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()"),
        ("Cross-Origin-Opener-Policy", "MEDIUM", "Add: Cross-Origin-Opener-Policy: same-origin"),
    ]
    for name, sev, fix in rules:
        if not hdrs.get(name):
            finding(sev, "vulnerabilities", f"Missing security header: {name}",
                    f"The response does not include the {name!r} header.", fix)

    csp = hdrs.get("Content-Security-Policy", "")
    if csp:
        for bad in ("'unsafe-inline'", "'unsafe-eval'", "* "):
            if bad in csp:
                finding("HIGH", "vulnerabilities",
                        f"Dangerous CSP directive: {bad.strip()}",
                        f"CSP: {csp[:250]}",
                        f"Remove {bad!r} from your CSP — it largely negates XSS protection.")

# ── Check: cookie flags ───────────────────────────────────────────────────────

def check_cookies(cfg: dict) -> None:
    status("Checking cookie security flags...")
    r = _req(cfg["url"], timeout=cfg["timeout"])
    if r is None:
        return
    _, hdrs, _ = r
    raw_cookies = hdrs.get("Set-Cookie", "")
    if not raw_cookies:
        return
    for raw in (raw_cookies if isinstance(raw_cookies, list) else [raw_cookies]):
        low = raw.lower()
        name = raw.split("=", 1)[0].strip()
        if "httponly" not in low:
            finding("MEDIUM", "vulnerabilities", f"Cookie missing HttpOnly: {name}",
                    f"Cookie {name!r} has no HttpOnly attribute — readable by JavaScript.",
                    "Add HttpOnly to all session and authentication cookies.")
        if "secure" not in low:
            finding("MEDIUM", "vulnerabilities", f"Cookie missing Secure flag: {name}",
                    f"Cookie {name!r} can be sent over plain HTTP.",
                    "Add the Secure flag to all cookies.")
        if "samesite" not in low:
            finding("LOW", "vulnerabilities", f"Cookie missing SameSite: {name}",
                    f"Cookie {name!r} has no SameSite restriction.",
                    "Set SameSite=Strict or SameSite=Lax on all cookies.")

# ── Check: CORS ───────────────────────────────────────────────────────────────

def check_cors(cfg: dict) -> None:
    status("Testing CORS policy...")
    r = _req(cfg["url"], headers={"Origin": "https://evil-attacker.com"}, timeout=cfg["timeout"])
    if r is None:
        return
    _, hdrs, _ = r
    acao = hdrs.get("Access-Control-Allow-Origin", "")
    acac = hdrs.get("Access-Control-Allow-Credentials", "").lower()
    if acao == "*":
        finding("MEDIUM", "vulnerabilities", "CORS: wildcard Access-Control-Allow-Origin",
                "Server returns ACAO: * — any origin can read responses.",
                "Restrict ACAO to an explicit allowlist. Never combine * with credentials.")
    if "evil-attacker.com" in acao:
        sev = "CRITICAL" if acac == "true" else "HIGH"
        note = " with credentials — session tokens exfiltrable!" if acac == "true" else ""
        finding(sev, "vulnerabilities", f"CORS: arbitrary Origin reflected{note}",
                f"ACAO: {acao}  ACAC: {acac}",
                "Validate the Origin header against a hardcoded server-side allowlist before reflecting it.")

# ── Check: sensitive files ────────────────────────────────────────────────────

_SENSITIVE_PATHS = [
    ("/.env",                        "Environment file exposed (.env)",              "CRITICAL"),
    ("/.env.local",                  "Local environment file exposed",               "CRITICAL"),
    ("/.env.production",             "Production environment file exposed",          "CRITICAL"),
    ("/.env.backup",                 "Backup environment file exposed",              "CRITICAL"),
    ("/.env.staging",                "Staging environment file exposed",             "CRITICAL"),
    ("/.git/HEAD",                   "Git repository exposed (HEAD)",                "CRITICAL"),
    ("/.git/config",                 "Git config exposed",                           "CRITICAL"),
    ("/.git/COMMIT_EDITMSG",         "Git commit message exposed",                   "HIGH"),
    ("/.git/index",                  "Git index exposed — full repo reconstructable","CRITICAL"),
    ("/wp-config.php",               "WordPress config exposed",                     "CRITICAL"),
    ("/wp-config.php.bak",           "WordPress config backup exposed",              "CRITICAL"),
    ("/backup.zip",                  "Backup archive exposed",                       "CRITICAL"),
    ("/backup.tar.gz",               "Backup archive exposed",                       "CRITICAL"),
    ("/backup.sql",                  "SQL backup exposed",                           "CRITICAL"),
    ("/dump.sql",                    "Database dump exposed",                        "CRITICAL"),
    ("/database.sql",                "Database SQL exposed",                         "CRITICAL"),
    ("/db.sql",                      "Database SQL exposed",                         "CRITICAL"),
    ("/terraform.tfstate",           "Terraform state — cloud credentials exposed",  "CRITICAL"),
    ("/.vault-token",                "HashiCorp Vault token exposed",                "CRITICAL"),
    ("/.ssh/id_rsa",                 "SSH private key exposed",                      "CRITICAL"),
    ("/private-key.pem",             "PEM private key exposed",                      "CRITICAL"),
    ("/server.key",                  "TLS server private key exposed",               "CRITICAL"),
    ("/config.php",                  "PHP config exposed",                           "HIGH"),
    ("/config.js",                   "JS config exposed",                            "HIGH"),
    ("/config.json",                 "JSON config exposed",                          "HIGH"),
    ("/config/database.yml",         "Rails database config exposed",                "HIGH"),
    ("/config/secrets.yml",          "Rails secrets exposed",                        "HIGH"),
    ("/settings.py",                 "Python settings exposed",                      "HIGH"),
    ("/web.config",                  "IIS web.config exposed",                       "HIGH"),
    ("/phpinfo.php",                 "phpinfo() leaks server internals",             "HIGH"),
    ("/info.php",                    "PHP info page exposed",                        "HIGH"),
    ("/_profiler",                   "Symfony profiler exposed",                     "HIGH"),
    ("/telescope",                   "Laravel Telescope debug dashboard",            "HIGH"),
    ("/horizon",                     "Laravel Horizon queue monitor",                "HIGH"),
    ("/storage/logs/laravel.log",    "Laravel log file exposed",                     "HIGH"),
    ("/error.log",                   "Error log exposed",                            "HIGH"),
    ("/.ssh/authorized_keys",        "SSH authorized_keys exposed",                  "HIGH"),
    ("/test.php",                    "Test PHP file on server",                      "MEDIUM"),
    ("/server-status",               "Apache server-status exposed",                 "MEDIUM"),
    ("/server-info",                 "Apache server-info exposed",                   "MEDIUM"),
    ("/wp-login.php",                "WordPress login detected",                     "MEDIUM"),
    ("/wp-admin",                    "WordPress admin panel",                        "MEDIUM"),
    ("/.htaccess",                   "htaccess config exposed",                      "MEDIUM"),
    ("/access.log",                  "Access log exposed",                           "MEDIUM"),
    ("/.DS_Store",                   "macOS .DS_Store exposes directory layout",     "LOW"),
    ("/package.json",                "package.json reveals dependency versions",     "LOW"),
    ("/package-lock.json",           "package-lock.json reveals full dependency tree","LOW"),
    ("/composer.json",               "composer.json reveals PHP dependencies",       "LOW"),
    ("/Gemfile",                     "Gemfile reveals Ruby dependencies",            "LOW"),
    ("/yarn.lock",                   "yarn.lock reveals full JS dependency tree",    "LOW"),
    ("/swagger-ui.html",             "Swagger UI — full API docs public",            "INFO"),
    ("/.well-known/security.txt",    "security.txt vulnerability disclosure policy", "INFO"),
]

def check_sensitive_files(cfg: dict) -> None:
    status(f"Probing {len(_SENSITIVE_PATHS)} sensitive paths...")
    base = cfg["base_url"].rstrip("/")
    workers = min(cfg["workers"], 20)

    def probe(path, title, sev):
        r = _req(base + path, method="HEAD", max_bytes=0, timeout=cfg["timeout"])
        if r and r[0] == 200:
            finding(sev, "vulnerabilities", title,
                    f"Path {base + path!r} returned HTTP 200.",
                    "Remove or restrict access to this path via server configuration.")

    with ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(lambda p: probe(*p), _SENSITIVE_PATHS))

# ── Check: APIs ───────────────────────────────────────────────────────────────

_API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/graphql", "/graphiql", "/graphql/playground",
    "/rest", "/rest/v1",
    "/swagger", "/swagger.json", "/swagger.yaml", "/swagger-ui.html",
    "/openapi.json", "/openapi.yaml",
    "/api-docs", "/docs/api",
    "/v1", "/v2", "/v3",
    "/.well-known/openid-configuration",
    "/wp-json", "/wp-json/wp/v2",
    "/admin/api", "/api/admin", "/internal/api",
]

_ENDPOINT_RE = re.compile(
    r'(?:fetch|axios\.[a-z]+)\s*\(\s*["\']([/][^"\'?\s]{2,80})["\']|["\'](/api/[^"\'?\s]{2,80})["\']'
)

def check_apis(cfg: dict) -> None:
    status("Discovering API endpoints...")
    base = cfg["base_url"].rstrip("/")
    workers = min(cfg["workers"], 20)

    def probe_path(p):
        r = _req(base + p, timeout=cfg["timeout"])
        if r and r[0] < 400:
            sev = "MEDIUM" if r[0] == 200 else "INFO"
            finding(sev, "apis", f"API endpoint found: {p}",
                    f"{base + p} returned HTTP {r[0]}.",
                    "Ensure the endpoint requires authentication and rate-limiting.")

    with ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(probe_path, _API_PATHS))

    r = _req(cfg["url"], timeout=cfg["timeout"])
    if r:
        _, _, body = r
        text = body.decode("utf-8", errors="ignore")
        seen = set()
        extra = []
        for m in _ENDPOINT_RE.finditer(text):
            ep = m.group(1) or m.group(2)
            if ep and ep not in seen:
                seen.add(ep)
                extra.append(ep)
        def probe_extra(ep):
            r2 = _req(base + ep, timeout=cfg["timeout"])
            if r2 and r2[0] < 400:
                finding("INFO", "apis", f"JS-mined API endpoint: {ep}",
                        f"Found in inline JS; {base + ep} returned HTTP {r2[0]}.",
                        "Verify this endpoint enforces proper authentication.")
        with ThreadPoolExecutor(max_workers=workers) as ex:
            list(ex.map(probe_extra, extra))

# ── Check: database admin interfaces ─────────────────────────────────────────

_DB_ENDPOINTS = [
    ("/phpmyadmin",   "phpMyAdmin"),
    ("/phpmyadmin/",  "phpMyAdmin"),
    ("/pma",          "phpMyAdmin"),
    ("/adminer.php",  "Adminer"),
    ("/adminer",      "Adminer"),
    ("/pgadmin",      "pgAdmin"),
    ("/pgadmin4",     "pgAdmin 4"),
    ("/mongo-express","Mongo Express"),
    ("/mongoexpress", "Mongo Express"),
    ("/redis",        "Redis Web UI"),
    ("/redisinsight", "RedisInsight"),
    ("/kibana",       "Kibana"),
    ("/_cat",         "Elasticsearch"),
    ("/couchdb",      "CouchDB"),
]

def check_databases(cfg: dict) -> None:
    status("Probing database admin interfaces...")
    base = cfg["base_url"].rstrip("/")
    workers = min(cfg["workers"], 14)

    def probe(path, name):
        r = _req(base + path, timeout=cfg["timeout"])
        if r and r[0] in (200, 302, 401, 403):
            sev = "CRITICAL" if r[0] == 200 else "HIGH"
            finding(sev, "database", f"DB admin interface accessible: {name}",
                    f"{name} returned HTTP {r[0]} at {base + path}.",
                    f"Restrict {name} to internal networks only. Use IP allowlisting or a VPN.")

    with ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(lambda ep: probe(*ep), _DB_ENDPOINTS))

# ── Check: SQL injection ──────────────────────────────────────────────────────

_SQLI_PAYLOADS = [
    "'", "''", '"', "\\", "1'1",
    "' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1'/*",
    '" OR "1"="1', '" OR "1"="1"--',
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
    "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
    "' AND SUBSTRING(@@version,1,1)='5'--",
    "%27", "%22", "0x27",
    "' OR 1=1%00", "' HAVING 1=1--", "' GROUP BY 1--",
    "' ORDER BY 1--", "' ORDER BY 100--",
    "' || '1'='1",
    "';SELECT 1;--",
    "' AND EXISTS(SELECT 1 FROM users)--",
]

_SQL_ERRORS = [
    "you have an error in your sql syntax", "warning: mysql", "mysql_fetch",
    "pg_query", "pg_exec", "sqlite3", "sqlstate", "ora-0",
    "microsoft sql server", "unclosed quotation", "syntax error", "sql syntax",
    "column not found", "table or view not found", "division by zero",
]

def check_sqli(cfg: dict) -> None:
    if not cfg["params"]:
        status("SQLi: no URL parameters found — skipping.")
        return
    status(f"Testing SQL injection ({len(_SQLI_PAYLOADS)} payloads × {len(cfg['params'])} params)...")
    reported = {}
    lock = threading.Lock()

    def test(param, payload):
        with lock:
            if reported.get(param):
                return
        injected = _inject_param(cfg["url"], param, payload)
        r = _req(injected, max_bytes=256 * 1024, timeout=cfg["timeout"])
        if not r:
            return
        body = r[2].decode("utf-8", errors="ignore").lower()
        for sig in _SQL_ERRORS:
            if sig in body:
                with lock:
                    if not reported.get(param):
                        reported[param] = True
                        finding("CRITICAL", "vulnerabilities",
                                f"SQL injection in parameter {param!r}",
                                f"Payload: {payload!r}\nError signature: {sig!r}\nURL: {injected}",
                                "Use parameterised queries / prepared statements. Never interpolate user input into SQL.")
                return

    jobs = [(p, pl) for p in cfg["params"] for pl in _SQLI_PAYLOADS]
    with ThreadPoolExecutor(max_workers=min(cfg["workers"], 20)) as ex:
        list(ex.map(lambda j: test(*j), jobs))

# ── Check: XSS ───────────────────────────────────────────────────────────────

_XSS_MARKER = "wh1t3cl4wXSS"
_XSS_PAYLOADS = [
    f"<script>alert('{_XSS_MARKER}')</script>",
    f"\"><script>alert('{_XSS_MARKER}')</script>",
    f"'><script>alert('{_XSS_MARKER}')</script>",
    f"</script><script>alert('{_XSS_MARKER}')</script>",
    f"<img src=x onerror=alert('{_XSS_MARKER}')>",
    f"\"><img src=x onerror=alert('{_XSS_MARKER}')>",
    f"<img src=\"x\" onerror=\"alert('{_XSS_MARKER}')\">",
    f"<img/src=\"x\"/onerror=alert('{_XSS_MARKER}')>",
    f"<img src=x oNeRrOr=alert('{_XSS_MARKER}')>",
    f"<svg onload=alert('{_XSS_MARKER}')>",
    f"<svg/onload=alert('{_XSS_MARKER}')>",
    f"\"><svg onload=alert('{_XSS_MARKER}')>",
    f"<body onload=alert('{_XSS_MARKER}')>",
    f"<input onfocus=alert('{_XSS_MARKER}') autofocus>",
    f"<details open ontoggle=alert('{_XSS_MARKER}')>",
    f"<select onfocus=alert('{_XSS_MARKER}') autofocus>",
    f"<textarea onfocus=alert('{_XSS_MARKER}') autofocus>",
    f"<ScRiPt>alert('{_XSS_MARKER}')</ScRiPt>",
    f"%3Cscript%3Ealert('{_XSS_MARKER}')%3C%2Fscript%3E",
    f"&#60;script&#62;alert('{_XSS_MARKER}')&#60;/script&#62;",
    f"\"-alert('{_XSS_MARKER}')-\"",
    f"'-alert('{_XSS_MARKER}')-'",
    f"<div style=\"width:expression(alert('{_XSS_MARKER}'))\">",
    f"<!--<script>--><script>alert('{_XSS_MARKER}')</script>",
    _XSS_MARKER,
]

def check_xss(cfg: dict) -> None:
    if not cfg["params"]:
        status("XSS: no URL parameters found — skipping.")
        return
    status(f"Testing reflected XSS ({len(_XSS_PAYLOADS)} payloads × {len(cfg['params'])} params)...")
    reported = {}
    lock = threading.Lock()

    def test(param, payload):
        with lock:
            if reported.get(param):
                return
        injected = _inject_param(cfg["url"], param, payload)
        r = _req(injected, max_bytes=256 * 1024, timeout=cfg["timeout"])
        if not r:
            return
        status_code, hdrs, body = r
        ct = hdrs.get("Content-Type", "")
        if "html" not in ct.lower():
            return
        if _XSS_MARKER in body.decode("utf-8", errors="ignore"):
            with lock:
                if not reported.get(param):
                    reported[param] = True
                    finding("HIGH", "vulnerabilities",
                            f"Reflected XSS in parameter {param!r}",
                            f"Payload reflected unescaped.\nPayload: {payload[:120]}\nURL: {injected}",
                            "HTML-encode all user input before rendering. Implement a strict Content-Security-Policy.")

    jobs = [(p, pl) for p in cfg["params"] for pl in _XSS_PAYLOADS]
    with ThreadPoolExecutor(max_workers=min(cfg["workers"], 20)) as ex:
        list(ex.map(lambda j: test(*j), jobs))

# ── Check: open redirect ──────────────────────────────────────────────────────

_REDIRECT_PAYLOADS = [
    "https://evil-attacker.com",
    "//evil-attacker.com",
    "/\\evil-attacker.com",
    "https://evil-attacker.com/",
    "https%3A%2F%2Fevil-attacker.com",
    "////evil-attacker.com",
]

def check_open_redirect(cfg: dict) -> None:
    status("Testing open redirect...")
    if not cfg["params"]:
        return
    for param in cfg["params"]:
        for payload in _REDIRECT_PAYLOADS:
            injected = _inject_param(cfg["url"], param, payload)
            r = _req(injected, timeout=cfg["timeout"])
            if not r:
                continue
            code, hdrs, _ = r
            if 300 <= code < 400:
                loc = hdrs.get("Location", "")
                parsed = urllib.parse.urlparse(loc)
                if "evil-attacker.com" in (parsed.netloc or ""):
                    finding("HIGH", "vulnerabilities",
                            f"Open redirect via parameter: {param}",
                            f"Server redirected to evil-attacker.com without validation.\nLocation: {loc}",
                            "Validate redirect destinations against an explicit allowlist. Reject external hosts.")
                    break

# ── Check: HTTP methods ───────────────────────────────────────────────────────

_DANGEROUS_METHODS = ["TRACE", "TRACK", "PUT", "DELETE", "PATCH", "PROPFIND"]

def check_http_methods(cfg: dict) -> None:
    status("Testing dangerous HTTP methods...")
    r = _req(cfg["url"], method="OPTIONS", timeout=cfg["timeout"])
    if r:
        _, hdrs, _ = r
        allow = hdrs.get("Allow", "").upper()
        if allow:
            finding("INFO", "vulnerabilities",
                    "HTTP OPTIONS reveals allowed methods",
                    f"Allow: {allow}",
                    "Restrict allowed methods to GET/POST/HEAD in your server config.")
            for m in _DANGEROUS_METHODS:
                if m in allow:
                    finding("HIGH", "vulnerabilities",
                            f"Dangerous HTTP method enabled: {m}",
                            f"OPTIONS Allow header includes {m}.",
                            f"Disable {m} in your web server configuration.")

    r2 = _req(cfg["url"], method="TRACE",
              headers={"X-Custom-Header": "whiteclaw-xst-probe"}, timeout=cfg["timeout"])
    if r2 and r2[0] == 200:
        finding("MEDIUM", "vulnerabilities",
                "HTTP TRACE enabled — Cross-Site Tracing (XST)",
                f"Server responded {r2[0]} to TRACE request.",
                "Disable TRACE: TraceEnable Off (Apache) or deny_methods TRACE (Nginx).")

# ── Check: path traversal ─────────────────────────────────────────────────────

_TRAVERSAL_PAYLOADS = [
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../etc/passwd%00",
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "..%252F..%252F..%252Fetc%252Fpasswd",
    "....//....//....//etc/passwd",
    "/etc/passwd",
    "/proc/self/environ",
    "..\\..\\windows\\win.ini",
    "../../../../Windows/System32/drivers/etc/hosts",
]

_TRAVERSAL_SIGS = [
    "root:x:", "root:0:", "/bin/bash", "/bin/sh",
    "[fonts]", "home=", "path=", "127.0.0.1   localhost",
]

def check_path_traversal(cfg: dict) -> None:
    if not cfg["params"]:
        status("Path traversal: no URL parameters — skipping.")
        return
    status(f"Testing path traversal ({len(_TRAVERSAL_PAYLOADS)} payloads × {len(cfg['params'])} params)...")
    reported = {}
    lock = threading.Lock()

    def test(param, payload):
        with lock:
            if reported.get(param):
                return
        injected = _inject_param(cfg["url"], param, payload)
        r = _req(injected, max_bytes=64 * 1024, timeout=cfg["timeout"])
        if not r:
            return
        body = r[2].decode("utf-8", errors="ignore").lower()
        for sig in _TRAVERSAL_SIGS:
            if sig in body:
                with lock:
                    if not reported.get(param):
                        reported[param] = True
                        finding("CRITICAL", "vulnerabilities",
                                f"Path traversal / LFI in parameter {param!r}",
                                f"Payload: {payload!r}\nFile signature: {sig!r}\nURL: {injected}",
                                "Validate paths against an allowlist. Use realpath() to ensure the canonical path stays within the expected directory.")
                return

    jobs = [(p, pl) for p in cfg["params"] for pl in _TRAVERSAL_PAYLOADS]
    with ThreadPoolExecutor(max_workers=min(cfg["workers"], 20)) as ex:
        list(ex.map(lambda j: test(*j), jobs))

# ── Check: SSRF ───────────────────────────────────────────────────────────────

_SSRF_TARGETS = [
    ("http://169.254.169.254/latest/meta-data/", "ami-id",         "AWS EC2 IMDSv1 metadata"),
    ("http://169.254.169.254/latest/user-data",  "",               "AWS EC2 user-data"),
    ("http://metadata.google.internal/computeMetadata/v1/", "computeMetadata", "GCP instance metadata"),
    ("http://100.100.100.200/latest/meta-data/",  "metadata",      "Alibaba Cloud metadata"),
    ("http://localhost/",                          "",              "localhost loopback"),
    ("http://127.0.0.1/",                          "",              "localhost (numeric)"),
    ("file:///etc/passwd",                         "root:x:",       "file:// LFI via SSRF"),
]

_URL_PARAM_KEYS = ["url", "uri", "src", "dest", "redirect", "link", "href",
                   "host", "endpoint", "proxy", "fetch", "load", "target"]

def check_ssrf(cfg: dict) -> None:
    if not cfg["params"]:
        return
    targets = [p for p in cfg["params"]
               if any(k in p.lower() for k in _URL_PARAM_KEYS)]
    if not targets:
        return
    status(f"Testing SSRF ({len(targets)} params)...")
    reported = {}
    lock = threading.Lock()

    def test(param, payload, sig, desc):
        with lock:
            if reported.get(param):
                return
        injected = _inject_param(cfg["url"], param, payload)
        r = _req(injected, max_bytes=32 * 1024, timeout=cfg["timeout"],
                 follow_redirects=True)
        if not r:
            return
        code, _, body_b = r
        body = body_b.decode("utf-8", errors="ignore")
        hit = (sig and sig.lower() in body.lower()) or (not sig and code == 200 and body)
        if hit:
            with lock:
                if not reported.get(param):
                    reported[param] = True
                    finding("CRITICAL", "vulnerabilities",
                            f"SSRF via parameter {param!r} ({desc})",
                            f"Server fetched internal resource.\nPayload: {payload}\nURL: {injected}",
                            "Block server-side requests to private IP ranges. Use an allowlist of permitted external domains. Enforce egress firewall rules.")

    jobs = [(p, pl, sig, desc) for p in targets for pl, sig, desc in _SSRF_TARGETS]
    with ThreadPoolExecutor(max_workers=min(cfg["workers"], 20)) as ex:
        list(ex.map(lambda j: test(*j), jobs))

# ── Check: JS secrets ─────────────────────────────────────────────────────────

_JS_PATTERNS = [
    ("AWS Access Key ID",     re.compile(r'(?:AKIA|ASIA|AROA)[A-Z0-9]{16}'),                                   "CRITICAL"),
    ("AWS Secret Key",        re.compile(r'(?i)aws.{0,20}secret.{0,20}["\'][A-Za-z0-9/+=]{40}["\']'),          "CRITICAL"),
    ("Google API Key",        re.compile(r'AIza[0-9A-Za-z\-_]{35}'),                                           "HIGH"),
    ("Stripe Secret Key",     re.compile(r'sk_live_[0-9a-zA-Z]{24,}'),                                         "CRITICAL"),
    ("Stripe Publishable Key",re.compile(r'pk_live_[0-9a-zA-Z]{24,}'),                                         "MEDIUM"),
    ("SendGrid API Key",      re.compile(r'SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}'),                      "HIGH"),
    ("GitHub PAT",            re.compile(r'ghp_[A-Za-z0-9]{36}'),                                              "CRITICAL"),
    ("OpenAI API Key",        re.compile(r'sk-[A-Za-z0-9]{48}'),                                               "CRITICAL"),
    ("Slack Token",           re.compile(r'xox[baprs]-[A-Za-z0-9\-]+'),                                        "HIGH"),
    ("Generic API Key",       re.compile(r'(?i)api[_\-]?key\s*[:=]\s*["\'][A-Za-z0-9_\-]{16,}["\']'),         "HIGH"),
    ("Hardcoded Password",    re.compile(r'(?i)password\s*[:=]\s*["\'][^"\']{6,}["\']'),                       "HIGH"),
    ("MongoDB URI",           re.compile(r'mongodb(?:\+srv)?://[^\s"\'<>]{10,}'),                              "CRITICAL"),
    ("PostgreSQL URI",        re.compile(r'postgres(?:ql)?://[^\s"\'<>]{10,}'),                                "CRITICAL"),
    ("Redis URI",             re.compile(r'redis://[^\s"\'<>]{6,}'),                                           "HIGH"),
    ("JWT Token",             re.compile(r'eyJ[A-Za-z0-9\-_=]+\.eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]+'), "MEDIUM"),
]

_SCRIPT_SRC_RE = re.compile(r'(?i)<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']')

def check_js_secrets(cfg: dict) -> None:
    status("Scanning JavaScript files for hardcoded secrets...")
    base = cfg["base_url"].rstrip("/")
    js_urls = list(cfg.get("js_urls", []))

    if not js_urls:
        r = _req(cfg["url"], timeout=cfg["timeout"])
        if r:
            body = r[2].decode("utf-8", errors="ignore")
            for m in _SCRIPT_SRC_RE.finditer(body):
                src = m.group(1)
                if src.startswith("//"):
                    src = "https:" + src
                elif not src.startswith("http"):
                    src = base + "/" + src.lstrip("/")
                js_urls.append(src)

    if not js_urls:
        status("JSSecrets: no JS files found.")
        return

    def scan_js(js_url):
        r = _req(js_url, max_bytes=2 * 1024 * 1024, timeout=cfg["timeout"])
        if not r:
            return
        src = r[2].decode("utf-8", errors="ignore")
        for name, pattern, sev in _JS_PATTERNS:
            m = pattern.search(src)
            if m:
                snippet = m.group(0)[:80]
                finding(sev, "vulnerabilities",
                        f"Hardcoded secret in JS: {name}",
                        f"File: {js_url}\nMatch: {snippet}",
                        "Move secrets to server-side environment variables. Never ship credentials in client-side bundles.")

    with ThreadPoolExecutor(max_workers=min(cfg["workers"], 10)) as ex:
        list(ex.map(scan_js, js_urls))

# ── Check: robots.txt and sitemap.xml ────────────────────────────────────────

_DISALLOW_RE  = re.compile(r'(?im)^Disallow:\s*(\S+)')
_SITEMAP_RE   = re.compile(r'(?im)^Sitemap:\s*(\S+)')
_SITEMAP_LOC  = re.compile(r'<loc>([^<]+)</loc>')

def check_robots_sitemap(cfg: dict) -> None:
    status("Checking robots.txt and sitemap.xml...")
    base = cfg["base_url"].rstrip("/")

    r = _req(base + "/robots.txt", timeout=cfg["timeout"])
    if r and r[0] == 200:
        text = r[2].decode("utf-8", errors="ignore")
        finding("INFO", "ctf", "robots.txt found",
                text[:800],
                "Never rely on robots.txt to hide sensitive paths — use proper access controls.")
        paths = [m.group(1).strip() for m in _DISALLOW_RE.finditer(text)
                 if m.group(1).strip() not in ("", "/")]
        if paths:
            finding("INFO", "ctf",
                    f"robots.txt discloses {len(paths)} hidden path(s)",
                    "\n".join(paths),
                    "Disallowed paths in robots.txt are public — use server-side auth to protect them.")
        for m in _SITEMAP_RE.finditer(text):
            finding("INFO", "ctf", "Sitemap discovered via robots.txt",
                    f"Sitemap: {m.group(1).strip()}",
                    "Review sitemap entries for unintentionally exposed endpoints.")

    r2 = _req(base + "/sitemap.xml", timeout=cfg["timeout"])
    if r2 and r2[0] == 200:
        body = r2[2].decode("utf-8", errors="ignore")
        urls = _SITEMAP_LOC.findall(body)
        finding("INFO", "ctf",
                f"sitemap.xml accessible ({len(urls)} URLs)",
                f"GET {base}/sitemap.xml returned 200.",
                "Review sitemap entries. If it contains admin or internal URLs, restrict access.")

# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    raw = sys.stdin.buffer.read().decode("utf-8-sig")
    try:
        cfg = json.loads(raw.strip())
    except Exception as e:
        error(f"Failed to parse scan config: {e}")
        done()
        return

    cfg.setdefault("workers", 20)
    cfg.setdefault("timeout", 8)
    cfg.setdefault("params", [])
    cfg.setdefault("js_urls", [])

    checks = [
        check_headers,
        check_security_headers,
        check_cookies,
        check_cors,
        check_sensitive_files,
        check_apis,
        check_databases,
        check_sqli,
        check_xss,
        check_open_redirect,
        check_http_methods,
        check_path_traversal,
        check_ssrf,
        check_js_secrets,
        check_robots_sitemap,
    ]

    with ThreadPoolExecutor(max_workers=len(checks)) as ex:
        futures = [ex.submit(fn, cfg) for fn in checks]
        for f in as_completed(futures):
            try:
                f.result()
            except Exception as e:
                error(f"Check error: {e}")

    done()

if __name__ == "__main__":
    main()
