#!/usr/bin/env python3
"""
WhiteClaw crawler — Python implementation of the TS/Playwright crawler checks.
Reads a JSON ScanConfig from stdin, emits newline-delimited JSON findings
to stdout, and terminates with a {"type":"done"} line.
Uses only stdlib + optional html.parser (no Playwright required).
"""

import base64
import html.parser
import json
import re
import sys
import urllib.parse
import urllib.request
import urllib.error
import ssl

# ── JSON output helpers ───────────────────────────────────────────────────────

def _emit(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
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

# ── HTTP helper ───────────────────────────────────────────────────────────────

_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE

_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

def _fetch(url: str, timeout: int = 30) -> tuple | None:
    """Returns (status, headers_dict, body_str) or None."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": _UA})
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(2 * 1024 * 1024).decode("utf-8", errors="ignore")
            return resp.status, dict(resp.headers), body
    except urllib.error.HTTPError as e:
        try:
            body = e.read(512 * 1024).decode("utf-8", errors="ignore")
        except Exception:
            body = ""
        return e.code, dict(e.headers), body
    except Exception:
        return None

# ── Cookie checks (equivalent to spaFetch.ts) ─────────────────────────────────

def check_cookies(cfg: dict) -> None:
    status("Crawler: checking Set-Cookie flags...")
    r = _fetch(cfg["url"], timeout=cfg.get("timeout", 30000) // 1000)
    if r is None:
        return
    _, hdrs, _ = r
    raw = hdrs.get("Set-Cookie", "")
    cookies = raw if isinstance(raw, list) else ([raw] if raw else [])
    for raw_c in cookies:
        low = raw_c.lower()
        name = raw_c.split("=", 1)[0].strip()
        if "httponly" not in low:
            finding("MEDIUM", "vulnerabilities",
                    f"Cookie missing HttpOnly: {name}",
                    f"Cookie {name!r} is readable by JavaScript.",
                    "Add HttpOnly to all session/auth cookies.")
        if "secure" not in low:
            finding("MEDIUM", "vulnerabilities",
                    f"Cookie missing Secure flag: {name}",
                    f"Cookie {name!r} can be transmitted over HTTP.",
                    "Add the Secure flag to all cookies.")
        if "samesite" not in low:
            finding("LOW", "vulnerabilities",
                    f"Cookie missing SameSite: {name}",
                    f"Cookie {name!r} has no SameSite restriction.",
                    "Set SameSite=Strict or SameSite=Lax on all cookies.")

# ── HTML parser for forms, comments, hidden inputs ───────────────────────────

class _PageParser(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self._forms: list[dict] = []
        self._current_form: dict | None = None
        self.comments: list[str] = []
        self.hidden_inputs: list[dict] = []
        self.inline_scripts: list[str] = []
        self._in_script = False
        self._script_buf = ""

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self._current_form = {
                "action": a.get("action", ""),
                "method": (a.get("method", "GET")).upper(),
                "inputs": [],
            }
            self._forms.append(self._current_form)
        elif tag == "input":
            inp = {
                "name": a.get("name") or a.get("id") or "(unnamed)",
                "type": a.get("type", "text"),
                "value": a.get("value", ""),
                "autocomplete": a.get("autocomplete"),
            }
            if self._current_form is not None:
                self._current_form["inputs"].append(inp)
            if inp["type"] == "hidden" and inp["value"]:
                self.hidden_inputs.append(inp)
        elif tag == "script" and "src" not in a:
            self._in_script = True
            self._script_buf = ""

    def handle_endtag(self, tag):
        if tag == "form":
            self._current_form = None
        elif tag == "script" and self._in_script:
            self._in_script = False
            if self._script_buf.strip():
                self.inline_scripts.append(self._script_buf)
            self._script_buf = ""

    def handle_data(self, data):
        if self._in_script:
            self._script_buf += data

    def handle_comment(self, data):
        txt = data.strip()
        if len(txt) > 3:
            self.comments.append(txt)

    @property
    def forms(self):
        return self._forms

# ── Form analysis (equivalent to forms.ts) ────────────────────────────────────

_CSRF_KEYS = ["csrf", "_token", "authenticity_token", "nonce", "xsrf"]

def check_forms(body: str, page_url: str) -> None:
    status("Crawler: analysing forms (CSRF, autocomplete)...")
    parser = _PageParser()
    try:
        parser.feed(body)
    except Exception:
        pass

    for i, form in enumerate(parser.forms, 1):
        inputs = form["inputs"]
        has_csrf = any(
            any(k in inp["name"].lower() for k in _CSRF_KEYS)
            for inp in inputs
        )
        has_password = any(inp["type"] == "password" for inp in inputs)

        if (form["method"] == "POST" or has_password) and not has_csrf:
            action = form["action"] or page_url
            finding("HIGH", "vulnerabilities",
                    f"Form #{i} missing CSRF token",
                    f"{form['method']} form (action: {action}) has no detectable CSRF token among {len(inputs)} input(s).",
                    "Add a synchroniser token or double-submit cookie CSRF defence to all state-changing forms.")

        for inp in inputs:
            if inp["type"] == "password" and inp["autocomplete"] not in ("off", "new-password", "current-password"):
                action = form["action"] or page_url
                finding("LOW", "vulnerabilities",
                        "Password field allows browser autocomplete",
                        f"Input {inp['name']!r} in form (action: {action}) has autocomplete={inp['autocomplete']!r}.",
                        'Set autocomplete="new-password" on registration fields and autocomplete="current-password" on login fields.')

    if parser.forms:
        status(f"Crawler: analysed {len(parser.forms)} form(s).")

    return parser  # reuse parsed data for DOM checks

# ── DOM analysis (equivalent to dom.ts) ───────────────────────────────────────

_B64_RE = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
_JWT_RE = re.compile(r'eyJ[A-Za-z0-9\-_=]+\.eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]+')

def check_dom(parser: _PageParser) -> None:
    status("Crawler: mining rendered DOM for hidden artifacts...")

    for comment in parser.comments:
        snippet = comment[:250] + ("..." if len(comment) > 250 else "")
        finding("LOW", "ctf",
                "HTML comment in rendered DOM",
                snippet,
                "Strip all HTML comments from production builds — they can leak credentials, paths, or logic.")

    for inp in parser.hidden_inputs:
        val = inp["value"]
        name = inp["name"]

        jwt_m = _JWT_RE.search(val)
        if jwt_m:
            tok = jwt_m.group(0)
            parts = tok.split(".")
            try:
                def _b64d(s):
                    s += "=="
                    return json.loads(base64.b64decode(s).decode("utf-8", errors="ignore"))
                header  = _b64d(parts[0])
                payload = _b64d(parts[1])
                alg = header.get("alg", "?")
                sev = "CRITICAL" if str(alg).upper() == "NONE" else "HIGH"
                finding(sev, "ctf",
                        f'JWT in hidden input: "{name}" (alg: {alg})',
                        f"Header: {json.dumps(header)}\nPayload: {json.dumps(payload)}",
                        "Do not store JWTs in hidden form fields. Use HttpOnly cookies. Never allow alg:none.")
            except Exception:
                finding("MEDIUM", "ctf",
                        f'JWT token in hidden input: "{name}"',
                        tok[:100],
                        "Do not store JWTs in hidden form fields. Use HttpOnly cookies.")
            continue

        b64_ms = _B64_RE.findall(val)
        found_b64 = False
        for match in b64_ms:
            try:
                decoded = base64.b64decode(match + "==").decode("utf-8", errors="ignore")
                if re.search(r'[\x20-\x7e]{8,}', decoded):
                    finding("LOW", "ctf",
                            f'Base64 blob in hidden input: "{name}"',
                            f"Encoded: {match[:60]}\nDecoded: {decoded[:120]}",
                            "Base64 is reversible — do not use it to obscure sensitive data.")
                    found_b64 = True
            except Exception:
                pass

        if not found_b64:
            finding("INFO", "ctf",
                    f'Hidden input field: "{name}"',
                    f"value={val[:120]}",
                    "Never trust hidden-field values for security decisions — they are trivially tampered.")

    inline_text = "\n".join(parser.inline_scripts)
    jwt_in_script = _JWT_RE.search(inline_text)
    if jwt_in_script:
        tok = jwt_in_script.group(0)
        finding("HIGH", "ctf",
                "JWT hardcoded in inline script",
                tok[:150] + ("..." if len(tok) > 150 else ""),
                "Never hardcode JWT tokens in client-side JavaScript.")

# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    raw = sys.stdin.buffer.read().decode("utf-8-sig")
    try:
        cfg = json.loads(raw.strip())
    except Exception as e:
        error(f"Failed to parse crawler config: {e}")
        done()
        return

    timeout_ms = cfg.get("timeout", 30000)
    timeout_s  = max(5, timeout_ms // 1000)

    check_cookies(cfg)

    r = _fetch(cfg["url"], timeout=timeout_s)
    if r is None:
        error(f"Crawler: could not fetch {cfg['url']}")
        done()
        return

    _, _, body = r
    parser = check_forms(body, cfg["url"])
    check_dom(parser)

    done()

if __name__ == "__main__":
    main()
