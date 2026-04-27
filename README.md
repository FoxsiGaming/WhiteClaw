# WhiteClaw CYBR

**Security Toolkit Hub** — Web scanner + CTF cipher solver, split into focused standalone tools.

> **For authorized use only.** Only test systems you own or have explicit written permission to test.

---

## Tools

| Tool | File | Purpose | Color |
|------|------|---------|-------|
| **WhiteClaw CYBR** | `whiteclaw_cybr.py` | Hub launcher | Deep purple |
| **WhiteClaw WEB** | `whiteclaw_web.py` | Web security scanner | Green |
| **WhiteClaw CTF** | `whiteclaw_ctf.py` | Cipher & encoding solver | Amber |

---

## Quick Start

```bash
python start.py
```

`start.py` checks your Python version, installs missing packages, verifies all tool files are present, then opens the **WhiteClaw CYBR** hub. From the hub click either **Launch WhiteClaw WEB** or **Launch WhiteClaw CTF** — each tool opens as a separate independent window.

You can also launch each tool directly:

```bash
python whiteclaw_web.py
python whiteclaw_ctf.py
```

---

## Requirements

- Python 3.9 or newer
- `tkinter` (included with most Python installers; on Linux: `sudo apt install python3-tk`)

Packages installed automatically by `start.py`:

```
requests>=2.31.0
beautifulsoup4>=4.12.0
urllib3>=2.0.0
anthropic>=0.34.0
openai>=1.30.0
google-genai>=1.0.0
```

To install manually:

```bash
pip install -r requirements.txt
```

---

## WhiteClaw WEB

A web vulnerability scanner that runs 18 automated checks against a target URL.

### Usage

1. Paste the target URL in the URL bar (e.g. `https://example.com?id=1`)
2. Press **SCAN** or hit Enter
3. Review findings across the tabs: **Vulnerabilities**, **APIs**, **Database**, **CTF Artifacts**, **General Info**
4. Optionally generate an **AI Report** using Claude / GPT-4o / Gemini

### Scan steps

| # | Check | What it finds |
|---|-------|---------------|
| 1 | Fetch page | Reachability, status, content type |
| 2 | HTTP headers | Version disclosure (Server, X-Powered-By) |
| 3 | Security headers | Missing HSTS, CSP, X-Frame-Options, etc. |
| 4 | Cookies | Missing HttpOnly / Secure / SameSite flags |
| 5 | CORS | Wildcard or reflected-origin misconfig |
| 6 | API discovery | Common paths + inline JS endpoint mining |
| 7 | JavaScript secrets | API keys, tokens, connection strings in JS |
| 8 | Sensitive files | 55 paths: `.env`, `.git`, backups, DB dumps |
| 9 | Database panels | phpMyAdmin, Adminer, pgAdmin, MongoDB, Redis |
| 10 | SQL injection | 40 payloads (union, boolean, time-based, error) |
| 11 | XSS reflection | 25 payloads with unique marker detection |
| 12 | Open redirect | URL parameter injection |
| 13 | HTTP methods | TRACE/TRACK/PUT/DELETE |
| 14 | Path traversal | `../etc/passwd`, Windows paths, encoded variants |
| 15 | SSRF | AWS/GCP metadata, localhost, file:// |
| 16 | Forms | CSRF tokens, password autocomplete |
| 17 | CTF artifacts | HTML comments, hidden inputs, Base64, JWTs |
| 18 | robots.txt / sitemap | Hidden paths, URL structure disclosure |

### Log-only mode

Check **Log only (no report files)** in the toolbar before scanning. When enabled, only `reports/<domain>/scan_log.txt` is written — no individual `.txt` file per finding. Useful when you just want a session summary.

### Report files

After each scan, files are saved to `reports/<domain>/`:

```
reports/
  example/
    20260427_211500_001_CRITICAL_env_file_exposed.txt
    20260427_211500_002_HIGH_Missing_header_HSTS.txt
    ...
    scan_log.txt    ← session summary, always appended
```

Use **Export Report** to save the on-screen text as one `.txt` file, or **Export All Findings** to save all findings sorted by severity into a single structured file.

### AI Report

Select an AI provider and paste your API key in the toolbar, then click **Generate AI Report** after a scan. The report includes executive summary, risk rating, finding details with CWE/OWASP references, attack chains, remediation roadmap, and compliance notes.

Supported providers:

| Provider | Models |
|----------|--------|
| Claude (Anthropic) | claude-opus-4-5, claude-sonnet-4-6, claude-haiku-4-5 |
| GPT-4o (OpenAI) | gpt-4o, gpt-4o-mini, gpt-4-turbo |
| Gemini (Google) | gemini-1.5-pro, gemini-1.5-flash, gemini-2.0-flash |

---

## WhiteClaw CTF

An auto-solver for CTF cipher and encoding challenges. Paste ciphertext and press **AUTO-SOLVE** — the engine tries all supported methods recursively (up to 8 nesting levels) to find a flag.

### Supported methods

| Method | Notes |
|--------|-------|
| JWT decode | Extracts header and payload |
| Hex | Space / colon / underscore separators |
| Binary | 8-bit aligned |
| Base64 | Standard + URL-safe |
| Base32 | RFC 4648 |
| Base85 | Python base85 + ASCII85 (`<~ ~>`) |
| Base58 | Bitcoin alphabet |
| URL decode | Percent-encoding |
| HTML entities | `&amp;`, `&#65;`, etc. |
| Morse code | Dot/dash with `/` word separator |
| ROT13 | Letter substitution |
| ROT47 | All printable ASCII |
| Caesar | Brute-forces all 25 shifts, picks best English score |
| Atbash | Mirror alphabet |
| XOR single-byte | Brute-forces keys 0x01–0xFF (input must be hex-encoded) |
| RSA detection | Finds `n`, `e`, `c` parameters and prints solution steps |

### Performance

The XOR solver uses a byte-frequency histogram and precomputed tables so each of the 255 keys is scored in O(256 distinct bytes) rather than O(n·255) with string allocations. Caesar, Atbash, and ROT47 use `str.translate` (C-level) instead of per-character Python loops.

### Tips

- **XOR**: input must be the raw ciphertext as a hex string (e.g. `4a2f3c…`), not ASCII.
- **Caesar table**: shows all 25 rotations sorted by English frequency score. Useful when auto-solve doesn't find a flag.
- **Custom flag regex**: override the default multi-platform pattern for non-standard CTF flag formats.
- **Ctrl+Enter**: keyboard shortcut to run auto-solve.
- **Save result**: exports the current output to a `.txt` file.
- The **history panel** on the right tracks all solves in the session; click any entry to reload it.

---

## File structure

```
WhiteClaw/
├── start.py             ← Run this first
├── whiteclaw_cybr.py    ← Hub GUI (WhiteClaw CYBR)
├── whiteclaw_web.py     ← Web scanner (WhiteClaw WEB)
├── whiteclaw_ctf.py     ← CTF solver (WhiteClaw CTF)
├── whiteclaw.py         ← Original monolithic version (kept as reference)
├── requirements.txt     ← Pip package list
├── reports/             ← Scan output (created automatically)
│   └── <domain>/
│       ├── scan_log.txt
│       └── *.txt
└── README.md
```

---

## Legal notice

WhiteClaw is designed for authorized security testing, CTF competitions, and educational research. Running active scans (SQL injection, XSS, path traversal, SSRF) against systems without explicit permission is illegal in most jurisdictions. The authors accept no liability for misuse.
