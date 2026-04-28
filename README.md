# WhiteClaw CYBR

**Security Toolkit Hub** — Web vulnerability scanner + CTF cipher solver.

> **For authorized use only.** Only test systems you own or have explicit written permission to test.

---

## Getting Started

### 1. Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| **Python** | 3.10 or newer | [python.org/downloads](https://www.python.org/downloads/) — tick **"Add Python to PATH"** during install |
| **Go** *(optional)* | 1.22+ | [go.dev/dl](https://go.dev/dl/) — enables the fast Go scanner |
| **Node.js** *(optional)* | LTS | [nodejs.org](https://nodejs.org/) — enables the Playwright DOM crawler |

tkinter ships with the standard Python installer on Windows and macOS. Linux users may need `sudo apt install python3-tk`.

---

### 2. Download

**Option A — Git clone**
```bash
git clone https://github.com/FoxsiGaming/WhiteClaw.git
cd WhiteClaw
```

**Option B — ZIP download**

1. Click the green **Code** button on the GitHub page
2. Select **Download ZIP**
3. Extract the ZIP and open a terminal inside the extracted folder

---

### 3. Install & Run

#### Quick start (Python only)

Run the startup script — it checks your Python version, installs missing packages automatically, then launches the hub:

```bash
python start.py
```

That's it. The **WhiteClaw CYBR** hub window opens. From there, click **Launch WhiteClaw WEB** or **Launch WhiteClaw CTF**.

---

#### Full setup (Go scanner + Node.js crawler)

For full performance, run the installer first. It builds the Go scanner binary and the TypeScript/Playwright crawler, then prints a readiness table:

```bash
python installer.py
```

After the installer completes, launch normally:

```bash
python start.py
```

---

#### Manual package install (optional)

If you prefer to install dependencies yourself before running:

```bash
pip install -r requirements.txt
```

---

### 4. Launch individual tools directly

```bash
python whiteclaw_cybr.py   # Hub
python whiteclaw_web.py    # Web scanner only
python whiteclaw_ctf.py    # CTF solver only
```

---

## Tools

| Tool | File | Purpose |
|------|------|---------|
| **WhiteClaw CYBR** | `whiteclaw_cybr.py` | Hub launcher |
| **WhiteClaw WEB** | `whiteclaw_web.py` | Web security scanner |
| **WhiteClaw CTF** | `whiteclaw_ctf.py` | Cipher & encoding solver |

---

## WhiteClaw WEB

A web vulnerability scanner that runs 18 automated checks against a target URL.

### Usage

1. Paste the target URL in the URL bar (e.g. `https://example.com?id=1`)
2. Press **SCAN** or hit Enter
3. Review findings across the tabs: **Vulnerabilities**, **APIs**, **Database**, **CTF Artifacts**, **General Info**
4. Optionally generate an **AI Report** using Claude / GPT-4o / Gemini

### Scan checks

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

Check **Log only (no report files)** in the toolbar before scanning. Only `reports/<domain>/scan_log.txt` is written — no individual `.txt` file per finding. Useful for quick session summaries.

### Report files

After each scan, files are saved to `reports/<domain>/`:

```
reports/
  example/
    20260427_211500_001_CRITICAL_env_file_exposed.txt
    20260427_211500_002_HIGH_Missing_header_HSTS.txt
    ...
    scan_log.txt
```

Use **Export Report** to save the on-screen text as one `.txt` file, or **Export All Findings** to save all findings sorted by severity into a single structured file.

### AI Report

Select an AI provider and paste your API key in the toolbar, then click **Generate AI Report** after a scan. The report includes executive summary, risk rating, finding details with CWE/OWASP references, attack chains, remediation roadmap, and compliance notes.

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

### Tips

- **XOR**: input must be the raw ciphertext as a hex string (e.g. `4a2f3c…`), not ASCII.
- **Caesar table**: shows all 25 rotations sorted by English frequency score.
- **Custom flag regex**: override the default multi-platform pattern for non-standard CTF flag formats.
- **Ctrl+Enter**: keyboard shortcut to run auto-solve.
- **Save result**: exports the current output to a `.txt` file.
- The **history panel** on the right tracks all solves in the session; click any entry to reload it.

---

## File structure

```
WhiteClaw/
├── start.py             ← Run this to launch the app
├── installer.py         ← Run this for full setup (Go + Node.js)
├── whiteclaw_cybr.py    ← Hub GUI (WhiteClaw CYBR)
├── whiteclaw_web.py     ← Web scanner (WhiteClaw WEB)
├── whiteclaw_ctf.py     ← CTF solver (WhiteClaw CTF)
├── requirements.txt     ← Pip package list
├── scanner/             ← Go scanner source + binary
├── crawler/             ← TypeScript/Playwright crawler source
└── reports/             ← Scan output (created automatically)
    └── <domain>/
        ├── scan_log.txt
        └── *.txt
```

---

## Legal notice

WhiteClaw is designed for authorized security testing, CTF competitions, and educational research. Running active scans (SQL injection, XSS, path traversal, SSRF) against systems without explicit permission is illegal in most jurisdictions. The authors accept no liability for misuse.
