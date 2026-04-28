#!/usr/bin/env python3
"""
WhiteClaw — Installer / Setup Checker
Run this first before using whiteclaw_web.py.

  python installer.py

What it does:
  1. Checks Python version (3.10+ required)
  2. Installs Python AI packages (anthropic, openai, google-genai)
  3. Checks for Go — if found, compiles scanner/whiteclaw-scanner.exe
  4. Checks for Node.js — if found, installs npm deps and compiles crawler
  5. Prints a final readiness table so you know exactly what works
"""

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

# Force UTF-8 output so Unicode characters work on all terminals
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# ── ANSI colour helpers (Windows 10+ supports VT100 via kernel32) ─────────────

def _enable_ansi() -> None:
    if sys.platform == "win32":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except Exception:
            pass

_enable_ansi()

RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
RED    = "\033[31m"
CYAN   = "\033[36m"
WHITE  = "\033[97m"

def ok(msg: str)   -> None: print(f"  {GREEN}[OK]{RESET}  {msg}")
def warn(msg: str) -> None: print(f"  {YELLOW}[!]{RESET}   {msg}")
def fail(msg: str) -> None: print(f"  {RED}[X]{RESET}  {msg}")
def info(msg: str) -> None: print(f"  {CYAN}-->{RESET}  {msg}")
def head(msg: str) -> None: print(f"\n{BOLD}{WHITE}{msg}{RESET}")
def sep()          -> None: print(f"  {DIM}{'-' * 58}{RESET}")

# ── helpers ───────────────────────────────────────────────────────────────────

def _run(cmd: list[str], cwd: Path | None = None) -> tuple[int, str, str]:
    """Run a command, return (returncode, stdout, stderr)."""
    try:
        r = subprocess.run(
            cmd, cwd=cwd,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=300,
        )
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return -1, "", "Timed out"
    except Exception as e:
        return -1, "", str(e)

def _find_exe(names: list[str]) -> str | None:
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    return None

# ── status tracking ───────────────────────────────────────────────────────────

class _Status:
    def __init__(self, label: str):
        self.label   = label
        self.state   = "skip"   # ok | warn | fail | skip
        self.detail  = ""

    def set(self, state: str, detail: str = "") -> None:
        self.state  = state
        self.detail = detail

_checks: dict[str, _Status] = {}

def _s(key: str, label: str) -> _Status:
    s = _Status(label)
    _checks[key] = s
    return s

# ── Step 1: Python version ────────────────────────────────────────────────────

def check_python() -> bool:
    head("Step 1 — Python version")
    sep()
    v = sys.version_info
    label = f"Python {v.major}.{v.minor}.{v.micro}"
    s = _s("python", label)
    if v >= (3, 10):
        ok(f"{label}  (3.10+ required — {GREEN}OK{RESET})")
        s.set("ok", label)
        return True
    else:
        fail(f"{label}  — WhiteClaw requires Python 3.10 or newer.")
        fail("Download: https://www.python.org/downloads/")
        s.set("fail", f"Found {label}, need 3.10+")
        return False

# ── Step 2: Python packages ───────────────────────────────────────────────────

_PY_PKGS = {
    "anthropic":   ("anthropic",  "0.34.0"),
    "openai":      ("openai",     "1.30.0"),
    "google-genai":("google.genai", None),
}

def install_python_packages() -> None:
    head("Step 2 — Python packages (AI providers)")
    sep()
    pip = _find_exe(["pip", "pip3"]) or f"{sys.executable} -m pip"
    pip_cmd = [pip] if shutil.which(pip) else [sys.executable, "-m", "pip"]

    for pkg_name, (import_name, _) in _PY_PKGS.items():
        s = _s(f"pkg_{pkg_name}", pkg_name)
        # Check if already installed
        try:
            import importlib
            importlib.import_module(import_name)
            ok(f"{pkg_name}  (already installed)")
            s.set("ok")
            continue
        except (ImportError, ModuleNotFoundError):
            pass

        info(f"Installing {pkg_name}…")
        rc, _, err = _run(pip_cmd + ["install", "--quiet", pkg_name])
        if rc == 0:
            ok(f"{pkg_name}  installed")
            s.set("ok")
        else:
            warn(f"{pkg_name}  install failed — {err[:80]}")
            warn(f"  Run manually:  pip install {pkg_name}")
            s.set("warn", "install failed — AI reporting may not work")

# ── Step 3: Go scanner ────────────────────────────────────────────────────────

def check_and_build_go() -> None:
    head("Step 3 — Go scanner (high-speed HTTP probing)")
    sep()
    s_go  = _s("go",      "Go toolchain")
    s_bin = _s("scanner", "whiteclaw-scanner binary")

    go = _find_exe(["go"])
    if not go:
        fail("Go not found in PATH.")
        info("Download Go from: https://go.dev/dl/")
        info("After installing, re-run this installer.")
        info("The Python scanner fallback will be used in the meantime.")
        s_go.set("warn", "not installed — Python fallback active")
        s_bin.set("warn", "not built — Python fallback active")
        return

    rc, ver, _ = _run([go, "version"])
    if rc != 0:
        fail(f"go version failed")
        s_go.set("fail")
        s_bin.set("skip")
        return

    ok(f"Go found: {ver}")
    s_go.set("ok", ver)

    scanner_dir = HERE / "scanner"
    ext = ".exe" if sys.platform == "win32" else ""
    out_bin = scanner_dir / f"whiteclaw-scanner{ext}"

    info(f"Building {out_bin.name}…")
    rc, _, err = _run([go, "build", "-o", str(out_bin), "."], cwd=scanner_dir)
    if rc == 0:
        ok(f"Built: scanner/whiteclaw-scanner{ext}")
        s_bin.set("ok", str(out_bin))
    else:
        fail(f"Build failed:\n    {err[:200]}")
        s_bin.set("fail", err[:120])

# ── Step 4: Node.js crawler ───────────────────────────────────────────────────

def check_and_build_node() -> None:
    head("Step 4 — TypeScript crawler (Playwright DOM analysis)")
    sep()
    s_node = _s("node",    "Node.js runtime")
    s_npm  = _s("npm",     "npm package manager")
    s_pw   = _s("playwright", "Playwright browser")
    s_dist = _s("crawler", "crawler dist build")

    node = _find_exe(["node", "node.exe"])
    npm  = _find_exe(["npm",  "npm.cmd"])

    if not node:
        fail("Node.js not found in PATH.")
        info("Download Node.js LTS from: https://nodejs.org/")
        info("After installing, re-run this installer.")
        info("The Python crawler fallback will be used in the meantime.")
        s_node.set("warn", "not installed — Python fallback active")
        for k in ("npm", "playwright", "crawler"):
            _checks[k] = _Status(k)
            _checks[k].set("skip", "Node not installed")
        return

    rc, ver, _ = _run([node, "--version"])
    ok(f"Node.js found: {ver}")
    s_node.set("ok", ver)

    if not npm:
        warn("npm not found in PATH — skipping crawler build.")
        s_npm.set("warn", "not found")
        return

    rc, ver, _ = _run([npm, "--version"])
    ok(f"npm found: v{ver}")
    s_npm.set("ok", f"v{ver}")

    crawler_dir = HERE / "crawler"
    if not (crawler_dir / "package.json").exists():
        warn("crawler/package.json not found — skipping.")
        s_dist.set("skip", "package.json missing")
        return

    info("Running npm install…")
    rc, _, err = _run([npm, "install", "--silent"], cwd=crawler_dir)
    if rc != 0:
        fail(f"npm install failed: {err[:120]}")
        s_dist.set("fail", "npm install failed")
        return

    info("Installing Playwright Chromium…")
    npx = _find_exe(["npx", "npx.cmd"]) or npm.replace("npm", "npx")
    rc, _, err = _run([npx, "playwright", "install", "chromium"], cwd=crawler_dir)
    if rc == 0:
        ok("Playwright Chromium installed")
        s_pw.set("ok")
    else:
        warn(f"Playwright install incomplete: {err[:80]}")
        s_pw.set("warn", "partial install")

    info("Compiling TypeScript (npm run build)…")
    rc, _, err = _run([npm, "run", "build"], cwd=crawler_dir)
    if rc == 0:
        ok("Built: crawler/dist/main.js")
        s_dist.set("ok")
    else:
        fail(f"Build failed: {err[:200]}")
        s_dist.set("fail", err[:120])

# ── Step 5: verify Python fallbacks exist ─────────────────────────────────────

def check_fallbacks() -> None:
    head("Step 5 — Python fallback scripts")
    sep()
    for key, path, label in [
        ("py_scanner", HERE / "scanner" / "scanner.py",   "scanner/scanner.py"),
        ("py_crawler", HERE / "crawler" / "crawler.py",   "crawler/crawler.py"),
    ]:
        s = _s(key, label)
        if path.exists():
            ok(f"{label}  present")
            s.set("ok")
        else:
            fail(f"{label}  MISSING — scan will not work!")
            s.set("fail", "file missing")

# ── Final summary ─────────────────────────────────────────────────────────────

_STATE_ICON = {
    "ok":   f"{GREEN}[OK]    READY{RESET}",
    "warn": f"{YELLOW}[!]     PARTIAL{RESET}",
    "fail": f"{RED}[X]     FAILED{RESET}",
    "skip": f"{DIM}[-]     SKIPPED{RESET}",
}

def print_summary() -> None:
    head("Setup Summary")
    sep()
    print(f"  {'Component':<30} {'Status':<20} Note")
    sep()

    order = [
        ("python",      "Python 3.10+"),
        ("pkg_anthropic",   "  AI — Claude"),
        ("pkg_openai",      "  AI — OpenAI"),
        ("pkg_google-genai","  AI — Gemini"),
        ("go",          "Go toolchain"),
        ("scanner",     "  Go scanner binary"),
        ("node",        "Node.js"),
        ("npm",         "  npm"),
        ("playwright",  "  Playwright"),
        ("crawler",     "  TS crawler build"),
        ("py_scanner",  "Python scanner fallback"),
        ("py_crawler",  "Python crawler fallback"),
    ]

    for key, label in order:
        if key not in _checks:
            continue
        s = _checks[key]
        icon = _STATE_ICON.get(s.state, s.state)
        note = s.detail[:38] if s.detail else ""
        print(f"  {label:<30} {icon:<30} {DIM}{note}{RESET}")

    sep()
    py_ok  = _checks.get("py_scanner") and _checks["py_scanner"].state == "ok"
    go_ok  = _checks.get("scanner")    and _checks["scanner"].state    == "ok"
    ts_ok  = _checks.get("crawler")    and _checks["crawler"].state    == "ok"

    if go_ok and ts_ok:
        print(f"\n  {GREEN}{BOLD}Full installation complete!{RESET}")
        print(f"  Both Go scanner and TS crawler are compiled.")
        print(f"  Run:  {CYAN}python whiteclaw_web.py{RESET}\n")
    elif py_ok:
        print(f"\n  {YELLOW}{BOLD}Partial installation — Python fallbacks active.{RESET}")
        if not go_ok:
            print(f"  Scanner: Python fallback  {DIM}(install Go for better performance){RESET}")
        if not ts_ok:
            print(f"  Crawler: Python fallback  {DIM}(install Node.js for Playwright DOM analysis){RESET}")
        print(f"\n  Run:  {CYAN}python whiteclaw_web.py{RESET}\n")
    else:
        print(f"\n  {RED}{BOLD}Installation incomplete — cannot run scanner.{RESET}")
        print("  Fix the FAILED items above, then re-run installer.py\n")

# ── entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    print(f"\n{BOLD}{GREEN}{'='*62}{RESET}")
    print(f"{BOLD}{GREEN}   WhiteClaw WEB — Installer / Setup Checker{RESET}")
    print(f"{BOLD}{GREEN}{'='*62}{RESET}")
    print(f"  {DIM}Authorized use only. Run against systems you own or have{RESET}")
    print(f"  {DIM}explicit written permission to test.{RESET}")

    if not check_python():
        print_summary()
        sys.exit(1)

    install_python_packages()
    check_and_build_go()
    check_and_build_node()
    check_fallbacks()
    print_summary()

if __name__ == "__main__":
    main()
