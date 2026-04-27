#!/usr/bin/env python3
"""
WhiteClaw CYBR launcher — auto-installs missing dependencies then starts the hub.
Run this file to open the WhiteClaw CYBR hub, from which you can launch
WhiteClaw WEB (web scanner) or WhiteClaw CTF (cipher solver).
"""

import sys
import os
import subprocess

MIN_PYTHON = (3, 9)

REQUIRED = {
    "requests":  "requests>=2.31.0",
    "bs4":       "beautifulsoup4>=4.12.0",
    "urllib3":   "urllib3>=2.0.0",
    "anthropic": "anthropic>=0.34.0",
    "openai":    "openai>=1.30.0",
}

REQUIRED_ALT = {
    "google.genai": "google-genai>=1.0.0",
}


def banner():
    print("\n" + "=" * 54)
    print("  ⬡  WhiteClaw CYBR — Security Toolkit Hub")
    print("     Startup check")
    print("=" * 54)


def check_python():
    if sys.version_info < MIN_PYTHON:
        print(f"[FAIL] Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ required "
              f"(you have {sys.version_info.major}.{sys.version_info.minor})")
        print("       Download from https://python.org")
        input("\nPress Enter to exit.")
        sys.exit(1)
    print(f"[OK]   Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")


def _try_import(import_name: str) -> bool:
    try:
        __import__(import_name)
        return True
    except ImportError:
        return False


def fix_deps():
    missing_specs = []
    for import_name, pip_spec in REQUIRED.items():
        label = pip_spec.split(">=")[0]
        if _try_import(import_name):
            print(f"[OK]   {label}")
        else:
            print(f"[MISS] {label} — will install")
            missing_specs.append(pip_spec)
    for import_name, pip_spec in REQUIRED_ALT.items():
        label = pip_spec.split(">=")[0]
        if _try_import(import_name):
            print(f"[OK]   {label}")
        else:
            print(f"[MISS] {label} — will install")
            missing_specs.append(pip_spec)

    if missing_specs:
        print(f"\nInstalling {len(missing_specs)} package(s)…")
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--quiet"] + missing_specs
        )
        if result.returncode != 0:
            print("\n[FAIL] pip install failed. Try manually:")
            print(f"       pip install {' '.join(missing_specs)}")
            input("\nPress Enter to exit.")
            sys.exit(1)
        print("[OK]   All packages installed.")


def check_tkinter():
    try:
        import tkinter  # noqa: F401
        print("[OK]   tkinter (built-in)")
    except ImportError:
        print("[FAIL] tkinter is missing.")
        if sys.platform.startswith("linux"):
            print("       Fix: sudo apt install python3-tk")
        elif sys.platform == "darwin":
            print("       Fix: brew install python-tk")
        else:
            print("       Fix: reinstall Python and tick 'tcl/tk' in the installer.")
        input("\nPress Enter to exit.")
        sys.exit(1)


def check_tools():
    here = os.path.dirname(os.path.abspath(__file__))
    for name in ("whiteclaw_cybr.py", "whiteclaw_web.py", "whiteclaw_ctf.py"):
        path = os.path.join(here, name)
        if os.path.exists(path):
            print(f"[OK]   {name}")
        else:
            print(f"[WARN] {name} not found — the corresponding tool will not launch.")


def launch():
    here   = os.path.dirname(os.path.abspath(__file__))
    target = os.path.join(here, "whiteclaw_cybr.py")
    if not os.path.exists(target):
        print(f"[FAIL] whiteclaw_cybr.py not found in {here}")
        input("\nPress Enter to exit.")
        sys.exit(1)

    print("\n" + "=" * 54)
    print("  All checks passed — launching WhiteClaw CYBR hub…")
    print("=" * 54 + "\n")

    # Replace current process with the hub so the window owns the terminal
    os.execv(sys.executable, [sys.executable, target])


if __name__ == "__main__":
    banner()
    check_python()
    check_tkinter()
    fix_deps()
    check_tools()
    launch()
