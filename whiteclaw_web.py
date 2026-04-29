#!/usr/bin/env python3
"""
WhiteClaw WEB — Web Security Scanner.
Authorized penetration testing and vulnerability discovery tool.
For use only on systems you own or have explicit written permission to test.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading
import time
import json
import re
import os
import sys
import subprocess
import base64
import urllib.parse
from datetime import datetime
from collections import defaultdict
import html as _html_mod
import random
from pathlib import Path

_anthropic_sdk = None
_openai_sdk    = None
_genai_sdk     = None

def _load_ai_sdks() -> None:
    global _anthropic_sdk, _openai_sdk, _genai_sdk
    try:
        import anthropic
        _anthropic_sdk = anthropic
    except ImportError:
        pass
    try:
        import openai
        _openai_sdk = openai
    except ImportError:
        pass
    try:
        from google import genai
        _genai_sdk = genai
    except ImportError:
        pass

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
# Splash screen — visible while AI SDKs load in background
# ─────────────────────────────────────────────────────────────────────────────
class SplashScreen:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.overrideredirect(True)
        root.configure(bg=BG)
        root.attributes("-topmost", True)

        w, h = 400, 240
        sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
        root.geometry(f"{w}x{h}+{(sw - w) // 2}+{(sh - h) // 2}")
        self._build()
        self._tick(0)

    def _build(self) -> None:
        try:
            src = tk.PhotoImage(file=str(Path(__file__).parent / "pic" / "favicon.png"))
            factor = max(1, src.height() // 72)
            img = src.subsample(factor, factor)
            lbl = tk.Label(self.root, image=img, bg=BG)
            lbl.image = img
            lbl._src = src
            lbl.pack(pady=(28, 6))
        except Exception:
            tk.Label(self.root, text="⬡", font=("Consolas", 36, "bold"),
                     fg=GREEN, bg=BG).pack(pady=(28, 6))

        tk.Label(self.root, text="WhiteClaw WEB",
                 font=("Consolas", 17, "bold"), fg=FG, bg=BG).pack()

        self._status_var = tk.StringVar(value="Loading AI providers…")
        tk.Label(self.root, textvariable=self._status_var,
                 font=("Consolas", 11), fg=FG2, bg=BG).pack(pady=(6, 12))

        self._cv = tk.Canvas(self.root, width=280, height=3,
                              bg=BG3, highlightthickness=0)
        self._cv.pack()
        self._bar = self._cv.create_rectangle(0, 0, 0, 3, fill=GREEN, outline="")

    def _tick(self, i: int) -> None:
        w, bw, half = 280, 90, 40
        pos = i % (half * 2)
        x = pos if pos <= half else half * 2 - pos
        x1 = int(x / half * (w - bw))
        self._cv.coords(self._bar, x1, 0, x1 + bw, 3)
        self._job = self.root.after(16, self._tick, i + 1)

    def close(self) -> None:
        if hasattr(self, "_job"):
            self.root.after_cancel(self._job)
        self.root.destroy()


# ─────────────────────────────────────────────────────────────────────────────
# Orchestrator — spawns Go scanner + TS crawler, streams JSON to GUI callback
# ─────────────────────────────────────────────────────────────────────────────
class WhiteClawOrchestrator:
    """
    Replaces the old monolithic WhiteClawScanner.
    Spawns two child processes (Go binary + Node.js crawler), writes a JSON
    config to each one's stdin, then streams newline-delimited JSON findings
    from stdout back to the tkinter GUI via the callback.
    """

    _HERE         = Path(__file__).parent
    SCANNER_BIN   = _HERE / "scanner" / "whiteclaw-scanner"
    SCANNER_PY    = _HERE / "scanner" / "scanner.py"
    CRAWLER_ENTRY = _HERE / "crawler" / "dist" / "main.js"
    CRAWLER_PY    = _HERE / "crawler" / "crawler.py"

    def __init__(self, url: str, callback):
        self.url      = url
        parsed        = urllib.parse.urlparse(url)
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"
        self.params   = list(urllib.parse.parse_qs(parsed.query).keys())
        self.callback = callback
        self._procs:      list[subprocess.Popen] = []
        self._findings:   dict                   = defaultdict(list)
        self._total:      int                    = 0
        self._done_count: int                    = 0
        self._lock        = threading.Lock()

    # ── config dicts sent to each child process via stdin ────────────────────

    def _scanner_config(self) -> dict:
        return {
            "url":      self.url,
            "base_url": self.base_url,
            "params":   self.params,
            "js_urls":  [],
            "workers":  20,
            "timeout":  8,
        }

    def _crawler_config(self) -> dict:
        return {
            "url":      self.url,
            "base_url": self.base_url,
            "timeout":  30_000,
        }

    # ── streaming reader (runs in a daemon thread per child) ─────────────────

    def _stream(self, proc: subprocess.Popen, name: str) -> None:
        try:
            for raw in proc.stdout:
                line = raw.strip()
                if not line:
                    continue
                try:
                    evt = json.loads(line)
                except json.JSONDecodeError:
                    self.callback("error", f"[{name}] malformed JSON: {line[:80]}")
                    continue
                t = evt.get("type", "")
                if t == "status":
                    self.callback("status", evt.get("message", ""))
                elif t == "finding":
                    f = {
                        "severity":  evt.get("severity",  "INFO"),
                        "category":  evt.get("category",  "general"),
                        "title":     evt.get("title",     ""),
                        "detail":    evt.get("detail",    ""),
                        "fix":       evt.get("fix",       ""),
                        "timestamp": datetime.now().isoformat(),
                    }
                    self._findings[f["category"]].append(f)
                    self.callback("finding", f)
                elif t == "error":
                    self.callback("error", f"[{name}] {evt.get('message', '')}")
                elif t == "done":
                    self._mark_done()
        except Exception as exc:
            self.callback("error", f"[{name}] stream error: {exc}")
            self._mark_done()

    def _mark_done(self) -> None:
        with self._lock:
            self._done_count += 1
            if self._done_count >= self._total:
                self.callback("done", dict(self._findings))

    # ── process spawning ─────────────────────────────────────────────────────

    def _spawn(self, cmd: list, config: dict, name: str) -> None:
        try:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                creationflags=(0x08000000 if sys.platform == "win32" else 0),
            )
            self._procs.append(proc)
            proc.stdin.write(json.dumps(config))
            proc.stdin.close()
            threading.Thread(
                target=self._stream, args=(proc, name), daemon=True
            ).start()
        except FileNotFoundError:
            self.callback("error", f"[{name}] binary not found: {cmd[0]}")
            self._mark_done()
        except Exception as exc:
            self.callback("error", f"[{name}] spawn failed: {exc}")
            self._mark_done()

    # ── public API ───────────────────────────────────────────────────────────

    def run(self) -> None:
        scanner_bin = self.SCANNER_BIN
        if sys.platform == "win32":
            scanner_bin = scanner_bin.with_suffix(".exe")

        tasks: list[tuple[str, list, dict]] = []

        # Prefer compiled Go binary; fall back to Python script
        if scanner_bin.exists():
            tasks.append(("Go scanner",     [str(scanner_bin)],                     self._scanner_config()))
        elif self.SCANNER_PY.exists():
            tasks.append(("Python scanner", [sys.executable, str(self.SCANNER_PY)], self._scanner_config()))
        else:
            self.callback("error", f"Scanner not found at {scanner_bin} or {self.SCANNER_PY}")

        # Prefer compiled TS crawler; fall back to Python script
        if self.CRAWLER_ENTRY.exists():
            tasks.append(("TS crawler",     ["node", str(self.CRAWLER_ENTRY)],      self._crawler_config()))
        elif self.CRAWLER_PY.exists():
            tasks.append(("Python crawler", [sys.executable, str(self.CRAWLER_PY)], self._crawler_config()))
        else:
            self.callback("error", f"Crawler not found at {self.CRAWLER_ENTRY} or {self.CRAWLER_PY}")

        if not tasks:
            self.callback("done", {})
            return

        self._total = len(tasks)
        for name, cmd, cfg in tasks:
            self.callback("status", f"Launching {name}...")
            self._spawn(cmd, cfg, name)

    def terminate(self) -> None:
        for proc in self._procs:
            try:
                proc.terminate()
            except Exception:
                pass


# ─────────────────────────────────────────────────────────────────────────────
# AI reporter
# ─────────────────────────────────────────────────────────────────────────────
class AIReporter:
    def __init__(self, provider: str, api_key: str, model: str):
        self.provider = provider
        self.api_key  = api_key
        self.model    = model

    def _build_prompt(self, url: str, findings: dict, timeline: list) -> str:
        flat: list = []
        for items in findings.values():
            flat.extend(items)
        counts: dict = defaultdict(int)
        for f in flat:
            counts[f.get("severity", "INFO")] += 1

        # Build a human-readable scan route from the recorded timeline
        route_lines: list[str] = []
        for entry in timeline:
            ts   = entry.get("ts", "")
            kind = entry.get("type", "")
            if kind == "status":
                route_lines.append(f"  [{ts}] CHECK  {entry.get('message', '')}")
            elif kind == "finding":
                sev  = entry.get("severity", "INFO")
                cat  = entry.get("category", "")
                titl = entry.get("title", "")
                route_lines.append(f"  [{ts}] FOUND  [{sev}][{cat}] {titl}")
            elif kind == "error":
                route_lines.append(f"  [{ts}] ERROR  {entry.get('message', '')}")
        scan_route = "\n".join(route_lines) if route_lines else "  (no timeline recorded)"

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

Scan route (chronological order of checks performed and findings discovered):
{scan_route}

Raw findings JSON:
{json.dumps(flat, indent=2)}

Write a complete penetration test report (Markdown):
1. **Executive Summary** — 3-4 sentences for a non-technical audience.
2. **Risk Rating** — Overall rating with justification.
3. **Scan Route Analysis** — Walk through the scan timeline above: what was tested in sequence, which checks triggered findings, and how the attack surface evolved as each check ran. Reference timestamps.
4. **Critical & High Findings** — title, impact, reproduction steps, remediation with code examples, CWE/OWASP.
5. **Medium & Low Findings** — Brief table: Finding | Severity | Quick Fix
6. **Attack Chains** — 1-3 realistic multi-step attack scenarios based on what was discovered, referencing the scan route to show how the chain could be executed.
7. **Remediation Roadmap** — Prioritised P1/P2/P3 with estimated effort.
8. **Compliance Notes** — OWASP Top 10, CWE IDs, GDPR/PCI-DSS.

Be specific, technical, and actionable. Use the scan route to ground attack scenarios in the actual sequence the tester followed."""

    def generate(self, url: str, findings: dict, timeline: list) -> str:
        prompt = self._build_prompt(url, findings, timeline)
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
        self.root.minsize(1200, 700)
        self.root.configure(bg=BG)

        self._findings: dict      = {}
        self._sev_counts: dict    = {s: 0 for s in SEV_COLOR}
        self._scan_url            = ""
        self._scan_timeline: list = []   # ordered record of every event for AI context
        self._log_only_var        = tk.BooleanVar(value=False)

        self._load_assets()
        self._build_styles()
        self._build_ui()

    def _load_assets(self) -> None:
        try:
            src = tk.PhotoImage(file=str(Path(__file__).parent / "pic" / "favicon.png"))
            self.root.iconphoto(True, src)
            factor = max(1, src.height() // 48)
            self._logo_img = src.subsample(factor, factor)
            self._logo_src = src
        except Exception:
            self._logo_img = None
            self._logo_src = None

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
        if self._logo_img:
            tk.Label(bar, image=self._logo_img, bg=BG2).pack(side="left", padx=(0, 10))
        tk.Label(bar, text="⬡ WhiteClaw WEB",
                 font=("Consolas", 28, "bold"), fg=GREEN, bg=BG2).pack(side="left")
        tk.Label(bar, text="  Web Security Scanner",
                 font=("Consolas", 17), fg=FG2, bg=BG2).pack(side="left", pady=2)
        tk.Label(bar, text="[ Authorized use only ]",
                 font=("Consolas", 15), fg=RED, bg=BG2).pack(side="right")

    def _build_toolbar(self) -> None:
        # ── Row 1: URL + SCAN (entry expands with window) ─────────────────────
        row1 = tk.Frame(self.root, bg=BG2, padx=20, pady=8)
        row1.pack(fill="x")
        row1.columnconfigure(1, weight=1)

        tk.Label(row1, text="URL:", font=("Consolas", 16),
                 fg=FG2, bg=BG2).grid(row=0, column=0, sticky="w", padx=(0, 8))
        self._url_var = tk.StringVar()
        url_entry = tk.Entry(row1, textvariable=self._url_var, font=("Consolas", 16),
                             bg=BG3, fg=FG, insertbackground=GREEN, relief="flat", bd=6)
        url_entry.grid(row=0, column=1, sticky="ew", padx=4, ipady=4)
        url_entry.insert(0, "https://")
        url_entry.bind("<Return>", lambda _: self._start_scan())

        self._scan_btn = tk.Button(row1, text="  SCAN  ", font=("Consolas", 16, "bold"),
                                   bg=DARK_GRN, fg="white", activebackground="#2ea043",
                                   relief="flat", padx=14, pady=4,
                                   command=self._start_scan)
        self._scan_btn.grid(row=0, column=2, sticky="e", padx=(8, 0))

        # ── Row 2: export actions + log-only ──────────────────────────────────
        row2 = tk.Frame(self.root, bg=BG2, padx=20, pady=4)
        row2.pack(fill="x")

        self._export_btn = tk.Button(row2, text="Export Report",
                                     font=("Consolas", 14), bg=BG3, fg=FG2,
                                     activebackground=BG4, relief="flat",
                                     padx=10, pady=3, command=self._export_report,
                                     state="disabled")
        self._export_btn.pack(side="left", padx=(0, 4))

        self._export_all_btn = tk.Button(row2, text="Export All Findings",
                                         font=("Consolas", 14), bg=BG3, fg=FG2,
                                         activebackground=BG4, relief="flat",
                                         padx=10, pady=3, command=self._export_all_findings,
                                         state="disabled")
        self._export_all_btn.pack(side="left", padx=4)

        tk.Frame(row2, bg=BG4, width=1).pack(side="left", fill="y", padx=14)

        tk.Checkbutton(
            row2, text="Log only (no report files)",
            variable=self._log_only_var,
            font=("Consolas", 13), fg=FG2, bg=BG2,
            selectcolor=BG3, activebackground=BG2, activeforeground=GREEN,
            relief="flat",
        ).pack(side="left")

        # ── Row 3: AI provider settings ───────────────────────────────────────
        row3 = tk.Frame(self.root, bg=BG2, padx=20, pady=4)
        row3.pack(fill="x")

        tk.Label(row3, text="AI:", font=("Consolas", 15),
                 fg=FG2, bg=BG2).pack(side="left")
        self._provider_var = tk.StringVar(value=list(PROVIDERS.keys())[0])
        provider_cb = ttk.Combobox(row3, textvariable=self._provider_var,
                                   values=list(PROVIDERS.keys()),
                                   state="readonly", width=20, font=("Consolas", 15))
        provider_cb.pack(side="left", padx=(6, 14), ipady=2)
        provider_cb.bind("<<ComboboxSelected>>", self._on_provider_change)

        tk.Label(row3, text="Model:", font=("Consolas", 15),
                 fg=FG2, bg=BG2).pack(side="left")
        self._model_var = tk.StringVar(value=PROVIDERS[list(PROVIDERS.keys())[0]]["models"][0])
        self._model_cb = ttk.Combobox(row3, textvariable=self._model_var,
                                      values=PROVIDERS[list(PROVIDERS.keys())[0]]["models"],
                                      state="readonly", width=28, font=("Consolas", 15))
        self._model_cb.pack(side="left", padx=(6, 14), ipady=2)

        tk.Label(row3, text="API Key:", font=("Consolas", 15),
                 fg=FG2, bg=BG2).pack(side="left")
        self._key_var = tk.StringVar()
        self._key_hint_var = tk.StringVar(value=PROVIDERS[list(PROVIDERS.keys())[0]]["hint"])
        tk.Entry(row3, textvariable=self._key_var, font=("Consolas", 15),
                 bg=BG3, fg=FG, insertbackground=GREEN,
                 relief="flat", bd=6, show="•", width=32).pack(side="left", padx=(6, 8), ipady=3)
        tk.Label(row3, textvariable=self._key_hint_var,
                 font=("Consolas", 13), fg=BG4, bg=BG2).pack(side="left")

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
        self._status_var = tk.StringVar(value="Ready? paste a URL and press SCAN.")
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

        self._findings      = {}
        self._scan_timeline = []
        self._sev_counts    = {s: 0 for s in SEV_COLOR}
        self._update_counters()
        self._export_btn.config(state="disabled")
        self._export_all_btn.config(state="disabled")
        self._scan_btn.config(state="disabled", text="SCANNING…")
        self._progress.start(12)
        self._scan_url = url

        self._log_banner(url)

        threading.Thread(target=self._run_scan, args=(url,), daemon=True).start()

    def _run_scan(self, url: str) -> None:
        def cb(event_type: str, data):
            self.root.after(0, self._handle_event, event_type, data)
        WhiteClawOrchestrator(url, cb).run()

    def _handle_event(self, event_type: str, data) -> None:
        ts = datetime.now().strftime("%H:%M:%S")

        if event_type == "status":
            self._status_var.set(data)
            self._scan_timeline.append({"type": "status", "ts": ts, "message": data})
            self._log_status(ts, data)

        elif event_type == "finding":
            cat  = data.get("category", "info")
            sev  = data.get("severity",  "INFO")
            titl = data.get("title",     "")
            det  = data.get("detail",    "")
            fix  = data.get("fix",       "")
            self._scan_timeline.append({
                "type": "finding", "ts": ts,
                "severity": sev, "category": cat, "title": titl,
            })
            tab = cat if cat in self._text_areas else "info"
            self._log_finding(tab, ts, sev, cat, titl, det, fix)
            self._log_finding("log", ts, sev, cat, titl, det, "")
            if sev in self._sev_counts:
                self._sev_counts[sev] += 1
                self._update_counters()

        elif event_type == "error":
            self._scan_timeline.append({"type": "error", "ts": ts, "message": str(data)})
            self._log_error(ts, str(data))

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
            self._log_done(ts, total)
            threading.Thread(
                target=self._save_reports,
                args=(self._scan_url, data),
                daemon=True,
            ).start()

    def _update_counters(self) -> None:
        for sev, lbl in self._counter_labels.items():
            lbl.config(text=f"{sev}: {self._sev_counts[sev]}")

    # ── log helpers ───────────────────────────────────────────────────────────

    def _write(self, tab: str, text: str, tag: str = "") -> None:
        """Low-level: append text to a tab's text area."""
        ta = self._text_areas.get(tab) or self._text_areas["log"]
        ta.config(state="normal")
        if tag:
            ta.insert("end", text, tag)
        else:
            ta.insert("end", text)
        ta.see("end")
        ta.config(state="disabled")

    def _log_banner(self, url: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        for ta in self._text_areas.values():
            ta.config(state="normal")
            ta.delete("1.0", "end")
            ta.config(state="disabled")
        self._write("log", "=" * 72 + "\n", "sep")
        self._write("log", f"  WhiteClaw WEB  |  {url}\n", "header")
        self._write("log", f"  Started {datetime.now().strftime('%Y-%m-%d')} at {ts}\n", "detail")
        self._write("log", "=" * 72 + "\n\n", "sep")

    def _log_status(self, ts: str, msg: str) -> None:
        self._write("log", f"  [{ts}]  ", "detail")
        self._write("log", ">>  ", "INFO")
        self._write("log", msg + "\n", "detail")

    def _log_finding(self, tab: str, ts: str, sev: str, cat: str,
                     title: str, detail: str, fix: str) -> None:
        ta = self._text_areas.get(tab) or self._text_areas["log"]
        ta.config(state="normal")
        ta.insert("end", "\n  +-- ", "sep")
        ta.insert("end", f"[{sev}]", sev)
        ta.insert("end", f"  [{ts}]  {cat.upper()}\n", "detail")
        ta.insert("end", f"  |   {title}\n", "header")
        if detail:
            for line in detail.splitlines():
                ta.insert("end", f"  |   {line}\n", "detail")
        if fix:
            ta.insert("end", f"  +-- FIX: {fix}\n", "fix")
        else:
            ta.insert("end", "  +--\n", "sep")
        ta.see("end")
        ta.config(state="disabled")

    def _log_error(self, ts: str, msg: str) -> None:
        self._write("log", f"\n  [{ts}]  ", "detail")
        self._write("log", f"[ERROR]  {msg}\n", "HIGH")

    def _log_done(self, ts: str, total: int) -> None:
        c = self._sev_counts
        self._write("log", "\n" + "=" * 72 + "\n", "sep")
        self._write("log", f"  [{ts}]  Scan complete -- {total} finding(s)\n", "header")
        self._write("log",
            f"  CRITICAL {c['CRITICAL']}  |  HIGH {c['HIGH']}  |  "
            f"MEDIUM {c['MEDIUM']}  |  LOW {c['LOW']}  |  INFO {c['INFO']}\n", "detail")
        self._write("log", "  Switch to the AI Report tab to generate a report.\n", "fix")
        self._write("log", "=" * 72 + "\n", "sep")

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

        timeline = list(self._scan_timeline)   # snapshot at report-generation time

        def _work():
            try:
                reporter = AIReporter(provider, key, model)
                text = reporter.generate(self._scan_url, self._findings, timeline)
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
        ts = datetime.now().strftime("%H:%M:%S")
        self._log_status(ts, f"Reports saved  reports/{provider}/  ({mode_str})")

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
    splash_root = tk.Tk()
    splash = SplashScreen(splash_root)
    splash_root.update()

    t = threading.Thread(target=_load_ai_sdks, daemon=True)
    t.start()

    while t.is_alive():
        splash_root.update()
        time.sleep(0.016)

    splash.close()

    root = tk.Tk()
    WhiteClawWebApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
