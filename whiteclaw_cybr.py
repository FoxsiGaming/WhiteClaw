#!/usr/bin/env python3
"""
WhiteClaw CYBR — Security toolkit hub.
Launch WhiteClaw WEB (web scanner) or WhiteClaw CTF (cipher solver) from here.
"""

import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import sys
import os
from pathlib import Path
from datetime import datetime

# ─────────────────────────────────────────────────────────────────────────────
# Colour palette — deep space / cyber purple
# ─────────────────────────────────────────────────────────────────────────────
BG      = "#08081a"
BG2     = "#0e0e2e"
BG3     = "#161640"
BG4     = "#22226a"
FG      = "#d0d8f0"
FG2     = "#8090b8"
PURPLE  = "#7c3aed"
PURPLE2 = "#6020d0"
BLUE    = "#3b82f6"
CYAN    = "#22d3ee"
GREEN   = "#22c55e"
AMBER   = "#f59e0b"
RED     = "#ef4444"
DARK    = "#050510"

HERE = Path(os.path.abspath(__file__)).parent


# ─────────────────────────────────────────────────────────────────────────────
# Hub GUI
# ─────────────────────────────────────────────────────────────────────────────
class WhiteClawCybrApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("WhiteClaw CYBR — Security Toolkit Hub")
        self.root.geometry("1260x800")
        self.root.resizable(False, False)
        self.root.configure(bg=BG)

        self._processes: list[subprocess.Popen] = []
        self._build_styles()
        self._build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_styles(self) -> None:
        s = ttk.Style()
        s.theme_use("clam")
        s.configure("TFrame", background=BG)

    def _build_ui(self) -> None:
        self._build_header()
        self._build_tools()
        self._build_log()
        self._build_footer()

    # ── header ────────────────────────────────────────────────────────────────

    def _build_header(self) -> None:
        top = tk.Frame(self.root, bg=BG2, pady=18, padx=30)
        top.pack(fill="x")

        tk.Label(top, text="⬡ WhiteClaw CYBR",
                 font=("Consolas", 32, "bold"), fg=PURPLE, bg=BG2).pack(side="left")
        tk.Label(top, text="  Security Toolkit Hub",
                 font=("Consolas", 18), fg=FG2, bg=BG2).pack(side="left", pady=2)

        ver = tk.Label(top, text="v2.1 | Authorized use only",
                       font=("Consolas", 13), fg=BG4, bg=BG2)
        ver.pack(side="right")

        # Animated pulse dot
        self._pulse_canvas = tk.Canvas(top, width=18, height=18,
                                       bg=BG2, highlightthickness=0)
        self._pulse_canvas.pack(side="right", padx=10)
        self._dot = self._pulse_canvas.create_oval(2, 2, 16, 16, fill=GREEN, outline="")
        self._pulse_state = True
        self._pulse()

    def _pulse(self) -> None:
        color = GREEN if self._pulse_state else BG2
        self._pulse_canvas.itemconfig(self._dot, fill=color)
        self._pulse_state = not self._pulse_state
        self.root.after(900, self._pulse)

    # ── tool cards ────────────────────────────────────────────────────────────

    def _build_tools(self) -> None:
        cards = tk.Frame(self.root, bg=BG, padx=30, pady=20)
        cards.pack(fill="x")

        cards.columnconfigure(0, weight=1, uniform="col")
        cards.columnconfigure(1, weight=1, uniform="col")

        self._build_web_card(cards)
        self._build_ctf_card(cards)

    def _build_web_card(self, parent: tk.Frame) -> None:
        card = tk.Frame(parent, bg=BG2, padx=24, pady=20, relief="flat")
        card.grid(row=0, column=0, padx=(0, 12), sticky="nsew")

        tk.Label(card, text="⬡  WEB",
                 font=("Consolas", 22, "bold"), fg=GREEN, bg=BG2).pack(anchor="w")
        tk.Label(card, text="WhiteClaw WEB",
                 font=("Consolas", 16, "bold"), fg=FG, bg=BG2).pack(anchor="w", pady=(2, 0))
        tk.Label(card, text="Web Security Scanner",
                 font=("Consolas", 13), fg=FG2, bg=BG2).pack(anchor="w")

        tk.Frame(card, bg=BG3, height=1).pack(fill="x", pady=10)

        features = [
            "✔  17-step automated vulnerability scan",
            "✔  SQL injection (40 payloads)",
            "✔  XSS reflection detection",
            "✔  Sensitive file probing (55 paths)",
            "✔  Security header analysis",
            "✔  CORS / CSRF / SSRF / SQLi checks",
            "✔  AI-powered pentest report (3 providers)",
            "✔  Log-only mode (no individual files)",
        ]
        for feat in features:
            tk.Label(card, text=feat, font=("Consolas", 13), fg=FG2, bg=BG2,
                     anchor="w").pack(fill="x", pady=1)

        tk.Frame(card, bg=BG3, height=1).pack(fill="x", pady=10)

        self._web_btn = tk.Button(
            card, text="  Launch WhiteClaw WEBpatch  ",
            font=("Consolas", 16, "bold"),
            bg=DARK_GRN(), fg="white",
            activebackground="#196127",
            relief="flat", padx=14, pady=8,
            command=self._launch_web,
        )
        self._web_btn.pack(fill="x")

    def _build_ctf_card(self, parent: tk.Frame) -> None:
        card = tk.Frame(parent, bg=BG2, padx=24, pady=20, relief="flat")
        card.grid(row=0, column=1, padx=(12, 0), sticky="nsew")

        tk.Label(card, text="⬡  CTF",
                 font=("Consolas", 22, "bold"), fg=AMBER, bg=BG2).pack(anchor="w")
        tk.Label(card, text="WhiteClaw CTF",
                 font=("Consolas", 16, "bold"), fg=FG, bg=BG2).pack(anchor="w", pady=(2, 0))
        tk.Label(card, text="Cipher & Encoding Solver",
                 font=("Consolas", 13), fg=FG2, bg=BG2).pack(anchor="w")

        tk.Frame(card, bg=BG3, height=1).pack(fill="x", pady=10)

        features = [
            "✔  Auto-detect 16+ encoding types",
            "✔  Recursive decode chains (8 levels)",
            "✔  Hex / Binary / Base64/32/58/85",
            "✔  ROT13 / ROT47 / Caesar / Atbash",
            "✔  XOR single-byte brute-force",
            "✔  Morse code decoder",
            "✔  JWT decode / RSA param detection",
            "✔  Solve history with replay",
        ]
        for feat in features:
            tk.Label(card, text=feat, font=("Consolas", 13), fg=FG2, bg=BG2,
                     anchor="w").pack(fill="x", pady=1)

        tk.Frame(card, bg=BG3, height=1).pack(fill="x", pady=10)

        self._ctf_btn = tk.Button(
            card, text="  Launch WhiteClaw CTF decoder  ",
            font=("Consolas", 16, "bold"),
            bg=DARK_AMBER(), fg="white",
            activebackground="#92600a",
            relief="flat", padx=14, pady=8,
            command=self._launch_ctf,
        )
        self._ctf_btn.pack(fill="x")

    # ── activity log ──────────────────────────────────────────────────────────

    def _build_log(self) -> None:
        log_frame = tk.Frame(self.root, bg=BG, padx=30, pady=0)
        log_frame.pack(fill="both", expand=True)

        tk.Label(log_frame, text="ACTIVITY CONSOLE",
                 font=("Consolas", 12, "bold"), fg=BG4, bg=BG, anchor="w"
                 ).pack(fill="x")

        self._log_text = tk.Text(
            log_frame, bg=BG2, fg=FG2, font=("Consolas", 13),
            relief="flat", height=4, state="disabled",
            insertbackground=CYAN, wrap="word", padx=8, pady=4,
        )
        self._log_text.pack(fill="both", expand=True)
        self._log_text.tag_configure("ts",     foreground=BG4)
        self._log_text.tag_configure("launch", foreground=CYAN)
        self._log_text.tag_configure("close",  foreground=RED)

        self._activity("Hub started. Select a tool to launch.")

    def _activity(self, msg: str, tag: str = "launch") -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        self._log_text.config(state="normal")
        self._log_text.insert("end", f"[{ts}] ", "ts")
        self._log_text.insert("end", msg + "\n", tag)
        self._log_text.see("end")
        self._log_text.config(state="disabled")

    # ── footer ────────────────────────────────────────────────────────────────

    def _build_footer(self) -> None:
        bar = tk.Frame(self.root, bg=BG2, padx=20, pady=6)
        bar.pack(fill="x", side="bottom")
        tk.Label(bar, text="WhiteClaw CYBR | For authorized security testing only",
                 font=("Consolas", 12), fg=BG4, bg=BG2).pack(side="left")
        tk.Label(bar, text="Ctrl+Q  quit",
                 font=("Consolas", 12), fg=BG4, bg=BG2).pack(side="right")
        self.root.bind("<Control-q>", lambda _: self._on_close())

    # ── launch logic ──────────────────────────────────────────────────────────

    def _launch_web(self) -> None:
        script = HERE / "whiteclaw_web.py"
        if not script.exists():
            messagebox.showerror("File missing",
                                 f"whiteclaw_web.py not found in:\n{HERE}")
            return
        proc = subprocess.Popen([sys.executable, str(script)],
                                 creationflags=_detach_flags())
        self._processes.append(proc)
        self._web_btn.config(text="  WEB running…  ")
        self.root.after(2000, lambda: self._web_btn.config(text="  Launch WhiteClaw WEB  "))
        self._activity("Launched WhiteClaw WEB", "launch")

    def _launch_ctf(self) -> None:
        script = HERE / "whiteclaw_ctf.py"
        if not script.exists():
            messagebox.showerror("File missing",
                                 f"whiteclaw_ctf.py not found in:\n{HERE}")
            return
        proc = subprocess.Popen([sys.executable, str(script)],
                                 creationflags=_detach_flags())
        self._processes.append(proc)
        self._ctf_btn.config(text="  CTF running…  ")
        self.root.after(2000, lambda: self._ctf_btn.config(text="  Launch WhiteClaw CTF  "))
        self._activity("Launched WhiteClaw CTF", "launch")

    def _on_close(self) -> None:
        self._activity("Hub closed.", "close")
        self.root.destroy()


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
def DARK_GRN() -> str:
    return "#196127"

def DARK_AMBER() -> str:
    return "#b45309"

def _detach_flags() -> int:
    """Windows: CREATE_NEW_CONSOLE so each tool gets its own window."""
    if sys.platform == "win32":
        return 0x00000010  # CREATE_NEW_CONSOLE
    return 0


def main() -> None:
    root = tk.Tk()
    WhiteClawCybrApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
