#!/usr/bin/env python3
"""
WhiteClaw CTF — Cipher & encoding auto-solver toolkit.
Authorized CTF / research use only.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading
import json
import re
import base64
import urllib.parse
import html as _html_mod
from datetime import datetime
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
# Colour palette — amber / hacker terminal
# ─────────────────────────────────────────────────────────────────────────────
BG      = "#0c0c0c"
BG2     = "#131007"
BG3     = "#1c180a"
BG4     = "#2e280e"
FG      = "#e8c96a"
FG2     = "#9a8040"
AMBER   = "#f0a000"
GREEN   = "#40e878"
RED     = "#ff4848"
ORANGE  = "#ff8820"
PURPLE  = "#a060f0"
CYAN    = "#40d8d8"
SOLVED_BG = "#0a1a08"

# ─────────────────────────────────────────────────────────────────────────────
# CTF constants
# ─────────────────────────────────────────────────────────────────────────────
FLAG_RE = re.compile(
    r'(?i)(?:flag|ctf|picoctf|htb|thm|ductf|uiuctf|nahamcon|pctf|wgmy|corctf|'
    r'dctf|rgbctf|lactf|secureflag|intigriti|crypto)\{[^}]{1,300}\}'
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

# Precomputed lookup tables for hot paths
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
# Solver engine
# ─────────────────────────────────────────────────────────────────────────────
class CTFSolverEngine:
    """
    Auto-detect and recursively decode CTF encoding / cipher challenges.
    Supports: Hex, Binary, Base64/32/58/85, URL, HTML entities, Morse,
              ROT13, ROT47, Caesar brute-force, Atbash, XOR single-byte,
              JWT decode, RSA parameter detection.
    """

    MAX_DEPTH = 8

    def solve(self, text: str, custom_flag_re: str = "") -> dict:
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

    def _recurse(self, text: str, visited: set, depth: int, flag_re) -> tuple[list, bool]:
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

    def _detect(self, text: str, flag_re) -> list[tuple[str, str]]:
        t = text.strip()
        results: list[tuple[str, str]] = []

        def _add(method: str, decoded):
            if decoded and decoded != t:
                results.append((method, decoded))

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

        _add("Atbash", self._try_atbash(t))

        for item in self._try_xor_single(t):
            results.append(item)

        rsa = self._try_rsa_detect(t)
        if rsa:
            results.append(("RSA detected", rsa))

        return results

    # ── decoders ─────────────────────────────────────────────────────────────

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
        try:
            decoded = base64.b85decode(t).decode('utf-8', errors='replace')
            if self._is_printable(decoded) and len(decoded) > 1:
                return decoded
        except Exception:
            pass
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

    def all_caesar_rotations(self, t: str) -> list[tuple[int, float, str]]:
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
# GUI
# ─────────────────────────────────────────────────────────────────────────────
class WhiteClawCTFApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("WhiteClaw CTF — Cipher & Encoding Solver")
        self.root.geometry("1200x820")
        self.root.minsize(900, 580)
        self.root.configure(bg=BG)

        self._history: list[dict] = []
        self._engine = CTFSolverEngine()

        self._load_assets()
        self._build_styles()
        self._build_ui()
        self.root.bind("<Control-Return>", lambda _: self._run_solver())

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
        s.configure("TFrame",        background=BG)
        s.configure("TLabel",        background=BG, foreground=FG)
        s.configure("TNotebook",     background=BG, borderwidth=0, tabmargins=0)
        s.configure("TNotebook.Tab", background=BG3, foreground=FG2,
                    padding=[14, 5], font=("Consolas", 15))
        s.map("TNotebook.Tab",
              background=[("selected", BG)],
              foreground=[("selected", AMBER)])
        s.configure("Horizontal.TProgressbar",
                    background=AMBER, troughcolor=BG3, borderwidth=0, thickness=4)

    def _build_ui(self) -> None:
        self._build_header()
        self._build_main()
        self._build_statusbar()

    def _build_header(self) -> None:
        bar = tk.Frame(self.root, bg=BG2, pady=10, padx=20)
        bar.pack(fill="x")
        if self._logo_img:
            tk.Label(bar, image=self._logo_img, bg=BG2).pack(side="left", padx=(0, 10))
        tk.Label(bar, text="⬡ WhiteClaw CTF",
                 font=("Consolas", 26, "bold"), fg=AMBER, bg=BG2).pack(side="left")
        tk.Label(bar, text="  Cipher & Encoding Auto-Solver",
                 font=("Consolas", 16), fg=FG2, bg=BG2).pack(side="left", pady=2)
        tk.Label(bar, text="[ CTF / Research use only ]",
                 font=("Consolas", 14), fg=ORANGE, bg=BG2).pack(side="right")

    def _build_main(self) -> None:
        pane = tk.PanedWindow(self.root, orient="horizontal", bg=BG,
                              sashwidth=4, sashrelief="flat", sashpad=2)
        pane.pack(fill="both", expand=True, padx=6, pady=6)

        # ── Left: solver panel ────────────────────────────────────────────────
        left = tk.Frame(pane, bg=BG)
        pane.add(left, minsize=600)

        self._build_solver_panel(left)

        # ── Right: history + tips ─────────────────────────────────────────────
        right = tk.Frame(pane, bg=BG2)
        pane.add(right, minsize=220)

        self._build_history_panel(right)

    def _build_solver_panel(self, parent: tk.Frame) -> None:
        # Input label
        tk.Label(parent, text="INPUT — paste ciphertext / encoded data:",
                 font=("Consolas", 14), fg=FG2, bg=BG, anchor="w",
                 ).pack(fill="x", padx=8, pady=(6, 1))

        self._input = scrolledtext.ScrolledText(
            parent, bg=BG3, fg=FG, font=("Consolas", 16),
            relief="flat", wrap="word", height=7,
            insertbackground=AMBER, padx=6, pady=4,
        )
        self._input.pack(fill="x", padx=6, pady=(0, 4))

        # Buttons row
        btn_row = tk.Frame(parent, bg=BG)
        btn_row.pack(fill="x", padx=8, pady=(0, 4))

        self._solve_btn = tk.Button(
            btn_row, text="  AUTO-SOLVE  ",
            font=("Consolas", 16, "bold"),
            bg=PURPLE, fg="white", activebackground="#7030c0",
            relief="flat", padx=14, pady=4,
            command=self._run_solver,
        )
        self._solve_btn.pack(side="left", padx=(0, 6))

        tk.Button(btn_row, text="Caesar table",
                  font=("Consolas", 15), bg=BG3, fg=FG2,
                  activebackground=BG4, relief="flat", padx=10, pady=4,
                  command=self._show_caesar_table,
                  ).pack(side="left", padx=(0, 4))

        tk.Button(btn_row, text="Save result",
                  font=("Consolas", 15), bg=BG3, fg=FG2,
                  activebackground=BG4, relief="flat", padx=10, pady=4,
                  command=self._save_result,
                  ).pack(side="left", padx=(0, 4))

        tk.Button(btn_row, text="Clear",
                  font=("Consolas", 15), bg=BG3, fg=FG2,
                  activebackground=BG4, relief="flat", padx=10, pady=4,
                  command=self._clear,
                  ).pack(side="left", padx=(0, 16))

        tk.Label(btn_row, text="Flag regex (opt):",
                 font=("Consolas", 14), fg=FG2, bg=BG).pack(side="left")
        self._flag_fmt_var = tk.StringVar()
        tk.Entry(btn_row, textvariable=self._flag_fmt_var,
                 font=("Consolas", 15), bg=BG3, fg=FG,
                 insertbackground=AMBER, relief="flat", bd=6, width=24,
                 ).pack(side="left", padx=6, ipady=2)

        tk.Label(parent, text="Ctrl+Enter to solve",
                 font=("Consolas", 12), fg=BG4, bg=BG, anchor="e",
                 ).pack(fill="x", padx=8)

        # Separator
        tk.Frame(parent, bg=BG4, height=1).pack(fill="x", padx=6, pady=4)

        # Results label
        tk.Label(parent, text="RESULTS:",
                 font=("Consolas", 14), fg=FG2, bg=BG, anchor="w",
                 ).pack(fill="x", padx=8, pady=(0, 2))

        # Output area
        self._output = scrolledtext.ScrolledText(
            parent, bg=BG, fg=FG, font=("Consolas", 15),
            relief="flat", wrap="word",
            insertbackground="white", padx=6, pady=4,
        )
        self._output.pack(fill="both", expand=True, padx=4, pady=(0, 4))
        self._output.config(state="disabled")

        so = self._output
        so.tag_configure("banner",  foreground=GREEN,  font=("Consolas", 17, "bold"), background=SOLVED_BG)
        so.tag_configure("flag",    foreground=GREEN,  font=("Consolas", 15, "bold"))
        so.tag_configure("method",  foreground=AMBER,  font=("Consolas", 15, "bold"))
        so.tag_configure("step",    foreground=FG)
        so.tag_configure("attempt", foreground=FG2,    font=("Consolas", 14, "italic"))
        so.tag_configure("label",   foreground=FG2,    font=("Consolas", 14))
        so.tag_configure("error",   foreground=RED)
        so.tag_configure("sep",     foreground=BG4)
        so.tag_configure("caesar",  foreground=CYAN,   font=("Consolas", 14))
        so.tag_configure("hint",    foreground=ORANGE, font=("Consolas", 14, "italic"))

    def _build_history_panel(self, parent: tk.Frame) -> None:
        tk.Label(parent, text="SOLVE HISTORY",
                 font=("Consolas", 13, "bold"), fg=AMBER, bg=BG2, anchor="w",
                 padx=8, pady=6).pack(fill="x")

        tk.Frame(parent, bg=BG4, height=1).pack(fill="x")

        self._history_list = tk.Listbox(
            parent, bg=BG2, fg=FG2, font=("Consolas", 13),
            selectbackground=BG4, selectforeground=AMBER,
            relief="flat", borderwidth=0, activestyle="none",
        )
        self._history_list.pack(fill="both", expand=True, padx=0, pady=0)
        self._history_list.bind("<<ListboxSelect>>", self._on_history_select)

        tk.Frame(parent, bg=BG4, height=1).pack(fill="x")

        tk.Button(parent, text="Clear history",
                  font=("Consolas", 13), bg=BG3, fg=FG2,
                  activebackground=BG4, relief="flat", pady=4,
                  command=self._clear_history,
                  ).pack(fill="x", padx=4, pady=4)

        tk.Frame(parent, bg=BG4, height=1).pack(fill="x")

        tips = (
            "TIPS\n\n"
            "XOR: input must be\nhex-encoded ciphertext\n\n"
            "Caesar: use Caesar\ntable to see all 25\nrotations + scores\n\n"
            "Chains: solver nests\nup to 8 decode layers\n\n"
            "Custom regex: override\nflag format for non-\nstandard CTFs"
        )
        tk.Label(parent, text=tips, font=("Consolas", 12), fg=BG4, bg=BG2,
                 justify="left", anchor="nw", padx=10, pady=10,
                 ).pack(fill="x")

    def _build_statusbar(self) -> None:
        bar = tk.Frame(self.root, bg=BG2, padx=12, pady=4)
        bar.pack(fill="x", side="bottom")
        self._status_var = tk.StringVar(value="Ready — paste encoded data above and press AUTO-SOLVE.")
        tk.Label(bar, textvariable=self._status_var,
                 font=("Consolas", 13), fg=FG2, bg=BG2).pack(side="left")
        self._progress = ttk.Progressbar(bar, style="Horizontal.TProgressbar",
                                          mode="indeterminate", length=140)
        self._progress.pack(side="right", pady=2)

    # ── solver ────────────────────────────────────────────────────────────────

    def _run_solver(self) -> None:
        text = self._input.get("1.0", "end").strip()
        if not text:
            return

        self._solve_btn.config(state="disabled", text="Solving…")
        self._progress.start(10)
        self._status_var.set("Running auto-solve…")

        so = self._output
        so.config(state="normal")
        so.delete("1.0", "end")
        so.insert("end", "Running auto-solve…\n", "label")
        so.config(state="disabled")

        fmt = self._flag_fmt_var.get().strip()

        def _work():
            try:
                result = self._engine.solve(text, custom_flag_re=fmt)
            except Exception as exc:
                self.root.after(0, self._show_error, str(exc))
                return
            self.root.after(0, self._show_result, text, result)

        threading.Thread(target=_work, daemon=True).start()

    def _show_error(self, msg: str) -> None:
        so = self._output
        so.config(state="normal")
        so.delete("1.0", "end")
        so.insert("end", f"Error: {msg}\n", "error")
        so.config(state="disabled")
        self._solve_btn.config(state="normal", text="  AUTO-SOLVE  ")
        self._progress.stop()
        self._status_var.set(f"Error: {msg}")

    def _show_result(self, original: str, result: dict) -> None:
        so = self._output
        so.config(state="normal")
        so.delete("1.0", "end")

        chain    = result["chain"]
        flag     = result["flag"]
        solved   = result["solved"]
        attempts = result.get("all_attempts", [])

        if solved and flag:
            banner = f"  FLAG FOUND: {flag}  "
            so.insert("end", "═" * 64 + "\n", "sep")
            so.insert("end", banner.center(64) + "\n", "banner")
            so.insert("end", "═" * 64 + "\n\n", "sep")
            self._status_var.set(f"FLAG: {flag}")
        else:
            so.insert("end", "─" * 64 + "\n", "sep")
            so.insert("end", "  AUTO-SOLVE RESULTS\n", "method")
            so.insert("end", "─" * 64 + "\n\n", "sep")
            if not chain:
                so.insert("end", "No successful decoding found.\n\n", "error")
                so.insert("end", "Suggestions:\n", "label")
                so.insert("end",
                    "  • Paste just the encoded/ciphered portion, not surrounding text.\n"
                    "  • For XOR: input must be hex-encoded ciphertext.\n"
                    "  • For Vigenère or AES: manual key required — not auto-solved.\n"
                    "  • Try the 'Caesar table' button to inspect all 25 rotations.\n",
                    "hint")
            self._status_var.set("Solve complete — no flag found.")

        if chain:
            so.insert("end", "Decode chain:\n\n", "label")
            for step in chain:
                n       = step["step"]
                method  = step["method"]
                inp     = step["input"]
                outp    = step["output"]
                is_flag = step.get("is_flag", False)
                so.insert("end", f"  Step {n}: ", "label")
                so.insert("end", method + "\n", "method")
                so.insert("end", f"    Input  : {inp[:100]}\n", "step")
                so.insert("end",  "    Output : ", "step")
                so.insert("end", outp[:400] + "\n\n", "flag" if is_flag else "step")

        if attempts:
            so.insert("end", "─" * 64 + "\n", "sep")
            so.insert("end", "All first-level decode attempts:\n\n", "label")
            for method, preview in attempts:
                so.insert("end", f"  {method:<24}", "attempt")
                so.insert("end", f"→ {preview[:80]}\n", "step")

        so.config(state="disabled")
        so.see("1.0")
        self._solve_btn.config(state="normal", text="  AUTO-SOLVE  ")
        self._progress.stop()

        # Add to history
        label = (flag if flag else original[:40] + ("…" if len(original) > 40 else ""))
        status = "✔ " if solved else "✗ "
        self._history.append({"input": original, "result": result, "label": label, "solved": solved})
        self._history_list.insert(0, status + label)

    def _show_caesar_table(self) -> None:
        text = self._input.get("1.0", "end").strip()
        if not text:
            return

        rotations = self._engine.all_caesar_rotations(text)
        so = self._output
        so.config(state="normal")
        so.delete("1.0", "end")
        so.insert("end", "─" * 64 + "\n", "sep")
        so.insert("end", "  CAESAR / ROT — ALL 25 ROTATIONS  (sorted by English score)\n", "method")
        so.insert("end", "─" * 64 + "\n\n", "sep")
        so.insert("end", f"  {'ROT':<6}{'Score':>7}   {'Preview (first 60 chars)'}\n", "label")
        so.insert("end", "  " + "─" * 56 + "\n", "sep")

        for shift, score, decoded in rotations:
            line = f"  ROT{shift:<3}  {score:>6.2f}   {decoded[:60]}\n"
            tag = "flag" if FLAG_RE.search(decoded) else "caesar"
            so.insert("end", line, tag)

        so.insert("end", "\n")
        so.config(state="disabled")
        so.see("1.0")
        self._status_var.set("Caesar table — sorted by English frequency score.")

    def _save_result(self) -> None:
        content = self._output.get("1.0", "end").strip()
        if not content:
            messagebox.showinfo("Nothing to save", "Run a solve first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text file", "*.txt"), ("All files", "*.*")],
            title="Save CTF Solve Result",
        )
        if not path:
            return
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(f"WhiteClaw CTF — Solve Result\n")
            fh.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            fh.write("=" * 64 + "\n\n")
            fh.write(content)
        messagebox.showinfo("Saved", f"Result saved to:\n{path}")

    def _clear(self) -> None:
        self._input.delete("1.0", "end")
        so = self._output
        so.config(state="normal")
        so.delete("1.0", "end")
        so.config(state="disabled")
        self._status_var.set("Cleared.")

    def _on_history_select(self, _event=None) -> None:
        sel = self._history_list.curselection()
        if not sel:
            return
        idx = sel[0]
        # History list is newest-first (insert at 0), so reverse index
        item = self._history[len(self._history) - 1 - idx]
        self._input.delete("1.0", "end")
        self._input.insert("1.0", item["input"])
        self._show_result(item["input"], item["result"])

    def _clear_history(self) -> None:
        self._history.clear()
        self._history_list.delete(0, "end")


def main() -> None:
    root = tk.Tk()
    WhiteClawCTFApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
