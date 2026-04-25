"""
secure_vault_gui.py
═══════════════════
Encrypted File Vault — Single-file Python GUI
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Cipher suite:
  • AES-256-GCM      — confidentiality + per-chunk auth tag
  • HMAC-SHA256      — file-level integrity
  • PBKDF2-SHA256    — passphrase → key (100,000 iterations)
  • Random 96-bit IV — unique per chunk (os.urandom)
  • Chunk AAD        — index bound into GCM, defeats reordering

Run:
    pip install cryptography
    python secure_vault_gui.py
"""

# ── stdlib ────────────────────────────────────────────────────────────────────
import os, sys, json, hmac, struct, secrets, threading, hashlib, mimetypes
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import tkinter.font as tkfont

# ── third-party (pip install cryptography) ────────────────────────────────────
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac
    from cryptography.hazmat.backends import default_backend
    from cryptography.exceptions import InvalidTag
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "cryptography", "-q"])
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac
    from cryptography.hazmat.backends import default_backend
    from cryptography.exceptions import InvalidTag

# ══════════════════════════════════════════════════════════════════════════════
#  CRYPTO ENGINE
# ══════════════════════════════════════════════════════════════════════════════
CHUNK_SIZE    = 64 * 1024
PBKDF2_ITERS  = 100_000
SALT_BYTES    = 16
IV_BYTES      = 12

@dataclass
class EncryptedChunk:
    index:      int
    iv:         bytes
    ciphertext: bytes

@dataclass
class EncryptedFile:
    file_id:        str
    filename:       str
    mime_type:      str
    plaintext_size: int
    aes_salt:       bytes
    hmac_salt:      bytes
    file_hmac:      bytes
    chunks:         List[EncryptedChunk] = field(default_factory=list)

def _derive(password: str, salt: bytes, usage: list) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=salt, iterations=PBKDF2_ITERS,
                     backend=default_backend())
    return kdf.derive(password.encode())

def derive_aes_key(pw, salt):  return _derive(pw, salt, ["encrypt"])
def derive_hmac_key(pw, salt): return _derive(pw, salt, ["sign"])

def encrypt_chunk(aes_key: bytes, data: bytes, idx: int) -> EncryptedChunk:
    iv  = os.urandom(IV_BYTES)
    aad = struct.pack(">I", idx)
    ct  = AESGCM(aes_key).encrypt(iv, data, aad)
    return EncryptedChunk(idx, iv, ct)

def decrypt_chunk(aes_key: bytes, chunk: EncryptedChunk) -> bytes:
    aad = struct.pack(">I", chunk.index)
    return AESGCM(aes_key).decrypt(chunk.iv, chunk.ciphertext, aad)

def compute_hmac(hmac_key: bytes, chunks: List[EncryptedChunk]) -> bytes:
    h = crypto_hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
    for c in sorted(chunks, key=lambda x: x.index):
        h.update(c.ciphertext)
    return h.finalize()

def verify_hmac(hmac_key, chunks, expected) -> bool:
    return hmac.compare_digest(compute_hmac(hmac_key, chunks), expected)

def encrypt_file(plaintext: bytes, password: str, filename: str,
                 mime_type: str = "application/octet-stream",
                 progress_cb=None) -> EncryptedFile:
    aes_salt  = os.urandom(SALT_BYTES)
    hmac_salt = os.urandom(SALT_BYTES)
    aes_key   = derive_aes_key(password, aes_salt)
    hmac_key  = derive_hmac_key(password, hmac_salt)
    n = max(1, -(-len(plaintext) // CHUNK_SIZE))
    chunks = []
    for i in range(n):
        sl = plaintext[i*CHUNK_SIZE:(i+1)*CHUNK_SIZE]
        chunks.append(encrypt_chunk(aes_key, sl, i))
        if progress_cb: progress_cb(i+1, n)
    mac = compute_hmac(hmac_key, chunks)
    return EncryptedFile(
        file_id=secrets.token_hex(16), filename=filename, mime_type=mime_type,
        plaintext_size=len(plaintext), aes_salt=aes_salt, hmac_salt=hmac_salt,
        file_hmac=mac, chunks=chunks)

def decrypt_file(enc: EncryptedFile, password: str, progress_cb=None) -> bytes:
    hmac_key = derive_hmac_key(password, enc.hmac_salt)
    if not verify_hmac(hmac_key, enc.chunks, enc.file_hmac):
        raise ValueError("HMAC failed — wrong password or file tampered.")
    aes_key = derive_aes_key(password, enc.aes_salt)
    plains  = []
    for i, c in enumerate(sorted(enc.chunks, key=lambda x: x.index)):
        plains.append(decrypt_chunk(aes_key, c))
        if progress_cb: progress_cb(i+1, len(enc.chunks))
    return b"".join(plains)

def serialize(enc: EncryptedFile) -> dict:
    return {"file_id": enc.file_id, "filename": enc.filename,
            "mime_type": enc.mime_type, "plaintext_size": enc.plaintext_size,
            "aes_salt": enc.aes_salt.hex(), "hmac_salt": enc.hmac_salt.hex(),
            "file_hmac": enc.file_hmac.hex(),
            "chunks": [{"index": c.index, "iv": c.iv.hex(),
                        "ciphertext": c.ciphertext.hex()} for c in enc.chunks]}

def deserialize(d: dict) -> EncryptedFile:
    return EncryptedFile(
        file_id=d["file_id"], filename=d["filename"], mime_type=d["mime_type"],
        plaintext_size=d["plaintext_size"], aes_salt=bytes.fromhex(d["aes_salt"]),
        hmac_salt=bytes.fromhex(d["hmac_salt"]), file_hmac=bytes.fromhex(d["file_hmac"]),
        chunks=[EncryptedChunk(c["index"], bytes.fromhex(c["iv"]),
                               bytes.fromhex(c["ciphertext"])) for c in d["chunks"]])

# ══════════════════════════════════════════════════════════════════════════════
#  STORAGE  (local .vault folder)
# ══════════════════════════════════════════════════════════════════════════════
VAULT_DIR = Path.home() / ".secure_vault"
VAULT_DIR.mkdir(exist_ok=True)

def vault_path(file_id: str) -> Path:
    return VAULT_DIR / f"{file_id}.enc.json"

def save_to_vault(enc: EncryptedFile):
    with open(vault_path(enc.file_id), "w") as f:
        json.dump(serialize(enc), f)

def load_all_vault() -> List[EncryptedFile]:
    result = []
    for p in VAULT_DIR.glob("*.enc.json"):
        with open(p) as f:
            result.append(deserialize(json.load(f)))
    return sorted(result, key=lambda x: x.file_id)

def delete_from_vault(file_id: str):
    vault_path(file_id).unlink(missing_ok=True)

# ══════════════════════════════════════════════════════════════════════════════
#  THEME / PALETTE
# ══════════════════════════════════════════════════════════════════════════════
BG        = "#0f1117"
BG2       = "#1a1d27"
BG3       = "#232635"
BORDER    = "#2d3148"
ACCENT    = "#6366f1"    # indigo
ACCENT2   = "#818cf8"
SUCCESS   = "#22d3a5"
DANGER    = "#f87171"
WARNING   = "#fbbf24"
TEXT      = "#e2e8f0"
TEXT2     = "#94a3b8"
TEXT3     = "#475569"

FONT_FAM  = "Segoe UI" if sys.platform == "win32" else \
            "SF Pro Display" if sys.platform == "darwin" else "Ubuntu"
MONO_FAM  = "Consolas" if sys.platform == "win32" else \
            "SF Mono"  if sys.platform == "darwin" else "Ubuntu Mono"

def _hex_to_rgb(h):
    h = h.lstrip("#")
    return tuple(int(h[i:i+2], 16) for i in (0, 2, 4))

# ══════════════════════════════════════════════════════════════════════════════
#  CUSTOM WIDGETS
# ══════════════════════════════════════════════════════════════════════════════
class RoundedButton(tk.Canvas):
    """Pill-shaped canvas button with hover effect."""
    def __init__(self, parent, text, command=None, color=ACCENT,
                 text_color=TEXT, width=140, height=38, radius=10, **kw):
        super().__init__(parent, width=width, height=height,
                         bg=parent["bg"], highlightthickness=0, **kw)
        self._cmd    = command
        self._color  = color
        self._hover  = self._brighten(color, 20)
        self._text   = text
        self._tc     = text_color
        self._r      = radius
        self._bw     = width
        self._bh     = height
        self._draw(self._color)
        self.bind("<Enter>",    lambda e: self._draw(self._hover))
        self.bind("<Leave>",    lambda e: self._draw(self._color))
        self.bind("<Button-1>", lambda e: self._click())

    def _brighten(self, hex_color, amt):
        r, g, b = _hex_to_rgb(hex_color)
        return "#{:02x}{:02x}{:02x}".format(
            min(255, r+amt), min(255, g+amt), min(255, b+amt))

    def _draw(self, color):
        self.delete("all")
        r, w, h = self._r, self._bw, self._bh
        self.create_arc(0,   0,   2*r, 2*r, start=90,  extent=90,  fill=color, outline=color)
        self.create_arc(w-2*r, 0,   w, 2*r, start=0,   extent=90,  fill=color, outline=color)
        self.create_arc(0, h-2*r, 2*r, h,   start=180, extent=90,  fill=color, outline=color)
        self.create_arc(w-2*r, h-2*r, w, h, start=270, extent=90,  fill=color, outline=color)
        self.create_rectangle(r, 0, w-r, h,   fill=color, outline=color)
        self.create_rectangle(0, r, w,   h-r, fill=color, outline=color)
        self.create_text(w//2, h//2, text=self._text, fill=self._tc,
                         font=(FONT_FAM, 11, "bold"))

    def _click(self):
        if self._cmd: self._cmd()

    def configure_text(self, text):
        self._text = text
        self._draw(self._color)


class GlowEntry(tk.Frame):
    """Entry field with animated focus glow."""
    def __init__(self, parent, placeholder="", show=None, **kw):
        super().__init__(parent, bg=BG2, highlightthickness=1,
                         highlightbackground=BORDER, **kw)
        self._ph    = placeholder
        self._show  = show
        self._active= False
        self.entry  = tk.Entry(self, bg=BG2, fg=TEXT, insertbackground=TEXT,
                               relief="flat", font=(FONT_FAM, 12),
                               disabledforeground=TEXT2,
                               show=show if show else "")
        self.entry.pack(fill="x", padx=12, pady=8)
        if placeholder:
            self.entry.insert(0, placeholder)
            self.entry.config(fg=TEXT3)
        self.entry.bind("<FocusIn>",  self._on_focus)
        self.entry.bind("<FocusOut>", self._on_blur)

    def _on_focus(self, _=None):
        self.config(highlightbackground=ACCENT)
        if self.entry.get() == self._ph:
            self.entry.delete(0, "end")
            self.entry.config(fg=TEXT, show=self._show or "")

    def _on_blur(self, _=None):
        self.config(highlightbackground=BORDER)
        if not self.entry.get() and self._ph:
            self.entry.config(show="")
            self.entry.insert(0, self._ph)
            self.entry.config(fg=TEXT3)

    def get(self):
        v = self.entry.get()
        return "" if v == self._ph else v

    def clear(self):
        self.entry.delete(0, "end")
        self._on_blur()


class StepIndicator(tk.Canvas):
    """Horizontal pipeline step indicators."""
    STEPS = ["Key Derive", "Chunking", "AES-GCM", "HMAC Sign", "Store"]

    def __init__(self, parent, **kw):
        super().__init__(parent, bg=BG, highlightthickness=0, height=68, **kw)
        self._active = -1
        self.bind("<Configure>", lambda e: self._draw())

    def set_step(self, idx):
        self._active = idx
        self._draw()

    def _draw(self):
        self.delete("all")
        W    = self.winfo_width() or 600
        n    = len(self.STEPS)
        sw   = W // n
        for i, label in enumerate(self.STEPS):
            cx = sw * i + sw // 2
            state = "done" if i < self._active else \
                    "active" if i == self._active else "idle"
            fill  = SUCCESS if state == "done" else \
                    ACCENT  if state == "active" else BG3
            out   = SUCCESS if state == "done" else \
                    ACCENT2 if state == "active" else BORDER
            r = 18
            self.create_oval(cx-r, 4, cx+r, 4+2*r, fill=fill, outline=out, width=2)
            icon = "✓" if state == "done" else str(i+1)
            self.create_text(cx, 4+r, text=icon,
                             fill=TEXT if state != "idle" else TEXT3,
                             font=(FONT_FAM, 10, "bold"))
            self.create_text(cx, 4+2*r+10, text=label,
                             fill=TEXT if state == "active" else TEXT2,
                             font=(FONT_FAM, 8))
            if i < n-1:
                lx = cx + r
                rx = cx + sw - r
                cy = 4 + r
                lc = SUCCESS if i < self._active else BORDER
                self.create_line(lx+2, cy, rx-2, cy, fill=lc, width=2)


class ChunkGrid(tk.Canvas):
    """Animated grid of chunk squares."""
    def __init__(self, parent, **kw):
        super().__init__(parent, bg=BG2, highlightthickness=0, height=60, **kw)
        self._total   = 0
        self._done    = 0
        self._current = -1

    def setup(self, total):
        self._total   = min(total, 80)
        self._done    = 0
        self._current = -1
        self._draw()

    def advance(self, done):
        self._done    = min(done, self._total)
        self._current = self._done
        self._draw()

    def complete(self):
        self._done    = self._total
        self._current = -1
        self._draw()

    def reset(self):
        self._total   = 0
        self._done    = 0
        self._current = -1
        self.delete("all")

    def _draw(self):
        self.delete("all")
        if not self._total: return
        SZ   = 12
        PAD  = 3
        cols = max(1, (self.winfo_width() or 600) // (SZ + PAD))
        for i in range(self._total):
            col = i % cols
            row = i // cols
            x   = 8 + col * (SZ + PAD)
            y   = 8 + row * (SZ + PAD)
            if i < self._done:
                clr = SUCCESS
            elif i == self._current:
                clr = WARNING
            else:
                clr = BG3
            self.create_rectangle(x, y, x+SZ, y+SZ, fill=clr, outline="")


class LogConsole(tk.Frame):
    """Dark scrolling log console."""
    TAGS = {
        "info":    TEXT,
        "success": SUCCESS,
        "warn":    WARNING,
        "error":   DANGER,
        "accent":  ACCENT2,
    }

    def __init__(self, parent, height=10, **kw):
        super().__init__(parent, bg=BG2, **kw)
        self.text = tk.Text(self, bg=BG2, fg=TEXT, relief="flat", height=height,
                            font=(MONO_FAM, 10), state="disabled",
                            selectbackground=BG3, wrap="word",
                            padx=12, pady=8)
        sb = ttk.Scrollbar(self, command=self.text.yview)
        self.text.config(yscrollcommand=sb.set)
        for tag, color in self.TAGS.items():
            self.text.tag_config(tag, foreground=color)
        sb.pack(side="right", fill="y")
        self.text.pack(fill="both", expand=True)

    def log(self, msg: str, kind: str = "info"):
        import time
        ts = time.strftime("%H:%M:%S")
        self.text.config(state="normal")
        self.text.insert("end", f"[{ts}] ", "accent")
        self.text.insert("end", msg + "\n", kind)
        self.text.see("end")
        self.text.config(state="disabled")

    def clear(self):
        self.text.config(state="normal")
        self.text.delete("1.0", "end")
        self.text.config(state="disabled")


class PasswordStrengthBar(tk.Frame):
    """Colour-changing strength indicator."""
    LEVELS = [
        (0,  "",          BG3),
        (1,  "Weak",      DANGER),
        (2,  "Fair",      WARNING),
        (3,  "Strong",    SUCCESS),
        (4,  "Excellent", "#10b981"),
    ]

    def __init__(self, parent, **kw):
        super().__init__(parent, bg=BG, **kw)
        self.bar_bg  = tk.Frame(self, bg=BG3, height=4)
        self.bar_bg.pack(fill="x", pady=(4, 2))
        self.bar_fg  = tk.Frame(self.bar_bg, bg=BG3, height=4)
        self.bar_fg.place(x=0, y=0, relheight=1, relwidth=0)
        self.label   = tk.Label(self, bg=BG, fg=TEXT3, font=(FONT_FAM, 9))
        self.label.pack(anchor="w")

    def update(self, password: str):
        v = password
        score = 0
        if len(v) >= 8:  score += 1
        if len(v) >= 14: score += 1
        if any(c.isupper() for c in v) and any(c.isdigit() for c in v): score += 1
        if any(c in "!@#$%^&*()-_=+[]{}|;:',.<>?/" for c in v): score += 1
        _, lbl, clr = self.LEVELS[min(score, 4)]
        self.bar_fg.place(relwidth=score / 4)
        self.bar_fg.config(bg=clr if score else BG3)
        self.label.config(text=lbl, fg=clr)


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN APPLICATION
# ══════════════════════════════════════════════════════════════════════════════
class SecureVaultApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure File Vault")
        self.geometry("940x720")
        self.minsize(800, 600)
        self.configure(bg=BG)
        self._vault: List[EncryptedFile] = []
        self._busy = False
        self._setup_styles()
        self._build_ui()
        self._refresh_vault()

    # ── ttk styles ────────────────────────────────────────────────────────────
    def _setup_styles(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure(".", background=BG, foreground=TEXT,
                    fieldbackground=BG2, troughcolor=BG3,
                    selectbackground=ACCENT, selectforeground=TEXT,
                    font=(FONT_FAM, 11))
        s.configure("Treeview", background=BG2, foreground=TEXT,
                    rowheight=42, fieldbackground=BG2, borderwidth=0)
        s.configure("Treeview.Heading", background=BG3, foreground=TEXT2,
                    relief="flat", font=(FONT_FAM, 10, "bold"))
        s.map("Treeview", background=[("selected", BG2)],
              foreground=[("selected", TEXT)])
        s.configure("Horizontal.TProgressbar", troughcolor=BG3,
                    background=ACCENT, borderwidth=0, thickness=6)
        s.configure("TSeparator", background=BORDER, fg=WARNING)

        s.configure("TNotebook.Tab", foreground=TEXT2, background=BG3, padding=[10, 7])
        s.map("TNotebook.Tab", foreground=[("selected", SUCCESS)], background=[("selected", BG2)])

    # ── UI skeleton ───────────────────────────────────────────────────────────
    def _build_ui(self):
        # ── Header ───────────────────────────────────────────────────────────
        hdr = tk.Frame(self, bg=BG2, height=64)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        tk.Label(hdr, text="🔐  Secure File Vault", bg=BG2, fg=TEXT2,
                 font=(FONT_FAM, 18, "bold")).pack(side="left", padx=20, pady=14)
        tk.Label(hdr, text="AES-256-GCM · HMAC-SHA256 · PBKDF2",
                 bg=BG2, fg=TEXT2, font=(MONO_FAM, 10)).pack(side="right", padx=20)
        ttk.Separator(self, orient="horizontal").pack(fill="x")

        # ── Notebook tabs ─────────────────────────────────────────────────────
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=16, pady=16)

        self.tab_enc = tk.Frame(nb, bg=BG)
        self.tab_vault= tk.Frame(nb, bg=BG)
        self.tab_threat=tk.Frame(nb, bg=BG)
        nb.add(self.tab_enc,    text="🔑Encrypt & Upload")
        nb.add(self.tab_vault,  text="🔐Secure Vault")
        nb.add(self.tab_threat, text="🛡Threat Model")

        self._build_encrypt_tab()
        self._build_vault_tab()
        self._build_threat_tab()

    # ══════════════════════════════════════════════════════════════════════════
    #  TAB 1 — ENCRYPT & UPLOAD
    # ══════════════════════════════════════════════════════════════════════════
    def _build_encrypt_tab(self):
        p = self.tab_enc

        # left column
        left = tk.Frame(p, bg=BG)
        left.pack(side="left", fill="both", expand=True, padx=(0,8), pady=4)

        # ── File drop zone ────────────────────────────────────────────────────
        dz = tk.Frame(left, bg=BG2, highlightthickness=1,
                      highlightbackground=BORDER)
        dz.pack(fill="x", pady=(0,10))
        self._dz_lbl = tk.Label(dz,
            text="📂  Drop a file here  or  click Browse",
            bg=BG2, fg=TEXT2, font=(FONT_FAM, 13), pady=28)
        self._dz_lbl.pack(fill="x")
        for w in (dz, self._dz_lbl):
            w.bind("<Button-1>",    lambda e: self._browse_file())
            w.bind("<Enter>",       lambda e: dz.config(highlightbackground=ACCENT))
            w.bind("<Leave>",       lambda e: dz.config(highlightbackground=BORDER))

        # enable drag-and-drop if tkinterdnd2 available (graceful fallback)
        try:
            from tkinterdnd2 import DND_FILES
            dz.drop_target_register(DND_FILES)
            dz.dnd_bind("<<Drop>>", self._on_drop)
        except Exception:
            pass

        # ── Password ──────────────────────────────────────────────────────────
        tk.Label(left, text="Passphrase", bg=BG, fg=TEXT2,
                 font=(FONT_FAM, 10, "bold")).pack(anchor="w", pady=(0,3))
        self.pw_entry = GlowEntry(left, placeholder="Enter strong passphrase …",
                                  show="•")
        self.pw_entry.pack(fill="x")
        self.pw_entry.entry.bind("<KeyRelease>",
            lambda e: self.pw_strength.update(self.pw_entry.get()))
        self.pw_strength = PasswordStrengthBar(left)
        self.pw_strength.pack(fill="x", pady=(4,0))

        # ── Output dir ────────────────────────────────────────────────────────
        tk.Label(left, text="Download folder (for decryption)",
                 bg=BG, fg=TEXT2, font=(FONT_FAM, 10, "bold")).pack(anchor="w", pady=(10,3))
        row_out = tk.Frame(left, bg=BG)
        row_out.pack(fill="x")
        self.out_entry = GlowEntry(row_out, placeholder=str(Path.home() / "Downloads"))
        self.out_entry.pack(side="left", fill="x", expand=True)
        RoundedButton(row_out, "Browse", command=self._browse_outdir,
                      color=BG3, width=80, height=34).pack(side="left", padx=(6,0))

        # ── Action buttons ────────────────────────────────────────────────────
        btn_row = tk.Frame(left, bg=BG)
        btn_row.pack(pady=12)
        RoundedButton(btn_row, "🔒  Encrypt & Save",
                      command=self._start_encrypt,
                      color=ACCENT, width=180).pack(side="left", padx=4)
        RoundedButton(btn_row, "🔓  Decrypt File",
                      command=self._decrypt_from_file,
                      color=BG3, width=160).pack(side="left", padx=4)

        # ── Progress pipeline ─────────────────────────────────────────────────
        tk.Label(left, text="Encryption pipeline",
                 bg=BG, fg=TEXT2, font=(FONT_FAM, 10, "bold")).pack(anchor="w")
        self.steps = StepIndicator(left)
        self.steps.pack(fill="x", pady=(4,6))

        # chunk grid
        tk.Label(left, text="Chunk progress",
                 bg=BG, fg=TEXT2, font=(FONT_FAM, 10, "bold")).pack(anchor="w")
        self.chunk_grid = ChunkGrid(left)
        self.chunk_grid.pack(fill="x", pady=(4,4))

        # progress bar + label
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(left, variable=self.progress_var,
                                            style="Horizontal.TProgressbar")
        self.progress_bar.pack(fill="x")
        self.progress_lbl = tk.Label(left, text="", bg=BG, fg=TEXT2,
                                     font=(MONO_FAM, 9))
        self.progress_lbl.pack(anchor="w", pady=2)

        # ── Log console ───────────────────────────────────────────────────────
        right = tk.Frame(p, bg=BG, width=320)
        right.pack(side="right", fill="both", padx=(8,0), pady=4)
        right.pack_propagate(False)
        hdr_row = tk.Frame(right, bg=BG)
        hdr_row.pack(fill="x")
        tk.Label(hdr_row, text="Security log", bg=BG, fg=TEXT2,
                 font=(FONT_FAM, 10, "bold")).pack(side="left")
        RoundedButton(hdr_row, "Clear", command=lambda: self.log.clear(),
                      color=BG3, width=60, height=26).pack(side="right")
        self.log = LogConsole(right, height=30)
        self.log.pack(fill="both", expand=True, pady=(4,0))
        self.log.log("Ready — AES-256-GCM + HMAC-SHA256 + PBKDF2", "accent")

        # state
        self._selected_file: Optional[Path] = None

    # ══════════════════════════════════════════════════════════════════════════
    #  TAB 2 — VAULT
    # ══════════════════════════════════════════════════════════════════════════
    def _build_vault_tab(self):
        p = self.tab_vault

        # stat row
        stat_row = tk.Frame(p, bg=BG)
        stat_row.pack(fill="x", pady=(0,10))
        self._stats = []
        for label in ("Files", "Chunks", "Total size"):
            card = tk.Frame(stat_row, bg=BG2, padx=20, pady=10)
            card.pack(side="left", padx=(0,10))
            val = tk.Label(card, text="0", bg=BG2, fg=TEXT,
                           font=(FONT_FAM, 24, "bold"))
            val.pack()
            tk.Label(card, text=label, bg=BG2, fg=TEXT2,
                     font=(FONT_FAM, 9)).pack()
            self._stats.append(val)

        # toolbar
        tb = tk.Frame(p, bg=BG)
        tb.pack(fill="x", pady=(0,6))
        RoundedButton(tb, "🔓  Decrypt & Download",
                      command=self._decrypt_selected,
                      color=ACCENT, width=200).pack(side="left", padx=(0,8))
        RoundedButton(tb, "🗑  Delete",
                      command=self._delete_selected,
                      color="#4b1c1c", text_color=DANGER, width=100).pack(side="left")
        RoundedButton(tb, "⟳  Refresh",
                      command=self._refresh_vault,
                      color=BG3, width=100).pack(side="right")

        # treeview
        cols = ("name", "size", "chunks", "id", "date")
        self.tree = ttk.Treeview(p, columns=cols, show="headings", selectmode="browse")
        for col, head, w in [
            ("name",   "Filename",   200),
            ("size",   "Size",        90),
            ("chunks", "Chunks",      70),
            ("id",     "File ID",    230),
            ("date",   "Encrypted",  160),
        ]:
            self.tree.heading(col, text=head)
            self.tree.column(col, width=w, anchor="w")
        sb = ttk.Scrollbar(p, orient="vertical", command=self.tree.yview)
        self.tree.config(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.tree.pack(fill="both", expand=True)

        # detail bar at bottom
        self.detail_lbl = tk.Label(p, text="", bg=BG2, fg=TEXT2, anchor="w",
                                    font=(MONO_FAM, 9), padx=10, pady=6)
        self.detail_lbl.pack(fill="x", side="bottom")
        self.tree.bind("<<TreeviewSelect>>", self._on_vault_select)

    # ══════════════════════════════════════════════════════════════════════════
    #  TAB 3 — THREAT MODEL
    # ══════════════════════════════════════════════════════════════════════════
    def _build_threat_tab(self):
        p = self.tab_threat

        canvas = tk.Canvas(p, bg=BG, highlightthickness=0)
        sb     = ttk.Scrollbar(p, orient="vertical", command=canvas.yview)
        canvas.config(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        canvas.pack(fill="both", expand=True)

        inner = tk.Frame(canvas, bg=BG)
        win   = canvas.create_window((0,0), window=inner, anchor="nw")
        def _resize(e):
            canvas.itemconfig(win, width=e.width)
        canvas.bind("<Configure>", _resize)
        inner.bind("<Configure>",
                   lambda e: canvas.config(scrollregion=canvas.bbox("all")))

        def section(title):
            tk.Label(inner, text=title, bg=BG, fg=ACCENT2,
                     font=(FONT_FAM, 13, "bold")).pack(anchor="w", pady=(16,4), padx=16)

        def threat(title, severity, attack, mitigation, sev_color):
            card = tk.Frame(inner, bg=BG2, padx=16, pady=12)
            card.pack(fill="x", padx=16, pady=4)
            # coloured left stripe
            stripe = tk.Frame(card, bg=sev_color, width=4)
            stripe.pack(side="left", fill="y", padx=(0,12))
            body = tk.Frame(card, bg=BG2)
            body.pack(fill="x", expand=True)
            top = tk.Frame(body, bg=BG2)
            top.pack(fill="x")
            tk.Label(top, text=title, bg=BG2, fg=TEXT,
                     font=(FONT_FAM, 11, "bold")).pack(side="left")
            tk.Label(top, text=severity, bg=sev_color, fg=BG,
                     font=(FONT_FAM, 9, "bold"), padx=6, pady=2).pack(side="right")
            tk.Label(body, text=f"Attack:  {attack}",
                     bg=BG2, fg=TEXT2, font=(FONT_FAM, 10),
                     wraplength=700, justify="left", anchor="w").pack(anchor="w", pady=2)
            tk.Label(body, text=f"Mitigation:  {mitigation}",
                     bg=BG2, fg=SUCCESS, font=(FONT_FAM, 10),
                     wraplength=700, justify="left", anchor="w").pack(anchor="w")

        section("Architecture")
        arch_txt = (
            "Keys are derived from a user passphrase using PBKDF2-HMAC-SHA256 with a "
            "random 128-bit salt and 100,000 iterations. Files are split into 64 KB "
            "chunks, each encrypted with AES-256-GCM using a unique 96-bit IV. The "
            "chunk index is bound as GCM Additional Authenticated Data (AAD), preventing "
            "reordering attacks. A separate HMAC-SHA256 key (independent salt) covers "
            "all ciphertext to provide file-level integrity.\n\n"
            "Vault storage: ~/.secure_vault/ — only ciphertext + salts + HMAC on disk. "
            "The encryption key never leaves memory."
        )
        tk.Label(inner, text=arch_txt, bg=BG, fg=TEXT2,
                 font=(FONT_FAM, 11), wraplength=860, justify="left",
                 padx=16).pack(anchor="w")

        section("Threat Analysis")
        threats = [
            ("Man-in-the-Middle (MitM)", "CRITICAL", DANGER,
             "Adversary intercepts the channel, reads or flips ciphertext.",
             "Use TLS 1.3 in production. AES-GCM 128-bit auth tag detects any bit-flip — decryption throws. HMAC catches reassembly tampering."),
            ("Data at Rest — Server Compromise", "CRITICAL", DANGER,
             "Attacker reads the disk. Wants plaintext.",
             "Vault stores opaque ciphertext only. No key is persisted — re-derived from passphrase on demand. Without the passphrase, data is indistinguishable from random bytes."),
            ("Brute-Force / Dictionary Attack", "CRITICAL", DANGER,
             "Offline dictionary attack using the stored salt to guess the passphrase.",
             "PBKDF2 × 100,000 iterations costs ~10 ms per guess on modern hardware. Use Argon2id in production for memory-hardness against GPU farms."),
            ("Chunk Reordering / Replay", "HIGH", WARNING,
             "Swap encrypted chunks between files, or replay old chunks.",
             "Chunk index bound as GCM AAD. Decrypting chunk i with index j≠i throws InvalidTag. HMAC-SHA256 over all ciphertext in order detects any reordering."),
            ("IV / Nonce Reuse", "HIGH", WARNING,
             "Reusing an IV with the same AES key in GCM leaks the auth key and enables forgery.",
             "os.urandom(12) per chunk — 96-bit random IV. Birthday collision probability across 2³² chunks < 2⁻³². Production: use a monotonic counter IV instead."),
            ("Key Management — Passphrase Loss", "MEDIUM", WARNING,
             "User forgets passphrase. Data permanently inaccessible.",
             "Implement envelope encryption: wrap the per-file AES key with an RSA public key; store wrapped key with ciphertext. Recovery via private key or escrow."),
            ("Timing Oracle", "LOW", SUCCESS,
             "Timing differences in MAC comparison leak valid vs. invalid MAC.",
             "hmac.compare_digest() performs constant-time comparison. Never compare MACs with ==."),
            ("Metadata Leakage", "LOW", SUCCESS,
             "File size, name, and chunk count remain visible even with encrypted content.",
             "Encrypt filenames and store as opaque IDs. Pad chunks to uniform size. Use ORAM or onion routing to hide access patterns."),
        ]
        for title, sev, sev_clr, attack, mitigation in threats:
            threat(title, sev, attack, mitigation, sev_clr)

        section("Key Derivation Flow")
        flow_txt = (
            "passphrase + salt₁  ──PBKDF2-SHA256──▶  AES-256 key\n"
            "                                               ↓\n"
            "                    AES-GCM(IV, chunk, AAD=index)  →  ciphertext + 128-bit auth tag\n\n"
            "passphrase + salt₂  ──PBKDF2-SHA256──▶  HMAC-SHA256 key\n"
            "                                               ↓\n"
            "                    HMAC(all_ciphertext in chunk order)  →  256-bit MAC"
        )
        tk.Label(inner, text=flow_txt, bg=BG2, fg=ACCENT2,
                 font=(MONO_FAM, 10), justify="left",
                 padx=16, pady=12).pack(fill="x", padx=16, pady=(4,16))

    # ══════════════════════════════════════════════════════════════════════════
    #  LOGIC — Encrypt
    # ══════════════════════════════════════════════════════════════════════════
    def _browse_file(self):
        path = filedialog.askopenfilename(title="Select file to encrypt")
        if path:
            self._selected_file = Path(path)
            sz = self._selected_file.stat().st_size
            self._dz_lbl.config(
                text=f"📄  {self._selected_file.name}  ({self._fmt_size(sz)})",
                fg=TEXT)
            self.log.log(f"File selected: {self._selected_file.name} ({self._fmt_size(sz)})")

    def _browse_outdir(self):
        d = filedialog.askdirectory(title="Select download/output folder")
        if d:
            self.out_entry.clear()
            self.out_entry.entry.delete(0, "end")
            self.out_entry.entry.insert(0, d)
            self.out_entry.entry.config(fg=TEXT)

    def _on_drop(self, event):
        path = event.data.strip().strip("{}")
        self._selected_file = Path(path)
        sz = self._selected_file.stat().st_size
        self._dz_lbl.config(
            text=f"📄  {self._selected_file.name}  ({self._fmt_size(sz)})", fg=TEXT)
        self.log.log(f"Dropped: {self._selected_file.name}")

    def _start_encrypt(self):
        if self._busy:
            return
        if not self._selected_file:
            messagebox.showwarning("No file", "Please select a file first.")
            return
        pw = self.pw_entry.get()
        if not pw:
            messagebox.showwarning("No passphrase", "Enter a passphrase.")
            return
        self._busy = True
        threading.Thread(target=self._do_encrypt, args=(pw,), daemon=True).start()

    def _do_encrypt(self, pw: str):
        try:
            self._set_step(0)
            self.log.log("Deriving AES-256 key — PBKDF2·SHA256·100k iter …", "accent")
            plaintext = self._selected_file.read_bytes()
            n_chunks  = max(1, -(-len(plaintext) // CHUNK_SIZE))
            self.log.log(f"Splitting into {n_chunks} chunk(s) × 64 KB …", "info")

            self._set_step(1)
            self.after(0, lambda: self.chunk_grid.setup(n_chunks))
            self.after(0, lambda: self.progress_bar.config(maximum=n_chunks))

            def _progress(done, total):
                pct = done / total * 100
                self.after(0, lambda: self.progress_var.set(pct))
                self.after(0, lambda: self.progress_lbl.config(
                    text=f"Chunk {done}/{total}"))
                self.after(0, lambda: self.chunk_grid.advance(done))

            self._set_step(2)
            mime = mimetypes.guess_type(str(self._selected_file))[0] or "application/octet-stream"
            enc  = encrypt_file(plaintext, pw, self._selected_file.name,
                                 mime_type=mime, progress_cb=_progress)

            self._set_step(3)
            self.log.log(f"HMAC-SHA256: {enc.file_hmac.hex()[:32]}…", "success")
            self._set_step(4)
            save_to_vault(enc)
            self.log.log(f"Saved to vault: {enc.file_id[:16]}…", "success")
            self.log.log(f"✓ Encryption complete — {n_chunks} chunk(s)", "success")

            self.after(0, self.chunk_grid.complete)
            self.after(0, lambda: self.progress_var.set(100))
            self.after(0, lambda: self.progress_lbl.config(text="✓ Complete"))
            self.after(0, self._refresh_vault)
            self.after(1500, self._reset_progress)
        except Exception as e:
            self.log.log(f"Error: {e}", "error")
        finally:
            self._busy = False

    def _set_step(self, idx):
        self.after(0, lambda: self.steps.set_step(idx))

    def _reset_progress(self):
        self.steps.set_step(-1)
        self.chunk_grid.reset()
        self.progress_var.set(0)
        self.progress_lbl.config(text="")

    # ══════════════════════════════════════════════════════════════════════════
    #  LOGIC — Decrypt (from file picker)
    # ══════════════════════════════════════════════════════════════════════════
    def _decrypt_from_file(self):
        path = filedialog.askopenfilename(
            title="Select .enc.json vault file",
            filetypes=[("Vault file", "*.enc.json"), ("All", "*.*")])
        if not path:
            return
        self._decrypt_vault_file(path)

    def _decrypt_vault_file(self, vault_json_path: str):
        pw = self.pw_entry.get()
        if not pw:
            pw_win = tk.Toplevel(self)
            pw_win.title("Passphrase")
            pw_win.configure(bg=BG)
            pw_win.geometry("360x130")
            tk.Label(pw_win, text="Enter decryption passphrase:",
                     bg=BG, fg=TEXT, font=(FONT_FAM, 11)).pack(pady=(18,4))
            e = GlowEntry(pw_win, placeholder="passphrase …", show="•")
            e.pack(fill="x", padx=20)
            result = {"pw": None}
            def ok():
                result["pw"] = e.get()
                pw_win.destroy()
            RoundedButton(pw_win, "Decrypt", command=ok,
                          color=ACCENT, width=120).pack(pady=10)
            pw_win.wait_window()
            pw = result["pw"]
        if not pw:
            return

        out_dir = self.out_entry.get() or str(Path.home() / "Downloads")
        threading.Thread(target=self._do_decrypt,
                         args=(vault_json_path, pw, out_dir), daemon=True).start()

    def _do_decrypt(self, vault_json_path, pw, out_dir):
        try:
            with open(vault_json_path) as f:
                d = json.load(f)
            enc = deserialize(d)
            self.log.log(f"Verifying HMAC for '{enc.filename}' …", "accent")

            def _progress(done, total):
                pct = done / total * 100
                self.after(0, lambda: self.progress_var.set(pct))
                self.after(0, lambda: self.progress_lbl.config(
                    text=f"Decrypting chunk {done}/{total}"))

            plaintext = decrypt_file(enc, pw, progress_cb=_progress)
            out = Path(out_dir) / enc.filename
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(plaintext)
            self.log.log(f"✓ Saved: {out}", "success")
            self.after(0, lambda: messagebox.showinfo(
                "Decrypted", f"File saved to:\n{out}"))
            self.after(0, lambda: self.progress_var.set(0))
            self.after(0, lambda: self.progress_lbl.config(text=""))
        except ValueError as e:
            self.log.log(f"✗ {e}", "error")
            self.after(0, lambda: messagebox.showerror("Failed", str(e)))
        except Exception as e:
            self.log.log(f"Error: {e}", "error")

    # ══════════════════════════════════════════════════════════════════════════
    #  LOGIC — Vault tab
    # ══════════════════════════════════════════════════════════════════════════
    def _refresh_vault(self):
        self._vault = load_all_vault()
        self.tree.delete(*self.tree.get_children())
        total_chunks = 0
        total_size   = 0
        for enc in self._vault:
            n_chunks = len(enc.chunks)
            total_chunks += n_chunks
            total_size   += enc.plaintext_size
            self.tree.insert("", "end", iid=enc.file_id, values=(
                enc.filename,
                self._fmt_size(enc.plaintext_size),
                str(n_chunks),
                enc.file_id[:28] + "…",
                "—",
            ))
        self._stats[0].config(text=str(len(self._vault)))
        self._stats[1].config(text=str(total_chunks))
        self._stats[2].config(text=self._fmt_size(total_size))

    def _on_vault_select(self, _=None):
        sel = self.tree.selection()
        if not sel:
            self.detail_lbl.config(text="")
            return
        fid = sel[0]
        enc = next((e for e in self._vault if e.file_id == fid), None)
        if enc:
            self.detail_lbl.config(
                text=f"  ID: {enc.file_id}   |   HMAC: {enc.file_hmac.hex()[:48]}…   "
                     f"|   AES-salt: {enc.aes_salt.hex()[:24]}…")

    def _decrypt_selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Select", "Select a file from the vault first.")
            return
        fid  = sel[0]
        path = vault_path(fid)
        self._decrypt_vault_file(str(path))

    def _delete_selected(self):
        sel = self.tree.selection()
        if not sel:
            return
        fid = sel[0]
        enc = next((e for e in self._vault if e.file_id == fid), None)
        if enc and messagebox.askyesno(
                "Delete", f"Permanently delete '{enc.filename}' from vault?"):
            delete_from_vault(fid)
            self.log.log(f"Deleted: {enc.filename}", "warn")
            self._refresh_vault()

    # ══════════════════════════════════════════════════════════════════════════
    #  UTILS
    # ══════════════════════════════════════════════════════════════════════════
    @staticmethod
    def _fmt_size(b: int) -> str:
        if b < 1024:       return f"{b} B"
        if b < 1_048_576:  return f"{b/1024:.1f} KB"
        return f"{b/1_048_576:.1f} MB"


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = SecureVaultApp()
    app.mainloop()