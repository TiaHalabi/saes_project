"""
S-AES Simple UI — Encrypt & Decrypt
Place this file next to: saes_core.py, saes_gf.py, saes_ctr.py
Run: python saes_ui.py
"""

import tkinter as tk
from tkinter import messagebox

# ── Import your project files ─────────────────────────────────────────────────
try:
    from saes_core import saes_encrypt, saes_decrypt
    from saes_ctr  import ctr_process
except ImportError:
    MODULUS = 0b10011
    SBOX    = [0x9,0x4,0xA,0xB,0xD,0x1,0x8,0x5,0x6,0x2,0x0,0x3,0xC,0xE,0xF,0x7]
    INV_SBOX= [0]*16
    for _i,_v in enumerate(SBOX): INV_SBOX[_v]=_i

    def gf_mult(a,b):
        r=0
        for _ in range(4):
            if b&1: r^=a
            b>>=1; a<<=1
            if a&0x10: a^=MODULUS
        return r&0xF

    def to_nibbles(v): return (v>>12)&0xF,(v>>8)&0xF,(v>>4)&0xF,v&0xF
    def from_nibbles(a,b,c,d): return(a<<12)|(b<<8)|(c<<4)|d
    def _snw(w): return(SBOX[(w>>4)&0xF]<<4)|SBOX[w&0xF]
    def _rn(w): return((w<<4)|(w>>4))&0xFF

    def key_expansion(k):
        W0,W1=(k>>8)&0xFF,k&0xFF
        W2=W0^0x80^_snw(_rn(W1)); W3=W2^W1
        W4=W2^0x30^_snw(_rn(W3)); W5=W4^W3
        return[(W0<<8)|W1,(W2<<8)|W3,(W4<<8)|W5]

    def nibble_sub(s,inv=False):
        box=INV_SBOX if inv else SBOX
        a,b,c,d=to_nibbles(s); return from_nibbles(box[a],box[b],box[c],box[d])

    def shift_row(s):
        a,b,c,d=to_nibbles(s); return from_nibbles(a,d,c,b)

    def mix_columns(s,inv=False):
        a,b,c,d=to_nibbles(s)
        if not inv: return from_nibbles(gf_mult(1,a)^gf_mult(4,c),gf_mult(1,b)^gf_mult(4,d),gf_mult(4,a)^gf_mult(1,c),gf_mult(4,b)^gf_mult(1,d))
        return from_nibbles(gf_mult(9,a)^gf_mult(2,c),gf_mult(9,b)^gf_mult(2,d),gf_mult(2,a)^gf_mult(9,c),gf_mult(2,b)^gf_mult(9,d))

    def saes_encrypt(pt,key):
        K=key_expansion(key); s=pt^K[0]
        s=nibble_sub(s); s=shift_row(s); s=mix_columns(s); s^=K[1]
        s=nibble_sub(s); s=shift_row(s); s^=K[2]; return s

    def saes_decrypt(ct,key):
        K=key_expansion(key); s=ct^K[2]
        s=shift_row(s); s=nibble_sub(s,True); s^=K[1]
        s=mix_columns(s,True); s=shift_row(s); s=nibble_sub(s,True); s^=K[0]; return s

    def ctr_process(data,key,nonce):
        out=[]
        padded=list(data) if len(data)%2==0 else list(data)+[0]
        for i in range(0,len(padded),2):
            cb=((nonce&0xFF)<<8)|((i//2)&0xFF)
            ks=saes_encrypt(cb,key)
            w=(padded[i]<<8)|padded[i+1]
            ct=w^ks; out+=[(ct>>8)&0xFF,ct&0xFF]
        return bytes(out[:len(data)])


# ── Helpers ───────────────────────────────────────────────────────────────────
def parse_hex(val, bits=16):
    try:
        return int(val.strip(), 16) & ((1 << bits) - 1)
    except Exception:
        return None

def bytes_to_printable(b):
    return ''.join(chr(x) if 32 <= x < 127 else '?' for x in b)


# ── Colors & Fonts ────────────────────────────────────────────────────────────
BG      = "#1a1a2e"
PANEL   = "#16213e"
CARD    = "#0f3460"
ACCENT  = "#00d4aa"
RED     = "#e94560"
TEXT    = "#eaeaea"
MUTED   = "#8892a4"
BORDER  = "#2a3a5c"


# ═════════════════════════════════════════════════════════════════════════════
class SAESApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("S-AES Encryption Tool")
        self.configure(bg=BG)
        self.resizable(True, True)
        self._build()

    def _build(self):

        # ── Title ─────────────────────────────────────────────────────────────
        top = tk.Frame(self, bg=PANEL, pady=10)
        top.pack(fill="x")
        tk.Label(top, text="🔐  S-AES Encryption Tool",
                 fg=ACCENT, bg=PANEL,
                 font=("Segoe UI", 15, "bold")).pack()
        tk.Label(top, text="Simplified AES · 16-bit Key · CTR Mode",
                 fg=MUTED, bg=PANEL,
                 font=("Segoe UI", 9)).pack()

        # ── Key + Nonce row ───────────────────────────────────────────────────
        kf = tk.Frame(self, bg=BG, pady=6)
        kf.pack(fill="x", padx=16)

        # Key
        kc = tk.Frame(kf, bg=BG)
        kc.pack(side="left", fill="x", expand=True, padx=(0,8))
        tk.Label(kc, text="Key  (4 hex digits)", fg=MUTED, bg=BG,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w")
        self.key_entry = self._entry(kc)
        self.key_entry.insert(0, "2B7E")
        self.key_entry.pack(fill="x", ipady=5)

        # Nonce
        nc = tk.Frame(kf, bg=BG)
        nc.pack(side="left", fill="x", expand=True)
        tk.Label(nc, text="Nonce  (2 hex digits)", fg=MUTED, bg=BG,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w")
        self.nonce_entry = self._entry(nc)
        self.nonce_entry.insert(0, "A3")
        self.nonce_entry.pack(fill="x", ipady=5)

        # ── Divider ───────────────────────────────────────────────────────────
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x", padx=16, pady=6)

        # ── ENCRYPT section ───────────────────────────────────────────────────
        tk.Label(self, text="  ENCRYPT", fg=ACCENT, bg=CARD,
                 font=("Consolas", 9, "bold"), anchor="w",
                 padx=8, pady=3).pack(fill="x", padx=16)

        ef = tk.Frame(self, bg=PANEL, highlightthickness=1,
                      highlightbackground=BORDER)
        ef.pack(fill="x", padx=16, pady=(0,6))

        tk.Label(ef, text="Plaintext  (your message)",
                 fg=MUTED, bg=PANEL, font=("Segoe UI", 9, "bold")).pack(
                 anchor="w", padx=12, pady=(8,2))
        self.pt_entry = self._entry(ef)
        self.pt_entry.insert(0, "Hello, S-AES!")
        self.pt_entry.pack(fill="x", padx=12, ipady=5)

        tk.Button(ef, text="🔒   ENCRYPT", command=self._do_encrypt,
                  bg=ACCENT, fg="#0d0f14",
                  font=("Segoe UI", 10, "bold"), relief="flat",
                  cursor="hand2", pady=6).pack(fill="x", padx=12, pady=8)

        tk.Label(ef, text="Ciphertext  (hex output)",
                 fg=MUTED, bg=PANEL, font=("Segoe UI", 9, "bold")).pack(
                 anchor="w", padx=12, pady=(0,2))
        self.ct_out = self._result_box(ef, ACCENT)
        self.ct_out.pack(fill="x", padx=12, ipady=6, pady=(0,10))

        # ── DECRYPT section ───────────────────────────────────────────────────
        tk.Label(self, text="  DECRYPT", fg=RED, bg=CARD,
                 font=("Consolas", 9, "bold"), anchor="w",
                 padx=8, pady=3).pack(fill="x", padx=16)

        df = tk.Frame(self, bg=PANEL, highlightthickness=1,
                      highlightbackground=BORDER)
        df.pack(fill="x", padx=16, pady=(0,6))

        tk.Label(df, text="Ciphertext  (auto-filled after encrypt, or paste here)",
                 fg=MUTED, bg=PANEL, font=("Segoe UI", 9, "bold")).pack(
                 anchor="w", padx=12, pady=(8,2))
        self.ct_entry = self._entry(df)
        self.ct_entry.pack(fill="x", padx=12, ipady=5)

        tk.Button(df, text="🔓   DECRYPT", command=self._do_decrypt,
                  bg=RED, fg=TEXT,
                  font=("Segoe UI", 10, "bold"), relief="flat",
                  cursor="hand2", pady=6).pack(fill="x", padx=12, pady=8)

        tk.Label(df, text="Recovered Plaintext",
                 fg=MUTED, bg=PANEL, font=("Segoe UI", 9, "bold")).pack(
                 anchor="w", padx=12, pady=(0,2))
        self.pt_out = self._result_box(df, ACCENT)
        self.pt_out.pack(fill="x", padx=12, ipady=6, pady=(0,10))

        # ── Footer ────────────────────────────────────────────────────────────
        tk.Label(self, text="S-AES Project  ·  Security Course",
                 fg=BORDER, bg=BG,
                 font=("Segoe UI", 8)).pack(pady=6)

    # ── Reusable widgets ──────────────────────────────────────────────────────
    def _entry(self, parent):
        return tk.Entry(parent, font=("Consolas", 11),
                        bg=CARD, fg=TEXT,
                        insertbackground=ACCENT, relief="flat",
                        highlightthickness=1,
                        highlightbackground=BORDER,
                        highlightcolor=ACCENT)

    def _result_box(self, parent, color):
        return tk.Entry(parent, font=("Consolas", 11, "bold"),
                        bg="#0d0f14", fg=color,
                        relief="flat", state="readonly",
                        highlightthickness=1,
                        highlightbackground=BORDER,
                        readonlybackground="#0d0f14")

    def _set_result(self, box, value):
        box.config(state="normal")
        box.delete(0, "end")
        box.insert(0, value)
        box.config(state="readonly")

    # ── Actions ───────────────────────────────────────────────────────────────
    def _do_encrypt(self):
        key   = parse_hex(self.key_entry.get())
        nonce = parse_hex(self.nonce_entry.get(), 8)
        pt    = self.pt_entry.get()

        if key is None:
            messagebox.showerror("Error", "Key must be 4 hex digits  (e.g. 2B7E)"); return
        if nonce is None:
            messagebox.showerror("Error", "Nonce must be 2 hex digits  (e.g. A3)"); return
        if not pt:
            messagebox.showerror("Error", "Please enter a message"); return

        ct_bytes = ctr_process(pt.encode("latin-1", "replace"), key, nonce)
        ct_hex   = ct_bytes.hex().upper()

        self._set_result(self.ct_out, ct_hex)
        self.ct_entry.delete(0, "end")
        self.ct_entry.insert(0, ct_hex)

    def _do_decrypt(self):
        key    = parse_hex(self.key_entry.get())
        nonce  = parse_hex(self.nonce_entry.get(), 8)
        ct_hex = self.ct_entry.get().strip().replace(" ", "")

        if key is None:
            messagebox.showerror("Error", "Key must be 4 hex digits  (e.g. 2B7E)"); return
        if nonce is None:
            messagebox.showerror("Error", "Nonce must be 2 hex digits  (e.g. A3)"); return
        if not ct_hex:
            messagebox.showerror("Error", "No ciphertext to decrypt"); return
        try:
            ct_bytes = bytes.fromhex(ct_hex)
        except ValueError:
            messagebox.showerror("Error", "Ciphertext must be valid hex"); return

        pt_bytes = ctr_process(ct_bytes, key, nonce)
        self._set_result(self.pt_out, bytes_to_printable(pt_bytes))


# ── Run ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = SAESApp()
    app.update_idletasks()
    w, h = app.winfo_reqwidth(), app.winfo_reqheight()
    sw, sh = app.winfo_screenwidth(), app.winfo_screenheight()
    app.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")
    app.mainloop()
