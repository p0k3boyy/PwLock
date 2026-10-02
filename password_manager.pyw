"""
Password Manager Sederhana — BRUTALIST EDITION
Menyimpan username, email, dan password dengan enkripsi AES (Fernet).
Dilindungi oleh master password custom.
"""

import json
import os
import sys
import hashlib
import base64
import secrets
import tkinter as tk
from tkinter import messagebox, simpledialog
from datetime import datetime
from pathlib import Path

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "cryptography"])
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

DATA_DIR = Path(os.environ.get("APPDATA", ".")) / "PasswordManager"
DATA_FILE = DATA_DIR / "vault.enc"
SALT_FILE = DATA_DIR / "salt.bin"
META_FILE = DATA_DIR / "meta.json"

# ── BRUTALIST PALETTE ────────────────────────────────────────────
BG        = "#000000"
FG        = "#ffffff"
FG_DIM    = "#666666"
BORDER    = "#ffffff"
ACCENT    = "#ff0000"
FIELD_BG  = "#0a0a0a"
SEL_BG    = "#ffffff"
SEL_FG    = "#000000"
DANGER_BG = "#ff0000"
DANGER_FG = "#ffffff"

FONT      = ("Consolas", 11)
FONT_B    = ("Consolas", 11, "bold")
FONT_HUGE = ("Consolas", 22, "bold")
FONT_BIG  = ("Consolas", 14, "bold")
FONT_SM   = ("Consolas", 9)
FONT_XS   = ("Consolas", 8)

BW = 2  # border width


def ensure_data_dir():
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def derive_key(master_password, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600_000)
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))


def encrypt_data(data, key):
    return Fernet(key).encrypt(json.dumps(data, ensure_ascii=False).encode("utf-8"))


def decrypt_data(token, key):
    return json.loads(Fernet(key).decrypt(token).decode("utf-8"))


def hash_password(pw):
    return hashlib.sha256(pw.encode()).hexdigest()


# ── MAIN APP ─────────────────────────────────────────────────────
class PasswordManagerApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("PASSWORD MANAGER // BRUTALIST")
        self.root.geometry("960x620")
        self.root.minsize(800, 520)
        self.root.configure(bg=BG)

        self.master_key = None
        self.credentials = []
        self.selected_index = None

        ensure_data_dir()

        if SALT_FILE.exists() and DATA_FILE.exists():
            self.show_login_screen()
        else:
            self.show_setup_screen()

        self.root.mainloop()

    def clear_window(self):
        for w in self.root.winfo_children():
            w.destroy()

    # ─── SETUP SCREEN ─────────────────────────────────────────────
    def show_setup_screen(self):
        self.clear_window()

        outer = tk.Frame(self.root, bg=BG)
        outer.place(relx=0.5, rely=0.5, anchor="center")

        tk.Label(outer, text="+=============================+", font=FONT_B, fg=FG, bg=BG).pack()
        tk.Label(outer, text="|  PASSWORD MANAGER  v1.0     |", font=FONT_HUGE, fg=FG, bg=BG).pack()
        tk.Label(outer, text="|  // BRUTALIST EDITION       |", font=FONT, fg=FG_DIM, bg=BG).pack()
        tk.Label(outer, text="+=============================+", font=FONT_B, fg=FG, bg=BG).pack(pady=(0, 5))
        tk.Label(outer, text="[ SETUP ] Buat master password", font=FONT_SM, fg=FG_DIM, bg=BG).pack(pady=(0, 25))

        box = tk.Frame(outer, bg=FIELD_BG, bd=BW, relief="solid",
                       highlightthickness=BW, highlightbackground=BORDER)
        box.pack()

        tk.Label(box, text="> Master Password:", font=FONT_B, fg=FG, bg=FIELD_BG).pack(anchor="w", padx=15, pady=(12, 2))
        self.setup_pw_entry = tk.Entry(
            box, font=("Consolas", 12), show="*", width=35, bg=BG, fg=FG,
            insertbackground=FG, relief="flat", bd=6,
            highlightthickness=BW, highlightbackground=BORDER, highlightcolor=ACCENT,
        )
        self.setup_pw_entry.pack(padx=15, pady=(0, 8))

        tk.Label(box, text="> Konfirmasi:", font=FONT_B, fg=FG, bg=FIELD_BG).pack(anchor="w", padx=15, pady=(0, 2))
        self.setup_confirm_entry = tk.Entry(
            box, font=("Consolas", 12), show="*", width=35, bg=BG, fg=FG,
            insertbackground=FG, relief="flat", bd=6,
            highlightthickness=BW, highlightbackground=BORDER, highlightcolor=ACCENT,
        )
        self.setup_confirm_entry.pack(padx=15, pady=(0, 15))

        btn = tk.Button(
            outer, text="[ BUAT VAULT ]", font=FONT_B,
            bg=DANGER_BG, fg=DANGER_FG, activebackground=DANGER_FG, activeforeground=DANGER_BG,
            relief="flat", bd=0, padx=20, pady=8, cursor="hand2", command=self.do_setup,
        )
        btn.pack(pady=15)

        self.setup_pw_entry.bind("<Return>", lambda e: self.setup_confirm_entry.focus())
        self.setup_confirm_entry.bind("<Return>", lambda e: self.do_setup())
        self.setup_pw_entry.focus()

    def do_setup(self):
        pw = self.setup_pw_entry.get()
        confirm = self.setup_confirm_entry.get()
        if len(pw) < 4:
            messagebox.showwarning("WARNING", "Password minimal 4 karakter!")
            return
        if pw != confirm:
            messagebox.showerror("ERROR", "Password tidak cocok!")
            return

        salt = os.urandom(16)
        key = derive_key(pw, salt)
        ensure_data_dir()
        SALT_FILE.write_bytes(salt)
        DATA_FILE.write_bytes(encrypt_data([], key))
        META_FILE.write_text(json.dumps({"pw_hash": hash_password(pw), "created": datetime.now().isoformat()}), encoding="utf-8")

        self.master_key = key
        self.credentials = []
        messagebox.showinfo("OK", "Vault berhasil dibuat!")
        self.show_main_screen()

    # ─── LOGIN SCREEN ─────────────────────────────────────────────
    def show_login_screen(self):
        self.clear_window()

        outer = tk.Frame(self.root, bg=BG)
        outer.place(relx=0.5, rely=0.5, anchor="center")

        tk.Label(outer, text="+=============================+", font=FONT_B, fg=FG, bg=BG).pack()
        tk.Label(outer, text="|  PASSWORD MANAGER  v1.0     |", font=FONT_HUGE, fg=FG, bg=BG).pack()
        tk.Label(outer, text="|  // BRUTALIST EDITION       |", font=FONT, fg=FG_DIM, bg=BG).pack()
        tk.Label(outer, text="+=============================+", font=FONT_B, fg=FG, bg=BG).pack(pady=(0, 5))
        tk.Label(outer, text="[ LOGIN ] Masukkan master password", font=FONT_SM, fg=FG_DIM, bg=BG).pack(pady=(0, 25))

        box = tk.Frame(outer, bg=FIELD_BG, bd=BW, relief="solid",
                       highlightthickness=BW, highlightbackground=BORDER)
        box.pack()

        tk.Label(box, text="> Master Password:", font=FONT_B, fg=FG, bg=FIELD_BG).pack(anchor="w", padx=15, pady=(12, 2))
        self.login_pw_entry = tk.Entry(
            box, font=("Consolas", 12), show="*", width=35, bg=BG, fg=FG,
            insertbackground=FG, relief="flat", bd=6,
            highlightthickness=BW, highlightbackground=BORDER, highlightcolor=ACCENT,
        )
        self.login_pw_entry.pack(padx=15, pady=(0, 15))

        btn_row = tk.Frame(box, bg=FIELD_BG)
        btn_row.pack(pady=(0, 15))

        tk.Button(
            btn_row, text="[ UNLOCK ]", font=FONT_B,
            bg=DANGER_BG, fg=DANGER_FG, activebackground=DANGER_FG, activeforeground=DANGER_BG,
            relief="flat", bd=0, padx=14, pady=6, cursor="hand2", command=self.do_login,
        ).pack(side="left", padx=5)

        tk.Button(
            btn_row, text="[ RESET ]", font=FONT_B,
            bg=FG, fg=BG, activebackground=BG, activeforeground=FG,
            relief="flat", bd=0, padx=14, pady=6, cursor="hand2", command=self.do_reset,
        ).pack(side="left", padx=5)

        self.login_pw_entry.bind("<Return>", lambda e: self.do_login())
        self.login_pw_entry.focus()

    def do_login(self):
        pw = self.login_pw_entry.get()
        if not pw:
            messagebox.showwarning("WARNING", "Masukkan password!")
            return
        meta = json.loads(META_FILE.read_text(encoding="utf-8"))
        if hash_password(pw) != meta["pw_hash"]:
            messagebox.showerror("ACCESS DENIED", "Password salah!")
            return
        salt = SALT_FILE.read_bytes()
        self.master_key = derive_key(pw, salt)
        self.credentials = decrypt_data(DATA_FILE.read_bytes(), self.master_key)
        self.show_main_screen()

    def do_reset(self):
        if messagebox.askyesno("RESET", ">> SEMUA DATA AKAN HILANG <<\n\nYakin?"):
            DATA_FILE.unlink(missing_ok=True)
            SALT_FILE.unlink(missing_ok=True)
            META_FILE.unlink(missing_ok=True)
            self.show_setup_screen()

    # ─── MAIN SCREEN ──────────────────────────────────────────────
    def show_main_screen(self):
        self.clear_window()
        self.root.configure(bg=BG)

        # ── TOP BAR ──
        top_bar = tk.Frame(self.root, bg=FG, bd=0, height=42)
        top_bar.pack(fill="x")
        top_bar.pack_propagate(False)

        tk.Label(top_bar, text="  PASSWORD MANAGER // BRUTALIST ", font=FONT_BIG, fg=BG, bg=FG).pack(side="left")
        tk.Label(top_bar, text=f" [{len(self.credentials)} ENTRIES] ", font=FONT, fg=BG, bg=FG_DIM).pack(side="left", padx=8)

        tk.Button(
            top_bar, text=" [LOCK] ", font=FONT_B, bg=BG, fg=DANGER_BG,
            activebackground=FG, activeforeground=DANGER_BG,
            relief="flat", bd=0, padx=10, pady=4, cursor="hand2", command=self.lock_vault,
        ).pack(side="right", padx=8, pady=7)

        tk.Button(
            top_bar, text=" [BACKUP] ", font=FONT_B, bg=BG, fg=FG,
            activebackground=FG, activeforeground=BG,
            relief="flat", bd=0, padx=10, pady=4, cursor="hand2", command=self.backup_data,
        ).pack(side="right", padx=2, pady=7)

        # ── MAIN AREA ──
        main_area = tk.Frame(self.root, bg=BG)
        main_area.pack(fill="both", expand=True, padx=10, pady=10)

        # ── LEFT PANEL ──
        left = tk.Frame(main_area, bg=BG, bd=BW, relief="solid",
                        highlightthickness=BW, highlightbackground=BORDER, width=300)
        left.pack(side="left", fill="y", padx=(0, 8))
        left.pack_propagate(False)

        # SEARCH BAR
        search_frame = tk.Frame(left, bg=FG, bd=0, height=34)
        search_frame.pack(fill="x")
        search_frame.pack_propagate(False)

        tk.Label(search_frame, text=" SEARCH > ", font=FONT_B, fg=BG, bg=FG).pack(side="left")

        self.search_var = tk.StringVar()
        self.search_var.trace("w", self.filter_list)
        se = tk.Entry(
            search_frame, textvariable=self.search_var, font=FONT,
            bg=FG, fg=BG, insertbackground=BG, relief="flat", bd=0, highlightthickness=0,
        )
        se.pack(side="left", fill="x", expand=True, padx=4, pady=4)

        # SEPARATOR
        tk.Frame(left, bg=FG, height=2).pack(fill="x")

        # LISTBOX
        list_frame = tk.Frame(left, bg=BG, bd=0)
        list_frame.pack(fill="both", expand=True)

        self.listbox = tk.Listbox(
            list_frame, font=FONT, bg=BG, fg=FG,
            selectbackground=SEL_BG, selectforeground=SEL_FG,
            relief="flat", bd=0, highlightthickness=0, activestyle="none",
        )
        self.listbox.pack(side="left", fill="both", expand=True)
        self.listbox.bind("<<ListboxSelect>>", self.on_select)

        sb = tk.Scrollbar(list_frame, command=self.listbox.yview)
        sb.pack(side="right", fill="y")
        self.listbox.config(yscrollcommand=sb.set)

        # SEPARATOR
        tk.Frame(left, bg=FG, height=2).pack(fill="x")

        # ACTION ROW
        action_row = tk.Frame(left, bg=BG, bd=0, height=40)
        action_row.pack(fill="x")
        action_row.pack_propagate(False)

        tk.Button(
            action_row, text=" [ + ADD ] ", font=FONT_B, bg=DANGER_BG, fg=DANGER_FG,
            activebackground=DANGER_FG, activeforeground=DANGER_BG,
            relief="flat", bd=0, padx=8, pady=4, cursor="hand2", command=self.add_credential,
        ).pack(side="left", fill="both", expand=True, padx=(2, 1), pady=4)

        tk.Button(
            action_row, text=" [ DEL ] ", font=FONT_B, bg=FG, fg=BG,
            activebackground=BG, activeforeground=FG,
            relief="flat", bd=0, padx=8, pady=4, cursor="hand2", command=self.delete_credential,
        ).pack(side="right", fill="both", expand=True, padx=(1, 2), pady=4)

        # ── RIGHT PANEL ──
        right = tk.Frame(main_area, bg=BG, bd=BW, relief="solid",
                         highlightthickness=BW, highlightbackground=BORDER)
        right.pack(side="right", fill="both", expand=True)

        # DETAIL HEADER
        detail_hdr = tk.Frame(right, bg=FG, bd=0, height=42)
        detail_hdr.pack(fill="x")
        detail_hdr.pack_propagate(False)

        self.detail_title = tk.Label(detail_hdr, text=" SELECT AN ENTRY ", font=FONT_BIG, fg=BG, bg=FG)
        self.detail_title.pack(side="left", padx=8)

        # DETAIL BODY
        self.detail_body = tk.Frame(right, bg=BG, bd=0)
        self.detail_body.pack(fill="both", expand=True)

        self.refresh_list()

    # ─── LIST MANAGEMENT ──────────────────────────────────────────
    def refresh_list(self):
        self.listbox.delete(0, tk.END)
        for c in self.credentials:
            label = c.get("title", "") or c.get("service", "???")
            self.listbox.insert(tk.END, f"  > {label.upper()}")

    def filter_list(self, *args):
        q = self.search_var.get().lower()
        self.listbox.delete(0, tk.END)
        for c in self.credentials:
            label = (c.get("title", "") or c.get("service", "???")).lower()
            if q in label or q in c.get("service", "").lower() or q in c.get("username", "").lower():
                display = c.get("title", "") or c.get("service", "???")
                self.listbox.insert(tk.END, f"  > {display.upper()}")

    def on_select(self, event):
        sel = self.listbox.curselection()
        if not sel:
            return
        idx = sel[0]
        q = self.search_var.get().lower()
        if q:
            filtered = [i for i, c in enumerate(self.credentials)
                        if q in (c.get("title", "") or c.get("service", "")).lower()
                        or q in c.get("service", "").lower()
                        or q in c.get("username", "").lower()]
            self.selected_index = filtered[idx] if idx < len(filtered) else None
        else:
            self.selected_index = idx
        self.show_detail()

    # ─── DETAIL VIEW ──────────────────────────────────────────────
    def show_detail(self):
        for w in self.detail_body.winfo_children():
            w.destroy()

        if self.selected_index is None or self.selected_index >= len(self.credentials):
            return

        c = self.credentials[self.selected_index]
        self.detail_title.config(text=f" {(c.get('title', '') or c.get('service', '???')).upper()} ")

        fields = [
            (">> TITLE",    "title"),
            (">> SERVICE",   "service"),
            (">> USERNAME", "username"),
            (">> EMAIL",    "email"),
            (">> PASSWORD", "password"),
            (">> URL",      "url"),
            (">> NOTES",    "notes"),
        ]

        for lbl_text, key in fields:
            val = c.get(key, "")
            if not val:
                continue

            row = tk.Frame(self.detail_body, bg=BG, bd=BW, relief="solid",
                           highlightthickness=1, highlightbackground=FG_DIM)
            row.pack(fill="x", padx=12, pady=3)

            # Label kiri (putih bg)
            tk.Label(row, text=f" {lbl_text} ", font=FONT_B, fg=BG, bg=FG, anchor="w").pack(side="left")

            # Nilai
            show_val = val if key != "password" else "*" * 20
            val_lbl = tk.Label(row, text=f" {show_val} ", font=FONT, fg=FG, bg=BG, anchor="w")
            val_lbl.pack(side="left", fill="x", expand=True, padx=4)

            # COPY btn
            def make_copy(v=val):
                def copy_it():
                    self.root.clipboard_clear()
                    self.root.clipboard_append(v)
                    messagebox.showinfo("COPIED", "Disalin ke clipboard!")
                return copy_it

            tk.Button(
                row, text=" COPY ", font=FONT_SM, bg=FG, fg=BG,
                activebackground=BG, activeforeground=FG,
                relief="flat", bd=0, padx=6, pady=2, cursor="hand2", command=make_copy(val),
            ).pack(side="right", padx=4, pady=4)

            # SHOW/HIDE btn untuk password
            if key == "password":
                shown = [False]
                def make_toggle(lbl=val_lbl, v=val, s=shown):
                    def toggle():
                        s[0] = not s[0]
                        lbl.config(text=f" {v if s[0] else '*' * 20} ")
                    return toggle

                tk.Button(
                    row, text=" SHOW ", font=FONT_SM, bg=DANGER_BG, fg=DANGER_FG,
                    activebackground=DANGER_FG, activeforeground=DANGER_BG,
                    relief="flat", bd=0, padx=6, pady=2, cursor="hand2", command=make_toggle(),
                ).pack(side="right", padx=(2, 0), pady=4)

        # META
        if c.get("created") or c.get("modified"):
            meta = tk.Frame(self.detail_body, bg=BG)
            meta.pack(fill="x", padx=12, pady=(8, 0))
            if c.get("created"):
                tk.Label(meta, text=f"CREATED: {c['created'][:19]}", font=FONT_XS, fg=FG_DIM, bg=BG).pack(side="left")
            if c.get("modified"):
                tk.Label(meta, text=f"MODIFIED: {c['modified'][:19]}", font=FONT_XS, fg=FG_DIM, bg=BG).pack(side="left", padx=10)

        # ── ACTION BAR (bottom) ──
        bar = tk.Frame(self.detail_body, bg=FG, bd=0, height=44)
        bar.pack(side="bottom", fill="x")
        bar.pack_propagate(False)

        tk.Button(
            bar, text="  [ EDIT ]  ", font=FONT_B, bg=BG, fg=FG,
            activebackground=FG, activeforeground=BG,
            relief="flat", bd=0, padx=12, pady=4, cursor="hand2", command=self.edit_credential,
        ).pack(side="left", padx=6, pady=7)

        tk.Button(
            bar, text="  [ GENERATE PW ]  ", font=FONT_B, bg=BG, fg=DANGER_BG,
            activebackground=FG, activeforeground=DANGER_BG,
            relief="flat", bd=0, padx=12, pady=4, cursor="hand2", command=self.generate_password,
        ).pack(side="left", padx=2, pady=7)

        tk.Button(
            bar, text="  [ DELETE ]  ", font=FONT_B, bg=DANGER_BG, fg=DANGER_FG,
            activebackground=DANGER_FG, activeforeground=DANGER_BG,
            relief="flat", bd=0, padx=12, pady=4, cursor="hand2", command=self.delete_credential,
        ).pack(side="right", padx=6, pady=7)

    # ─── CRUD ─────────────────────────────────────────────────────
    def add_credential(self):
        self._open_form()

    def edit_credential(self):
        if self.selected_index is None:
            messagebox.showinfo("INFO", "Pilih entri terlebih dahulu")
            return
        self._open_form(self.credentials[self.selected_index])

    def _open_form(self, existing=None):
        win = tk.Toplevel(self.root)
        win.title("EDIT" if existing else "NEW ENTRY")
        win.geometry("500x580")
        win.configure(bg=BG)
        win.resizable(False, False)
        win.transient(self.root)
        win.grab_set()

        # HEADER
        hdr = tk.Frame(win, bg=FG, height=42)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        tk.Label(hdr, text="  EDIT ENTRY  " if existing else "  NEW ENTRY  ",
                 font=FONT_BIG, fg=BG, bg=FG).pack(side="left", padx=8)

        # FOOTER (pack dulu supaya selalu visible di bawah)
        footer = tk.Frame(win, bg=FG, height=50)
        footer.pack(fill="x", side="bottom")
        footer.pack_propagate(False)

        def save():
            data = {k: ent.get().strip() for k, ent in entries.items()}
            if not data["title"]:
                messagebox.showwarning("WARNING", "Title wajib diisi!", parent=win)
                return
            data["created"] = (existing.get("created", datetime.now().isoformat())
                               if existing else datetime.now().isoformat())
            data["modified"] = datetime.now().isoformat()
            if existing:
                self.credentials[self.credentials.index(existing)] = data
            else:
                self.credentials.append(data)
            self.save_vault()
            self.refresh_list()
            self.show_detail()
            win.destroy()

        tk.Button(
            footer, text="  [ SAVE ]  ", font=FONT_B, bg=DANGER_BG, fg=DANGER_FG,
            activebackground=DANGER_FG, activeforeground=DANGER_BG,
            relief="flat", bd=0, padx=16, pady=6, cursor="hand2", command=save,
        ).pack(side="left", padx=10, pady=8)

        tk.Button(
            footer, text="  [ CANCEL ]  ", font=FONT_B, bg=BG, fg=FG,
            activebackground=FG, activeforeground=BG,
            relief="flat", bd=0, padx=16, pady=6, cursor="hand2", command=win.destroy,
        ).pack(side="left", padx=4, pady=8)

        # SCROLLABLE BODY (pack setelah footer)
        canvas = tk.Canvas(win, bg=BG, highlightthickness=0)
        scr = tk.Scrollbar(win, orient="vertical", command=canvas.yview)
        inner = tk.Frame(canvas, bg=BG)
        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=inner, anchor="nw")
        canvas.configure(yscrollcommand=scr.set)
        canvas.pack(fill="both", expand=True)
        scr.pack(side="right", fill="y")

        body = tk.Frame(inner, bg=BG, padx=25, pady=15)
        body.pack(fill="both", expand=True)

        fields = [
            ("TITLE *",       "title"),
            ("LAYANAN / SITUS", "service"),
            ("USERNAME",  "username"),
            ("EMAIL",     "email"),
            ("PASSWORD",  "password"),
            ("URL",       "url"),
            ("CATATAN",   "notes"),
        ]

        entries = {}
        for lbl_text, key in fields:
            tk.Label(body, text=f" {lbl_text} ", font=FONT_B, fg=BG, bg=FG_DIM).pack(anchor="w", pady=(10, 2))
            e = tk.Entry(
                body, font=("Consolas", 12), show="*" if key == "password" else "", width=42,
                bg=FIELD_BG, fg=FG, insertbackground=FG, relief="flat", bd=6,
                highlightthickness=BW, highlightbackground=BORDER, highlightcolor=ACCENT,
            )
            e.pack(fill="x")
            if existing and key in existing:
                e.insert(0, existing[key])
            entries[key] = e

        show_var = tk.BooleanVar(value=False)
        def toggle_show():
            entries["password"].config(show="" if show_var.get() else "*")

        tk.Checkbutton(
            body, text="SHOW PASSWORD", variable=show_var, command=toggle_show,
            font=FONT, fg=FG, bg=BG, selectcolor=FG,
            activebackground=BG, activeforeground=FG,
        ).pack(anchor="w", pady=(5, 0))

        def on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        canvas.bind_all("<MouseWheel>", on_mousewheel)
        win.protocol("WM_DELETE_WINDOW", lambda: (canvas.unbind_all("<MouseWheel>"), win.destroy()))

    def delete_credential(self):
        if self.selected_index is None:
            messagebox.showinfo("INFO", "Pilih entri terlebih dahulu")
            return
        name = self.credentials[self.selected_index].get("title", "") or self.credentials[self.selected_index].get("service", "???")
        if messagebox.askyesno("CONFIRM DELETE", f">> HAPUS '{name.upper()}' ?"):
            self.credentials.pop(self.selected_index)
            self.selected_index = None
            self.save_vault()
            self.refresh_list()
            for w in self.detail_body.winfo_children():
                w.destroy()
            self.detail_title.config(text=" SELECT AN ENTRY ")

    def save_vault(self):
        DATA_FILE.write_bytes(encrypt_data(self.credentials, self.master_key))

    def lock_vault(self):
        self.master_key = None
        self.credentials = []
        self.selected_index = None
        self.show_login_screen()

    def backup_data(self):
        from tkinter import filedialog
        dest = filedialog.askdirectory(title="Pilih lokasi backup")
        if dest:
            import shutil
            dest_path = Path(dest) / "pm_backup"
            dest_path.mkdir(exist_ok=True)
            shutil.copy2(DATA_FILE, dest_path / "vault.enc")
            shutil.copy2(SALT_FILE, dest_path / "salt.bin")
            shutil.copy2(META_FILE, dest_path / "meta.json")
            messagebox.showinfo("BACKUP OK", f"Disimpan ke:\n{dest_path}")

    def generate_password(self):
        length = simpledialog.askinteger("GENERATE", "Panjang password:", initialvalue=24, minvalue=8, maxvalue=128)
        if not length:
            return
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+"
        pw = "".join(secrets.choice(chars) for _ in range(length))
        if self.selected_index is not None:
            self.credentials[self.selected_index]["password"] = pw
            self.save_vault()
            self.show_detail()
        self.root.clipboard_clear()
        self.root.clipboard_append(pw)
        messagebox.showinfo("GENERATED", f">> {length} CHARS <<\n\n{pw}\n\nDisalin ke clipboard.")


if __name__ == "__main__":
    PasswordManagerApp()
