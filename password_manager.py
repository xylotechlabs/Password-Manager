import json
import os
import secrets
import string
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
from tkinter.scrolledtext import ScrolledText
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import base64

VAULT_FILE = "vault.bin"
SALT_SIZE = 16
KDF_ITERATIONS = 390_000  

def derive_key(password: str, salt: bytes) -> bytes:
    password_bytes = password.encode("utf-8")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    key = kdf.derive(password_bytes)
    return base64.urlsafe_b64encode(key)

def create_new_vault(master_password: str) -> dict:
    vault = {}
    save_vault(master_password, vault)
    return vault

def load_vault(master_password: str) -> dict:
    if not os.path.exists(VAULT_FILE):
        return create_new_vault(master_password)

    with open(VAULT_FILE, "rb") as f:
        data = f.read()
    if len(data) < SALT_SIZE:
        raise ValueError("Vault file corrupted (no salt).")

    salt = data[:SALT_SIZE]
    token = data[SALT_SIZE:]
    key = derive_key(master_password, salt)
    fernet = Fernet(key)
    try:
        decrypted = fernet.decrypt(token)
    except Exception as e:
        raise ValueError("Incorrect master password or corrupted vault.") from e

    vault = json.loads(decrypted.decode("utf-8"))
    return vault

def save_vault(master_password: str, vault: dict):
    if os.path.exists(VAULT_FILE):
        with open(VAULT_FILE, "rb") as f:
            existing = f.read()
        if len(existing) >= SALT_SIZE:
            salt = existing[:SALT_SIZE]
        else:
            salt = secrets.token_bytes(SALT_SIZE)
    else:
        salt = secrets.token_bytes(SALT_SIZE)

    key = derive_key(master_password, salt)
    fernet = Fernet(key)
    plaintext = json.dumps(vault, ensure_ascii=False).encode("utf-8")
    token = fernet.encrypt(plaintext)
    with open(VAULT_FILE, "wb") as f:
        f.write(salt + token)


def generate_password(length=16, use_symbols=True, use_numbers=True, use_upper=True, use_lower=True) -> str:
    pools = []
    if use_lower:
        pools.append(string.ascii_lowercase)
    if use_upper:
        pools.append(string.ascii_uppercase)
    if use_numbers:
        pools.append(string.digits)
    if use_symbols:
        pools.append("!@#$%^&*()-_=+[]{};:,.<>?/|")

    if not pools:
        return ""

    password_chars = [secrets.choice(pool) for pool in pools]
    all_chars = "".join(pools)
    while len(password_chars) < length:
        password_chars.append(secrets.choice(all_chars))
    secrets.SystemRandom().shuffle(password_chars)
    return "".join(password_chars[:length])

class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager")
        self.master_password = None
        self.vault = {}
        self.current_selection = None
        ok = self.ask_master_password()
        if not ok:
            root.destroy()
            return

        self.build_ui()
        self.refresh_listbox()

    def ask_master_password(self) -> bool:
        while True:
            pwd = simpledialog.askstring("Master Password", "Enter master password:", show="*", parent=self.root)
            if pwd is None:
                return False
            try:
                self.vault = load_vault(pwd)
                self.master_password = pwd
                return True
            except ValueError as e:
                retry = messagebox.askretrycancel("Error", str(e) + "\n\nTry again?")
                if not retry:
                    return False

    def build_ui(self):
        left_frame = ttk.Frame(self.root, padding=8)
        left_frame.grid(row=0, column=0, sticky="ns")

        ttk.Label(left_frame, text="Services").pack(anchor="w")
        self.listbox = tk.Listbox(left_frame, width=30, height=20)
        self.listbox.pack(side="left", fill="y")
        self.listbox.bind("<<ListboxSelect>>", self.on_select)

        scrollbar = ttk.Scrollbar(left_frame, orient="vertical", command=self.listbox.yview)
        scrollbar.pack(side="right", fill="y")
        self.listbox.config(yscrollcommand=scrollbar.set)

        right_frame = ttk.Frame(self.root, padding=8)
        right_frame.grid(row=0, column=1, sticky="nsew")

        ttk.Label(right_frame, text="Service:").grid(row=0, column=0, sticky="w")
        self.entry_service = ttk.Entry(right_frame, width=40)
        self.entry_service.grid(row=0, column=1, sticky="w", pady=2)

        ttk.Label(right_frame, text="Username:").grid(row=1, column=0, sticky="w")
        self.entry_username = ttk.Entry(right_frame, width=40)
        self.entry_username.grid(row=1, column=1, sticky="w", pady=2)

        ttk.Label(right_frame, text="Password:").grid(row=2, column=0, sticky="w")
        pass_frame = ttk.Frame(right_frame)
        pass_frame.grid(row=2, column=1, sticky="w", pady=2)
        self.entry_password = ttk.Entry(pass_frame, width=30, show="*")
        self.entry_password.pack(side="left")
        ttk.Button(pass_frame, text="Show", command=self.toggle_show_password).pack(side="left", padx=4)
        ttk.Button(pass_frame, text="Copy", command=self.copy_password).pack(side="left", padx=4)

        ttk.Label(right_frame, text="Notes:").grid(row=3, column=0, sticky="nw")
        self.text_notes = ScrolledText(right_frame, width=40, height=6)
        self.text_notes.grid(row=3, column=1, pady=4)

        ctrl_frame = ttk.Frame(right_frame)
        ctrl_frame.grid(row=4, column=1, sticky="w", pady=6)
        ttk.Button(ctrl_frame, text="Add / Update", command=self.add_or_update).pack(side="left", padx=4)
        ttk.Button(ctrl_frame, text="Delete", command=self.delete_entry).pack(side="left", padx=4)
        ttk.Button(ctrl_frame, text="Generate", command=self.open_generator).pack(side="left", padx=4)
        ttk.Button(ctrl_frame, text="Save Vault", command=self.save_now).pack(side="left", padx=4)

        self.root.columnconfigure(1, weight=1)
        self.root.rowconfigure(0, weight=1)

    def refresh_listbox(self):
        self.listbox.delete(0, tk.END)
        services = sorted(self.vault.keys(), key=str.lower)
        for s in services:
            self.listbox.insert(tk.END, s)

    def on_select(self, event):
        sel = self.listbox.curselection()
        if not sel:
            return
        idx = sel[0]
        service = self.listbox.get(idx)
        self.current_selection = service
        record = self.vault.get(service, {})
        self.entry_service.delete(0, tk.END)
        self.entry_service.insert(0, service)
        self.entry_username.delete(0, tk.END)
        self.entry_username.insert(0, record.get("username", ""))
        self.entry_password.delete(0, tk.END)
        self.entry_password.insert(0, record.get("password", ""))
        self.text_notes.delete(1.0, tk.END)
        self.text_notes.insert(tk.END, record.get("notes", ""))

    def toggle_show_password(self):
        if self.entry_password.cget('show') == '':
            self.entry_password.config(show='*')
        else:
            self.entry_password.config(show='')

    def copy_password(self):
        pwd = self.entry_password.get()
        if not pwd:
            messagebox.showinfo("Empty", "No password to copy.")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(pwd)
        messagebox.showinfo("Copied", "Password copied to clipboard. (Remember to clear clipboard if needed.)")

    def add_or_update(self):
        service = self.entry_service.get().strip()
        if not service:
            messagebox.showwarning("Missing", "Service name is required.")
            return
        username = self.entry_username.get().strip()
        password = self.entry_password.get().strip()
        notes = self.text_notes.get(1.0, tk.END).strip()
        self.vault[service] = {"username": username, "password": password, "notes": notes}
        self.refresh_listbox()
        messagebox.showinfo("Saved", f"Entry for '{service}' saved into vault.")
        self.save_now()

    def delete_entry(self):
        service = self.entry_service.get().strip()
        if not service or service not in self.vault:
            messagebox.showwarning("Not found", "Select a valid entry to delete.")
            return
        confirm = messagebox.askyesno("Confirm", f"Delete entry for '{service}'?")
        if not confirm:
            return
        del self.vault[service]
        self.refresh_listbox()
        self.entry_service.delete(0, tk.END)
        self.entry_username.delete(0, tk.END)
        self.entry_password.delete(0, tk.END)
        self.text_notes.delete(1.0, tk.END)
        self.save_now()

    def open_generator(self):
        gen = PasswordGeneratorDialog(self.root)
        self.root.wait_window(gen.top)
        if gen.result:
            self.entry_password.delete(0, tk.END)
            self.entry_password.insert(0, gen.result)

    def save_now(self):
        try:
            save_vault(self.master_password, self.vault)
            messagebox.showinfo("Saved", "Vault encrypted and saved.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save vault: {e}")

class PasswordGeneratorDialog:
    def __init__(self, parent):
        self.top = tk.Toplevel(parent)
        self.top.title("Generate Password")
        self.result = None

        ttk.Label(self.top, text="Length:").grid(row=0, column=0, sticky="w")
        self.spin_len = tk.Spinbox(self.top, from_=6, to=64, width=5)
        self.spin_len.grid(row=0, column=1, sticky="w")

        self.var_lower = tk.BooleanVar(value=True)
        self.var_upper = tk.BooleanVar(value=True)
        self.var_numbers = tk.BooleanVar(value=True)
        self.var_symbols = tk.BooleanVar(value=True)

        ttk.Checkbutton(self.top, text="Lowercase", variable=self.var_lower).grid(row=1, column=0, sticky="w")
        ttk.Checkbutton(self.top, text="Uppercase", variable=self.var_upper).grid(row=1, column=1, sticky="w")
        ttk.Checkbutton(self.top, text="Numbers", variable=self.var_numbers).grid(row=2, column=0, sticky="w")
        ttk.Checkbutton(self.top, text="Symbols", variable=self.var_symbols).grid(row=2, column=1, sticky="w")

        self.entry_preview = ttk.Entry(self.top, width=40)
        self.entry_preview.grid(row=3, column=0, columnspan=2, pady=6)

        btn_frame = ttk.Frame(self.top)
        btn_frame.grid(row=4, column=0, columnspan=2)
        ttk.Button(btn_frame, text="Generate", command=self.generate_once).pack(side="left", padx=6)
        ttk.Button(btn_frame, text="Use", command=self.use_and_close).pack(side="left", padx=6)
        ttk.Button(btn_frame, text="Cancel", command=self.top.destroy).pack(side="left", padx=6)

    def generate_once(self):
        length = int(self.spin_len.get())
        pw = generate_password(
            length=length,
            use_symbols=self.var_symbols.get(),
            use_numbers=self.var_numbers.get(),
            use_upper=self.var_upper.get(),
            use_lower=self.var_lower.get()
        )
        self.entry_preview.delete(0, tk.END)
        self.entry_preview.insert(0, pw)

    def use_and_close(self):
        self.result = self.entry_preview.get()
        self.top.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerApp(root)
    try:
        root.mainloop()
    except Exception:
        pass
