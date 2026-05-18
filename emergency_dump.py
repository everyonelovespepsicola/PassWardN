import sys
import struct
import os
import re
import threading
import tkinter as tk
from tkinter import filedialog, messagebox

# --- Hotfix for tkinterdnd2 'tix' ImportError in PyInstaller & Python 3.13+ ---
try:
    from tkinter import tix
except ImportError:
    import types
    tk.tix = types.ModuleType('tkinter.tix')
    tk.tix.Tk = tk.Tk
    sys.modules['tkinter.tix'] = tk.tix
# ------------------------------------------------------------------------------

from tkinterdnd2 import TkinterDnD, DND_FILES
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from argon2.low_level import hash_secret_raw, Type

class EmergencyExtractor(TkinterDnD.Tk):
    def __init__(self):
        super().__init__()
        self.title("PassWardN Emergency Extractor")
        self.geometry("500x450")
        self.configure(padx=20, pady=20)

        self.vault_path = tk.StringVar()
        self.password = tk.StringVar()

        # Title
        tk.Label(self, text="PassWardN Emergency Extractor", font=("Arial", 16, "bold")).pack(pady=(0, 15))

        # File selection frame
        frame_file = tk.Frame(self)
        frame_file.pack(fill=tk.X, pady=5)
        tk.Label(frame_file, text="Vault File:", font=("Arial", 10, "bold")).pack(anchor=tk.W)

        # Drag & Drop Area
        self.drop_area = tk.Label(frame_file, text="⬇ Drag & Drop secure_vault.bin here ⬇\n\nOR",
                                  bg="#e0e0e0", relief="groove", borderwidth=2, height=4, font=("Arial", 10))
        self.drop_area.pack(fill=tk.X, pady=5)
        self.drop_area.drop_target_register(DND_FILES)
        self.drop_area.dnd_bind('<<Drop>>', self.on_drop)

        # File Browse Button
        tk.Button(frame_file, text="Browse for Vault File...", command=self.browse_file, width=20).pack(pady=5)

        # Selected File Label
        self.lbl_selected = tk.Label(frame_file, textvariable=self.vault_path, fg="blue", wraplength=450, font=("Arial", 9))
        self.lbl_selected.pack(fill=tk.X, pady=5)

        # Password frame
        frame_pwd = tk.Frame(self)
        frame_pwd.pack(fill=tk.X, pady=10)
        tk.Label(frame_pwd, text="Master Password:", font=("Arial", 10, "bold")).pack(anchor=tk.W)
        tk.Entry(frame_pwd, textvariable=self.password, show="*", font=("Courier", 12)).pack(fill=tk.X, pady=5)

        # Status
        self.status_lbl = tk.Label(self, text="Ready.", fg="gray", font=("Arial", 10))
        self.status_lbl.pack(pady=5)

        # Buttons
        frame_btns = tk.Frame(self)
        frame_btns.pack(fill=tk.X, side=tk.BOTTOM, pady=10)

        tk.Button(frame_btns, text="Cancel", command=self.destroy, width=12, font=("Arial", 10)).pack(side=tk.RIGHT, padx=5)
        self.btn_extract = tk.Button(frame_btns, text="Extract Vault", command=self.start_extraction, width=15, bg="#b30000", fg="white", font=("Arial", 10, "bold"))
        self.btn_extract.pack(side=tk.RIGHT, padx=5)

    def on_drop(self, event):
        # Clean up curly braces from tk drag-and-drop paths
        file_path = event.data
        if file_path.startswith('{') and file_path.endswith('}'):
            file_path = file_path[1:-1]
        self.vault_path.set(file_path)

    def browse_file(self):
        path = filedialog.askopenfilename(title="Select Vault File", filetypes=[("PassWardN Vault", "*.bin"), ("All Files", "*.*")])
        if path:
            self.vault_path.set(path)

    def start_extraction(self):
        vp = self.vault_path.get().strip()
        pwd = self.password.get()
        if not vp or not os.path.exists(vp):
            messagebox.showerror("Error", "Please select a valid vault file first.")
            return
        if not pwd:
            messagebox.showerror("Error", "Please enter your Master Password.")
            return

        self.btn_extract.config(state=tk.DISABLED)
        self.status_lbl.config(text="Extracting... Please wait.", fg="black")

        # Run in background thread to keep GUI responsive
        threading.Thread(target=self.extract_vault_thread, args=(vp, pwd), daemon=True).start()

    def update_status(self, msg, color="black"):
        self.status_lbl.config(text=msg, fg=color)

    def extract_vault_thread(self, vault_path, password):
        out_dir = "PassWardN_Emergency_Dump"
        try:
            with open(vault_path, 'rb') as f:
                magic = f.read(4)
                if magic == b"GVL2": header_size = 200
                elif magic == b"GVLT": header_size = 140
                else:
                    self.after(0, lambda: messagebox.showerror("Error", "Not a valid PassWardN vault!"))
                    self.after(0, lambda: self.update_status("Extraction failed: Invalid format.", "red"))
                    self.after(0, lambda: self.btn_extract.config(state=tk.NORMAL))
                    return

                salt = f.read(16)
                slot1_nonce = f.read(12)
                slot1_ct = f.read(48)

                self.after(0, lambda: self.update_status("Deriving Master Key (Argon2)..."))
                # Rust argon2 crate defaults: m=19456, t=2, p=1
                kek = hash_secret_raw(secret=password.encode('utf-8'), salt=salt, time_cost=2, memory_cost=19456, parallelism=1, hash_len=32, type=Type.ID)
                chacha = ChaCha20Poly1305(kek)

                try:
                    master_key = chacha.decrypt(slot1_nonce, slot1_ct, None)
                except Exception:
                    self.after(0, lambda: messagebox.showerror("Error", "Failed to decrypt master key. Incorrect password?"))
                    self.after(0, lambda: self.update_status("Decryption failed.", "red"))
                    self.after(0, lambda: self.btn_extract.config(state=tk.NORMAL))
                    return

                f.seek(header_size)
                os.makedirs(out_dir, exist_ok=True)
                chunk_idx = 0
                master_chacha = ChaCha20Poly1305(master_key)

                recovered_count = 0
                with open(os.path.join(out_dir, "recovered_text.txt"), "w", encoding="utf-8") as strings_file:
                    while True:
                        len_bytes = f.read(4)
                        if len(len_bytes) < 4: break
                        chunk_len = struct.unpack('<I', len_bytes)[0]
                        pt = master_chacha.decrypt(f.read(12), f.read(chunk_len), None)

                        with open(os.path.join(out_dir, f"payload_{chunk_idx}.bin"), 'wb') as out_f: out_f.write(pt)

                        strings_file.write(f"\n--- Chunk {chunk_idx} ({len(pt)} bytes) ---\n")

                        # Skip string extraction on massive file payloads to prevent garbage output and save memory
                        if len(pt) < 1024 * 1024 * 5: # 5 MB limit
                            for s in re.findall(b'[ -~]{4,}', pt):
                                strings_file.write(s.decode('ascii', errors='ignore') + "\n")
                        else:
                            strings_file.write("[Large binary payload skipped - rename the corresponding payload_X.bin file to recover it]\n")

                        recovered_count += 1
                        chunk_idx += 1

                        # Safe UI update during long extraction
                        if chunk_idx % 5 == 0:
                            self.after(0, lambda c=chunk_idx: self.update_status(f"Recovered {c} chunks..."))

            self.after(0, lambda: messagebox.showinfo("Success", f"🎉 Extraction complete!\n\nRecovered {recovered_count} payload chunks.\n\nAll files are in the '{out_dir}' folder next to this app."))
            self.after(0, lambda: self.update_status("Extraction complete!", "green"))
        except Exception as e:
            self.after(0, lambda err=e: messagebox.showerror("Error", f"An error occurred:\n{str(err)}"))
            self.after(0, lambda: self.update_status("Extraction error.", "red"))
        finally:
            self.after(0, lambda: self.btn_extract.config(state=tk.NORMAL))
            self.after(0, lambda: self.password.set(""))

if __name__ == '__main__':
    app = EmergencyExtractor()
    app.mainloop()
