#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EDIP GUI v2 (Tkinter) - Optimized
---------------------------------
Optimizations:
- Memory usage: File reading in chunks for large files
- Performance: Background threading for encryption/decryption
- UI responsiveness: Non-blocking operations
- Security: Secure password handling with immediate clearing
- Error handling: More robust exception management
"""

import os
import sys
import time
import base64
import hashlib
import secrets
import struct
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from typing import Tuple, Optional, Callable

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except Exception as e:
    raise SystemExit("'cryptography' paketi gerekli. Kur: pip install cryptography\n\nHata: " + str(e))

# =========================
# Kripto Sabitleri & Yapı
# =========================
MAGIC = b"EDIP"
VERSION = 2
KDF_SCRYPT = 2
DEFAULT_SALT_LEN = 16
DEFAULT_NONCE_LEN = 12
DEFAULT_LOG2N = 15
DEFAULT_R = 8
DEFAULT_P = 1
CHUNK_SIZE = 64 * 1024  # 64KB chunks for file operations

PKT_MAGIC = b"PKT1"

# Dark mode renkleri
BG = "#111418"
FG = "#E6E8EB"
ACCENT = "#6E56CF"
MUTED = "#9BA1A6"
ERR = "#EF4444"
OK = "#22C55E"
WARNING = "#F59E0B"

# =========================
# Yardımcı Fonksiyonlar
# =========================

def password_policy_ok(pw: str) -> bool:
    """Optimized password policy check with early termination"""
    if len(pw) < 12:
        return False
    
    has_lower = has_upper = has_digit = has_special = False
    
    for char in pw:
        if not has_lower and 'a' <= char <= 'z':
            has_lower = True
        elif not has_upper and 'A' <= char <= 'Z':
            has_upper = True
        elif not has_digit and char.isdigit():
            has_digit = True
        elif not has_special and not char.isalnum():
            has_special = True
            
        if has_lower and has_upper and has_digit and has_special:
            return True
            
    return False

def derive_key_scrypt(password: bytes, salt: bytes, log2N: int, r: int, p: int, dklen: int = 32) -> bytes:
    """Optimized key derivation with memory limits"""
    N = 1 << log2N
    # Calculate appropriate maxmem based on parameters
    max_mem = 128 * 1024 * 1024  # 128MB limit
    return hashlib.scrypt(password, salt=salt, n=N, r=r, p=p, maxmem=max_mem, dklen=dklen)

def build_header(salt: bytes, nonce: bytes, log2N: int, r: int, p: int) -> bytes:
    return MAGIC + bytes([VERSION, KDF_SCRYPT, len(salt), len(nonce), log2N & 0xFF, r & 0xFF, p & 0xFF]) + salt + nonce

def parse_header(data: bytes) -> Tuple[int, int, int, int, int, int, int, bytes, bytes, int]:
    """Optimized header parsing with bounds checking"""
    if len(data) < 11:
        raise ValueError("Dosya çok kısa veya bozuk")
    
    if data[0:4] != MAGIC:
        raise ValueError("Geçersiz EDIP imzası")
    
    version, kdf_id, salt_len, nonce_len = data[4], data[5], data[6], data[7]
    log2N, r, p = data[8], data[9], data[10]
    
    if version != VERSION:
        raise ValueError(f"Desteklenmeyen sürüm: {version}")
    if kdf_id != KDF_SCRYPT:
        raise ValueError(f"Desteklenmeyen KDF id: {kdf_id}")
    
    idx = 11
    required_len = idx + salt_len + nonce_len
    if len(data) < required_len:
        raise ValueError("Başlık eksik")
    
    salt = data[idx:idx+salt_len]
    idx += salt_len
    nonce = data[idx:idx+nonce_len]
    idx += nonce_len
    
    return (version, kdf_id, salt_len, nonce_len, log2N, r, p, salt, nonce, idx)

def pack_plain(filepath: str, file_size: int) -> bytes:
    """Create header without loading entire file into memory"""
    fname = os.path.basename(filepath).encode('utf-8')
    if len(fname) > 65535:
        raise ValueError("Dosya adı çok uzun")
    return PKT_MAGIC + struct.pack('>H', len(fname)) + fname + struct.pack('>Q', file_size)

def unpack_plain(blob: bytes) -> Tuple[str, int]:
    """Extract filename and size from package header"""
    if len(blob) < 4 or blob[:4] != PKT_MAGIC:
        raise ValueError("Şifre çözmede paket hatası")
    
    pos = 4
    nlen = struct.unpack('>H', blob[pos:pos+2])[0]
    pos += 2
    
    if len(blob) < pos + nlen + 8:
        raise ValueError("Paket başlığı eksik")
    
    fname = blob[pos:pos+nlen].decode('utf-8', errors='replace')
    pos += nlen
    file_size = struct.unpack('>Q', blob[pos:pos+8])[0]
    
    return fname, file_size

def encrypt_file_to_edip(in_path: str, out_path: str, password: str, 
                        log2N=DEFAULT_LOG2N, r=DEFAULT_R, p=DEFAULT_P,
                        progress_callback: Optional[Callable[[int, int], None]] = None):
    """Optimized encryption with chunked processing"""
    if not password_policy_ok(password):
        raise ValueError("Parola politikası: min 12 ve [a-z][A-Z][0-9][özel] şart")
    
    # Get file size first
    file_size = os.path.getsize(in_path)
    
    # Generate crypto materials
    salt = secrets.token_bytes(DEFAULT_SALT_LEN)
    nonce = secrets.token_bytes(DEFAULT_NONCE_LEN)
    key = derive_key_scrypt(password.encode('utf-8'), salt, log2N, r, p, dklen=32)
    header = build_header(salt, nonce, log2N, r, p)
    aad = header
    
    # Create package header
    pkg_header = pack_plain(in_path, file_size)
    
    aesgcm = AESGCM(key)
    
    with open(in_path, 'rb') as fin, open(out_path, 'wb') as fout:
        # Write header and package header (will be authenticated but not encrypted)
        fout.write(header)
        
        # Encrypt and write file in chunks
        total_processed = 0
        while True:
            chunk = fin.read(CHUNK_SIZE)
            if not chunk:
                break
            
            # For the first chunk, prepend package header
            if total_processed == 0:
                chunk = pkg_header + chunk
            
            encrypted_chunk = aesgcm.encrypt(nonce, chunk, aad)
            fout.write(encrypted_chunk)
            total_processed += len(chunk)
            
            if progress_callback:
                progress_callback(total_processed, file_size + len(pkg_header))

def decrypt_edip_to_file(in_path: str, out_dir: str, password: str,
                        progress_callback: Optional[Callable[[int, int], None]] = None) -> str:
    """Optimized decryption with chunked processing"""
    file_size = os.path.getsize(in_path)
    
    with open(in_path, 'rb') as fin:
        # Read and parse header
        header_data = fin.read(64)  # Read more than needed for header
        (version, kdf_id, salt_len, nonce_len, log2N, r, p, salt, nonce, idx) = parse_header(header_data)
        
        # Seek to correct position after header
        fin.seek(idx)
        
        key = derive_key_scrypt(password.encode('utf-8'), salt, log2N, r, p, dklen=32)
        aad = header_data[:idx]
        aesgcm = AESGCM(key)
        
        # Read and decrypt first chunk to get package header
        first_chunk = fin.read(CHUNK_SIZE)
        if not first_chunk:
            raise ValueError("Dosya boş")
        
        decrypted_first_chunk = aesgcm.decrypt(nonce, first_chunk, aad)
        
        # Parse package header from decrypted data
        try:
            # Find the actual length of the package header
            if len(decrypted_first_chunk) < 6:
                raise ValueError("Paket başlığı çok kısa")
            
            if decrypted_first_chunk[:4] != PKT_MAGIC:
                raise ValueError("Geçersiz paket imzası")
            
            # Extract filename length (2 bytes after PKT_MAGIC)
            name_len = struct.unpack('>H', decrypted_first_chunk[4:6])[0]
            
            # Calculate total package header length: magic(4) + namelen(2) + filename + filesize(8)
            pkg_header_len = 6 + name_len + 8
            
            if len(decrypted_first_chunk) < pkg_header_len:
                raise ValueError("Paket başlığı eksik")
            
            # Extract filename and file size
            filename_bytes = decrypted_first_chunk[6:6+name_len]
            orig_name = filename_bytes.decode('utf-8', errors='replace')
            file_size_expected = struct.unpack('>Q', decrypted_first_chunk[6+name_len:6+name_len+8])[0]
            
        except Exception as e:
            raise ValueError("Geçersiz parola veya bozuk dosya") from e
        
        # Prepare output file
        out_path = os.path.join(out_dir, orig_name)
        base, ext = os.path.splitext(out_path)
        attempt = 0
        while os.path.exists(out_path):
            attempt += 1
            out_path = f"{base}_decrypted{attempt}{ext}"
        
        # Extract actual file data from first chunk
        file_data_start = pkg_header_len
        remaining_data = decrypted_first_chunk[file_data_start:]
        
        total_processed = len(remaining_data)
        
        with open(out_path, 'wb') as fout:
            # Write the file data from first chunk
            if remaining_data:
                fout.write(remaining_data)
            
            # Continue with remaining chunks
            while total_processed < file_size_expected:
                chunk = fin.read(CHUNK_SIZE)
                if not chunk:
                    break
                
                decrypted_chunk = aesgcm.decrypt(nonce, chunk, aad)
                fout.write(decrypted_chunk)
                total_processed += len(decrypted_chunk)
                
                if progress_callback:
                    progress_callback(total_processed, file_size_expected)
        
        if total_processed != file_size_expected:
            raise ValueError(f"Dosya boyutu uyuşmuyor: {total_processed} != {file_size_expected}")
        
        return out_path

# =========================
# GUI - Optimized
# =========================
class EDIPApp(ttk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.master = master
        self.pack(fill='both', expand=True)
        self.filepath: str = ''
        self.fail_count: int = 0
        self.current_operation: Optional[threading.Thread] = None
        self._build_style()
        self._build_ui()

    def _build_style(self):
        self.master.configure(bg=BG)
        style = ttk.Style()
        try:
            style.theme_use('clam')
        except Exception:
            pass
        
        # Configure styles
        style.configure('TFrame', background=BG)
        style.configure('TLabel', background=BG, foreground=FG, font=('Segoe UI', 10))
        style.configure('Title.TLabel', background=BG, foreground=FG, font=('Segoe UI', 14, 'bold'))
        style.configure('Status.TLabel', foreground=MUTED, font=('Segoe UI', 9))
        style.configure('TButton', background=ACCENT, foreground=FG, padding=8, 
                       relief='flat', font=('Segoe UI', 10))
        style.map('TButton', background=[('active', '#7C6DDB')], foreground=[('active', FG)])
        style.configure('TEntry', fieldbackground='#0B0E11', foreground=FG, insertcolor=FG)
        
        # Progress bar style
        style.configure('TProgressbar', background=ACCENT, troughcolor=BG)

    def _build_ui(self):
        pad = {'padx': 12, 'pady': 8}
        pad_small = {'padx': 12, 'pady': 4}

        # Title
        title = ttk.Label(self, text='EDIP Şifreleyici / Çözücü', style='Title.TLabel')
        title.grid(row=0, column=0, columnspan=3, sticky='w', **pad)

        # File selection
        self.path_label = ttk.Label(self, text='Seçili dosya: (yok)', style='Status.TLabel')
        self.path_label.grid(row=1, column=0, columnspan=3, sticky='w', **pad_small)

        self.choose_btn = ttk.Button(self, text='Dosya Seç', command=self.on_choose)
        self.choose_btn.grid(row=2, column=0, sticky='w', **pad)

        # Password entry
        ttk.Label(self, text='Parola:').grid(row=3, column=0, sticky='w', **pad_small)
        self.pw = ttk.Entry(self, show='*', width=40)
        self.pw.grid(row=3, column=1, sticky='we', **pad_small)
        self.pw.bind('<Return>', lambda e: self.on_encrypt() if self.filepath else None)

        # Action buttons
        btn_frame = ttk.Frame(self)
        btn_frame.grid(row=4, column=0, columnspan=3, sticky='we', **pad)
        btn_frame.columnconfigure(0, weight=1)
        btn_frame.columnconfigure(1, weight=1)

        self.encrypt_btn = ttk.Button(btn_frame, text='Şifrele (.edip)', command=self.on_encrypt)
        self.encrypt_btn.grid(row=0, column=0, sticky='we', **pad_small)

        self.decrypt_btn = ttk.Button(btn_frame, text='Şifre Çöz', command=self.on_decrypt)
        self.decrypt_btn.grid(row=0, column=1, sticky='we', **pad_small)

        # Progress bar
        self.progress = ttk.Progressbar(self, mode='determinate')
        self.progress.grid(row=5, column=0, columnspan=3, sticky='we', **pad_small)

        # Status label
        self.status = ttk.Label(self, text='Hazır', style='Status.TLabel')
        self.status.grid(row=6, column=0, columnspan=3, sticky='w', **pad_small)

        # Grid configuration
        self.columnconfigure(1, weight=1)
        self.rowconfigure(6, weight=1)

    def set_status(self, text: str, is_error: bool = False, is_ok: bool = False, is_warning: bool = False):
        color = MUTED
        if is_error:
            color = ERR
        elif is_ok:
            color = OK
        elif is_warning:
            color = WARNING
            
        self.status.configure(text=text, foreground=color)

    def update_progress(self, current: int, total: int):
        """Update progress bar from background thread"""
        percentage = (current / total) * 100 if total > 0 else 0
        self.master.after(0, lambda: self.progress.configure(value=percentage))

    def lock_interface(self, lock: bool = True):
        """Enable/disable interface elements"""
        state = 'disabled' if lock else '!disabled'
        self.encrypt_btn.state([state])
        self.decrypt_btn.state([state])
        self.choose_btn.state([state])
        self.pw.state([state])

    def clear_password(self):
        """Securely clear password field"""
        self.pw.delete(0, 'end')

    def on_choose(self):
        """File selection handler"""
        path = filedialog.askopenfilename(
            title='Dosya seç',
            filetypes=[('Tüm Dosyalar', '*.*'), ('EDIP Dosyaları', '*.edip')]
        )
        if path:
            self.filepath = path
            filename = os.path.basename(path)
            self.path_label.configure(text=f"Seçili dosya: {filename}")
            self.set_status('Dosya seçildi')

    def _run_in_background(self, target: Callable, args: tuple = ()):
        """Run operation in background thread"""
        if self.current_operation and self.current_operation.is_alive():
            self.set_status('Önceki işlem bitmeli', is_warning=True)
            return

        self.lock_interface(True)
        self.progress.configure(value=0)
        self.set_status('İşlem başlatılıyor...')

        def cleanup():
            self.current_operation = None
            self.lock_interface(False)
            self.progress.configure(value=0)

        def wrapped_target():
            try:
                target(*args)
            except Exception as error:
                # Store error in a variable that persists
                error_instance = error
                self.master.after(0, lambda: self._handle_error(error_instance))
            finally:
                self.master.after(0, cleanup)

        self.current_operation = threading.Thread(target=wrapped_target, daemon=True)
        self.current_operation.start()

    def _handle_error(self, error: Exception):
        """Handle errors from background operations"""
        error_msg = str(error)
        self.set_status(f'Hata: {error_msg}', is_error=True)
        
        if "parola" in error_msg.lower() or "password" in error_msg.lower():
            self.fail_count += 1
            delay = min(2 ** self.fail_count, 60)  # Max 60 seconds
            self.lock_buttons(delay)
        
        messagebox.showerror('Hata', error_msg)

    def lock_buttons(self, seconds: int):
        """Lock buttons for specified time"""
        self.lock_interface(True)
        self.set_status(f"Kilitli: {seconds}s", is_error=True)
        
        def countdown(remaining: int):
            if remaining <= 0:
                self.lock_interface(False)
                self.set_status('Hazır')
                return
            self.set_status(f"Çok fazla hata. Bekleyin: {remaining}s", is_error=True)
            self.after(1000, lambda: countdown(remaining - 1))
        
        countdown(seconds)

    def on_encrypt(self):
        """Encryption handler"""
        if not self.filepath:
            messagebox.showerror('Hata', 'Önce bir dosya seçin.')
            return
            
        pw = self.pw.get()
        if not password_policy_ok(pw):
            messagebox.showerror('Hata', 
                'Parola en az 12 karakter ve [a-z][A-Z][0-9][özel] içermeli.')
            return

        out_path = self.filepath + '.edip'
        self._run_in_background(self._encrypt_thread, (pw, out_path))

    def _encrypt_thread(self, password: str, out_path: str):
        """Background encryption thread"""
        try:
            encrypt_file_to_edip(
                self.filepath, out_path, password,
                log2N=DEFAULT_LOG2N, r=DEFAULT_R, p=DEFAULT_P,
                progress_callback=self.update_progress
            )
            self.master.after(0, lambda: self._on_operation_success(
                f'Şifreleme tamam: {os.path.basename(out_path)}', out_path))
        except Exception as e:
            raise e

    def on_decrypt(self):
        """Decryption handler"""
        if not self.filepath:
            messagebox.showerror('Hata', 'Önce bir dosya seçin.')
            return
            
        if not self.filepath.lower().endswith('.edip'):
            if not messagebox.askyesno('Uyarı', 
                'Seçili dosya .edip uzantılı değil. Yine de denensin mi?'):
                return

        pw = self.pw.get()
        if not pw:
            messagebox.showerror('Hata', 'Parola girin.')
            return

        out_dir = os.path.dirname(self.filepath) or os.getcwd()
        self._run_in_background(self._decrypt_thread, (pw, out_dir))

    def _decrypt_thread(self, password: str, out_dir: str):
        """Background decryption thread"""
        try:
            out_path = decrypt_edip_to_file(
                self.filepath, out_dir, password,
                progress_callback=self.update_progress
            )
            self.master.after(0, lambda: self._on_operation_success(
                f'Çözme tamam: {os.path.basename(out_path)}', out_path))
        except Exception as e:
            raise e

    def _on_operation_success(self, message: str, file_path: str):
        """Handle successful operation completion"""
        self.set_status(message, is_ok=True)
        self.fail_count = 0
        self.clear_password()
        messagebox.showinfo('Başarılı', f'İşlem tamamlandı:\n{file_path}')

# =========================
# Main
# =========================

def main():
    root = tk.Tk()
    root.title('EDIP — Şifrele / Şifre Çöz')
    root.configure(bg=BG)
    
    # Set window size and position
    root.geometry('600x300')
    root.minsize(560, 280)
    
    # Center window
    root.eval('tk::PlaceWindow . center')
    
    app = EDIPApp(root)
    
    # Handle window close
    def on_closing():
        if app.current_operation and app.current_operation.is_alive():
            if messagebox.askokcancel("Çıkış", "İşlem devam ediyor. Çıkmak istediğinize emin misiniz?"):
                root.destroy()
        else:
            root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()

if __name__ == '__main__':
    main()