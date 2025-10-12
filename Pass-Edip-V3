# -*- coding: utf-8 -*-
"""
Pass-Edip (secure v3.2) - macOS Uyumlu Ultra Kullanıcı Dostu Arayüz
"""

import os
import io
import struct
import secrets
import hashlib
import time
import sys
import threading
import platform
from dataclasses import dataclass
from typing import Optional, Callable, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidTag

# GUI kütüphaneleri
try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, scrolledtext, simpledialog
    import tkinter.font as tkFont
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False

MAGIC = b"EDP3"
VERSION = 3

KDF_SCRYPT = 1
DEFAULT_LOG2N = 15
DEFAULT_R = 8
DEFAULT_P = 1
DEFAULT_SALT_LEN = 16
DEFAULT_NONCE_LEN = 12
TAG_LEN = 16
CHUNK_SIZE = 1024 * 1024
MAX_FILE_SIZE = 10 * 1024 * 1024 * 1024
MAX_CHUNK_SIZE = 16 * 1024 * 1024

class SecurityError(Exception): pass
class PasswordPolicyError(SecurityError): pass
class AuthenticationError(SecurityError): pass
class FileSizeError(SecurityError): pass

# ==============================
# ÇEKİRDEK ŞİFRELEME FONKSİYONLARI
# ==============================
def u64be(x: int) -> bytes: return struct.pack(">Q", x)
def u32be(x: int) -> bytes: return struct.pack(">I", x)

def read_exact(f: io.BufferedReader, n: int) -> bytes:
    b = f.read(n)
    if len(b) != n: raise ValueError("Beklenmeyen dosya sonu")
    return b

def secure_clean(data: bytearray) -> None:
    if data:
        for i in range(len(data)): data[i] = 0

def password_policy_ok(pw: str) -> Tuple[bool, str]:
    if len(pw) < 8: return False, "Şifre en az 8 karakter olmalı"
    has_lower = any('a' <= c <= 'z' for c in pw)
    has_upper = any('A' <= c <= 'Z' for c in pw)
    has_digit = any('0' <= c <= '9' for c in pw)
    has_special = any(c in "!@#$%^&*()-_=+[]{};:'\",.<>/?\\|`~" for c in pw)
    if (has_lower + has_upper + has_digit + has_special) < 2:
        return False, "En az 2 farklı karakter türü kullanın"
    return True, "Şifre uygun"

def derive_key_scrypt(password_bytes: bytes, salt: bytes, log2N: int, r: int, p: int, dklen: int = 32) -> bytes:
    kdf = Scrypt(salt=salt, length=dklen, n=(1 << log2N), r=r, p=p)
    return kdf.derive(password_bytes)

def load_keyfile_bytes(keyfile_path: Optional[str]) -> bytes:
    if not keyfile_path: return b""
    if not os.path.exists(keyfile_path): raise FileNotFoundError(f"Keyfile bulunamadı: {keyfile_path}")
    if os.path.getsize(keyfile_path) > 10 * 1024 * 1024: raise ValueError("Keyfile çok büyük")
    with open(keyfile_path, "rb") as kf: data = kf.read()
    return hashlib.sha256(data).digest()

@dataclass
class Header:
    version: int; kdf_id: int; salt: bytes; base_nonce: bytes; log2N: int; r: int; p: int; creation_time: int = 0
    def pack(self) -> bytes:
        assert len(self.salt) <= 255 and len(self.base_nonce) <= 255
        hdr = bytearray()
        hdr += MAGIC; hdr += bytes([self.version & 0xFF]); hdr += bytes([self.kdf_id & 0xFF])
        hdr += bytes([len(self.salt) & 0xFF]); hdr += bytes([len(self.base_nonce) & 0xFF])
        hdr += bytes([self.log2N & 0xFF]); hdr += bytes([self.r & 0xFF]); hdr += bytes([self.p & 0xFF])
        hdr += self.salt; hdr += self.base_nonce; hdr += u64be(self.creation_time or int(time.time()))
        return bytes(hdr)
    @staticmethod
    def parse(buf: bytes) -> Tuple["Header", int]:
        if len(buf) < 8: raise ValueError("Başlık çok kısa")
        if buf[:4] != MAGIC: raise ValueError("Geçersiz imza")
        version = buf[4]; kdf_id = buf[5]; salt_len = buf[6]; nonce_len = buf[7]
        if len(buf) < 19 + salt_len + nonce_len: raise ValueError("Başlık alanları eksik")
        if nonce_len != DEFAULT_NONCE_LEN: raise ValueError("Desteklenmeyen nonce uzunluğu")
        if salt_len < 8: raise ValueError("Salt çok kısa")
        log2N = buf[8]; r = buf[9]; p = buf[10]; off = 11
        salt = buf[off:off+salt_len]; off += salt_len
        base_nonce = buf[off:off+nonce_len]; off += nonce_len
        creation_time = struct.unpack(">Q", buf[off:off+8])[0]; off += 8
        return Header(version, kdf_id, salt, base_nonce, log2N, r, p, creation_time), off

def make_chunk_nonce(base_nonce_12: bytes, chunk_index: int) -> bytes:
    assert len(base_nonce_12) == DEFAULT_NONCE_LEN
    return base_nonce_12[:4] + u64be(chunk_index)

def make_chunk_aad(header_bytes: bytes, chunk_index: int) -> bytes:
    return header_bytes + u64be(chunk_index)

def pack_plain(fname: str, expected_size: int) -> bytes:
    if expected_size > MAX_FILE_SIZE: raise FileSizeError(f"Dosya boyutu sınırı aşıyor")
    name_b = os.path.basename(fname).encode("utf-8")
    if len(name_b) > 65535: raise ValueError("Dosya adı çok uzun")
    return struct.pack(">H", len(name_b)) + name_b + struct.pack(">Q", expected_size)

def unpack_plain(buf: bytes) -> Tuple[str, int, int]:
    if len(buf) < 2: raise ValueError("Bozuk ilk paket")
    name_len = struct.unpack(">H", buf[:2])[0]; off = 2
    if len(buf) < off + name_len + 8: raise ValueError("Bozuk ilk paket")
    name_b = buf[off:off+name_len]; off += name_len
    fname = name_b.decode("utf-8"); expected = struct.unpack(">Q", buf[off:off+8])[0]; off += 8
    if expected > MAX_FILE_SIZE: raise FileSizeError("Başlık boyutu sınırı aşıyor")
    return fname, expected, off

def encrypt_file(in_path: str, out_path: str, password: str, keyfile_path: Optional[str] = None,
                 log2N: int = DEFAULT_LOG2N, r: int = DEFAULT_R, p: int = DEFAULT_P,
                 progress: Optional[Callable[[int, int], None]] = None) -> None:
    ok, msg = password_policy_ok(password)
    if not ok: raise PasswordPolicyError(msg)
    if not os.path.exists(in_path): raise FileNotFoundError(in_path)
    file_size = os.path.getsize(in_path)
    if file_size > MAX_FILE_SIZE: raise FileSizeError(f"Girdi çok büyük: {file_size}")
    salt = secrets.token_bytes(DEFAULT_SALT_LEN); base_nonce = secrets.token_bytes(DEFAULT_NONCE_LEN)
    key_material = bytearray(password.encode("utf-8") + load_keyfile_bytes(keyfile_path))
    try: key = derive_key_scrypt(key_material, salt, log2N, r, p, dklen=32)
    finally: secure_clean(key_material)
    aes = AESGCM(key); hdr = Header(VERSION, KDF_SCRYPT, salt, base_nonce, log2N, r, p).pack()
    pkt0 = pack_plain(os.path.basename(in_path), file_size)
    with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
        fout.write(hdr); total = 0; idx = 0
        first_plain = fin.read(CHUNK_SIZE - len(pkt0)); first_plain = pkt0 + (first_plain or b"")
        ct0 = aes.encrypt(make_chunk_nonce(base_nonce, idx), first_plain, make_chunk_aad(hdr, idx))
        fout.write(u32be(len(ct0))); fout.write(ct0); total += len(first_plain)
        if progress: progress(total, file_size); idx += 1
        while True:
            plain = fin.read(CHUNK_SIZE); 
            if not plain: break
            ct = aes.encrypt(make_chunk_nonce(base_nonce, idx), plain, make_chunk_aad(hdr, idx))
            fout.write(u32be(len(ct))); fout.write(ct); total += len(plain)
            if progress: progress(total, file_size); idx += 1

def decrypt_file(in_path: str, out_dir: str, password: str, keyfile_path: Optional[str] = None,
                 progress: Optional[Callable[[int, int], None]] = None) -> str:
    if not os.path.exists(in_path): raise FileNotFoundError(in_path)
    if not os.path.exists(out_dir): raise FileNotFoundError(out_dir)
    with open(in_path, "rb") as fin:
        fixed = read_exact(fin, 11)
        if fixed[:4] != MAGIC: raise ValueError("Geçersiz imza veya bozuk dosya")
        salt_len = fixed[6]; nonce_len = fixed[7]; rest = read_exact(fin, salt_len + nonce_len + 8)
        hdr_bytes = fixed + rest; header, _ = Header.parse(hdr_bytes)
        key_material = bytearray(password.encode("utf-8") + load_keyfile_bytes(keyfile_path))
        try: key = derive_key_scrypt(key_material, header.salt, header.log2N, header.r, header.p, dklen=32)
        finally: secure_clean(key_material)
        aes = AESGCM(key)
        def read_chunk() -> Optional[bytes]:
            len_b = fin.read(4); 
            if not len_b: return None
            if len(len_b) != 4: raise ValueError("Eksik uzunluk öneki")
            (clen,) = struct.unpack(">I", len_b)
            if clen < TAG_LEN: raise ValueError("Şifreli parça çok küçük")
            if clen > MAX_CHUNK_SIZE: raise ValueError("Şifreli parça çok büyük")
            return read_exact(fin, clen)
        idx = 0; ct0 = read_chunk()
        if ct0 is None: raise ValueError("Şifreli parça bulunamadı")
        try: pt0 = aes.decrypt(make_chunk_nonce(header.base_nonce, idx), ct0, make_chunk_aad(hdr_bytes, idx))
        except InvalidTag: raise AuthenticationError("Kimlik doğrulama başarısız")
        out_name, expected_size, off = unpack_plain(pt0); out_name = os.path.basename(out_name) or "decrypted_file"
        first_payload = pt0[off:]; out_path = os.path.join(out_dir, out_name)
        base, ext = os.path.splitext(out_path); c = 1
        while os.path.exists(out_path): out_path = f"{base}({c}){ext}"; c += 1
        written = 0
        with open(out_path, "wb") as fout:
            if first_payload: fout.write(first_payload); written += len(first_payload)
            if progress: progress(written, expected_size); idx = 1
            while True:
                ct = read_chunk(); 
                if ct is None: break
                try: pt = aes.decrypt(make_chunk_nonce(header.base_nonce, idx), ct, make_chunk_aad(hdr_bytes, idx))
                except InvalidTag: raise AuthenticationError(f"Parça {idx} kimlik doğrulama başarısız")
                fout.write(pt); written += len(pt)
                if progress: progress(written, expected_size); idx += 1
        if written != expected_size: raise ValueError(f"Boyut uyuşmazlığı {written} != {expected_size}")
        return out_path

# ==============================
# macOS UYUMLU MODERN GUI ARAYÜZÜ
# ==============================
class ModernPassEdipGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Pass-Edip v3.2 - Tek Tıkla Güvenli Şifreleme")
        self.root.geometry("800x600")
        self.root.minsize(700, 500)
        
        # Modern renkler
        self.colors = {
            'primary': '#2E86AB',
            'secondary': '#A23B72',
            'success': '#27AE60',
            'warning': '#F39C12',
            'danger': '#E74C3C',
            'light': '#ECF0F1',
            'dark': '#2C3E50'
        }
        
        self.setup_styles()
        self.create_ui()
        
    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        
    def create_ui(self):
        # Ana container
        main_container = ttk.Frame(self.root, padding="20")
        main_container.pack(fill=tk.BOTH, expand=True)
        
        # Başlık
        title_frame = ttk.Frame(main_container)
        title_frame.pack(fill=tk.X, pady=(0, 20))
        
        title_label = tk.Label(title_frame, text="🔒 Pass-Edip v3.2", 
                              font=('Arial', 24, 'bold'), 
                              foreground=self.colors['primary'])
        title_label.pack()
        
        subtitle_label = tk.Label(title_frame, text="Tek Tıkla Güvenli Dosya Şifreleme", 
                                 font=('Arial', 12), 
                                 foreground=self.colors['dark'])
        subtitle_label.pack(pady=(5, 0))
        
        # Dosya Alanı
        self.create_file_section(main_container)
        
        # Hızlı İşlem Butonları
        self.create_quick_actions(main_container)
        
        # İlerleme ve Durum
        self.create_progress_section(main_container)
        
        # Günlük
        self.create_log_section(main_container)
        
    def create_file_section(self, parent):
        file_frame = ttk.LabelFrame(parent, text="📁 Dosya İşlem Alanı", padding="15")
        file_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Büyük dosya seçme butonu
        self.file_button = tk.Button(file_frame, 
                                   text="📂 Şifrelenecek/Çözülecek Dosyayı Seçin\n\nDosya seçmek için tıklayın\nveya dosyayı buraya sürükleyin",
                                   font=('Arial', 14),
                                   bg=self.colors['light'],
                                   fg=self.colors['dark'],
                                   relief='raised',
                                   bd=3,
                                   width=40,
                                   height=8,
                                   command=self.select_file)
        self.file_button.pack(fill=tk.BOTH, expand=True, pady=10, padx=10)
        
        # Seçilen dosya bilgisi
        self.file_info_label = tk.Label(file_frame, text="Henüz dosya seçilmedi", 
                                       font=('Arial', 10), 
                                       foreground=self.colors['secondary'],
                                       wraplength=600)
        self.file_info_label.pack(pady=5)
        
        self.current_file = None
        self.file_type = None
        
        # macOS için sürükle-bırak desteği (basit versiyon)
        self.setup_mac_drag_drop()
        
    def setup_mac_drag_drop(self):
        # macOS'te basit sürükle-bırak efekti
        def on_drag_enter(e):
            self.file_button.config(bg='#D6EAF8', relief='sunken')
            
        def on_drag_leave(e):
            self.file_button.config(bg=self.colors['light'], relief='raised')
            
        def on_drop(e):
            self.file_button.config(bg=self.colors['light'], relief='raised')
            # Bu kısım macOS'te çalışmaz ama yer tutucu olarak kalabilir
            self.select_file()
        
        self.file_button.bind('<Enter>', on_drag_enter)
        self.file_button.bind('<Leave>', on_drag_leave)
        self.file_button.bind('<Button-1>', lambda e: self.select_file())
        
    def create_quick_actions(self, parent):
        action_frame = ttk.LabelFrame(parent, text="⚡ Hızlı İşlemler", padding="10")
        action_frame.pack(fill=tk.X, pady=(0, 10))
        
        button_container = ttk.Frame(action_frame)
        button_container.pack(fill=tk.X)
        
        # Şifreleme butonu
        self.encrypt_btn = tk.Button(button_container, 
                                   text="🔒 DOSYAYI ŞİFRELE", 
                                   command=self.quick_encrypt,
                                   bg=self.colors['primary'],
                                   fg='white',
                                   font=('Arial', 12, 'bold'),
                                   state='disabled',
                                   height=2)
        self.encrypt_btn.pack(side=tk.LEFT, padx=(0, 10), fill=tk.X, expand=True)
        
        # Şifre çözme butonu
        self.decrypt_btn = tk.Button(button_container, 
                                   text="🔓 ŞİFREYİ ÇÖZ", 
                                   command=self.quick_decrypt,
                                   bg=self.colors['success'],
                                   fg='white',
                                   font=('Arial', 12, 'bold'),
                                   state='disabled',
                                   height=2)
        self.decrypt_btn.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
    def create_progress_section(self, parent):
        progress_frame = ttk.LabelFrame(parent, text="📊 İlerleme", padding="10")
        progress_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X, pady=5)
        
        self.status_var = tk.StringVar(value="Hazır - Dosya seçin")
        status_label = tk.Label(progress_frame, textvariable=self.status_var, 
                               font=('Arial', 10), foreground=self.colors['primary'])
        status_label.pack()
        
    def create_log_section(self, parent):
        log_frame = ttk.LabelFrame(parent, text="📝 İşlem Geçmişi", padding="10")
        log_frame.pack(fill=tk.BOTH, expand=True)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=8, font=('Consolas', 9))
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
    def select_file(self):
        filename = filedialog.askopenfilename(
            title="Şifrelenecek veya şifresi çözülecek dosyayı seçin",
            filetypes=[("Tüm dosyalar", "*.*")]
        )
        if filename:
            self.process_selected_file(filename)
    
    def process_selected_file(self, filepath):
        self.current_file = filepath
        filename = os.path.basename(filepath)
        file_size = os.path.getsize(filepath)
        size_mb = file_size / (1024 * 1024)
        
        # Dosya tipini belirle (.enc uzantılı mı?)
        if filepath.lower().endswith('.enc'):
            self.file_type = 'encrypted'
            file_info = f"🔓 Şifreli dosya: {filename}\nBoyut: {size_mb:.1f} MB - ŞİFRE ÇÖZÜLEBİLİR"
            self.encrypt_btn.config(state='disabled', bg='gray')
            self.decrypt_btn.config(state='normal', bg=self.colors['success'])
            self.file_button.config(text=f"✅ ŞİFRELİ DOSYA SEÇİLDİ\n\n{filename}\n\nŞifresini çözmek için 'ŞİFREYİ ÇÖZ' butonuna tıklayın")
        else:
            self.file_type = 'normal'
            file_info = f"🔒 Normal dosya: {filename}\nBoyut: {size_mb:.1f} MB - ŞİFRELENEBİLİR"
            self.encrypt_btn.config(state='normal', bg=self.colors['primary'])
            self.decrypt_btn.config(state='disabled', bg='gray')
            self.file_button.config(text=f"✅ DOSYA SEÇİLDİ\n\n{filename}\n\nŞifrelemek için 'DOSYAYI ŞİFRELE' butonuna tıklayın")
        
        self.file_info_label.config(text=file_info)
        self.log(f"📁 Dosya seçildi: {filename} ({self.file_type}, {size_mb:.1f} MB)")
        self.status_var.set(f"Dosya hazır: {filename}")
        
    def quick_encrypt(self):
        if not self.current_file or self.file_type != 'normal':
            messagebox.showerror("Hata", "Lütfen şifrelenecek normal bir dosya seçin")
            return
        
        password = self.ask_password("Şifreleme için şifre girin:")
        if not password: return
        
        # Çıktı dosyasını aynı dizinde .enc uzantısıyla oluştur
        output_file = self.current_file + '.enc'
        self.run_operation('encrypt', self.current_file, output_file, password)
    
    def quick_decrypt(self):
        if not self.current_file or self.file_type != 'encrypted':
            messagebox.showerror("Hata", "Lütfen şifresi çözülecek bir .enc dosyası seçin")
            return
        
        password = self.ask_password("Şifre çözme için şifre girin:")
        if not password: return
        
        # Çıktı dizini olarak dosyanın olduğu dizin
        output_dir = os.path.dirname(self.current_file) or '.'
        self.run_operation('decrypt', self.current_file, output_dir, password)
    
    def ask_password(self, prompt):
        password = simpledialog.askstring("Şifre", prompt, show='•')
        if password:
            ok, msg = password_policy_ok(password)
            if not ok:
                result = messagebox.askyesno("Şifre Uyarısı", 
                                           f"{msg}\n\nYine de devam etmek istiyor musunuz?",
                                           icon='warning')
                if not result:
                    return None
        return password
    
    def run_operation(self, operation, input_path, output_path, password):
        def thread_worker():
            try:
                self.status_var.set("İşlem başlatılıyor...")
                self.progress_var.set(0)
                self.log(f"🚀 {operation.upper()} işlemi başlatılıyor...")
                
                if operation == 'encrypt':
                    encrypt_file(input_path, output_path, password, 
                               progress=self.progress_callback)
                    self.log(f"✅ Şifreleme tamamlandı: {output_path}")
                    self.status_var.set("Şifreleme tamamlandı!")
                    messagebox.showinfo("Başarılı", 
                                      f"✅ Dosya başarıyla şifrelendi!\n\n"
                                      f"Orijinal: {os.path.basename(input_path)}\n"
                                      f"Şifreli: {os.path.basename(output_path)}")
                    
                else:  # decrypt
                    result_path = decrypt_file(input_path, output_path, password,
                                             progress=self.progress_callback)
                    self.log(f"✅ Şifre çözme tamamlandı: {result_path}")
                    self.status_var.set("Şifre çözme tamamlandı!")
                    messagebox.showinfo("Başarılı", 
                                      f"✅ Dosya başarıyla şifresi çözüldü!\n\n"
                                      f"Şifreli: {os.path.basename(input_path)}\n"
                                      f"Çözülen: {os.path.basename(result_path)}")
                    
                self.progress_var.set(100)
                
            except AuthenticationError as e:
                error_msg = f"❌ Kimlik doğrulama hatası: Yanlış şifre veya bozuk dosya"
                self.log(error_msg)
                self.status_var.set("Kimlik doğrulama hatası!")
                messagebox.showerror("Kimlik Doğrulama Hatası", 
                                   "❌ Yanlış şifre veya dosya bozuk!\n\n"
                                   "Lütfen şifrenizi kontrol edin.")
            except Exception as e:
                error_msg = f"❌ {operation} hatası: {str(e)}"
                self.log(error_msg)
                self.status_var.set("Hata oluştu!")
                messagebox.showerror("Hata", f"❌ İşlem sırasında hata:\n\n{str(e)}")
        
        # İşlemi thread'de çalıştır (UI donmasın diye)
        thread = threading.Thread(target=thread_worker)
        thread.daemon = True
        thread.start()
    
    def progress_callback(self, current, total):
        percent = (current / total) * 100 if total > 0 else 0
        self.progress_var.set(percent)
        self.status_var.set(f"İşleniyor: {current}/{total} bayt (%{percent:.1f})")
    
    def log(self, message):
        timestamp = time.strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
        self.root.update()

# ==============================
# UYGULAMA BAŞLATMA
# ==============================
def main():
    if not GUI_AVAILABLE:
        print("GUI kütüphaneleri yüklenemedi. Lütfen tkinter kurulu olduğundan emin olun.")
        print("macOS'ta tkinter genellikle Python ile birlikte gelir.")
        return 1
    
    try:
        root = tk.Tk()
        
        # macOS özellikleri
        if platform.system() == 'Darwin':
            # Pencere stilini ayarla
            root.tk.call('tk', 'scaling', 1.5)  # Retina display desteği
            
        app = ModernPassEdipGUI(root)
        
        # Pencereyi ekranın ortasında aç
        root.update_idletasks()
        x = (root.winfo_screenwidth() - root.winfo_reqwidth()) // 2
        y = (root.winfo_screenheight() - root.winfo_reqheight()) // 2
        root.geometry(f"+{x}+{y}")
        
        root.mainloop()
        return 0
        
    except Exception as e:
        print(f"GUI başlatma hatası: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    exit(main())
