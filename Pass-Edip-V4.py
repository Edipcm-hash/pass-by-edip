# -*- coding: utf-8 -*-
"""
Pass-Edip (secure v4.0) - Ultimate Security Edition
Root Detection, Memory Protection, Enhanced Security
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
import atexit
import gc
import ctypes
import mmap
import functools
import subprocess
import warnings
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

# ==============================
# GÜVENLİK SİSTEMİ - ROOT TESPİT
# ==============================
class RootDetector:
    """Çoklu platformda root/admin tespiti"""
    
    @staticmethod
    def is_root() -> bool:
        """Root kullanıcı mı kontrol et"""
        system = platform.system()
        
        if system == "Linux" or system == "Darwin":  # macOS
            return os.geteuid() == 0  # Unix/Linux root ID = 0
            
        elif system == "Windows":
            try:
                # Windows admin kontrolü
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except:
                # Fallback method
                try:
                    subprocess.run(["net", "session"], 
                                 capture_output=True, 
                                 check=True,
                                 timeout=2)
                    return True
                except:
                    return False
        
        return False
    
    @staticmethod
    def is_sudo() -> bool:
        """Sudo ile mi çalıştırıldı?"""
        return "SUDO_UID" in os.environ or "SUDO_USER" in os.environ
    
    @staticmethod
    def has_root_capabilities() -> bool:
        """Root yetkileri var mı?"""
        if platform.system() in ["Linux", "Darwin"]:
            # Dosya testi ile yetki kontrolü
            test_file = "/etc/shadow"
            try:
                with open(test_file, "rb") as f:
                    f.read(1)
                return True
            except PermissionError:
                return False
            except:
                return False
        return False
    
    @staticmethod
    def check_debuggers() -> bool:
        """Debugger/dumping araçları tespiti"""
        try:
            # ptrace kontrolü (Linux)
            if platform.system() in ["Linux", "Darwin"]:
                with open("/proc/self/status", "r") as f:
                    for line in f:
                        if line.startswith("TracerPid:"):
                            tracer_pid = int(line.split(":")[1].strip())
                            return tracer_pid != 0
        except:
            pass
        
        # GDB, strace, lldb kontrolü
        debuggers = ["gdb", "strace", "lldb", "radare2", "ida"]
        try:
            if platform.system() in ["Linux", "Darwin"]:
                processes = subprocess.run(["ps", "aux"], 
                                         capture_output=True, 
                                         text=True,
                                         timeout=2).stdout.lower()
                return any(debugger in processes for debugger in debuggers)
        except:
            pass
        
        return False
    
    @staticmethod
    def check_virtualization() -> bool:
        """Sanal makine/container'da mı?"""
        indicators = [
            "/.dockerenv",  # Docker
            "/.dockerinit",  # Docker (eski)
            "/proc/1/cgroup",  # Container kontrolü
        ]
        
        for indicator in indicators:
            if os.path.exists(indicator):
                return True
        
        try:
            if platform.system() == "Linux":
                with open("/proc/cpuinfo", "r") as f:
                    cpuinfo = f.read()
                    return "hypervisor" in cpuinfo.lower()
        except:
            pass
        
        return False

class SecurityEnvironment:
    """Çalışma ortamı güvenlik değerlendirmesi"""
    
    @staticmethod
    def get_security_score() -> dict:
        """Ortam güvenlik skorlaması"""
        score = 100
        warnings = []
        critical = []
        
        detector = RootDetector()
        
        # 1. Root kontrolü (-50 puan)
        if detector.is_root():
            score -= 50
            critical.append("Uygulama root yetkileriyle çalışıyor!")
        
        # 2. Sudo kontrolü (-30 puan)
        if detector.is_sudo():
            score -= 30
            warnings.append("Sudo ile çalıştırıldı")
        
        # 3. Debugger kontrolü (-40 puan)
        if detector.check_debuggers():
            score -= 40
            critical.append("Debugger tespit edildi!")
        
        # 4. Sanal ortam kontrolü (+10 puan, daha güvenli)
        if detector.check_virtualization():
            score += 10
            warnings.append("Sanal ortamda çalışıyor")
        
        # 5. Memory dumping araçları kontrolü
        if SecurityEnvironment._check_memory_tools():
            score -= 35
            warnings.append("Memory analysis araçları tespit edildi")
        
        # 6. Network dinleme araçları
        if SecurityEnvironment._check_sniffers():
            score -= 25
            warnings.append("Network sniffing araçları bulundu")
        
        return {
            "score": max(0, score),
            "level": SecurityEnvironment._get_security_level(score),
            "warnings": warnings,
            "critical": critical,
            "is_secure": score >= 70
        }
    
    @staticmethod
    def _check_memory_tools() -> bool:
        """Memory dumping araçları tespiti"""
        tools = ["gdb", "lldb", "radare2", "fmem", "dumpit"]
        try:
            if platform.system() in ["Linux", "Darwin"]:
                result = subprocess.run(
                    ["which"] + tools,
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                return bool(result.stdout.strip())
        except:
            pass
        return False
    
    @staticmethod
    def _check_sniffers() -> bool:
        """Network sniffing araçları"""
        sniffers = ["wireshark", "tshark", "tcpdump", "ettercap"]
        try:
            if platform.system() in ["Linux", "Darwin"]:
                processes = subprocess.run(["ps", "aux"], 
                                         capture_output=True, 
                                         text=True,
                                         timeout=2).stdout.lower()
                return any(sniffer in processes for sniffer in sniffers)
        except:
            pass
        return False
    
    @staticmethod
    def _get_security_level(score: int) -> str:
        if score >= 90:
            return "ÇOK GÜVENLİ"
        elif score >= 70:
            return "GÜVENLİ"
        elif score >= 50:
            return "ORTA RISK"
        elif score >= 30:
            return "YÜKSEK RISK"
        else:
            return "KRİTİK RİSK"

class SecurityLogger:
    """Güvenlik olaylarını logla"""
    
    def __init__(self):
        self.log_file = self._get_log_path()
        
    def _get_log_path(self):
        """Platforma göre log dosyası yolu"""
        if platform.system() == "Windows":
            path = os.path.join(os.environ.get("APPDATA", "."), 
                              "PassEdip", "security.log")
        else:
            path = os.path.expanduser("~/.passedip/security.log")
        
        os.makedirs(os.path.dirname(path), exist_ok=True)
        return path
    
    def log_security_event(self, security_status: dict):
        """Güvenlik olayını logla"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        
        log_entry = f"""
[{timestamp}] SECURITY SCAN
Score: {security_status['score']}/100
Level: {security_status['level']}
Secure: {security_status['is_secure']}
Warnings: {len(security_status['warnings'])}
Critical: {len(security_status['critical'])}
User: {os.environ.get('USER', os.environ.get('USERNAME', 'Unknown'))}
PID: {os.getpid()}
Platform: {platform.platform()}
{'='*50}
"""
        
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(log_entry)
                
            # Log dosyasını koru (sadece owner okuyabilsin)
            if platform.system() in ["Linux", "Darwin"]:
                os.chmod(self.log_file, 0o600)
        except:
            pass  # Log yazılamazsa sessizce devam et

class RestrictedMode:
    """Root altında kısıtlı modda çalıştır"""
    
    ACTIVE = False
    ORIGINAL_MAX_FILE_SIZE = None
    ORIGINAL_CHUNK_SIZE = None
    
    @staticmethod
    def can_run_in_root() -> bool:
        """Root'ta çalışmaya izin verilsin mi?"""
        if not GUI_AVAILABLE:
            print("⚠️  Root erişimi tespit edildi. Kısıtlı modda devam ediliyor.")
            return True
            
        try:
            root = tk.Tk()
            root.withdraw()
            response = messagebox.askyesno(
                "Root Erişimi Tespit Edildi",
                "⚠️  Uygulama root yetkileriyle çalışıyor.\n\n"
                "Bu, güvenlik riski oluşturabilir.\n"
                "Kısıtlı modda devam etmek ister misiniz?\n\n"
                "Kısıtlı modda:\n"
                "• Anahtar uzun süre RAM'de tutulmaz\n"
                "• Memory dumping korumaları aktif\n"
                "• Otomatik temizlik sıklaştırılır\n"
                "• Büyük dosya şifreleme devre dışı",
                icon='warning'
            )
            root.destroy()
            return response
        except:
            return False
    
    @staticmethod
    def apply_restrictions():
        """Kısıtlı mod ayarlarını uygula"""
        RestrictedMode.ACTIVE = True
        
        # Global değişkenleri kaydet
        RestrictedMode.ORIGINAL_MAX_FILE_SIZE = globals().get('MAX_FILE_SIZE')
        RestrictedMode.ORIGINAL_CHUNK_SIZE = globals().get('CHUNK_SIZE')
        
        # Limitleri düşür
        globals()['MAX_FILE_SIZE'] = 100 * 1024 * 1024  # 100MB
        globals()['CHUNK_SIZE'] = 64 * 1024  # 64KB
        
        print("🔒 Kısıtlı mod aktif: MAX_FILE_SIZE=100MB, CHUNK_SIZE=64KB")
    
    @staticmethod
    def restore_restrictions():
        """Orijinal ayarları geri yükle"""
        if RestrictedMode.ACTIVE:
            if RestrictedMode.ORIGINAL_MAX_FILE_SIZE:
                globals()['MAX_FILE_SIZE'] = RestrictedMode.ORIGINAL_MAX_FILE_SIZE
            if RestrictedMode.ORIGINAL_CHUNK_SIZE:
                globals()['CHUNK_SIZE'] = RestrictedMode.ORIGINAL_CHUNK_SIZE
            RestrictedMode.ACTIVE = False

# ==============================
# GÜVENLİ MEMORY YÖNETİMİ
# ==============================
def secure_memory_allocation(size: int):
    """RAM'de secure memory tahsisi"""
    try:
        if platform.system() in ["Linux", "Darwin"]:
            # mmap ile secure alan oluştur
            PROT_READ = 0x1
            PROT_WRITE = 0x2
            MAP_PRIVATE = 0x02
            MAP_ANONYMOUS = 0x20
            
            # Create memory area
            buf = mmap.mmap(-1, size, flags=MAP_PRIVATE | MAP_ANONYMOUS, 
                          prot=PROT_READ | PROT_WRITE)
            
            # Try to lock memory to prevent swapping
            try:
                libc = ctypes.CDLL("libc.so.6")
                libc.mlock(ctypes.c_void_p(ctypes.addressof(ctypes.c_char.from_buffer(buf))), size)
            except:
                pass
            
            return buf
        else:
            # Windows veya diğer sistemler için normal bytearray
            return bytearray(size)
    except:
        return bytearray(size)

def secure_clean(data) -> None:
    """Veriyi güvenli temizle"""
    if data:
        if isinstance(data, (bytes, bytearray)):
            # Bytearray veya bytes'ı sıfırla
            if isinstance(data, bytearray):
                for i in range(len(data)):
                    data[i] = 0
            elif isinstance(data, bytes):
                # bytes immutable olduğu için temizleyemeyiz
                # ama referansını None yapabiliriz
                pass
        elif hasattr(data, '__len__'):
            # Diğer buffer benzeri objeler
            try:
                for i in range(len(data)):
                    data[i] = 0
            except:
                pass

def secure_cleanup(func):
    """Fonksiyon sonunda hassas verileri temizle"""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        finally:
            # Hassas argümanları temizle
            for i, arg in enumerate(args):
                if isinstance(arg, (bytearray, bytes)):
                    secure_clean(arg)
            # GC ile temizlik
            gc.collect()
    return wrapper

# ==============================
# ANA GÜVENLİK POLİTİKASI
# ==============================
def enforce_security_policy():
    """Güvenlik politikasını zorla"""
    
    env = SecurityEnvironment.get_security_score()
    
    # Güvenlik logger'ını başlat
    logger = SecurityLogger()
    logger.log_security_event(env)
    
    # GUI için mesaj hazırla
    message = "🔒 Güvenlik Değerlendirmesi:\n\n"
    message += f"Güvenlik Seviyesi: {env['level']}\n"
    message += f"Güvenlik Skoru: {env['score']}/100\n\n"
    
    if env['warnings']:
        message += "⚠️  Uyarılar:\n"
        for warn in env['warnings']:
            message += f"  • {warn}\n"
        message += "\n"
    
    if env['critical']:
        message += "🚨 Kritik Riskler:\n"
        for crit in env['critical']:
            message += f"  • {crit}\n"
        message += "\n"
    
    # Root veya kritik risk varsa
    if RootDetector.is_root():
        if RestrictedMode.can_run_in_root():
            RestrictedMode.apply_restrictions()
            message += "⚠️  KISITLI MOD AKTİF\n\n"
            message += "Uygulama kısıtlı modda çalışacak.\n"
            message += "Bazı özellikler devre dışı bırakıldı."
            
            if GUI_AVAILABLE:
                try:
                    root = tk.Tk()
                    root.withdraw()
                    messagebox.showwarning(
                        "Kısıtlı Mod Aktif - Pass-Edip",
                        message
                    )
                    root.destroy()
                except:
                    print(message)
            else:
                print(message)
        else:
            message += "❌ BU ORTAM GÜVENLİ DEĞİL!\n\n"
            message += "Pass-Edip yüksek güvenlik riski nedeniyle çalıştırılamaz.\n"
            message += "Lütfen normal kullanıcı hesabıyla çalıştırın."
            
            if GUI_AVAILABLE:
                try:
                    root = tk.Tk()
                    root.withdraw()
                    messagebox.showerror(
                        "Güvenlik Engellendi - Pass-Edip",
                        message,
                        icon='error'
                    )
                    root.destroy()
                except:
                    print(message)
            else:
                print(message)
            
            sys.exit(1)
    
    # Debugger varsa uyar
    elif RootDetector.check_debuggers() and GUI_AVAILABLE:
        message += "⚠️  Debugger tespit edildi!\n\n"
        message += "Güvenlik için debugger kapatmanız önerilir."
        
        try:
            root = tk.Tk()
            root.withdraw()
            response = messagebox.askyesno(
                "Debugger Tespit Edildi - Pass-Edip",
                message + "\n\nDevam etmek istiyor musunuz?",
                icon='warning'
            )
            root.destroy()
            
            if not response:
                sys.exit(0)
        except:
            pass
    
    return env

# ==============================
# ÇEKİRDEK ŞİFRELEME KONSTANTLARI
# ==============================
MAGIC = b"EDP3"
VERSION = 4  # Version 4'e yükseltildi

KDF_SCRYPT = 1
DEFAULT_LOG2N = 15
DEFAULT_R = 8
DEFAULT_P = 1
DEFAULT_SALT_LEN = 16
DEFAULT_NONCE_LEN = 12
TAG_LEN = 16
CHUNK_SIZE = 1024 * 1024  # 1MB
MAX_FILE_SIZE = 10 * 1024 * 1024 * 1024  # 10GB
MAX_CHUNK_SIZE = 16 * 1024 * 1024  # 16MB

# ==============================
# HATA SINIFLARI
# ==============================
class SecurityError(Exception): pass
class PasswordPolicyError(SecurityError): pass
class AuthenticationError(SecurityError): pass
class FileSizeError(SecurityError): pass
class RootAccessError(SecurityError): pass

# ==============================
# ÇEKİRDEK ŞİFRELEME FONKSİYONLARI
# ==============================
def u64be(x: int) -> bytes: return struct.pack(">Q", x)
def u32be(x: int) -> bytes: return struct.pack(">I", x)

def read_exact(f: io.BufferedReader, n: int) -> bytes:
    b = f.read(n)
    if len(b) != n: raise ValueError("Beklenmeyen dosya sonu")
    return b

def password_policy_ok(pw: str) -> Tuple[bool, str]:
    """Şifre politikası kontrolü"""
    if len(pw) < 8: return False, "Şifre en az 8 karakter olmalı"
    has_lower = any('a' <= c <= 'z' for c in pw)
    has_upper = any('A' <= c <= 'Z' for c in pw)
    has_digit = any('0' <= c <= '9' for c in pw)
    has_special = any(c in "!@#$%^&*()-_=+[]{};:'\",.<>/?\\|`~" for c in pw)
    if (has_lower + has_upper + has_digit + has_special) < 2:
        return False, "En az 2 farklı karakter türü kullanın"
    return True, "Şifre uygun"

@secure_cleanup
def derive_key_scrypt(password_bytes: bytes, salt: bytes, log2N: int, r: int, p: int, dklen: int = 32) -> bytes:
    """Güvenli key türetme"""
    kdf = Scrypt(salt=salt, length=dklen, n=(1 << log2N), r=r, p=p)
    return kdf.derive(password_bytes)

def load_keyfile_bytes(keyfile_path: Optional[str]) -> bytes:
    """Keyfile yükleme"""
    if not keyfile_path: return b""
    if not os.path.exists(keyfile_path): raise FileNotFoundError(f"Keyfile bulunamadı: {keyfile_path}")
    if os.path.getsize(keyfile_path) > 10 * 1024 * 1024: raise ValueError("Keyfile çok büyük")
    with open(keyfile_path, "rb") as kf: data = kf.read()
    return hashlib.sha256(data).digest()

@dataclass
class Header:
    """Şifreleme başlığı"""
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
    if expected_size > MAX_FILE_SIZE: 
        raise FileSizeError(f"Dosya boyutu sınırı aşıyor: {expected_size} > {MAX_FILE_SIZE}")
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

@secure_cleanup
def encrypt_file(in_path: str, out_path: str, password: str, keyfile_path: Optional[str] = None,
                 log2N: int = DEFAULT_LOG2N, r: int = DEFAULT_R, p: int = DEFAULT_P,
                 progress: Optional[Callable[[int, int], None]] = None) -> None:
    """Dosya şifreleme"""
    # Güvenlik kontrolü
    if RootDetector.is_root() and not RestrictedMode.ACTIVE:
        raise RootAccessError("Root erişiminde şifreleme yapılamaz")
    
    ok, msg = password_policy_ok(password)
    if not ok: raise PasswordPolicyError(msg)
    if not os.path.exists(in_path): raise FileNotFoundError(in_path)
    
    file_size = os.path.getsize(in_path)
    if file_size > MAX_FILE_SIZE: 
        raise FileSizeError(f"Girdi çok büyük: {file_size} > {MAX_FILE_SIZE}")
    
    salt = secrets.token_bytes(DEFAULT_SALT_LEN)
    base_nonce = secrets.token_bytes(DEFAULT_NONCE_LEN)
    
    # Key material güvenli oluşturma
    key_material = secure_memory_allocation(len(password) + 32)  # Password + keyfile hash
    try:
        # Password'ü güvenli kopyala
        pw_bytes = password.encode("utf-8")
        key_material[:len(pw_bytes)] = pw_bytes
        
        # Keyfile ekle
        keyfile_hash = load_keyfile_bytes(keyfile_path)
        if keyfile_hash:
            key_material[len(pw_bytes):len(pw_bytes)+len(keyfile_hash)] = keyfile_hash
        
        # Key türet
        key = derive_key_scrypt(bytes(key_material[:len(pw_bytes)+len(keyfile_hash)]), 
                               salt, log2N, r, p, dklen=32)
    finally:
        secure_clean(key_material)
    
    aes = AESGCM(key)
    hdr = Header(VERSION, KDF_SCRYPT, salt, base_nonce, log2N, r, p).pack()
    pkt0 = pack_plain(os.path.basename(in_path), file_size)
    
    with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
        fout.write(hdr)
        total = 0
        idx = 0
        
        first_plain = fin.read(CHUNK_SIZE - len(pkt0))
        first_plain = pkt0 + (first_plain or b"")
        
        ct0 = aes.encrypt(make_chunk_nonce(base_nonce, idx), first_plain, make_chunk_aad(hdr, idx))
        fout.write(u32be(len(ct0)))
        fout.write(ct0)
        total += len(first_plain)
        
        if progress: 
            progress(total, file_size)
        idx += 1
        
        while True:
            plain = fin.read(CHUNK_SIZE)
            if not plain: 
                break
            ct = aes.encrypt(make_chunk_nonce(base_nonce, idx), plain, make_chunk_aad(hdr, idx))
            fout.write(u32be(len(ct)))
            fout.write(ct)
            total += len(plain)
            
            if progress: 
                progress(total, file_size)
            idx += 1
        
        # Key'i temizle (mümkünse)
        secure_clean(key)

@secure_cleanup
def decrypt_file(in_path: str, out_dir: str, password: str, keyfile_path: Optional[str] = None,
                 progress: Optional[Callable[[int, int], None]] = None) -> str:
    """Dosya şifre çözme"""
    # Güvenlik kontrolü
    if RootDetector.is_root() and not RestrictedMode.ACTIVE:
        raise RootAccessError("Root erişiminde şifre çözme yapılamaz")
    
    if not os.path.exists(in_path): 
        raise FileNotFoundError(in_path)
    if not os.path.exists(out_dir): 
        raise FileNotFoundError(out_dir)
    
    with open(in_path, "rb") as fin:
        fixed = read_exact(fin, 11)
        if fixed[:4] != MAGIC: 
            raise ValueError("Geçersiz imza veya bozuk dosya")
        
        salt_len = fixed[6]
        nonce_len = fixed[7]
        rest = read_exact(fin, salt_len + nonce_len + 8)
        hdr_bytes = fixed + rest
        header, _ = Header.parse(hdr_bytes)
        
        # Key material güvenli oluşturma
        key_material = secure_memory_allocation(len(password) + 32)
        try:
            pw_bytes = password.encode("utf-8")
            key_material[:len(pw_bytes)] = pw_bytes
            
            keyfile_hash = load_keyfile_bytes(keyfile_path)
            if keyfile_hash:
                key_material[len(pw_bytes):len(pw_bytes)+len(keyfile_hash)] = keyfile_hash
            
            key = derive_key_scrypt(bytes(key_material[:len(pw_bytes)+len(keyfile_hash)]), 
                                   header.salt, header.log2N, header.r, header.p, dklen=32)
        finally:
            secure_clean(key_material)
        
        aes = AESGCM(key)
        
        def read_chunk() -> Optional[bytes]:
            len_b = fin.read(4)
            if not len_b: 
                return None
            if len(len_b) != 4: 
                raise ValueError("Eksik uzunluk öneki")
            
            (clen,) = struct.unpack(">I", len_b)
            if clen < TAG_LEN: 
                raise ValueError("Şifreli parça çok küçük")
            if clen > MAX_CHUNK_SIZE: 
                raise ValueError("Şifreli parça çok büyük")
            
            return read_exact(fin, clen)
        
        idx = 0
        ct0 = read_chunk()
        if ct0 is None: 
            raise ValueError("Şifreli parça bulunamadı")
        
        try:
            pt0 = aes.decrypt(make_chunk_nonce(header.base_nonce, idx), ct0, make_chunk_aad(hdr_bytes, idx))
        except InvalidTag: 
            raise AuthenticationError("Kimlik doğrulama başarısız")
        
        out_name, expected_size, off = unpack_plain(pt0)
        out_name = os.path.basename(out_name) or "decrypted_file"
        first_payload = pt0[off:]
        out_path = os.path.join(out_dir, out_name)
        
        # Dosya çakışmasını önle
        base, ext = os.path.splitext(out_path)
        c = 1
        while os.path.exists(out_path): 
            out_path = f"{base}({c}){ext}"
            c += 1
        
        written = 0
        with open(out_path, "wb") as fout:
            if first_payload: 
                fout.write(first_payload)
                written += len(first_payload)
            
            if progress: 
                progress(written, expected_size)
            
            idx = 1
            while True:
                ct = read_chunk()
                if ct is None: 
                    break
                
                try:
                    pt = aes.decrypt(make_chunk_nonce(header.base_nonce, idx), ct, make_chunk_aad(hdr_bytes, idx))
                except InvalidTag: 
                    raise AuthenticationError(f"Parça {idx} kimlik doğrulama başarısız")
                
                fout.write(pt)
                written += len(pt)
                
                if progress: 
                    progress(written, expected_size)
                idx += 1
        
        if written != expected_size: 
            raise ValueError(f"Boyut uyuşmazlığı {written} != {expected_size}")
        
        # Key'i temizle
        secure_clean(key)
        
        return out_path

# ==============================
# MODERN GUI ARAYÜZÜ
# ==============================
class ModernPassEdipGUI:
    def __init__(self, root, security_status=None):
        self.root = root
        self.security_status = security_status or {}
        
        self.root.title("Pass-Edip v4.0 - Ultimate Security Edition")
        self.root.geometry("900x700")
        self.root.minsize(800, 600)
        
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
        self.create_security_indicator()
        
        # Emergency cleanup on exit
        atexit.register(self.emergency_cleanup)
        
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
        
        title_label = tk.Label(title_frame, text="🔒 Pass-Edip v4.0", 
                              font=('Arial', 28, 'bold'), 
                              foreground=self.colors['primary'])
        title_label.pack()
        
        subtitle_label = tk.Label(title_frame, text="Ultimate Security Edition | Root Protection Active", 
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
        
    def create_security_indicator(self):
        """Güvenlik durum göstergesi"""
        if not self.security_status:
            return
        
        # Sağ üst köşede güvenlik göstergesi
        security_frame = ttk.Frame(self.root)
        security_frame.place(relx=0.98, rely=0.02, anchor="ne")
        
        score = self.security_status.get('score', 100)
        level = self.security_status.get('level', 'Bilinmiyor')
        
        # Renk belirle
        if score >= 70:
            color = self.colors['success']
            emoji = "🟢"
        elif score >= 50:
            color = self.colors['warning']
            emoji = "🟡"
        else:
            color = self.colors['danger']
            emoji = "🔴"
        
        # Gösterge etiketi
        self.security_label = tk.Label(
            security_frame,
            text=f"{emoji} Güvenlik: {score}/100",
            font=('Arial', 10, 'bold'),
            fg=color,
            cursor="hand2",
            bg='white',
            relief='raised',
            padx=10,
            pady=5
        )
        self.security_label.pack()
        
        # Tıklanınca detay göster
        self.security_label.bind("<Button-1>", self.show_security_details)
    
    def show_security_details(self, event=None):
        """Güvenlik detaylarını göster"""
        if not self.security_status:
            return
        
        details = "🔒 Güvenlik Durumu:\n\n"
        details += f"Skor: {self.security_status.get('score', 100)}/100\n"
        details += f"Seviye: {self.security_status.get('level', 'Bilinmiyor')}\n"
        details += f"Güvenli: {'✅' if self.security_status.get('is_secure') else '❌'}\n\n"
        
        if RootDetector.is_root():
            details += "⚠️  ROOT ERİŞİMİ AKTİF\n"
            if RestrictedMode.ACTIVE:
                details += "✅ Kısıtlı Mod Aktif\n\n"
            else:
                details += "❌ Kısıtlı Mod Kapalı\n\n"
        
        if self.security_status.get('warnings'):
            details += "⚠️  Uyarılar:\n"
            for warn in self.security_status['warnings']:
                details += f"• {warn}\n"
            details += "\n"
        
        if self.security_status.get('critical'):
            details += "🚨 Kritik Riskler:\n"
            for crit in self.security_status['critical']:
                details += f"• {crit}\n"
        
        messagebox.showinfo("Güvenlik Durumu - Pass-Edip v4.0", details)
    
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
                                   width=50,
                                   height=8,
                                   command=self.select_file)
        self.file_button.pack(fill=tk.BOTH, expand=True, pady=10, padx=10)
        
        # Seçilen dosya bilgisi
        self.file_info_label = tk.Label(file_frame, text="Henüz dosya seçilmedi", 
                                       font=('Arial', 10), 
                                       foreground=self.colors['secondary'],
                                       wraplength=700)
        self.file_info_label.pack(pady=5)
        
        # Kısıtlı mod göstergesi
        self.restricted_mode_label = tk.Label(file_frame, text="", 
                                             font=('Arial', 9, 'italic'),
                                             foreground=self.colors['warning'])
        self.restricted_mode_label.pack(pady=2)
        
        self.current_file = None
        self.file_type = None
        
        # Kısıtlı mod kontrolü
        if RestrictedMode.ACTIVE:
            self.restricted_mode_label.config(
                text="⚠️  KISITLI MOD: Maks. dosya boyutu 100MB",
                foreground=self.colors['warning']
            )
        
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
        
        # Gelişmiş ayarlar butonu
        self.advanced_btn = tk.Button(button_container, 
                                    text="⚙️ Gelişmiş",
                                    command=self.show_advanced_settings,
                                    bg=self.colors['dark'],
                                    fg='white',
                                    font=('Arial', 10),
                                    height=2)
        self.advanced_btn.pack(side=tk.LEFT, padx=(10, 0), fill=tk.X, expand=False)
    
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
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=10, font=('Consolas', 9))
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # Log temizleme butonu
        clear_btn = tk.Button(log_frame, text="🗑️ Geçmişi Temizle", 
                            command=self.clear_log,
                            font=('Arial', 8),
                            bg=self.colors['light'])
        clear_btn.pack(anchor='se', pady=(5, 0))
    
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
            
            # Kısıtlı modda dosya boyutu kontrolü
            if RestrictedMode.ACTIVE and file_size > 100 * 1024 * 1024:
                file_info += f"\n🚨 KISITLI MOD: Dosya boyutu 100MB'ı aşıyor!"
                self.encrypt_btn.config(state='disabled', bg='gray')
            else:
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
        
        # Dosya boyutu kontrolü
        file_size = os.path.getsize(self.current_file)
        if RestrictedMode.ACTIVE and file_size > 100 * 1024 * 1024:
            messagebox.showerror("Hata", "Kısıtlı modda maksimum dosya boyutu 100MB'dır!")
            return
        
        password = self.ask_password("Şifreleme için şifre girin:")
        if not password: 
            return
        
        # Çıktı dosyasını aynı dizinde .enc uzantısıyla oluştur
        output_file = self.current_file + '.enc'
        self.run_operation('encrypt', self.current_file, output_file, password)
    
    def quick_decrypt(self):
        if not self.current_file or self.file_type != 'encrypted':
            messagebox.showerror("Hata", "Lütfen şifresi çözülecek bir .enc dosyası seçin")
            return
        
        password = self.ask_password("Şifre çözme için şifre girin:")
        if not password: 
            return
        
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
            except RootAccessError as e:
                error_msg = f"❌ Root erişim hatası: {str(e)}"
                self.log(error_msg)
                self.status_var.set("Root erişim hatası!")
                messagebox.showerror("Root Erişim Hatası", 
                                   "❌ Root erişiminde bu işlem yapılamaz!\n\n"
                                   "Lütfen normal kullanıcı ile çalıştırın.")
            except FileSizeError as e:
                error_msg = f"❌ Dosya boyutu hatası: {str(e)}"
                self.log(error_msg)
                self.status_var.set("Dosya boyutu hatası!")
                messagebox.showerror("Dosya Boyutu Hatası", 
                                   f"❌ Dosya boyutu sınırı aşıldı!\n\n{str(e)}")
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
        mb_current = current / (1024 * 1024)
        mb_total = total / (1024 * 1024)
        self.status_var.set(f"İşleniyor: {mb_current:.1f}/{mb_total:.1f} MB (%{percent:.1f})")
    
    def log(self, message):
        timestamp = time.strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
        self.root.update_idletasks()
    
    def clear_log(self):
        self.log_text.delete(1.0, tk.END)
        self.log("🗑️ Günlük temizlendi")
    
    def show_advanced_settings(self):
        """Gelişmiş ayarlar penceresi"""
        adv_window = tk.Toplevel(self.root)
        adv_window.title("Gelişmiş Ayarlar - Pass-Edip v4.0")
        adv_window.geometry("500x400")
        adv_window.resizable(False, False)
        
        # Pencereyi ortala
        adv_window.transient(self.root)
        adv_window.grab_set()
        
        ttk.Label(adv_window, text="⚙️ Gelişmiş Ayarlar", font=('Arial', 16, 'bold')).pack(pady=10)
        
        # Güvenlik bilgileri
        sec_frame = ttk.LabelFrame(adv_window, text="Güvenlik Durumu", padding="10")
        sec_frame.pack(fill=tk.X, padx=20, pady=10)
        
        detector = RootDetector()
        is_root = detector.is_root()
        is_sudo = detector.is_sudo()
        
        ttk.Label(sec_frame, text=f"Root Erişimi: {'✅ VAR' if is_root else '❌ YOK'}").pack(anchor='w')
        ttk.Label(sec_frame, text=f"Sudo: {'✅ VAR' if is_sudo else '❌ YOK'}").pack(anchor='w')
        ttk.Label(sec_frame, text=f"Kısıtlı Mod: {'✅ AKTİF' if RestrictedMode.ACTIVE else '❌ KAPALI'}").pack(anchor='w')
        
        # Ayarlar
        settings_frame = ttk.LabelFrame(adv_window, text="Ayarlar", padding="10")
        settings_frame.pack(fill=tk.X, padx=20, pady=10)
        
        # Otomatik temizlik
        self.auto_clean_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(settings_frame, text="İşlem sonrası otomatik bellek temizliği", 
                       variable=self.auto_clean_var).pack(anchor='w', pady=5)
        
        # Detaylı log
        self.detailed_log_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(settings_frame, text="Detaylı güvenlik log kaydı", 
                       variable=self.detailed_log_var).pack(anchor='w', pady=5)
        
        # Butonlar
        btn_frame = ttk.Frame(adv_window)
        btn_frame.pack(pady=20)
        
        ttk.Button(btn_frame, text="Güvenlik Raporu", 
                  command=self.show_security_details).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(btn_frame, text="Log Dosyasını Aç", 
                  command=self.open_log_file).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(btn_frame, text="Kapat", 
                  command=adv_window.destroy).pack(side=tk.LEFT, padx=5)
    
    def open_log_file(self):
        """Log dosyasını aç"""
        try:
            logger = SecurityLogger()
            log_file = logger.log_file
            
            if os.path.exists(log_file):
                if platform.system() == "Windows":
                    os.startfile(log_file)
                elif platform.system() == "Darwin":
                    subprocess.run(["open", log_file])
                else:
                    subprocess.run(["xdg-open", log_file])
            else:
                messagebox.showinfo("Bilgi", "Log dosyası henüz oluşturulmamış.")
        except Exception as e:
            messagebox.showerror("Hata", f"Log dosyası açılamadı: {str(e)}")
    
    def emergency_cleanup(self):
        """Acil durum temizliği"""
        self.log("🛡️  Acil bellek temizliği yapılıyor...")
        gc.collect()
        
        # Global değişkenleri temizle
        self.current_file = None
        self.file_type = None
        
        if hasattr(self, 'security_status'):
            self.security_status = {}
        
        self.log("✅ Bellek temizliği tamamlandı")

# ==============================
# UYGULAMA BAŞLATMA
# ==============================
def main():
    """Ana program akışı"""
    
    # 1. Platform kontrolü
    print(f"🔍 Pass-Edip v4.0 - {platform.system()} ({platform.release()})")
    print(f"🔍 Python {sys.version}")
    
    # 2. Acil çıkış temizliği
    def exit_cleanup():
        print("🛡️  Program sonlandırılıyor...")
        gc.collect()
        RestrictedMode.restore_restrictions()
    
    atexit.register(exit_cleanup)
    
    # 3. Güvenlik kontrolü
    try:
        security_status = enforce_security_policy()
        print(f"✅ Güvenlik kontrolü tamam: {security_status['score']}/100")
    except Exception as e:
        print(f"⚠️  Güvenlik kontrol hatası: {e}")
        security_status = {"is_secure": True, "score": 100, "level": "BİLİNMİYOR"}
    
    # 4. GUI kontrolü
    if not GUI_AVAILABLE:
        print("❌ GUI kütüphaneleri yüklenemedi. Lütfen tkinter kurulu olduğundan emin olun.")
        print("📦 Kurulum: pip install tkinter (veya sistem paket yöneticisi)")
        return 1
    
    # 5. GUI'yi başlat
    try:
        root = tk.Tk()
        
        # macOS özellikleri
        if platform.system() == 'Darwin':
            # Pencere stilini ayarla
            try:
                root.tk.call('tk', 'scaling', 1.5)  # Retina display desteği
            except:
                pass
            
            # macOS spesifik ayarlar
            root.configure(menu=tk.Menu(root))  # Menü bar için
        
        # Uygulamayı oluştur
        app = ModernPassEdipGUI(root, security_status)
        
        # Pencereyi ekranın ortasında aç
        root.update_idletasks()
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        window_width = root.winfo_reqwidth()
        window_height = root.winfo_reqheight()
        
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2
        
        root.geometry(f"+{x}+{y}")
        root.deiconify()  # Pencereyi göster
        
        # Başlangıç mesajı
        app.log(f"🚀 Pass-Edip v4.0 başlatıldı")
        app.log(f"📋 Platform: {platform.platform()}")
        app.log(f"🛡️  Güvenlik seviyesi: {security_status['level']} ({security_status['score']}/100)")
        
        if RootDetector.is_root():
            app.log("⚠️  ROOT ERİŞİMİ AKTİF - Kısıtlı modda çalışılıyor")
        
        root.mainloop()
        return 0
        
    except Exception as e:
        print(f"❌ GUI başlatma hatası: {e}")
        import traceback
        traceback.print_exc()
        return 1

# ==============================
# PROGRAM GİRİŞ NOKTASI
# ==============================
if __name__ == "__main__":
    # Hata yakalama
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\n⚠️  Program kullanıcı tarafından durduruldu.")
        sys.exit(130)
    except Exception as e:
        print(f"\n\n❌ Beklenmeyen hata: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)