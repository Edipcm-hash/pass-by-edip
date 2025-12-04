# -*- coding: utf-8 -*-
"""
Pass-Edip v7.2 "Sentinel Pro Elite" - Enhanced Security Edition
Tam Entegre Sürüm: Şifreleme + Şifre Üretici + GUI + Güvenlik Tarama
"""

import os
import sys
import struct
import secrets
import hashlib
import time
import threading
import platform
import atexit
import gc
import json
import hmac
import math
import random
import string
import base64
import ctypes
import mmap
import functools
import subprocess
import warnings
from typing import Optional, Tuple, List, Dict, Any, Union, Callable
from enum import IntEnum
from datetime import datetime
from dataclasses import dataclass, field
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.hashes import SHA256, SHA512, SHA3_256, SHA3_512
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import constant_time

# GUI kontrolü
try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, scrolledtext, simpledialog
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False

# ==============================
# GÜVENLİK TARAMA SİSTEMİ (V4.0'dan)
# ==============================
class AdvancedRootDetector:
    """Çoklu platformda root/admin tespiti"""
    
    @staticmethod
    def is_root() -> bool:
        system = platform.system()
        if system in ["Linux", "Darwin"]:
            return os.geteuid() == 0
        elif system == "Windows":
            try:
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except:
                try:
                    subprocess.run(["net", "session"], capture_output=True, timeout=2)
                    return True
                except:
                    return False
        return False
    
    @staticmethod
    def check_debuggers() -> bool:
        try:
            if platform.system() in ["Linux", "Darwin"]:
                with open("/proc/self/status", "r") as f:
                    for line in f:
                        if line.startswith("TracerPid:"):
                            return int(line.split(":")[1].strip()) != 0
        except:
            pass
        
        debuggers = ["gdb", "strace", "lldb", "radare2", "ida", "ollydbg"]
        try:
            if platform.system() in ["Linux", "Darwin"]:
                ps_output = subprocess.run(["ps", "aux"], capture_output=True, text=True, timeout=2).stdout.lower()
                return any(dbg in ps_output for dbg in debuggers)
        except:
            pass
        
        return False

class SecurityEnvironmentScanner:
    """Çalışma ortamı güvenlik değerlendirmesi"""
    
    @staticmethod
    def get_security_score() -> Dict[str, Any]:
        score = 100
        warnings = []
        critical = []
        
        detector = AdvancedRootDetector()
        
        if detector.is_root():
            score -= 50
            critical.append("Root/admin yetkileriyle çalışıyor!")
        
        if detector.check_debuggers():
            score -= 40
            critical.append("Debugger tespit edildi!")
        
        # Bytecode kontrolü
        if sys.dont_write_bytecode:
            score += 10
        
        return {
            "score": max(0, score),
            "level": SecurityEnvironmentScanner._get_security_level(score),
            "warnings": warnings,
            "critical": critical,
            "is_secure": score >= 70,
            "timestamp": datetime.now().isoformat(),
            "platform": platform.platform(),
            "python_version": sys.version.split()[0]
        }
    
    @staticmethod
    def _get_security_level(score: int) -> str:
        if score >= 90: return "ÇOK GÜVENLİ"
        elif score >= 70: return "GÜVENLİ"
        elif score >= 50: return "ORTA RİSK"
        elif score >= 30: return "YÜKSEK RİSK"
        else: return "KRİTİK RİSK"

class RestrictedSecurityMode:
    """Kısıtlı güvenlik modu"""
    
    ACTIVE = False
    
    @classmethod
    def evaluate_and_activate(cls, security_status: Dict[str, Any]) -> bool:
        if security_status['score'] < 70:
            if GUI_AVAILABLE:
                try:
                    root = tk.Tk()
                    root.withdraw()
                    response = messagebox.askyesno(
                        "Güvenlik Uyarısı",
                        f"Güvenlik Skoru: {security_status['score']}/100\n\n" +
                        "Kısıtlı modda devam etmek ister misiniz?\n" +
                        "(Dosya boyutu 100MB ile sınırlı)",
                        icon='warning'
                    )
                    root.destroy()
                    if response:
                        cls.ACTIVE = True
                        return True
                except:
                    pass
            else:
                print(f"⚠️  Düşük güvenlik skoru: {security_status['score']}/100")
                print("🔒 Kısıtlı mod otomatik aktif edildi")
                cls.ACTIVE = True
                return True
        return False

# ==============================
# HATA SINIFLARI
# ==============================
class SecurityError(Exception): pass
class EncryptionError(Exception): pass
class PasswordError(Exception): pass
class FileSizeError(Exception): pass

# ==============================
# GÜVENLİK SEVİYELERİ (V5.0'dan)
# ==============================
class SecurityLevel(IntEnum):
    BASIC = 1
    COMMERCIAL = 2
    GOVERNMENT = 3
    FORTRESS = 4

@dataclass
class SecurityPreset:
    """Güvenlik ön ayarları"""
    name: str
    description: str
    key_size: int
    kdf_iterations: int
    chunk_size: int
    max_file_size: int
    password_min_length: int
    password_entropy_min: int
    require_keyfile: bool = False
    enable_compression: bool = False
    enable_integrity: bool = True
    anti_forensics: bool = False

# Güvenlik preset'leri (kısıtlı mod düzenlemeli)
SECURITY_PRESETS = {
    SecurityLevel.BASIC: SecurityPreset(
        name="Temel",
        description="Kişisel dosyalar için",
        key_size=32,
        kdf_iterations=2**14,
        chunk_size=1 * 1024 * 1024,
        max_file_size=1 * 1024**3,
        password_min_length=8,
        password_entropy_min=40,
        enable_compression=True
    ),
    SecurityLevel.COMMERCIAL: SecurityPreset(
        name="Profesyonel",
        description="İş belgeleri için",
        key_size=48,
        kdf_iterations=2**16,
        chunk_size=2 * 1024 * 1024,
        max_file_size=10 * 1024**3,
        password_min_length=12,
        password_entropy_min=60,
        enable_integrity=True
    ),
    SecurityLevel.GOVERNMENT: SecurityPreset(
        name="Askeri Seviye",
        description="Gizli belgeler için",
        key_size=64,
        kdf_iterations=2**18,
        chunk_size=4 * 1024 * 1024,
        max_file_size=100 * 1024**3,
        password_min_length=16,
        password_entropy_min=80,
        require_keyfile=True,
        anti_forensics=True
    ),
    SecurityLevel.FORTRESS: SecurityPreset(
        name="KALE MODU",
        description="Maximum güvenlik",
        key_size=96,
        kdf_iterations=2**20,
        chunk_size=8 * 1024 * 1024,
        max_file_size=1 * 1024**4,
        password_min_length=24,
        password_entropy_min=120,
        require_keyfile=True,
        anti_forensics=True
    )
}

# ==============================
# GÜVENLİ ŞİFRE ÜRETİCİ (V5.0'dan - Tam)
# ==============================
class SecurePasswordGenerator:
    """Güvenli parola üretici"""
    
    CHARSETS = {
        'lower': string.ascii_lowercase,
        'upper': string.ascii_uppercase,
        'digits': string.digits,
        'symbols': "!@#$%^&*()_+-=[]{}|;:,.<>?/",
        'extended': "~`\"'\\"
    }
    
    @staticmethod
    def generate_password(security_level: SecurityLevel, include_words: bool = False) -> Tuple[str, Dict[str, Any]]:
        preset = SECURITY_PRESETS[security_level]
        
        if security_level == SecurityLevel.BASIC:
            length = random.randint(12, 16)
            charset_keys = ['lower', 'upper', 'digits']
        elif security_level == SecurityLevel.COMMERCIAL:
            length = random.randint(16, 20)
            charset_keys = ['lower', 'upper', 'digits', 'symbols']
        elif security_level == SecurityLevel.GOVERNMENT:
            length = random.randint(20, 24)
            charset_keys = ['lower', 'upper', 'digits', 'symbols', 'extended']
        else:
            length = random.randint(24, 32)
            charset_keys = ['lower', 'upper', 'digits', 'symbols', 'extended']
        
        if include_words and security_level in [SecurityLevel.BASIC, SecurityLevel.COMMERCIAL]:
            password = SecurePasswordGenerator._generate_memorable_password(length)
        else:
            password = SecurePasswordGenerator._generate_random_password(length, charset_keys)
        
        analysis = SecurePasswordGenerator.analyze_password(password)
        
        if analysis['entropy_bits'] < preset.password_entropy_min:
            return SecurePasswordGenerator.generate_password(security_level, include_words=False)
        
        return password, analysis
    
    @staticmethod
    def _generate_random_password(length: int, charset_keys: List[str]) -> str:
        all_chars = ''
        for key in charset_keys:
            all_chars += SecurePasswordGenerator.CHARSETS[key]
        
        password_chars = []
        for key in charset_keys:
            password_chars.append(secrets.choice(SecurePasswordGenerator.CHARSETS[key]))
        
        remaining = length - len(password_chars)
        for _ in range(remaining):
            password_chars.append(secrets.choice(all_chars))
        
        secrets.SystemRandom().shuffle(password_chars)
        return ''.join(password_chars)
    
    @staticmethod
    def _generate_memorable_password(length: int) -> str:
        words = ['kale', 'güneş', 'ayna', 'deniz', 'orman', 'kitap', 'kalem',
                'bilgisayar', 'şifre', 'güvenlik', 'kod', 'program', 'veri']
        
        password_parts = []
        total_len = 0
        
        while total_len < length:
            word = secrets.choice(words)
            if random.random() > 0.5:
                word = word.upper()
            elif random.random() > 0.3:
                word = word.capitalize()
            
            password_parts.append(word)
            total_len += len(word)
            
            if random.random() > 0.7 and total_len < length - 2:
                symbol = secrets.choice(SecurePasswordGenerator.CHARSETS['symbols'])
                password_parts.append(symbol)
                total_len += 1
        
        password = ''.join(password_parts)
        if len(password) > length:
            password = password[:length]
        
        return password
    
    @staticmethod
    def analyze_password(password: str) -> Dict[str, Any]:
        analysis = {
            'length': len(password),
            'has_lower': any(c.islower() for c in password),
            'has_upper': any(c.isupper() for c in password),
            'has_digit': any(c.isdigit() for c in password),
            'has_symbol': any(c in SecurePasswordGenerator.CHARSETS['symbols'] for c in password),
            'has_extended': any(c in SecurePasswordGenerator.CHARSETS['extended'] for c in password),
            'character_sets': 0,
            'entropy_bits': 0.0,
            'strength': 'çok_zayıf'
        }
        
        analysis['character_sets'] = sum([
            analysis['has_lower'],
            analysis['has_upper'], 
            analysis['has_digit'],
            analysis['has_symbol'],
            analysis['has_extended']
        ])
        
        charset_size = 0
        if analysis['has_lower']: charset_size += 26
        if analysis['has_upper']: charset_size += 26
        if analysis['has_digit']: charset_size += 10
        if analysis['has_symbol']: charset_size += 32
        if analysis['has_extended']: charset_size += 7
        
        if charset_size > 0:
            analysis['entropy_bits'] = len(password) * math.log2(charset_size)
        
        entropy = analysis['entropy_bits']
        if entropy >= 128:
            analysis['strength'] = 'mükemmel'
        elif entropy >= 100:
            analysis['strength'] = 'çok_güçlü'
        elif entropy >= 80:
            analysis['strength'] = 'güçlü'
        elif entropy >= 60:
            analysis['strength'] = 'orta'
        elif entropy >= 40:
            analysis['strength'] = 'zayıf'
        else:
            analysis['strength'] = 'çok_zayıf'
        
        return analysis
    
    @staticmethod
    def save_password_to_desktop(password: str, filename: str = None, metadata: Dict[str, Any] = None) -> str:
        try:
            if platform.system() == "Windows":
                desktop = os.path.join(os.path.expanduser("~"), "Desktop")
            else:
                desktop = os.path.join(os.path.expanduser("~"), "Desktop")
                if not os.path.exists(desktop):
                    desktop = os.path.expanduser("~")
            
            if not filename:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"PassEdip_Password_{timestamp}.txt"
            
            filepath = os.path.join(desktop, filename)
            
            content = f"""🔐 Pass-Edip v7.2 - Güvenli Parola Kaydı
{'='*50}

📅 Oluşturulma: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
🔒 Parola: {password}

{'='*50}

📋 PAROLA BİLGİLERİ:
• Uzunluk: {len(password)} karakter
• Entropi: {SecurePasswordGenerator.analyze_password(password)['entropy_bits']:.1f} bit
• Güç: {SecurePasswordGenerator.analyze_password(password)['strength']}

{'='*50}

⚠️  GÜVENLİK UYARILARI:
1. Bu dosyayı güvenli bir yerde saklayın
2. Parolayı kimseyle paylaşmayın
3. Mümkünse bu dosyayı şifreleyin
4. İşiniz bitince bu dosyayı güvenli şekilde silin

{'='*50}

📝 Ek Bilgiler:
"""
            
            if metadata:
                for key, value in metadata.items():
                    content += f"• {key}: {value}\n"
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            
            if platform.system() in ["Linux", "Darwin"]:
                os.chmod(filepath, 0o600)
            
            return filepath
            
        except Exception as e:
            raise PasswordError(f"Parola kaydedilemedi: {e}")

# ==============================
# GÜVENLİ BELLEK YÖNETİCİSİ
# ==============================
class SecureMemoryManager:
    def __init__(self):
        self._allocations = []
        atexit.register(self._cleanup_all)
    
    def allocate(self, size: int, description: str = "") -> bytearray:
        try:
            data = bytearray(size)
            self._allocations.append({
                'data': data,
                'size': size,
                'description': description
            })
            return data
        except Exception as e:
            print(f"⚠️  Bellek tahsisi başarısız: {e}")
            return bytearray(size)
    
    def wipe(self, data: bytearray, method: str = "DOD3"):
        if not data:
            return
        
        if method == "ZERO":
            for i in range(len(data)):
                data[i] = 0
        elif method == "DOD3":
            for i in range(len(data)):
                data[i] = 0
            for i in range(len(data)):
                data[i] = 0xFF
            for i in range(len(data)):
                data[i] = secrets.randbits(8)
            for i in range(len(data)):
                data[i] = 0
        elif method == "RANDOM":
            for i in range(len(data)):
                data[i] = secrets.randbits(8)
        
        for i, alloc in enumerate(self._allocations):
            if alloc['data'] is data:
                self._allocations.pop(i)
                break
    
    def _cleanup_all(self):
        print("🔒 Bellek temizleniyor...")
        for alloc in self._allocations:
            try:
                self.wipe(alloc['data'], "DOD3")
            except:
                pass
        self._allocations.clear()
        gc.collect()

# ==============================
# ANA ŞİFRELEME MOTORU (V5.0'dan - Tam)
# ==============================
class SentinelEncryptionEngine:
    """Düzeltilmiş ve test edilmiş şifreleme motoru"""
    
    VERSION = 7
    MAGIC = b"SEN7"
    HEADER_SIZE = 512
    
    def __init__(self, security_level: SecurityLevel = SecurityLevel.COMMERCIAL):
        self.security_level = security_level
        self.preset = self._get_preset_with_restrictions(security_level)
        self.memory_manager = SecureMemoryManager()
        
        print(f"✅ Motor başlatıldı: {self.preset.name}")
    
    def _get_preset_with_restrictions(self, security_level: SecurityLevel) -> SecurityPreset:
        """Kısıtlı modda preset ayarlarını düzenle"""
        preset = SECURITY_PRESETS[security_level]
        
        if RestrictedSecurityMode.ACTIVE:
            # Kısıtlı modda dosya boyutunu sınırla
            max_file_size = min(preset.max_file_size, 100 * 1024 * 1024)  # 100MB
            chunk_size = min(preset.chunk_size, 512 * 1024)  # 512KB
            
            return SecurityPreset(
                name=f"{preset.name} (Kısıtlı)",
                description=f"{preset.description} [Kısıtlı Mod]",
                key_size=preset.key_size,
                kdf_iterations=preset.kdf_iterations,
                chunk_size=chunk_size,
                max_file_size=max_file_size,
                password_min_length=preset.password_min_length,
                password_entropy_min=preset.password_entropy_min,
                require_keyfile=preset.require_keyfile,
                enable_compression=preset.enable_compression,
                enable_integrity=preset.enable_integrity,
                anti_forensics=preset.anti_forensics
            )
        
        return preset
    
    def check_password_policy(self, password: str) -> Tuple[bool, Dict[str, Any]]:
        if not password:
            return False, {'error': 'Parola boş olamaz'}
        
        analysis = SecurePasswordGenerator.analyze_password(password)
        
        checks_passed = []
        checks_failed = []
        
        if len(password) >= self.preset.password_min_length:
            checks_passed.append(f"Uzunluk ≥ {self.preset.password_min_length}")
        else:
            checks_failed.append(f"Minimum uzunluk {self.preset.password_min_length}")
        
        if analysis['entropy_bits'] >= self.preset.password_entropy_min:
            checks_passed.append(f"Entropi ≥ {self.preset.password_entropy_min} bit")
        else:
            checks_failed.append(f"Minimum entropi {self.preset.password_entropy_min} bit")
        
        if analysis['character_sets'] >= 3:
            checks_passed.append(f"{analysis['character_sets']} karakter seti")
        else:
            checks_failed.append(f"En az 3 karakter seti gerekli")
        
        is_valid = len(checks_failed) == 0
        
        result = {
            'is_valid': is_valid,
            'checks_passed': checks_passed,
            'checks_failed': checks_failed,
            'analysis': analysis
        }
        
        return is_valid, result
    
    def encrypt_file(self, input_path: str, output_path: str, password: str,
                    keyfile_path: Optional[str] = None,
                    progress_callback: Optional[Callable[[int, int, str], None]] = None) -> Dict[str, Any]:
        
        if not os.path.exists(input_path):
            raise FileNotFoundError(f"Dosya bulunamadı: {input_path}")
        
        file_size = os.path.getsize(input_path)
        if file_size == 0:
            raise ValueError("Boş dosya şifrelenemez")
        
        if file_size > self.preset.max_file_size:
            raise FileSizeError(f"Dosya çok büyük: {file_size} > {self.preset.max_file_size}")
        
        is_valid, policy_result = self.check_password_policy(password)
        if not is_valid and self.security_level >= SecurityLevel.GOVERNMENT:
            raise PasswordError(f"Parola yetersiz: {policy_result['checks_failed']}")
        
        if progress_callback:
            progress_callback(0, 100, "Başlatılıyor...")
        
        key_material = password.encode('utf-8')
        
        if keyfile_path and os.path.exists(keyfile_path):
            try:
                with open(keyfile_path, 'rb') as f:
                    keyfile_data = f.read()
                    key_material += hashlib.sha256(keyfile_data).digest()
            except Exception as e:
                print(f"⚠️  Keyfile okunamadı: {e}")
        
        salt = secrets.token_bytes(32)
        
        if progress_callback:
            progress_callback(5, 100, "Anahtar türetiliyor...")
        
        derived_key = self._derive_key(key_material, salt)
        master_key = secrets.token_bytes(self.preset.key_size)
        encrypted_master_key = self._encrypt_key(master_key, derived_key)
        header = self._create_header(salt, encrypted_master_key, input_path, file_size)
        
        try:
            with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
                fout.write(header)
                
                chunk_index = 0
                total_read = 0
                
                while True:
                    if progress_callback:
                        percent = int((total_read / file_size) * 90) + 5
                        progress_callback(percent, 100, f"Şifreleniyor... {chunk_index}")
                    
                    chunk = fin.read(self.preset.chunk_size)
                    if not chunk:
                        break
                    
                    encrypted_chunk, nonce, tag = self._encrypt_chunk(
                        chunk, master_key, chunk_index)
                    
                    chunk_header = struct.pack('<I', len(encrypted_chunk))
                    fout.write(chunk_header)
                    fout.write(nonce)
                    fout.write(tag)
                    fout.write(encrypted_chunk)
                    
                    total_read += len(chunk)
                    chunk_index += 1
                
                print(f"✅ Şifreleme tamam: {chunk_index} chunk")
            
            metadata = {
                'original_file': input_path,
                'encrypted_file': output_path,
                'original_size': file_size,
                'encrypted_size': os.path.getsize(output_path),
                'chunks': chunk_index,
                'security_level': self.preset.name,
                'timestamp': datetime.now().isoformat(),
                'password_strength': policy_result['analysis']['strength']
            }
            
            self._secure_cleanup(master_key, derived_key, key_material)
            
            if progress_callback:
                progress_callback(100, 100, "Şifreleme tamamlandı")
            
            return metadata
            
        except Exception as e:
            self._secure_cleanup(master_key, derived_key, key_material)
            
            if os.path.exists(output_path):
                try:
                    os.remove(output_path)
                except:
                    pass
            
            raise EncryptionError(f"Şifreleme başarısız: {e}")
    
    def decrypt_file(self, input_path: str, output_path: str, password: str,
                    keyfile_path: Optional[str] = None,
                    progress_callback: Optional[Callable[[int, int, str], None]] = None) -> Dict[str, Any]:
        
        if not os.path.exists(input_path):
            raise FileNotFoundError(f"Dosya bulunamadı: {input_path}")
        
        file_size = os.path.getsize(input_path)
        if file_size < self.HEADER_SIZE:
            raise ValueError("Geçersiz dosya boyutu")
        
        if progress_callback:
            progress_callback(0, 100, "Başlatılıyor...")
        
        try:
            with open(input_path, 'rb') as fin:
                magic = fin.read(4)
                if magic != self.MAGIC:
                    raise ValueError("Geçersiz dosya formatı")
                
                fin.seek(0)
                header_data = fin.read(self.HEADER_SIZE)
                if len(header_data) < self.HEADER_SIZE:
                    raise ValueError("Header okunamadı")
                
                salt = header_data[32:64]
                key_length = struct.unpack('<I', header_data[64:68])[0]
                
                if 68 + key_length > len(header_data):
                    raise ValueError("Header bozuk")
                
                encrypted_master_key = header_data[68:68+key_length]
                key_material = password.encode('utf-8')
                
                if keyfile_path and os.path.exists(keyfile_path):
                    try:
                        with open(keyfile_path, 'rb') as f:
                            keyfile_data = f.read()
                            key_material += hashlib.sha256(keyfile_data).digest()
                    except Exception as e:
                        print(f"⚠️  Keyfile okunamadı: {e}")
                
                if progress_callback:
                    progress_callback(10, 100, "Anahtar türetiliyor...")
                
                derived_key = self._derive_key(key_material, salt)
                master_key = self._decrypt_key(encrypted_master_key, derived_key)
                
                with open(output_path, 'wb') as fout:
                    fin.seek(self.HEADER_SIZE)
                    
                    chunk_index = 0
                    total_written = 0
                    
                    while True:
                        chunk_header = fin.read(4)
                        if not chunk_header or len(chunk_header) < 4:
                            break
                        
                        chunk_size = struct.unpack('<I', chunk_header)[0]
                        nonce = fin.read(12)
                        tag = fin.read(16)
                        ciphertext = fin.read(chunk_size)
                        
                        if len(ciphertext) != chunk_size:
                            raise ValueError(f"Chunk {chunk_index} boyut uyuşmazlığı")
                        
                        try:
                            plaintext = self._decrypt_chunk(
                                ciphertext, nonce, tag, master_key, chunk_index)
                            
                            fout.write(plaintext)
                            total_written += len(plaintext)
                            
                        except InvalidTag as e:
                            raise SecurityError(f"Chunk {chunk_index} doğrulama başarısız: {e}")
                        
                        if progress_callback:
                            current_pos = fin.tell()
                            percent = 10 + int((current_pos / file_size) * 85)
                            progress_callback(percent, 100, f"Deşifre ediliyor... {chunk_index}")
                        
                        chunk_index += 1
                    
                    print(f"✅ Deşifreleme tamam: {chunk_index} chunk, {total_written} byte")
                
                metadata = {
                    'decrypted_file': output_path,
                    'bytes_written': total_written,
                    'chunks_processed': chunk_index,
                    'timestamp': datetime.now().isoformat()
                }
                
                self._secure_cleanup(master_key, derived_key, key_material)
                
                if progress_callback:
                    progress_callback(100, 100, "Deşifreleme tamamlandı")
                
                return metadata
                
        except Exception as e:
            if 'master_key' in locals():
                self.memory_manager.wipe(master_key)
            if 'derived_key' in locals():
                self.memory_manager.wipe(derived_key)
            
            if os.path.exists(output_path):
                try:
                    os.remove(output_path)
                except:
                    pass
            
            raise EncryptionError(f"Deşifreleme başarısız: {e}")
    
    def _derive_key(self, key_material: bytes, salt: bytes) -> bytearray:
        try:
            kdf = Scrypt(
                salt=salt,
                length=32,
                n=self.preset.kdf_iterations,
                r=8,
                p=1,
                backend=default_backend()
            )
            
            derived = kdf.derive(key_material)
            secure_key = self.memory_manager.allocate(32, "DERIVED_KEY")
            secure_key[:] = derived
            return secure_key
            
        except Exception as e:
            raise EncryptionError(f"Anahtar türetme başarısız: {e}")
    
    def _encrypt_key(self, key: bytes, enc_key: bytearray) -> bytes:
        try:
            aesgcm = AESGCM(bytes(enc_key[:32]))
            nonce = secrets.token_bytes(12)
            ciphertext = aesgcm.encrypt(nonce, key, b"")
            return nonce + ciphertext
        except Exception as e:
            raise EncryptionError(f"Anahtar şifreleme başarısız: {e}")
    
    def _decrypt_key(self, encrypted_key: bytes, dec_key: bytearray) -> bytearray:
        try:
            nonce = encrypted_key[:12]
            ciphertext = encrypted_key[12:]
            
            aesgcm = AESGCM(bytes(dec_key[:32]))
            plaintext = aesgcm.decrypt(nonce, ciphertext, b"")
            
            secure_key = self.memory_manager.allocate(len(plaintext), "MASTER_KEY")
            secure_key[:] = plaintext
            return secure_key
            
        except InvalidTag as e:
            raise SecurityError(f"Anahtar doğrulama başarısız: {e}")
        except Exception as e:
            raise EncryptionError(f"Anahtar deşifreleme başarısız: {e}")
    
    def _encrypt_chunk(self, chunk: bytes, key: bytearray, chunk_index: int) -> Tuple[bytes, bytes, bytes]:
        try:
            aesgcm = AESGCM(bytes(key[:32]))
            nonce = struct.pack('<Q', chunk_index)[:4] + secrets.token_bytes(8)
            ciphertext = aesgcm.encrypt(nonce, chunk, b"")
            tag = ciphertext[-16:]
            ciphertext = ciphertext[:-16]
            return ciphertext, nonce, tag
        except Exception as e:
            raise EncryptionError(f"Chunk şifreleme başarısız: {e}")
    
    def _decrypt_chunk(self, ciphertext: bytes, nonce: bytes, tag: bytes,
                      key: bytearray, chunk_index: int) -> bytes:
        try:
            aesgcm = AESGCM(bytes(key[:32]))
            full_ciphertext = ciphertext + tag
            plaintext = aesgcm.decrypt(nonce, full_ciphertext, b"")
            return plaintext
        except InvalidTag as e:
            raise SecurityError(f"Chunk {chunk_index} doğrulama başarısız: {e}")
        except Exception as e:
            raise EncryptionError(f"Chunk deşifreleme başarısız: {e}")
    
    def _create_header(self, salt: bytes, encrypted_master_key: bytes, 
                      filename: str, file_size: int) -> bytes:
        header = bytearray(self.HEADER_SIZE)
        header[0:4] = self.MAGIC
        header[4] = self.VERSION
        header[5] = self.security_level.value
        
        timestamp = int(time.time())
        header[6:14] = struct.pack('<Q', timestamp)
        header[14:22] = struct.pack('<Q', file_size)
        header[22:26] = struct.pack('<I', self.preset.chunk_size)
        header[26:30] = struct.pack('<I', self.preset.key_size)
        header[32:64] = salt
        
        key_len = len(encrypted_master_key)
        header[64:68] = struct.pack('<I', key_len)
        header[68:68+key_len] = encrypted_master_key
        
        offset = 68 + key_len
        name_bytes = os.path.basename(filename).encode('utf-8')
        name_len = len(name_bytes)
        if offset + name_len + 2 <= self.HEADER_SIZE - 32:
            header[offset:offset+2] = struct.pack('<H', name_len)
            offset += 2
            header[offset:offset+name_len] = name_bytes
            offset += name_len
        
        hmac_key = hashlib.sha256(salt).digest()
        h = hmac.new(hmac_key, header[:offset], hashlib.sha256)
        header_digest = h.digest()
        header[self.HEADER_SIZE-32:self.HEADER_SIZE] = header_digest
        
        return bytes(header)
    
    def _secure_cleanup(self, *data_items):
        for item in data_items:
            if isinstance(item, (bytes, bytearray)):
                if isinstance(item, bytearray):
                    self.memory_manager.wipe(item, "DOD3")
                else:
                    temp = bytearray(item)
                    self.memory_manager.wipe(temp, "DOD3")

# ==============================
# MODERN GUI (V5.0'dan - Tam)
# ==============================
class SentinelProGUI:
    """Tam entegre GUI"""
    
    def __init__(self, root, security_status: Dict[str, Any]):
        self.root = root
        self.security_status = security_status
        self.root.title("Pass-Edip v7.2 Sentinel Pro Elite")
        self.root.geometry("1000x750")
        self.root.minsize(900, 650)
        
        self.security_level = SecurityLevel.COMMERCIAL
        self.engine = SentinelEncryptionEngine(self.security_level)
        
        self.current_file = None
        self.keyfile_path = None
        self.is_processing = False
        
        self.colors = {
            'primary': '#2C3E50',
            'secondary': '#E74C3C',
            'success': '#27AE60',
            'warning': '#F39C12',
            'info': '#3498DB',
            'light': '#ECF0F1',
            'dark': '#2C3E50'
        }
        
        self.setup_ui()
        self.setup_bindings()
        atexit.register(self.cleanup)
    
    def setup_ui(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Güvenlik Dashboard
        self.create_security_dashboard(main_frame)
        
        # Üst bölüm
        self.create_top_section(main_frame)
        
        # Orta bölüm
        self.create_middle_section(main_frame)
        
        # Alt bölüm
        self.create_bottom_section(main_frame)
    
    def create_security_dashboard(self, parent):
        """Güvenlik durumu paneli"""
        score = self.security_status['score']
        level = self.security_status['level']
        
        if score >= 70:
            color = "#27AE60"
            emoji = "🟢"
        elif score >= 50:
            color = "#F39C12"
            emoji = "🟡"
        else:
            color = "#E74C3C"
            emoji = "🔴"
        
        dashboard_frame = ttk.LabelFrame(parent, text="🛡️ Güvenlik Durumu", padding="10")
        dashboard_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Skor göstergesi
        canvas = tk.Canvas(dashboard_frame, height=30, bg='white')
        canvas.pack(fill=tk.X, pady=5)
        
        bar_width = 300
        fill_width = (score / 100) * bar_width
        
        canvas.create_rectangle(10, 10, 10 + bar_width, 25, outline="#BDC3C7", width=2)
        canvas.create_rectangle(10, 10, 10 + fill_width, 25, fill=color, outline="")
        canvas.create_text(10 + bar_width + 20, 17, 
                          text=f"{emoji} {score}/100 - {level}",
                          font=('Arial', 11, 'bold'),
                          fill=color,
                          anchor='w')
        
        # Hızlı durum
        status_frame = ttk.Frame(dashboard_frame)
        status_frame.pack(fill=tk.X, pady=5)
        
        root_status = "✅ YOK" if not AdvancedRootDetector.is_root() else "❌ VAR"
        debugger_status = "✅ YOK" if not AdvancedRootDetector.check_debuggers() else "❌ VAR"
        
        ttk.Label(status_frame, text=f"Root: {root_status}", width=15).pack(side=tk.LEFT, padx=5)
        ttk.Label(status_frame, text=f"Debugger: {debugger_status}", width=15).pack(side=tk.LEFT, padx=5)
        
        if RestrictedSecurityMode.ACTIVE:
            restricted_label = tk.Label(dashboard_frame,
                                       text="🔒 KISITLI MOD AKTİF - Max: 100MB",
                                       font=('Arial', 10, 'bold'),
                                       fg="#E74C3C",
                                       bg="#FDEDEC",
                                       padx=10,
                                       pady=5)
            restricted_label.pack(fill=tk.X, pady=5)
    
    def create_top_section(self, parent):
        top_frame = ttk.Frame(parent)
        top_frame.pack(fill=tk.X, pady=(0, 10))
        
        title_label = tk.Label(top_frame, 
                              text="🔒 Pass-Edip v7.2 Sentinel Pro Elite",
                              font=('Arial', 20, 'bold'),
                              fg=self.colors['primary'])
        title_label.pack(side=tk.LEFT)
        
        level_frame = ttk.Frame(top_frame)
        level_frame.pack(side=tk.RIGHT)
        
        ttk.Label(level_frame, text="Güvenlik:", font=('Arial', 10)).pack(side=tk.LEFT, padx=(0, 5))
        
        self.level_var = tk.StringVar(value=SECURITY_PRESETS[self.security_level].name)
        level_combo = ttk.Combobox(level_frame, 
                                  textvariable=self.level_var,
                                  values=[preset.name for preset in SECURITY_PRESETS.values()],
                                  state="readonly",
                                  width=15)
        level_combo.pack(side=tk.LEFT)
        level_combo.bind('<<ComboboxSelected>>', self.on_security_level_changed)
    
    def create_middle_section(self, parent):
        middle_frame = ttk.Frame(parent)
        middle_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Sol panel - Dosya işlemleri
        left_panel = ttk.LabelFrame(middle_frame, text="📁 Dosya İşlemleri", padding="15")
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        # Dosya seçimi
        file_frame = ttk.Frame(left_panel)
        file_frame.pack(fill=tk.X, pady=(0, 15))
        
        self.file_button = tk.Button(file_frame,
                                   text="Dosya Seç",
                                   command=self.select_file,
                                   font=('Arial', 11),
                                   bg=self.colors['info'],
                                   fg='white',
                                   height=2)
        self.file_button.pack(fill=tk.X)
        
        self.file_label = tk.Label(left_panel,
                                  text="Henüz dosya seçilmedi",
                                  font=('Arial', 9),
                                  fg=self.colors['dark'],
                                  wraplength=300,
                                  justify=tk.LEFT)
        self.file_label.pack(fill=tk.X, pady=5)
        
        # Keyfile
        keyfile_frame = ttk.Frame(left_panel)
        keyfile_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(keyfile_frame,
                  text="Keyfile Seç",
                  command=self.select_keyfile,
                  width=12).pack(side=tk.LEFT, padx=(0, 5))
        
        self.keyfile_label = tk.Label(keyfile_frame,
                                     text="Keyfile yok",
                                     font=('Arial', 8),
                                     fg=self.colors['dark'])
        self.keyfile_label.pack(side=tk.LEFT)
        
        # İşlem butonları
        button_frame = ttk.Frame(left_panel)
        button_frame.pack(fill=tk.X, pady=10)
        
        self.encrypt_btn = tk.Button(button_frame,
                                    text="🔒 DOSYAYI ŞİFRELE",
                                    command=self.encrypt_action,
                                    font=('Arial', 11, 'bold'),
                                    bg=self.colors['success'],
                                    fg='white',
                                    height=2,
                                    state='disabled')
        self.encrypt_btn.pack(fill=tk.X, pady=(0, 5))
        
        self.decrypt_btn = tk.Button(button_frame,
                                    text="🔓 ŞİFREYİ ÇÖZ",
                                    command=self.decrypt_action,
                                    font=('Arial', 11, 'bold'),
                                    bg=self.colors['warning'],
                                    fg='white',
                                    height=2,
                                    state='disabled')
        self.decrypt_btn.pack(fill=tk.X)
        
        # Sağ panel - Şifre üretici
        right_panel = ttk.LabelFrame(middle_frame, text="🔐 Şifre Üretici", padding="15")
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        ttk.Label(right_panel, text="Güvenlik Seviyesi:", font=('Arial', 10)).pack(anchor=tk.W)
        
        self.pass_level_var = tk.IntVar(value=self.security_level.value)
        
        for level in SecurityLevel:
            rb = ttk.Radiobutton(right_panel,
                                text=SECURITY_PRESETS[level].name,
                                value=level.value,
                                variable=self.pass_level_var)
            rb.pack(anchor=tk.W, pady=2)
        
        self.memorable_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(right_panel,
                       text="Hatırlanabilir şifre üret",
                       variable=self.memorable_var).pack(anchor=tk.W, pady=10)
        
        ttk.Button(right_panel,
                  text="🎲 Şifre Üret",
                  command=self.generate_password).pack(fill=tk.X, pady=5)
        
        self.generated_pass_var = tk.StringVar()
        pass_entry = ttk.Entry(right_panel,
                              textvariable=self.generated_pass_var,
                              font=('Consolas', 10),
                              state='readonly')
        pass_entry.pack(fill=tk.X, pady=5)
        
        self.pass_info_label = tk.Label(right_panel,
                                       text="",
                                       font=('Arial', 9),
                                       fg=self.colors['dark'],
                                       justify=tk.LEFT,
                                       wraplength=250)
        self.pass_info_label.pack(fill=tk.X, pady=5)
        
        ttk.Button(right_panel,
                  text="💾 Masaüstüne Kaydet",
                  command=self.save_password_to_desktop).pack(fill=tk.X, pady=5)
    
    def create_bottom_section(self, parent):
        bottom_frame = ttk.Frame(parent)
        bottom_frame.pack(fill=tk.BOTH, expand=False, pady=(10, 0))
        
        progress_frame = ttk.Frame(bottom_frame)
        progress_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(progress_frame,
                                           variable=self.progress_var,
                                           maximum=100)
        self.progress_bar.pack(fill=tk.X, side=tk.LEFT, expand=True)
        
        self.progress_label = tk.Label(progress_frame,
                                      text="%0",
                                      font=('Arial', 9),
                                      width=5)
        self.progress_label.pack(side=tk.RIGHT, padx=(5, 0))
        
        self.status_var = tk.StringVar(value="Hazır")
        status_label = tk.Label(bottom_frame,
                               textvariable=self.status_var,
                               font=('Arial', 10),
                               fg=self.colors['primary'])
        status_label.pack(fill=tk.X, pady=(0, 10))
        
        log_frame = ttk.LabelFrame(bottom_frame, text="📝 İşlem Logu", padding="10")
        log_frame.pack(fill=tk.BOTH, expand=True)
        
        self.log_text = scrolledtext.ScrolledText(log_frame,
                                                 height=8,
                                                 font=('Consolas', 9))
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        ttk.Button(log_frame,
                  text="Log'u Temizle",
                  command=self.clear_log,
                  width=15).pack(anchor=tk.SE, pady=(5, 0))
    
    def setup_bindings(self):
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def on_security_level_changed(self, event=None):
        level_name = self.level_var.get()
        for level, preset in SECURITY_PRESETS.items():
            if preset.name == level_name:
                self.security_level = level
                self.engine = SentinelEncryptionEngine(self.security_level)
                self.log_message(f"🛡️  Güvenlik seviyesi: {preset.name}")
                break
    
    def select_file(self):
        filename = filedialog.askopenfilename(
            title="Dosya seçin",
            filetypes=[("Tüm dosyalar", "*.*")]
        )
        
        if filename:
            self.current_file = filename
            basename = os.path.basename(filename)
            size = os.path.getsize(filename)
            size_mb = size / (1024 * 1024)
            
            # Kısıtlı modda dosya boyutu kontrolü
            if RestrictedSecurityMode.ACTIVE and size > 100 * 1024 * 1024:
                messagebox.showerror("Hata", "Kısıtlı modda maksimum dosya boyutu 100MB'dır!")
                return
            
            if filename.lower().endswith('.sen7'):
                self.file_type = 'encrypted'
                self.file_label.config(
                    text=f"🔓 Şifreli dosya: {basename}\nBoyut: {size_mb:.1f} MB",
                    fg=self.colors['warning']
                )
                self.encrypt_btn.config(state='disabled')
                self.decrypt_btn.config(state='normal')
            else:
                self.file_type = 'normal'
                self.file_label.config(
                    text=f"🔒 Normal dosya: {basename}\nBoyut: {size_mb:.1f} MB",
                    fg=self.colors['info']
                )
                self.encrypt_btn.config(state='normal')
                self.decrypt_btn.config(state='disabled')
            
            self.log_message(f"📁 Dosya seçildi: {basename} ({size_mb:.1f} MB)")
    
    def select_keyfile(self):
        filename = filedialog.askopenfilename(title="Keyfile seçin")
        if filename:
            self.keyfile_path = filename
            self.keyfile_label.config(text=os.path.basename(filename))
            self.log_message(f"🔑 Keyfile seçildi: {os.path.basename(filename)}")
    
    def encrypt_action(self):
        if not self.current_file or self.file_type != 'normal':
            messagebox.showerror("Hata", "Lütfen şifrelenecek bir dosya seçin")
            return
        
        if self.is_processing:
            messagebox.showwarning("Uyarı", "Zaten bir işlem devam ediyor")
            return
        
        choice = messagebox.askyesno("Parola",
                                    "Otomatik güçlü parola üretilsin mi?\n\n"
                                    "Evet: Güvenli parola üretilir\n"
                                    "Hayır: Kendi parolanızı girin")
        
        if choice:
            password, analysis = SecurePasswordGenerator.generate_password(
                self.security_level, include_words=False)
            
            pass_window = tk.Toplevel(self.root)
            pass_window.title("Üretilen Parola")
            pass_window.geometry("400x300")
            pass_window.resizable(False, False)
            pass_window.transient(self.root)
            pass_window.grab_set()
            
            tk.Label(pass_window, text="🔐 ÜRETİLEN PAROLA", 
                    font=('Arial', 14, 'bold')).pack(pady=10)
            
            tk.Label(pass_window, text=password, 
                    font=('Consolas', 16, 'bold'),
                    bg='black', fg='white',
                    padx=20, pady=10).pack(pady=10)
            
            tk.Label(pass_window, 
                    text=f"Uzunluk: {analysis['length']} | "
                         f"Güç: {analysis['strength']} | "
                         f"Entropi: {analysis['entropy_bits']:.1f} bit",
                    font=('Arial', 10)).pack(pady=5)
            
            def save_and_close():
                try:
                    filepath = SecurePasswordGenerator.save_password_to_desktop(
                        password, 
                        metadata={
                            'dosya': os.path.basename(self.current_file),
                            'güvenlik_seviyesi': SECURITY_PRESETS[self.security_level].name,
                            'tarih': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        }
                    )
                    self.log_message(f"💾 Parola kaydedildi: {os.path.basename(filepath)}")
                    messagebox.showinfo("Başarılı", f"Parola masaüstüne kaydedildi:\n{filepath}")
                except Exception as e:
                    messagebox.showerror("Hata", f"Parola kaydedilemedi: {e}")
                
                pass_window.destroy()
                self.start_encryption(password)
            
            tk.Button(pass_window, text="💾 Kaydet ve Devam Et",
                     command=save_and_close,
                     bg=self.colors['success'],
                     fg='white',
                     font=('Arial', 11)).pack(pady=20)
            
            tk.Button(pass_window, text="İptal",
                     command=pass_window.destroy).pack()
            
        else:
            password = simpledialog.askstring("Parola",
                                             "Şifreleme parolasını girin:",
                                             show='*')
            if password:
                self.start_encryption(password)
    
    def start_encryption(self, password: str):
        if not password:
            return
        
        output_file = self.current_file + '.sen7'
        counter = 1
        while os.path.exists(output_file):
            base, ext = os.path.splitext(self.current_file)
            output_file = f"{base}_{counter}.sen7"
            counter += 1
        
        self.is_processing = True
        self.disable_buttons()
        
        thread = threading.Thread(
            target=self._encrypt_thread,
            args=(self.current_file, output_file, password),
            daemon=True
        )
        thread.start()
    
    def _encrypt_thread(self, input_file, output_file, password):
        try:
            self.update_status("Şifreleme başlatılıyor...", 0)
            self.log_message(f"🔒 Şifreleme başlatıldı: {os.path.basename(input_file)}")
            
            def progress_callback(current, total, message):
                percent = (current / total * 100) if total > 0 else 0
                self.update_status(message, percent)
            
            metadata = self.engine.encrypt_file(
                input_file, output_file, password,
                self.keyfile_path, progress_callback
            )
            
            self.update_status("Şifreleme tamamlandı", 100)
            
            self.root.after(0, lambda: messagebox.showinfo(
                "Başarılı",
                f"✅ Dosya başarıyla şifrelendi!\n\n"
                f"Dosya: {os.path.basename(output_file)}\n"
                f"Boyut: {metadata['encrypted_size']:,} bayt\n"
                f"Parçalar: {metadata['chunks']}\n"
                f"Güvenlik: {metadata['security_level']}"
            ))
            
            self.log_message(f"✅ Şifreleme tamam: {os.path.basename(output_file)}")
            self.log_message(f"   Boyut: {metadata['encrypted_size']:,} bayt")
            self.log_message(f"   Parçalar: {metadata['chunks']}")
            
        except Exception as e:
            error_msg = str(e)
            self.log_message(f"❌ Şifreleme hatası: {error_msg}")
            self.update_status("Hata oluştu", 0)
            
            self.root.after(0, lambda: messagebox.showerror(
                "Hata",
                f"Şifreleme başarısız:\n\n{error_msg}"
            ))
        
        finally:
            self.is_processing = False
            self.root.after(0, self.enable_buttons)
    
    def decrypt_action(self):
        if not self.current_file or self.file_type != 'encrypted':
            messagebox.showerror("Hata", "Lütfen deşifre edilecek bir .sen7 dosyası seçin")
            return
        
        if self.is_processing:
            messagebox.showwarning("Uyarı", "Zaten bir işlem devam ediyor")
            return
        
        password = simpledialog.askstring("Parola",
                                         "Deşifreleme parolasını girin:",
                                         show='*')
        if not password:
            return
        
        base_name = os.path.basename(self.current_file)
        if base_name.endswith('.sen7'):
            output_name = base_name[:-5]
        else:
            output_name = f"decrypted_{base_name}"
        
        output_dir = os.path.dirname(self.current_file) or '.'
        output_file = os.path.join(output_dir, output_name)
        
        counter = 1
        while os.path.exists(output_file):
            name, ext = os.path.splitext(output_name)
            output_file = os.path.join(output_dir, f"{name}_{counter}{ext}")
            counter += 1
        
        self.is_processing = True
        self.disable_buttons()
        
        thread = threading.Thread(
            target=self._decrypt_thread,
            args=(self.current_file, output_file, password),
            daemon=True
        )
        thread.start()
    
    def _decrypt_thread(self, input_file, output_file, password):
        try:
            self.update_status("Deşifreleme başlatılıyor...", 0)
            self.log_message(f"🔓 Deşifreleme başlatıldı: {os.path.basename(input_file)}")
            
            def progress_callback(current, total, message):
                percent = (current / total * 100) if total > 0 else 0
                self.update_status(message, percent)
            
            metadata = self.engine.decrypt_file(
                input_file, output_file, password,
                self.keyfile_path, progress_callback
            )
            
            self.update_status("Deşifreleme tamamlandı", 100)
            
            self.root.after(0, lambda: messagebox.showinfo(
                "Başarılı",
                f"✅ Dosya başarıyla deşifre edildi!\n\n"
                f"Dosya: {os.path.basename(output_file)}\n"
                f"Boyut: {metadata['bytes_written']:,} bayt\n"
                f"Parçalar: {metadata['chunks_processed']}"
            ))
            
            self.log_message(f"✅ Deşifreleme tamam: {os.path.basename(output_file)}")
            self.log_message(f"   Boyut: {metadata['bytes_written']:,} bayt")
            
        except Exception as e:
            error_msg = str(e)
            self.log_message(f"❌ Deşifreleme hatası: {error_msg}")
            self.update_status("Hata oluştu", 0)
            
            self.root.after(0, lambda: messagebox.showerror(
                "Hata",
                f"Deşifreleme başarısız:\n\n{error_msg}"
            ))
        
        finally:
            self.is_processing = False
            self.root.after(0, self.enable_buttons)
    
    def generate_password(self):
        level_value = self.pass_level_var.get()
        level = SecurityLevel(level_value)
        memorable = self.memorable_var.get()
        
        try:
            password, analysis = SecurePasswordGenerator.generate_password(level, memorable)
            self.generated_pass_var.set(password)
            
            info_text = (f"Uzunluk: {analysis['length']} karakter\n"
                        f"Güç: {analysis['strength']}\n"
                        f"Entropi: {analysis['entropy_bits']:.1f} bit")
            
            self.pass_info_label.config(text=info_text, fg=self.colors['dark'])
            self.log_message(f"🔐 Parola üretildi: {analysis['strength']} seviye")
            
        except Exception as e:
            messagebox.showerror("Hata", f"Parola üretilemedi: {e}")
    
    def save_password_to_desktop(self):
        password = self.generated_pass_var.get()
        if not password:
            messagebox.showwarning("Uyarı", "Önce bir parola üretin")
            return
        
        try:
            filepath = SecurePasswordGenerator.save_password_to_desktop(
                password,
                metadata={
                    'güvenlik_seviyesi': SECURITY_PRESETS[SecurityLevel(self.pass_level_var.get())].name,
                    'hatırlanabilir': self.memorable_var.get(),
                    'tarih': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
            )
            
            messagebox.showinfo("Başarılı", f"Parola masaüstüne kaydedildi:\n{filepath}")
            self.log_message(f"💾 Parola kaydedildi: {os.path.basename(filepath)}")
            
        except Exception as e:
            messagebox.showerror("Hata", f"Parola kaydedilemedi: {e}")
    
    def update_status(self, message: str, percent: int):
        def _update():
            self.status_var.set(message)
            self.progress_var.set(percent)
            self.progress_label.config(text=f"%{percent}")
        self.root.after(0, _update)
    
    def log_message(self, message: str):
        def _log():
            timestamp = datetime.now().strftime("%H:%M:%S")
            self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
            self.log_text.see(tk.END)
        self.root.after(0, _log)
    
    def clear_log(self):
        self.log_text.delete(1.0, tk.END)
        self.log_message("🗑️ Log temizlendi")
    
    def disable_buttons(self):
        self.encrypt_btn.config(state='disabled')
        self.decrypt_btn.config(state='disabled')
        self.file_button.config(state='disabled')
    
    def enable_buttons(self):
        self.file_button.config(state='normal')
        if hasattr(self, 'file_type'):
            if self.file_type == 'normal':
                self.encrypt_btn.config(state='normal')
                self.decrypt_btn.config(state='disabled')
            elif self.file_type == 'encrypted':
                self.encrypt_btn.config(state='disabled')
                self.decrypt_btn.config(state='normal')
    
    def on_closing(self):
        if self.is_processing:
            if not messagebox.askyesno("Çıkış",
                                      "Bir işlem devam ediyor. Çıkmak istiyor musunuz?"):
                return
        
        self.cleanup()
        self.root.destroy()
    
    def cleanup(self):
        if hasattr(self, 'engine'):
            self.engine.memory_manager._cleanup_all()
        self.log_message("👋 Program kapatılıyor...")

# ==============================
# ANA PROGRAM
# ==============================
def main():
    print("""
    ╔══════════════════════════════════════════════════════════╗
    ║         Pass-Edip v7.2 "Sentinel Pro Elite"             ║
    ║       Tam Entegre: Şifreleme + Güvenlik + GUI           ║
    ╚══════════════════════════════════════════════════════════╝
    """)
    
    print(f"📋 Platform: {platform.system()} {platform.release()}")
    print(f"🐍 Python: {sys.version.split()[0]}")
    
    # Güvenlik taraması
    print("\n🔍 Güvenlik taraması yapılıyor...")
    security_status = SecurityEnvironmentScanner.get_security_score()
    
    print(f"   • Güvenlik Skoru: {security_status['score']}/100")
    print(f"   • Seviye: {security_status['level']}")
    
    if security_status['critical']:
        print(f"   • Kritik Riskler: {len(security_status['critical'])}")
        for crit in security_status['critical']:
            print(f"     - {crit}")
    
    # Kısıtlı mod kontrolü
    RestrictedSecurityMode.evaluate_and_activate(security_status)
    
    if RestrictedSecurityMode.ACTIVE:
        print("🔒 KISITLI MOD AKTİF: Maksimum dosya boyutu 100MB")
    
    # Kritik risk kontrolü
    if security_status['score'] < 30:
        print("\n🚨 KRİTİK GÜVENLİK RİSKİ!")
        response = input("Devam etmek istiyor musunuz? (e/h): ")
        if response.lower() != 'e':
            print("👋 Program kapatılıyor...")
            return
    
    # GUI kontrolü
    if not GUI_AVAILABLE:
        print("\n❌ GUI kütüphaneleri yüklenemedi!")
        print("📦 Kurulum komutları:")
        print("   Windows: pip install tk")
        print("   Linux: sudo apt-get install python3-tk")
        print("   macOS: brew install python-tk")
        run_cli_mode(security_status)
        return
    
    # GUI'yi başlat
    try:
        root = tk.Tk()
        
        if platform.system() == 'Darwin':
            try:
                root.tk.call('tk', 'scaling', 1.5)
            except:
                pass
        
        app = SentinelProGUI(root, security_status)
        
        root.update_idletasks()
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        window_width = 1000
        window_height = 750
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2
        
        root.geometry(f"{window_width}x{window_height}+{x}+{y}")
        root.mainloop()
        
    except Exception as e:
        print(f"\n❌ GUI başlatma hatası: {e}")
        print("\n🔧 CLI moduna geçiliyor...")
        run_cli_mode(security_status)

def run_cli_mode(security_status: Dict[str, Any]):
    """CLI modu"""
    print("\n" + "="*60)
    print("CLI MODU - Pass-Edip v7.2")
    print("="*60)
    
    print(f"\n🛡️  Güvenlik Durumu: {security_status['score']}/100 - {security_status['level']}")
    if RestrictedSecurityMode.ACTIVE:
        print("🔒 KISITLI MOD: Maks. dosya boyutu 100MB")
    
    engine = SentinelEncryptionEngine(SecurityLevel.COMMERCIAL)
    
    while True:
        print("\n1. Dosya Şifrele")
        print("2. Dosya Deşifrele")
        print("3. Parola Üret")
        print("4. Çıkış")
        
        try:
            choice = input("\nSeçim (1-4): ").strip()
            
            if choice == '1':
                input_file = input("Şifrelenecek dosya: ").strip()
                if not os.path.exists(input_file):
                    print("❌ Dosya bulunamadı")
                    continue
                
                auto_pass = input("Otomatik parola üretilsin mi? (e/h): ").strip().lower()
                
                if auto_pass == 'e':
                    password, analysis = SecurePasswordGenerator.generate_password(
                        SecurityLevel.COMMERCIAL, False)
                    
                    print(f"\n🔐 Üretilen Parola: {password}")
                    print(f"   Uzunluk: {analysis['length']}")
                    print(f"   Güç: {analysis['strength']}")
                    print(f"   Entropi: {analysis['entropy_bits']:.1f} bit")
                    
                    save = input("Parolayı masaüstüne kaydetmek ister misiniz? (e/h): ").strip().lower()
                    if save == 'e':
                        try:
                            filepath = SecurePasswordGenerator.save_password_to_desktop(password)
                            print(f"✅ Parola kaydedildi: {filepath}")
                        except Exception as e:
                            print(f"❌ Kayıt başarısız: {e}")
                    
                    confirm = input("Bu parolayı kullanarak şifrelemeye devam edilsin mi? (e/h): ")
                    if confirm.lower() != 'e':
                        continue
                
                else:
                    password = input("Parola: ").strip()
                    if not password:
                        print("❌ Parola gerekli")
                        continue
                
                output_file = input_file + '.sen7'
                
                print("\n🔒 Şifreleme başlatılıyor...")
                
                try:
                    def progress_callback(current, total, message):
                        percent = (current / total * 100) if total > 0 else 0
                        print(f"\r{message}: %{percent:.1f}", end='')
                    
                    metadata = engine.encrypt_file(input_file, output_file, password,
                                                  progress_callback=progress_callback)
                    
                    print(f"\n✅ Şifreleme tamam: {output_file}")
                    print(f"   Boyut: {metadata['encrypted_size']:,} bayt")
                    print(f"   Parçalar: {metadata['chunks']}")
                    
                except Exception as e:
                    print(f"\n❌ Hata: {e}")
            
            elif choice == '2':
                input_file = input("Deşifre edilecek dosya (.sen7): ").strip()
                if not os.path.exists(input_file):
                    print("❌ Dosya bulunamadı")
                    continue
                
                password = input("Parola: ").strip()
                if not password:
                    print("❌ Parola gerekli")
                    continue
                
                output_file = input("Çıktı dosyası: ").strip()
                if not output_file:
                    base = os.path.basename(input_file)
                    output_file = base[:-5] if base.endswith('.sen7') else f"decrypted_{base}"
                
                print("\n🔓 Deşifreleme başlatılıyor...")
                
                try:
                    def progress_callback(current, total, message):
                        percent = (current / total * 100) if total > 0 else 0
                        print(f"\r{message}: %{percent:.1f}", end='')
                    
                    metadata = engine.decrypt_file(input_file, output_file, password,
                                                  progress_callback=progress_callback)
                    
                    print(f"\n✅ Deşifreleme tamam: {output_file}")
                    print(f"   Boyut: {metadata['bytes_written']:,} bayt")
                    
                except Exception as e:
                    print(f"\n❌ Hata: {e}")
            
            elif choice == '3':
                print("\nGüvenlik seviyeleri:")
                for level, preset in SECURITY_PRESETS.items():
                    print(f"  {level.value}. {preset.name} ({preset.description})")
                
                level_choice = input("\nSeviye (1-4): ").strip()
                try:
                    level = SecurityLevel(int(level_choice))
                    
                    memorable = input("Hatırlanabilir şifre olsun mu? (e/h): ").lower() == 'e'
                    
                    password, analysis = SecurePasswordGenerator.generate_password(level, memorable)
                    
                    print(f"\n🔐 ÜRETİLEN PAROLA: {password}")
                    print(f"   Uzunluk: {analysis['length']} karakter")
                    print(f"   Güç: {analysis['strength']}")
                    print(f"   Entropi: {analysis['entropy_bits']:.1f} bit")
                    
                    save = input("\nMasaüstüne kaydetmek ister misiniz? (e/h): ").lower()
                    if save == 'e':
                        try:
                            filepath = SecurePasswordGenerator.save_password_to_desktop(password)
                            print(f"✅ Parola kaydedildi: {filepath}")
                        except Exception as e:
                            print(f"❌ Kayıt başarısız: {e}")
                    
                except (ValueError, KeyError):
                    print("❌ Geçersiz seviye")
            
            elif choice == '4':
                print("\n👋 Çıkılıyor...")
                break
            
            else:
                print("❌ Geçersiz seçim")
                
        except KeyboardInterrupt:
            print("\n\nİptal edildi")
            break
        except Exception as e:
            print(f"\n❌ Hata: {e}")

# ==============================
# GİRİŞ NOKTASI
# ==============================
if __name__ == "__main__":
    sys.dont_write_bytecode = True
    
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nProgram kullanıcı tarafından durduruldu.")
    except Exception as e:
        print(f"\n\n❌ Beklenmeyen hata: {e}")
        import traceback
        traceback.print_exc()