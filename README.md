# 🚀 Pass-Edip v4.0 - Ultimate Security Edition

**Root Detection & Memory Protection System**

## 🔥 MAJOR NEW FEATURES

### 🛡️ **Advanced Security System**
- **Root Detection**: Multi-platform root/admin access detection with blocking capabilities
- **Debugger Detection**: Automatic detection of GDB, strace, lldb and other debugging tools
- **Virtual Environment Control**: Enhanced security in VM/Container environments
- **Memory Dumping Protection**: Proactive defense against RAM analysis tools
- **Restricted Mode**: Automatic safety restrictions when running with elevated privileges

### 🔒 **Secure Memory Management**
- **Memory Locking**: `mlock()` implementation to prevent swapping sensitive data
- **Automatic Cleanup**: Immediate wiping of cryptographic material from memory
- **Secure Buffer Allocation**: Protected memory regions for key operations
- **Emergency Wipe**: Self-destruct mechanisms on security breaches

### ⚡ **Performance & Architecture**
- **Streaming Encryption**: Length-prefixed chunks for efficient large file processing
- **Optimized Scrypt KDF**: Configurable memory-hard parameters
- **Background Threading**: Non-blocking operations with responsive GUI
- **Chunk Integrity**: Index-based authentication preventing reordering attacks

### 🎨 **Modern User Interface**
- **Security Score Indicator**: Real-time security status display
- **Smart File Detection**: Automatic .enc file recognition
- **Progress Tracking**: Live progress bars with detailed logging
- **Cross-Platform**: Fully compatible with Windows, macOS, and Linux

## 📊 **SECURITY LEVELS & PROTECTION**

### Security Scoring System
- **90+**: VERY SECURE ✅ (Normal user, no debuggers)
- **70-89**: SECURE ✅ (Minor warnings)
- **50-69**: MEDIUM RISK ⚠️ (Sudo usage, etc.)
- **30-49**: HIGH RISK 🚨 (Root access or debugger)
- **0-29**: CRITICAL RISK ❌ (Multiple threats detected)

### Protection Features
- **Anti-Forensic**: Memory obfuscation and secure wiping
- **Process Hardening**: Core dump prevention and ptrace protection
- **Network Security**: Sniffer detection and protection
- **Authentication**: Enhanced password policy with user warnings

## 🐛 **SECURITY FIXES & IMPROVEMENTS**

### Critical Fixes
- **Root Access Vulnerability**: Complete protection against RAM dumping in elevated environments
- **Memory Leak Prevention**: Secure cleanup of all cryptographic material
- **Nonce Management**: Counter-based unique nonces per data chunk
- **Header Validation**: Strict bounds checking and format verification

### Performance Optimizations
- **Chunk-Based Processing**: 1MB chunks optimized for memory usage
- **Streaming Support**: Length-prefixed ciphertext for large files
- **Background Operations**: Threaded encryption/decryption
- **Early Validation**: Quick password policy checks

## 🔧 **TECHNICAL CHANGES**

### New Classes & Components
- `RootDetector`: Multi-platform privilege detection
- `SecurityEnvironment`: Comprehensive security assessment
- `SecurityLogger`: Centralized security event logging  
- `RestrictedMode`: Safe operation under elevated privileges
- `SecureMemoryManager`: Protected memory operations

### Enhanced Exceptions
- `RootAccessError`: Blocked operations under root
- `SecurityError`: Base security exception class
- `AuthenticationError`: Enhanced credential validation
- `FileSizeError`: Enforced size limits

### Configuration Updates
- **VERSION**: 3 → 4 (File format update)
- **MAX_FILE_SIZE**: 10GB (Normal), 100MB (Restricted Mode)
- **CHUNK_SIZE**: 1MB (Normal), 64KB (Restricted Mode)
- **Security Logging**: Platform-specific secure log locations

## 🚨 **BREAKING CHANGES**

### Important Updates
1. **Root Execution Restricted**: Automatic blocking or limited mode
2. **Debugger Detection**: Warnings when analysis tools detected
3. **File Format**: v4 incompatible with previous versions (encryption only)
4. **Memory Protection**: Requires modern Python memory management

### Backward Compatibility
- ✅ v3 files can be decrypted with v4
- ✅ v3 encryption algorithms maintained for decryption
- ❌ v4 encrypted files cannot be opened with v3
- ✅ Password policies remain compatible

## 📦 **INSTALLATION & REQUIREMENTS**

```bash
# Clone repository
git clone https://github.com/Edipcm-hash/pass-edip-v4.git
cd pass-edip-v4

# Install dependencies
pip install cryptography

# Run application
python passedip_v4.py
```

### Platform-Specific Notes
- **macOS**: Python 3.8+ from python.org recommended
- **Linux**: `sudo apt-get install python3-tk` for GUI support
- **Windows**: Ensure "tcl/tk" option selected during Python installation
- **All**: Tkinter typically included with Python distributions

## 📁 **FILE STRUCTURE**

```
Pass-Edip-v4.0/
├── passedip_v4.py          # Main application
├── README.md              # Documentation
├── security.log           # Security events (auto-generated)
├── requirements.txt       # Python dependencies
└── CHANGELOG.md          # Version history
```

## 🧪 **TESTED ENVIRONMENTS**

- ✅ **macOS 12+** (Intel & Apple Silicon)
- ✅ **Ubuntu 20.04+** / **Debian 11+**
- ✅ **Windows 10/11** (Python 3.8+)
- ✅ **Fedora 36+** / **CentOS 8+**
- ✅ **Docker Containers** (Limited mode)

## ⚡ **PERFORMANCE METRICS**

- **Normal Mode**: Up to 10GB file support
- **Restricted Mode**: 100MB file limit (root environments)
- **Encryption Speed**: ~50-100 MB/s (SSD dependent)
- **Memory Usage**: Constant regardless of file size
- **CPU Utilization**: Optimized multi-core support

## 🛡️ **SECURITY ARCHITECTURE**

### Cryptographic Foundation
- **Algorithm**: AES-256-GCM with proper nonce management
- **Key Derivation**: Scrypt KDF with 128MB memory hardness
- **Authentication**: Chunk-level AAD with index protection
- **Integrity**: Tamper-evident design with validation

### Protection Layers
1. **Process Security**: Memory locking and anti-debugging
2. **Environmental Security**: Root and VM detection
3. **Data Security**: End-to-end encryption with integrity
4. **Operational Security**: Secure cleanup and logging

## 🤝 **CONTRIBUTING**

We welcome contributions from the security community:

1. **Fork** the repository
2. **Create** feature branch (`git checkout -b feature/security-improvement`)
3. **Commit** changes (`git commit -m 'Add security enhancement'`)
4. **Push** to branch (`git push origin feature/security-improvement`)
5. **Open** a Pull Request

### Contribution Guidelines
- Follow existing code style and security practices
- Include comprehensive tests for security features
- Document all security-related changes thoroughly
- Report security issues via private channels initially

## 📄 **LICENSE**

MIT License - See [LICENSE](LICENSE) file for details

## 🙏 **ACKNOWLEDGEMENTS**

- **Cryptography Team** for robust cryptographic primitives
- **Tkinter Developers** for cross-platform GUI framework
- **Security Researchers** for vulnerability disclosures
- **Open Source Community** for continuous improvement

## 🐛 **BUG REPORTING & SECURITY**

### Reporting Issues
1. Open [GitHub Issues](https://github.com/Edipcm-hash/pass-edip/issues)
2. Include **Version**: v4.0
3. Specify **Platform**: macOS/Linux/Windows
4. Provide **Steps**: Detailed reproduction steps
5. Attach **Logs**: security.log excerpts (sanitized)

### Security Vulnerability Disclosure
For critical security issues, please contact:
- **Email**: security@edipcam.com
- **PGP Key**: Available on project page
- **Response Time**: 48 hours for critical issues

---

## 📈 **VERSION HISTORY COMPARISON**

| Feature | v2.0 | v3.2 | v4.0 |
|---------|------|------|------|
| **Root Detection** | ❌ | ❌ | ✅ |
| **Memory Protection** | Basic | Enhanced | Advanced |
| **Debugger Detection** | ❌ | ❌ | ✅ |
| **Restricted Mode** | ❌ | ❌ | ✅ |
| **Security Scoring** | ❌ | ❌ | ✅ |
| **File Size Limit** | 2GB | 10GB | 10GB/100MB* |
| **Chunk Size** | 64KB | 1MB | 1MB/64KB* |
| **Nonce Management** | Fixed | Per-chunk | Per-chunk+ |
| **Integrity Protection** | Basic | AAD-indexed | Enhanced |
| **GUI Features** | Basic | Modern | Advanced |

*Restricted Mode values

---

**Pass-Edip v4.0 represents a paradigm shift in secure file encryption tools, offering proactive protection against both remote and physical attacks while maintaining exceptional usability.**

**#CyberSecurity #Encryption #PrivacyTools #OpenSource #MemoryProtection** 🔐

---
*"Security is not a product, but a process." - Pass-Edip v4.0*

""Contact - edipcam0@icloud.com
