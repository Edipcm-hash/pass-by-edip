Pass-Edip v3.2
Pass-Edip v3.2 is a significantly enhanced secure file encryption tool featuring major security improvements, optimized performance, and a modern user-friendly interface. Built with Python and Tkinter, it now provides enterprise-grade encryption with comprehensive protection against modern cryptographic threats.

🚀 What's New & Improved in v3.2
Security Enhancements
Fixed Critical Nonce Reuse Vulnerability: Implemented counter-based unique nonces for each data chunk, eliminating AES-GCM security risks

Chunk Integrity Protection: Integrated chunk indices into AAD (Additional Authenticated Data) to prevent reordering and duplication attacks

Secure Memory Management: Immediate wiping of sensitive data from memory using secure cleanup routines

Enhanced Header Validation: Strict parsing with bounds checking and format verification

Size Limit Enforcement: 10GB maximum file size and 16MB chunk size limits

Performance & Architecture
Streaming Encryption Support: Length-prefixed ciphertext chunks enable efficient large file processing

Optimized Scrypt KDF: Configurable parameters with memory-hard key derivation

Early Termination Checks: Improved password policy validation performance

Background Threading: Non-blocking operations maintain responsive GUI during encryption/decryption

User Experience
Modern Dark Theme: Clean, professional interface with intuitive controls

One-Click Operations: Smart automatic file type detection and single-click encryption/decryption

Real-time Progress Tracking: Live progress bars and detailed operation logging

Cross-Platform Compatibility: Fully tested on Windows, macOS, and Linux

✨ Features
Military-Grade Encryption: AES-256-GCM with secure nonce management per chunk

Advanced Key Derivation: Scrypt KDF with configurable memory hardness parameters

Chunk-Based Processing: Efficient 1MB chunk size for optimal memory usage

Authentication & Integrity: Protection against tampering and replay attacks

Smart File Detection: Automatic recognition of encrypted (.enc) vs normal files

Secure Password Policy: Enforces strong passwords with comprehensive character requirements

Keyfile Support: Optional keyfile integration for multi-factor security

Comprehensive Error Handling: Detailed feedback for invalid files, wrong passwords, and corrupted data

📦 Installation
bash
# Clone the repository
git clone https://github.com/Edipcm-hash/pass-by-edip/

# Install dependencies
pip install cryptography

# Run the application
python Pass-Edip-v3.2.py
🎯 Usage
Launch the application

Select File: Click "Choose File" or use drag-and-drop (Windows/Linux)

Automatic Detection: The interface automatically detects file type and enables appropriate actions

Enter Password: Provide a secure password meeting policy requirements

Single-Click Operation: Click "ENCRYPT" for normal files or "DECRYPT" for .enc files

Monitor Progress: Watch real-time progress bars and detailed operation logs

🔐 Password Policy
Your password must:

Be at least 8 characters long (12+ recommended)

Contain at least 2 different character types:

Lowercase letters (a-z)

Uppercase letters (A-Z)

Numbers (0-9)

Special characters (!@#$%^&*(), etc.)

Avoid common patterns and dictionary words

🛡️ Security Architecture
Cryptographic Foundation: AES-256-GCM with proper nonce management

Key Protection: Scrypt KDF with 128MB memory limit resistance to GPU attacks

Data Integrity: Chunk-level authentication preventing manipulation

Memory Safety: Immediate cleanup of passwords and keys from memory

Brute Force Protection: Progressive lockouts after repeated failures

Stream Security: Protection against chunk reordering and replay attacks

🔄 Technical Improvements from v2
Component	v2 (Previous)	v3.2 (Current)
Nonce Management	Single nonce per file	Unique nonce per chunk
Integrity Protection	Basic authentication	Chunk-level AAD with indexing
Memory Security	No explicit cleaning	Secure wiping routines
File Processing	Simple chunking	Length-prefixed streaming
Header Security	Basic validation	Strict format verification
Attack Resistance	Limited protection	Comprehensive anti-tampering
🤝 Contributing
We welcome contributions! Please feel free to:

Open issues for bug reports or security concerns

Submit pull requests for enhancements and fixes

Suggest new features or improvements

Help with testing and documentation

📞 Contact
Author: Edip ÇAM
Email: edipcam0@icloud.com
Project: Pass-Edip Secure File Encryption





EDIP GUI v2

EDIP GUI v2 is a secure, user-friendly file encryption and decryption tool built with Python and Tkinter, designed for high performance, responsiveness, and security.

Features
	•	Strong Encryption: AES-GCM with scrypt-based key derivation ensures high security.
	•	Chunked File Processing: Efficient memory usage for large files (64KB chunks).
	•	Non-blocking GUI: Operations run in background threads to keep the interface responsive.
	•	Password Security: Enforces strong passwords (min 12 chars, including upper, lower, digit, special), and clears passwords immediately after use.
	•	Dark Mode Interface: Modern and clean dark-themed UI.
	•	Robust Error Handling: Detects invalid files, incorrect passwords, and prevents repeated rapid failed attempts.
	•	Cross-platform: Works on Windows, macOS, and Linux.

Installation
1.	Clone the repository: git clone https://github.com/Edipcm-hash/pass-by-edip/
2.	Install dependencies: pip install cryptography
3.	Run the application: python Pass-Edip.py

   Usage
	1.	Open the GUI.
	2.	Click “Choose File” to select a file.
	3.	Enter a secure password.
	4.	Click “Encrypt (.edip)” to encrypt the file, or “Decrypt” to decrypt an .edip file.
	5.	Monitor progress via the progress bar.

Password Policy

Your password must:
	•	Be at least 12 characters long
	•	Contain at least one lowercase letter
	•	Contain at least one uppercase letter
	•	Contain at least one number
	•	Contain at least one special character

Security Notes
	•	AES-GCM encryption ensures both confidentiality and integrity.
	•	Password-derived keys are generated using scrypt, a memory-hard KDF.
	•	The application clears sensitive data from memory immediately after use.
	•	Repeated failed password attempts trigger a temporary lockout to prevent brute force attacks.


Contributing

Contributions are welcome! Please open an issue or submit a pull request for improvements, bug fixes, or new features.

Contact

Author: Edip ÇAM
Email: edipcam0@icloud.com
