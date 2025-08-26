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
