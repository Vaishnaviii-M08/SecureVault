# SecureVault
SecureVault is a powerful encryption tool with a modern GUI, designed to encrypt and decrypt files securely using AES-256 encryption. This tool supports various file types, including Word documents (.docx) and text files.

Features

AES-256 Encryption: Secure your files with advanced encryption.

User-Friendly GUI: Built using Tkinter for an intuitive experience.

Supports Multiple File Types: Encrypts and decrypts text files, Word documents, and more.

Password-Based Encryption: Uses PBKDF2 key derivation for enhanced security.

No File Duplication: Encrypted files replace the original file for security.

Installation

Prerequisites

Make sure you have Python installed. Then, install the required dependencies:

pip install cryptography tk

Running the Application

Run the following command:

python securevault.py

Usage

Open the application.

Select a file using the Browse Files button.

Enter a secure password.

Click Encrypt File to encrypt or Decrypt File to decrypt.

Code Explanation

This application is built using Python with Tkinter for the GUI and the Cryptography library for secure encryption.

PBKDF2 Key Derivation: Generates a secure encryption key from a user-provided password.

Fernet Encryption: Uses AES-256 to encrypt and decrypt files securely.

File Handling: Reads and writes encrypted/decrypted data to replace the original file.

GUI: Provides an intuitive interface to select files, input passwords, and perform encryption/decryption.

Contributing

Feel free to contribute by submitting issues or pull requests.

License

This project is licensed under the MIT License.
