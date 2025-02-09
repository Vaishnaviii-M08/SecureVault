import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os

class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SecureVault - Military Grade Encryption")
        self.root.geometry("800x600")
        self.setup_ui()
        
        # Security parameters
        self.iterations = 100000  # PBKDF2 iteration count

    def setup_ui(self):
        # Modern color scheme
        self.bg_color = "#2a2a2a"
        self.accent_color = "#4CAF50"
        self.text_color = "#ffffff"
        self.input_bg = "#404040"

        # Configure main window
        self.root.configure(bg=self.bg_color)
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Custom styles
        self.style.configure('TFrame', background=self.bg_color)
        self.style.configure('TLabel', background=self.bg_color, foreground=self.text_color)
        self.style.configure('TButton', background=self.accent_color, foreground=self.text_color,
                            font=('Helvetica', 10, 'bold'), borderwidth=1)
        self.style.map('TButton', 
                      background=[('active', '#45a049'), ('disabled', '#373737')])

        # Main container
        main_frame = ttk.Frame(self.root)
        main_frame.pack(pady=20, padx=20, fill=tk.BOTH, expand=True)

        # File selection
        file_frame = ttk.Frame(main_frame)
        file_frame.pack(fill=tk.X, pady=10)
        
        self.file_entry = ttk.Entry(file_frame, width=50, font=('Helvetica', 10),
                                  background=self.input_bg, foreground=self.text_color)
        self.file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        ttk.Button(file_frame, text="Browse Files", command=self.browse_file).pack(side=tk.LEFT)

        # Password input
        ttk.Label(main_frame, text="Enter Password:", font=('Helvetica', 11)).pack(pady=(20, 5), anchor=tk.W)
        self.password_entry = ttk.Entry(main_frame, show="•", width=40, font=('Helvetica', 12))
        self.password_entry.pack(fill=tk.X)

        # Action buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(pady=30)
        
        ttk.Button(btn_frame, text="Encrypt File", command=self.encrypt_file).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="Decrypt File", command=self.decrypt_file).pack(side=tk.LEFT, padx=10)

        # Status bar
        self.status = ttk.Label(self.root, text="Ready", foreground=self.accent_color,
                              font=('Helvetica', 10, 'italic'))
        self.status.pack(side=tk.BOTTOM, fill=tk.X)

    def browse_file(self):
        filename = filedialog.askopenfilename(filetypes=[("All Files", "*.*"),
                                                         ("Word Documents", "*.docx"),
                                                         ("Text Files", "*.txt")])
        self.file_entry.delete(0, tk.END)
        self.file_entry.insert(0, filename)

    def derive_key(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.iterations
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def encrypt_file(self):
        self.process_file(encrypt=True)

    def decrypt_file(self):
        self.process_file(encrypt=False)

    def process_file(self, encrypt=True):
        file_path = self.file_entry.get()
        password = self.password_entry.get()

        if not file_path or not password:
            messagebox.showwarning("Input Error", "Please select a file and enter password")
            return

        try:
            with open(file_path, 'rb') as f:
                data = f.read()

            salt = os.urandom(16) if encrypt else data[:16]
            key = self.derive_key(password, salt)
            fernet = Fernet(key)
            processed_data = fernet.encrypt(data) if encrypt else fernet.decrypt(data[16:])

            with open(file_path, 'wb') as f:
                f.write(salt + processed_data if encrypt else processed_data)

            self.status.config(text=f"File {'encrypted' if encrypt else 'decrypted'} successfully!")
            messagebox.showinfo("Success", f"File {os.path.basename(file_path)} updated")

        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.status.config(text="Operation failed")

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()
