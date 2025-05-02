import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os, base64

root = tk.Tk()
root.title("File Encryptor")

# Password entry
tk.Label(root, text="Password:").grid(row=0, column=0, sticky="e")
password_entry = tk.Entry(root, show="*", width=30)
password_entry.grid(row=0, column=1, padx=10, pady=5)

def derive_key(password, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=1200000)
    return base64.urlsafe_b64encode(kdf.derive(password))

def encrypt_file():
    file_path = filedialog.askopenfilename(title="Select text file to encrypt",
                                           filetypes=[("Text Files","*.txt")])
    if not file_path:
        return
    password = password_entry.get().encode()
    if not password:
        messagebox.showwarning("Input Error", "Enter a password.")
        return

    salt = os.urandom(16)
    key = derive_key(password, salt)
    fernet = Fernet(key)

    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        token = fernet.encrypt(data)

        dir_name, base_name = os.path.split(file_path)
        name, _ = os.path.splitext(base_name)
        new_filename = os.path.join(dir_name, f"{name}_encrypted.enc")

        with open(new_filename, 'wb') as out:
            out.write(salt + token)

        messagebox.showinfo("Success", f"File encrypted and saved as:\n{new_filename}")
    except Exception as e:
        messagebox.showerror("Encryption Error", str(e))

def decrypt_file():
    file_path = filedialog.askopenfilename(title="Select file to decrypt",
                                           filetypes=[("Encrypted Files","*.enc")])
    if not file_path:
        return
    password = password_entry.get().encode()
    if not password:
        messagebox.showwarning("Input Error", "Enter the password used for encryption.")
        return

    try:
        raw = open(file_path, 'rb').read()
        salt, token = raw[:16], raw[16:]
        key = derive_key(password, salt)
        fernet = Fernet(key)
        plaintext = fernet.decrypt(token)

        dir_name, base_name = os.path.split(file_path)
        name, _ = os.path.splitext(base_name)
        new_filename = os.path.join(dir_name, f"{name}_decrypted.txt")

        with open(new_filename, 'wb') as out:
            out.write(plaintext)

        messagebox.showinfo("Success", f"File decrypted and saved as:\n{new_filename}")
    except InvalidToken:
        messagebox.showerror("Decryption Error", "Incorrect password or corrupted file.")
    except Exception as e:
        messagebox.showerror("Decryption Error", str(e))

# Buttons for actions
encrypt_btn = tk.Button(root, text="Encrypt File", command=encrypt_file)
encrypt_btn.grid(row=1, column=0, pady=10, padx=5)
decrypt_btn = tk.Button(root, text="Decrypt File", command=decrypt_file)
decrypt_btn.grid(row=1, column=1, pady=10, padx=5)

root.mainloop()
