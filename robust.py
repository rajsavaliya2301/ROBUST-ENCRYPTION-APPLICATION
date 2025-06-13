import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(file_path, password):
    with open(file_path, 'rb') as f:
        data = f.read()

    salt = os.urandom(16)
    iv = os.urandom(16)
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()

    with open(file_path + '.enc', 'wb') as f:
        f.write(salt + iv + encrypted_data)

    messagebox.showinfo("Success", "File encrypted successfully!")

def decrypt_file(file_path, password):
    with open(file_path, 'rb') as f:
        raw = f.read()

    salt = raw[:16]
    iv = raw[16:32]
    encrypted_data = raw[32:]
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    original_path = file_path.replace('.enc', '')
    with open(original_path + '_decrypted', 'wb') as f:
        f.write(decrypted_data)

    messagebox.showinfo("Success", "File decrypted successfully!")

def select_file_encrypt():
    file_path = filedialog.askopenfilename()
    password = entry.get()
    if file_path and password:
        encrypt_file(file_path, password)
    else:
        messagebox.showerror("Error", "Please select a file and enter password.")

def select_file_decrypt():
    file_path = filedialog.askopenfilename()
    password = entry.get()
    if file_path and password:
        decrypt_file(file_path, password)
    else:
        messagebox.showerror("Error", "Please select a file and enter password.")

# GUI
root = tk.Tk()
root.title("🔐 AES-256 File Encryptor/Decryptor")
root.geometry("400x200")

tk.Label(root, text="🔑 Enter Password:").pack(pady=10)
entry = tk.Entry(root, width=30, show="*")
entry.pack()

tk.Button(root, text="📁 Encrypt File", command=select_file_encrypt, bg="lightgreen").pack(pady=10)
tk.Button(root, text="📂 Decrypt File", command=select_file_decrypt, bg="lightblue").pack(pady=5)

root.mainloop()
