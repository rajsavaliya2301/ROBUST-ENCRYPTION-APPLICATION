# ROBUST-ENCRYPTION-APPLICATION
A TOOL TO ENCRYPT AND  DECRYPT FILES USING ADVANCED  ALGORITHMS LIKE AES-256


A simple and secure Python application to **encrypt and decrypt files** using **AES-256 encryption**, built with a clean and user-friendly **Tkinter GUI**.

---

## 🚀 Features

✨ AES-256 encryption using the `cryptography` library  
🔑 Password-protected with PBKDF2 key derivation  
🖼️ Graphical interface with buttons and input fields  
📁 Encrypt and decrypt any file  
🛡️ Keeps your data safe from unauthorized access

---

## 📦 Requirements

- Python 3.x
- `cryptography` module
- `tkinter` (usually pre-installed with Python)

### 🛠️ Install Dependencies

```bash
pip install cryptography
```
🧠 How It Works
🔐 Encryption

Takes a password from the user.

Derives a 256-bit key using PBKDF2.

Encrypts the selected file using AES in CFB mode.

Saves the encrypted file with .enc extension.

🔓 Decryption

Takes the same password used for encryption.

Reads salt and IV from the encrypted file.

Decrypts and saves it as a _decrypted file.

🎮 Usage
Run the script:
```
python robust.py
```
GUI will open:

Enter a strong password.

Click "📁 Encrypt File" or "📂 Decrypt File".

Select the file you want to encrypt/decrypt.

Done! 🥳
You’ll see a success message once the operation completes.

📂 Output Example
Action	Output File Name
Encrypt	file.txt.enc
Decrypt	file.txt_decrypted

📸 Screenshot (Optional)
(Insert a screenshot of the GUI here if needed)

⚠️ Security Tip
Always remember your encryption password.
Without it, the data cannot be recovered!

📄 License
This project is open-source and free to use for educational purposes.
