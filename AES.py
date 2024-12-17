import os
import sys
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hmac import HMAC
import secrets
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt(data: bytes, key: bytes) -> bytes:
    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted_data

def decrypt(encrypted_data: bytes, key: bytes) -> bytes:
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data

def hmac_sign(data: bytes, key: bytes) -> bytes:
    hmac = HMAC(key, hashes.SHA256(), backend=default_backend())
    hmac.update(data)
    return hmac.finalize()

def hmac_verify(data: bytes, key: bytes, signature: bytes) -> bool:
    try:
        hmac = HMAC(key, hashes.SHA256(), backend=default_backend())
        hmac.update(data)
        hmac.verify(signature)
        return True
    except Exception:
        return False

def save_to_file(file_path: str, data: bytes):
    with open(file_path, 'wb') as f:
        f.write(data)

def load_from_file(file_path: str) -> bytes:
    with open(file_path, 'rb') as f:
        return f.read()

def encrypt_file():
    file_path = filedialog.askopenfilename()
    if not file_path:
        return

    password = password_entry.get()
    if not password:
        messagebox.showerror("Error", "Please enter a password")
        return

    try:
        data = load_from_file(file_path)
        salt = secrets.token_bytes(16)
        key = derive_key(password, salt)
        encrypted_data = encrypt(data, key)
        hmac_signature = hmac_sign(encrypted_data, key)

        output_path = file_path + '.enc'
        save_to_file(output_path, salt + hmac_signature + encrypted_data)
        messagebox.showinfo("Success", f"File encrypted and saved to {output_path}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def decrypt_file():
    file_path = filedialog.askopenfilename()
    if not file_path:
        return

    password = password_entry.get()
    if not password:
        messagebox.showerror("Error", "Please enter a password")
        return

    try:
        encrypted_file_data = load_from_file(file_path)
        salt = encrypted_file_data[:16]
        hmac_signature = encrypted_file_data[16:48]
        encrypted_data = encrypted_file_data[48:]

        key = derive_key(password, salt)

        if not hmac_verify(encrypted_data, key, hmac_signature):
            messagebox.showerror("Error", "HMAC verification failed, the file might have been tampered with")
            return

        decrypted_data = decrypt(encrypted_data, key)
        output_path = file_path.replace('.enc', '')
        save_to_file(output_path, decrypted_data)
        messagebox.showinfo("Success", f"File decrypted and saved to {output_path}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def select_folder():
    folder_path = filedialog.askdirectory()
    if folder_path:
        messagebox.showinfo("Selected Folder", f"You selected: {folder_path}")

def create_animation(widget):
    def hover_in(event):
        widget.configure(bg="#45A049")
    def hover_out(event):
        widget.configure(bg="#4CAF50")

    widget.bind("<Enter>", hover_in)
    widget.bind("<Leave>", hover_out)

app = tk.Tk()
app.title("CyberEdu Encryptor")
app.geometry("500x500")
app.configure(bg="black")

title_frame = tk.Frame(app, bg="black")
title_frame.pack(pady=20)

canvas = tk.Canvas(title_frame, width=150, height=150, bg="black", highlightthickness=0)
canvas.pack()
canvas.create_oval(10, 10, 140, 140, outline="white", width=4)
canvas.create_text(75, 75, text="CyberEdu\nEncryptor", fill="white", font=("Arial", 14, "bold"), justify="center")

frame = tk.Frame(app, bg="black")
frame.pack(pady=20)

tk.Label(frame, text="Enter Password:", bg="black", fg="white", font=("Arial", 12)).pack(pady=10)
password_entry = tk.Entry(frame, show="*", width=30, font=("Arial", 12))
password_entry.pack(pady=5)

def create_styled_button(parent, text, command):
    button = tk.Button(parent, text=text, bg="#4CAF50", fg="white", font=("Arial", 12), command=command)
    create_animation(button)
    return button

encrypt_button = create_styled_button(frame, "Encrypt File", encrypt_file)
decrypt_button = create_styled_button(frame, "Decrypt File", decrypt_file)
select_folder_button = create_styled_button(frame, "Select Folder", select_folder)

encrypt_button.pack(pady=10)
decrypt_button.pack(pady=10)
select_folder_button.pack(pady=10)

app.mainloop()
