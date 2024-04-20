import tkinter as tk
from tkinter import messagebox
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class KeyGeneratorApp:
    def __init__(self, master):
        self.master = master
        master.title("RSA Key Generator")
        master.geometry("300x100")

        self.label = tk.Label(master, text="Enter PIN:")
        self.label.pack()

        self.pin_entry = tk.Entry(master, show="*")
        self.pin_entry.pack()

        self.generate_button = tk.Button(master, text="Generate Keys", command=self.generate_keys)
        self.generate_button.pack()

    def generate_keys(self):
        pin = self.pin_entry.get()

        if not pin:
            messagebox.showerror("Error", "Please enter a PIN.")
            return

        # Generowanie klucza AES z PIN
        aes_key = self.derive_aes_key(pin)

        # Generowanie kluczy RSA
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )

        # Szyfrowanie klucza prywatnego RSA za pomocą klucza AES
        encrypted_private_key = self.encrypt_private_key(private_key, aes_key)

        # Zapis kluczy do plików
        self.save_keys(private_key, encrypted_private_key)

        messagebox.showinfo("Success", "RSA keys generated and encrypted successfully.")

    def derive_aes_key(self, pin):
        salt = b'salt_'  # Sól dla funkcji pochodnej klucza (może być losowa)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        aes_key = kdf.derive(pin.encode())
        return aes_key

    def encrypt_private_key(self, private_key, aes_key):
        # Konwersja klucza prywatnego do formatu PEM
        pem_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Szyfrowanie klucza prywatnego za pomocą AES
        iv = b'iv_iv_iv_iv_iv_'  # Wektor inicjalizacyjny (może być losowy)
        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_private_key = encryptor.update(pem_private_key) + encryptor.finalize()

        return encrypted_private_key

    def save_keys(self, private_key, encrypted_private_key):
        with open("private_key.pem", "wb") as private_key_file:
            private_key_file.write(encrypted_private_key)

        with open("public_key.pem", "wb") as public_key_file:
            public_key = private_key.public_key()
            public_key_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            public_key_file.write(public_key_bytes)

def main():
    root = tk.Tk()
    app = KeyGeneratorApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
