import tkinter as tk
from tkinter import messagebox
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import hashlib

class KeyGeneratorApp:
    def __init__(self, master):
        self.master = master
        master.title("RSA Key Generator")
        master.geometry("300x100")

        self.label = tk.Label(master, text="Enter PIN:")
        self.label.pack(pady=5)

        self.pin_entry = tk.Entry(master)
        self.pin_entry.pack(pady=5)

        self.generate_button = tk.Button(master, text="Generate Keys", command=self.generate_keys)
        self.generate_button.pack(pady=5)

    def generate_keys(self):
        pin = self.pin_entry.get()

        if not pin:
            messagebox.showerror("Error", "Please enter a PIN.")
            return

        # Klucz AES i IV
        # aes_key = b'This is a key123'
        aes_key = hashlib.sha256(pin.encode('utf-8')).digest()
        iv = b'This is an IV456'

        # Tworzenie obiektu szyfrującego AES
        aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)

        # Generowanie kluczy RSA
        key_pair = RSA.generate(4096)
        private_key = key_pair.export_key()
        public_key = key_pair.public_key().export_key()

        # Padding
        padded_private_key = pad(private_key,16)

        # Szyfrowanie klucza
        encrypted_private_key = aes_cipher.encrypt(padded_private_key)

        # # Tworzenie nowego obiektu AES do deszyfrowania
        # aes_cipher_decrypt = AES.new(aes_key, AES.MODE_CBC, iv)

        # # Deszyfrowanie klucza
        # decrypted_private_key = aes_cipher_decrypt.decrypt(encrypted_private_key)

        # # Usunięcie paddingu
        # decrypted_private_key = decrypted_private_key[:-padding[-1]]

        # # Dekodowanie klucza
        # decrypted_private_key = decrypted_private_key.decode('utf-8')

        # Zapis kluczy do plików
        with open("private_key.enc", "wb") as encrypted_key_file:
            encrypted_key_file.write(encrypted_private_key)

        # with open("decrypted_private_key.pem", "w") as decrypted_key_file:
        #     decrypted_key_file.write(decrypted_private_key)

        with open("private_key.pem", "wb") as private_key_file:
            private_key_file.write(private_key)

        with open("public_key.pem", "w") as public_key_file:
            public_key_file.write(public_key.decode())
        messagebox.showinfo("Success", "RSA keys generated and encrypted successfully.")

def main():
    root = tk.Tk()
    app = KeyGeneratorApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
