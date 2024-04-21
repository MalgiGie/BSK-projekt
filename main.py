import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from key_finder import KeyFinder
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes
import hashlib
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from xades import Xades
import os


class MainApp:
    def __init__(self, master):
        self.private_key = ""
        self.master = master
        master.title("BSK Application")

        master.geometry("400x200")

        self.select_button = tk.Button(self.master, text="Enter PIN", command=self.enter_pin)
        self.select_button.pack(pady=5)

        self.label = tk.Label(master, text="Select document to sign:")
        self.label.pack(pady=10)

        self.selected_file_label = tk.Label(master, text="")
        self.selected_file_label.pack(pady=5)

        # Utworzenie ramki do umieszczenia przycisków obok siebie
        self.button_frame = tk.Frame(master)
        self.button_frame.pack()

        self.select_button = tk.Button(self.button_frame, text="Select File", command=self.select_file)
        self.select_button.pack(side=tk.LEFT, padx=5)  # Ustawienie przycisku na lewej stronie

        self.sign_button = tk.Button(self.button_frame, text="Sign Document", command=self.sign_document, state=tk.DISABLED)
        self.sign_button.pack(side=tk.LEFT, padx=5)  # Ustawienie przycisku na lewej stronie

    def select_file(self):
        self.file_path = filedialog.askopenfilename()
        if self.file_path:
            self.selected_file_label.config(text=f"Selected file: {self.file_path}")
            self.sign_button.config(state=tk.NORMAL)

    def enter_pin(self):
        # Odszukanie zaszyfrowanego klucza na pendrivie
        key_finder = KeyFinder()
        encrypted_key_path = key_finder.find_encrypted_key_file()
        if not encrypted_key_path:
            return
        
        # Podanie PINu
        pin = simpledialog.askstring("PIN", "Please enter your PIN:", parent=self.master)
        if pin is None:
            # User clicked cancel
            return

        # Odczytanie zaszyfrowanego klucza prywatnego z pliku
        with open(encrypted_key_path, "rb") as private_key_file:
            encrypted_private_key = private_key_file.read()


        # Tworzenie nowego obiektu AES do deszyfrowania
        # aes_key = b'This is a key123'
        aes_key = hashlib.sha256(pin.encode('utf-8')).digest()
        iv = b'This is an IV456'

        aes_cipher_decrypt = AES.new(aes_key, AES.MODE_CBC, iv)

        try:
            # Deszyfrowanie klucza
            decrypted_private_key = aes_cipher_decrypt.decrypt(encrypted_private_key)

            # Usunięcie paddingu
            decrypted_private_key = unpad(decrypted_private_key, 16)

            # Dekodowanie klucza
            decrypted_private_key = decrypted_private_key.decode('utf-8')
            self.private_key = decrypted_private_key
        except ValueError:
            # Obsługa błędu deszyfrowania
            messagebox.showerror("Error", "Incorrect PIN. Please try again.")
            return
        
        # Zapisanie odszyfrowanego klucza prywatnego do pliku
        # with open("private_key.pem", "w") as decrypted_private_key_file:
        #     decrypted_private_key_file.write(decrypted_private_key)
        
        messagebox.showinfo("Login", "PIN is correct!")

    def sign_document(self):
        if self.private_key == "":
            messagebox.showerror("Error", "Please enter PIN first.")
            return
        with open(self.file_path, 'rb') as file:
            file_content = file.read()
        
        # key = RSA.import_key(self.private_key)
        # hash_obj = SHA256.new(file_content)
        # signer = PKCS1_v1_5.new(key)
        # signature = signer.sign(hash_obj)

        # print(signature)

        # Inicjalizuj obiekt Signer
        signer = xmlsig.Signer()

        # Dodaj dokument do podpisu
        signer.add_document(self.file_data)

        # Wygeneruj podpis XAdES
        signature = signer.sign()

        # Zapisz podpis do pliku
        signature_file_path = f"{self.file_path}.xmlsig"
        with open(signature_file_path, "wb") as signature_file:
            signature_file.write(signature)

        print(f"Podpis XAdES został wygenerowany i zapisany do: {signature_file_path}")

        messagebox.showinfo("Signature", "Document signed successfully!")

def main():
    root = tk.Tk()
    app = MainApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
