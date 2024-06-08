import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from key_finder import KeyFinder
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad
from Crypto.Signature import pkcs1_15
import hashlib
from Crypto.Hash import SHA256
import os
import base64
from lxml import etree
import time

class MainApp:
    def __init__(self, master):
        self.private_key = None
        self.public_key = None
        self.pin = ""
        try:
            with open("public_key.pem", "rb") as public_key_file:
                self.public_key = RSA.import_key(public_key_file.read())
        except FileNotFoundError:
            messagebox.showerror("Error", "Missing public key")
        self.name = os.getlogin()
        self.master = master
        master.title("BSK Application")

        master.geometry("400x200")

        self.select_button = tk.Button(self.master, text="Enter PIN", command=self.enter_pin)
        self.select_button.pack(pady=20)

        # Utworzenie ramki do umieszczenia przycisków obok siebie
        self.button_frame = tk.Frame(master)
        self.button_frame.pack()

        self.sign_button = tk.Button(self.button_frame, text="Sign Document", command=self.sign_document, state=tk.DISABLED)
        self.sign_button.pack(side=tk.LEFT, padx=5)  # Ustawienie przycisku na lewej stronie

        self.verify_button = tk.Button(self.button_frame, text="Verify Signature", command=self.verify_signature, state=tk.DISABLED)
        self.verify_button.pack(side=tk.LEFT, padx=5)  # Ustawienie przycisku na lewej stronie

        self.button_frame = tk.Frame(master)
        self.button_frame.pack(pady=20)

        self.encrypt_button = tk.Button(self.button_frame, text="Encrypt File", command=self.basic_encryption_with_RSA_keys, state=tk.DISABLED)
        self.encrypt_button.pack(side=tk.LEFT, padx=5)  # Ustawienie przycisku na lewej stronie

        self.decrypt_button = tk.Button(self.button_frame, text="Decrypt File", command=self.basic_decryption_with_RSA_keys, state=tk.DISABLED)
        self.decrypt_button.pack(side=tk.LEFT, padx=5)  # Ustawienie przycisku na lewej stronie

    def enter_pin(self):
        # Odszukanie zaszyfrowanego klucza na pendrivie
        key_finder = KeyFinder()
        encrypted_key_path = key_finder.find_encrypted_key_file()
        if not encrypted_key_path:
            return
        
        # Podanie PINu
        self.pin = simpledialog.askstring("PIN", "Please enter your PIN:", parent=self.master)
        if self.pin is None:
            # User clicked cancel
            return

        # Odczytanie zaszyfrowanego klucza prywatnego z pliku
        with open(encrypted_key_path, "rb") as private_key_file:
            encrypted_private_key = private_key_file.read()

        # Tworzenie nowego obiektu AES do deszyfrowania
        # aes_key = b'This is a key123'
        aes_key = hashlib.sha256(self.pin.encode('utf-8')).digest()
        iv = b'This is an IV456'

        aes_cipher_decrypt = AES.new(aes_key, AES.MODE_CBC, iv)

        try:
            # Deszyfrowanie klucza
            decrypted_private_key = aes_cipher_decrypt.decrypt(encrypted_private_key)

            # Usunięcie paddingu
            decrypted_private_key = unpad(decrypted_private_key, 16)

            # Dekodowanie klucza
            decrypted_private_key = decrypted_private_key.decode('utf-8')
            self.private_key = RSA.import_key(decrypted_private_key)
        except ValueError:
            # Obsługa błędu deszyfrowania
            messagebox.showerror("Error", "Incorrect PIN. Please try again.")
            return
        
        # Zapisanie odszyfrowanego klucza prywatnego do pliku
        # with open("private_key.pem", "w") as decrypted_private_key_file:
        #     decrypted_private_key_file.write(decrypted_private_key)
        
        messagebox.showinfo("Login", "PIN is correct!")
        self.sign_button.config(state=tk.NORMAL)
        self.verify_button.config(state=tk.NORMAL)
        self.encrypt_button.config(state=tk.NORMAL)
        self.decrypt_button.config(state=tk.NORMAL)
    
    def sign_document(self):
        file_path = filedialog.askopenfilename()

        if not self.private_key:
            messagebox.showerror("Error", "Please enter PIN first.")
            return
        with open(file_path, 'rb') as file:
            file_content = file.read()
        
        # Hashing data
        hashed_content = SHA256.new(file_content)

        # Signing the data
        signature = pkcs1_15.new(rsa_key=self.private_key).sign(hashed_content)
        signature_base64 = base64.b64encode(signature).decode('utf-8')

        # Create the structure for xml in the desired standard
        root = etree.Element("Signature", xmlns="http://www.w3.org/2000/09/xmldsig#")

        # Information about the document
        doc_info = etree.SubElement(root, "DocumentInfo")
        etree.SubElement(doc_info, "Size").text = str(os.path.getsize(file_path))
        etree.SubElement(doc_info, "Extension").text = os.path.splitext(file_path)[1]
        etree.SubElement(doc_info, "ModificationDate").text = time.ctime(os.path.getmtime(file_path))

        # Information about the user signing the document
        user_info_elem = etree.SubElement(root, "UserInfo")
        etree.SubElement(user_info_elem, "Name").text = self.name

        signed_info = etree.SubElement(root, "SignedInfo")
        etree.SubElement(signed_info, "CanonicalizationMethod", Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315")
        etree.SubElement(signed_info, "SignatureMethod", Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")

        reference = etree.SubElement(signed_info, "Reference", URI=file_path)
        transforms = etree.SubElement(reference, "Transforms")
        etree.SubElement(transforms, "Transform", Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature")
        digest_method = etree.SubElement(reference, "DigestMethod", Algorithm="http://www.w3.org/2001/04/xmlenc#sha256")
        digest_value = etree.SubElement(reference, "DigestValue")
        digest_value.text = base64.b64encode(hashed_content.digest()).decode('utf-8')

        signature_value = etree.SubElement(root, "SignatureValue")
        signature_value.text = signature_base64

        key_info = etree.SubElement(root, "KeyInfo")
        key_value = etree.SubElement(key_info, "KeyValue")
        rsa_key_value = etree.SubElement(key_value, "RSAKeyValue")

        modulus = base64.b64encode(
            self.private_key.publickey().n.to_bytes((self.private_key.publickey().n.bit_length() + 7) // 8, 'big')).decode('utf-8')
        exponent = base64.b64encode(
            self.private_key.publickey().e.to_bytes((self.private_key.publickey().e.bit_length() + 7) // 8, 'big')).decode('utf-8')

        etree.SubElement(rsa_key_value, "Modulus").text = modulus
        etree.SubElement(rsa_key_value, "Exponent").text = exponent

        # Encrypted hash of the document
        encrypted_hash = base64.b64encode(hashed_content.digest()).decode('utf-8')
        encrypted_hash_elem = etree.SubElement(root, "EncryptedHash")
        encrypted_hash_elem.text = encrypted_hash

        timestamp = etree.SubElement(root, "Timestamp")
        timestamp.text = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())

        tree = etree.ElementTree(root)
        with open("signature_file.xml", "wb") as f:
            tree.write(f, pretty_print=True, xml_declaration=True, encoding="UTF-8")

        messagebox.showinfo("Signature", "Document signed successfully!")

    def verify_signature(self):
        signature_file = filedialog.askopenfilename(filetypes=[("Pliki XML", "*.xml")])

        # Wczytanie pliku XML
        with open(signature_file, "rb") as f:
            xml_data = f.read()

        # Parsowanie pliku XML
        root = etree.fromstring(xml_data)

        try:
            # Wczytanie podpisu
            signature_value = root.find(".//{http://www.w3.org/2000/09/xmldsig#}SignatureValue").text.strip()
            signature = base64.b64decode(signature_value.encode('utf-8'))

            # Wczytanie zaszyfrowanego hasha dokumentu
            encrypted_hash_elem = root.find(".//{http://www.w3.org/2000/09/xmldsig#}EncryptedHash")
            if encrypted_hash_elem is None:
                raise ValueError("Nie znaleziono elementu EncryptedHash")
            encrypted_hash = encrypted_hash_elem.text.strip()
            encrypted_hash_bytes = base64.b64decode(encrypted_hash.encode('utf-8'))

            # Wczytanie informacji o dokumencie
            doc_info = {
                "Size": int(root.find(".//{http://www.w3.org/2000/09/xmldsig#}Size").text.strip()),
                "Extension": root.find(".//{http://www.w3.org/2000/09/xmldsig#}Extension").text.strip(),
                "ModificationDate": root.find(".//{http://www.w3.org/2000/09/xmldsig#}ModificationDate").text.strip(),
            }

            # Wczytanie znacznika czasu
            timestamp = root.find(".//{http://www.w3.org/2000/09/xmldsig#}Timestamp").text.strip()
            
            user_name = root.find(".//{http://www.w3.org/2000/09/xmldsig#}Name").text.strip()
        except:
            messagebox.showinfo("Not a signature", "The chosen file is not a signature")
            return

        signed_file = filedialog.askopenfilename()
        # Hashowanie oryginalnego dokumentu
        with open(signed_file, "rb") as f:
            original_data = f.read()
        h = SHA256.new(original_data)

        # Weryfikacja hash dokumentu z DigestValue
        digest_value = root.find(".//{http://www.w3.org/2000/09/xmldsig#}DigestValue").text.strip()
        if base64.b64encode(h.digest()).decode('utf-8') != digest_value:
            #raise ValueError("Hash dokumentu nie zgadza się z DigestValue")
            messagebox.showinfo("Verification", "The signature is not valid")
            return

        try:
            pkcs1_15.new(self.public_key).verify(h, signature)
            messagebox.showinfo("Informacje", 
                        "Podpis cyfrowy jest poprawny.\n\n"
                        "Informacje o dokumencie:\n"
                        f"Rozmiar: {doc_info['Size']} bajtów\n"
                        f"Rozszerzenie: {doc_info['Extension']}\n"
                        f"Data modyfikacji: {doc_info['ModificationDate']}\n"
                        f"Znacznik czasu podpisu: {timestamp}\n"
                        f"Użytkownik podpisujący: {user_name}")
        except (ValueError, TypeError):
            messagebox.showinfo("Verification", "The signature is not valid")

    def basic_encryption_with_RSA_keys(self):
        file_path = filedialog.askopenfilename()
        
        with open(file_path, "rb") as f:
            file_data = f.read()

        padded_file = pad(file_data,16)

        # Klucz AES i IV
        aes_key = hashlib.sha256(self.pin.encode('utf-8')).digest()
        iv = b'This is an IV456'

        # Tworzenie obiektu szyfrującego AES
        aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        encrypted_file = aes_cipher.encrypt(padded_file)

        # Pobranie rozszerzenia pliku
        file_extension = os.path.splitext(file_path)[1]

        # Zapisanie zaszyfrowanego pliku wraz z rozszerzeniem
        with open(f"encrypted_{os.path.splitext(os.path.basename(file_path))[0]}.enc", "wb") as encrypted_key_file:
            encrypted_key_file.write(file_extension.encode('utf-8') + b'\0' + encrypted_file)

        # with open("encrypted_file.enc", "wb") as encrypted_key_file:
        #     encrypted_key_file.write(encrypted_file)

    def basic_decryption_with_RSA_keys(self):
        encrypted_file_path = filedialog.askopenfilename(filetypes=[("Pliki zaszyfrowane", "*.enc")])
        with open(encrypted_file_path, "rb") as f:
            encrypted_file_data = f.read()
        
        # Odczytanie rozszerzenia pliku
        file_extension, encrypted_file_data = encrypted_file_data.split(b'\0', 1)
        file_extension = file_extension.decode('utf-8')

        aes_key = hashlib.sha256(self.pin.encode('utf-8')).digest()
        iv = b'This is an IV456'

        aes_cipher_decrypt = AES.new(aes_key, AES.MODE_CBC, iv)
        try:
            # Deszyfrowanie klucza
            decrypted_file = unpad(aes_cipher_decrypt.decrypt(encrypted_file_data), 16).decode('utf-8')
            with open(f"decrypted_{os.path.splitext(os.path.basename(encrypted_file_path))[0]}{file_extension}", "w") as decrypted_private_key_file:
                decrypted_private_key_file.write(decrypted_file)

        except ValueError:
            # Obsługa błędu deszyfrowania
            messagebox.showerror("Error", "Incorrect PIN. Please try again.")
            return
        

def main():
    root = tk.Tk()
    app = MainApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
