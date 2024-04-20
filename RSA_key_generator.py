import tkinter as tk
from tkinter import messagebox
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class KeyGeneratorApp:
    def __init__(self, master):
        self.master = master
        master.title("RSA Key Generator")
        master.geometry("300x100")

        self.label = tk.Label(master, text="Enter PIN:")
        self.label.pack()

        self.pin_entry = tk.Entry(master)#, show="*")
        self.pin_entry.pack()

        self.generate_button = tk.Button(master, text="Generate Keys", command=self.generate_keys)
        self.generate_button.pack()

    def generate_keys(self):
        pin = self.pin_entry.get()

        if not pin:
            messagebox.showerror("Error", "Please enter a PIN.")
            return

        # Generowanie klucza AES z PIN
        pin_key = pin.encode() * 16 # Pad PIN to 16 bytes (AES block size)
        aes_key = AES.new(pin_key[:16], AES.MODE_EAX)

        # Generowanie kluczy RSA
        key_pair = RSA.generate(4096)
        private_key = key_pair.export_key()
        public_key = key_pair.public_key().export_key()

        # Szyfrowanie klucza prywatnego
        encrypted_private_key = aes_key.encrypt(private_key)

        # Zapis kluczy do plików
        with open("private_key.enc", "wb") as private_key_file:
            private_key_file.write(encrypted_private_key)

            # Save public key to a file
        with open("public_key.pem", "w") as public_key_file:
            public_key_file.write(public_key.decode())
        messagebox.showinfo("Success", "RSA keys generated and encrypted successfully.")

def main():
    root = tk.Tk()
    app = KeyGeneratorApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
