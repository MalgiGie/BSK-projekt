import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog

class SignatureApp:
    def __init__(self, master):
        self.master = master
        master.title("Electronic Signature Application")

        master.geometry("400x200")

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

    def sign_document(self):
        if not hasattr(self, 'file_path') or not self.file_path:
            messagebox.showerror("Error", "Please select a file first.")
            return
        
        # Place your signing logic here

        # Odszukanie zaszyfrowanego klucza na pendrivie

        # Podanie PINu
        pin = simpledialog.askstring("PIN", "Please enter your PIN:", parent=self.master)
        if pin is None:
            # User clicked cancel
            return
        

        messagebox.showinfo("Signature", "Document signed successfully!")

def main():
    root = tk.Tk()
    app = SignatureApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
