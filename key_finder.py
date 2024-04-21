import os
import psutil
from tkinter import messagebox

class KeyFinder:
    def detect_usb_drives(self):
        usb_drives = []
        all_partitions = psutil.disk_partitions()
        
        for partition in all_partitions:
            if 'removable' in partition.opts:
                usb_drives.append(partition.mountpoint)
        
        return usb_drives

    def search_encrypted_file(self, usb_drives):
        for drive in usb_drives:
            for root, dirs, files in os.walk(drive):
                for file in files:
                    if file.endswith('.enc'):
                        return os.path.join(root, file)
        return None
    
    def find_encrypted_key_file(self):
        usb_drives = self.detect_usb_drives()
        if usb_drives:
            encrypted_file_path = self.search_encrypted_file(usb_drives)
            if encrypted_file_path:
                return encrypted_file_path
            else:
                messagebox.showerror("Error", "Could not find any .enc file")
                return ""
        else:
            messagebox.showerror("Error", "Please connect the pendrive with the encrypted key first")
            return ""
    
if __name__ == "__main__":
    key_finder = KeyFinder()
    print(key_finder.find_encrypted_key_file())
