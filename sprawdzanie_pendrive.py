import os

def sprawdz_pendrive():
    # Litera dysku pendrive'a (zmień na odpowiednią dla Twojego systemu)
    pendrive_dysk = "G:/"

    # Sprawdzenie czy pendrive jest podłączony
    if os.path.exists(pendrive_dysk):
        # Przeszukaj pliki na pendrive'ie
        for plik in os.listdir(pendrive_dysk):
            if plik.endswith(".enc"):
                print("Znaleziono plik z rozszerzeniem .enc na pendrivie.")
                return True
        print("Na pendrivie nie znaleziono pliku z rozszerzeniem .enc.")
        return False
    else:
        print("Pendrive nie jest podłączony.")
        return False

sprawdz_pendrive()
