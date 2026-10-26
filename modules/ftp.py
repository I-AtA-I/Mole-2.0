# modules/ftp.py
"""
FTP pripojeni pres ftp.exe (soucast Windows).
"""
import subprocess
from colorama import Fore


def run():
    user = input("FTP user: ").strip()
    host = input("FTP host: ").strip()

    print(Fore.YELLOW + f"[*] Pripojuji na {host} jako {user}")
    print(Fore.YELLOW + "[*] (ftp.exe se zepta na heslo)")

    # ftp.exe chce: open host -> user -> pass
    # PowerShell neni potreba, staci cmd
    subprocess.run(["ftp", "-n", host], shell=False)
    # Pozn.: -n zakaze auto-login, uzivatel zada user/pass rucne.
    # Pokud chces automaticky, pridej "-s:script.txt" s 'user' a 'pass'.