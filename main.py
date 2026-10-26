# main.py
import os
import sys
import time
from getpass import getpass

from colorama import init, Fore

from config import CONFIG_FILE, PASSWORD_ENV, load_json, save_json
from utils import clear, hash_pw, setup_logging

init(autoreset=True)


def get_password_hash():
    data = load_json(CONFIG_FILE)
    if data and "password_hash" in data:
        return data["password_hash"]

    pw = getpass("Set a new password: ")
    hashed = hash_pw(pw)
    save_json(CONFIG_FILE, {"password_hash": hashed})
    print("Password saved.")
    return hashed


def authenticate():
    stored = get_password_hash()

    dev_pw = os.environ.get(PASSWORD_ENV)
    if dev_pw and hash_pw(dev_pw) == stored:
        print("Access granted (env).")
        return

    while True:
        pw = getpass("Enter password: ")
        if hash_pw(pw) == stored:
            print("Access granted.")
            return
        print("Incorrect password.")


def ask_logging():
    enabled = os.environ.get("MOLE_LOG", "").lower() in ("1", "y", "yes", "true")
    setup_logging(enabled)
    return enabled


def banner():
    art = r"""
 __  __	 ____  _      ______
|  \/  |/ __ \| |    |  ____|
| \  / | |  | | |    | |__
| |\/| | |  | | |    |  __|
| |  | | |__| | |____| |____
|_|  |_|\____/|______|______|
    """
    print(Fore.RED + art)
    time.sleep(2)
    print()


def main():
    clear()
    authenticate()
    ask_logging()
    clear()
    banner()

    print(Fore.YELLOW + "!!! Tento program je potreba spustit z CMD s admin opravnenim !!!")
    time.sleep(4)
    clear()

    from menu import run_menu
    run_menu()


if __name__ == "__main__":
    main()