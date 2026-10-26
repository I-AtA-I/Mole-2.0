# modules/netscan.py
"""
Dump sitovych informaci: cmdkey, net use, wifi profily.
"""
import os
import platform
import subprocess
from datetime import datetime

from colorama import Fore


def run():
    print(Fore.YELLOW + "[*] Sber sitovych informaci...")
    sections = []

    sections.append(_cmdkey())
    sections.append(_net_use())
    sections.append(_wifi_profiles())

    _save(sections)


def _cmdkey():
    print(Fore.CYAN + "\n[1] Windows Credential Manager:")
    try:
        r = subprocess.run(["cmdkey", "/list"], capture_output=True, text=True)
    except OSError as e:
        return ("CREDENTIAL MANAGER", f"error: {e}")
    if r.stdout:
        print(Fore.GREEN + "[+] nalezeno")
        print(r.stdout)
        return ("CREDENTIAL MANAGER", r.stdout)
    print(Fore.YELLOW + "[!] zadne credentials")
    return ("CREDENTIAL MANAGER", "(none)")


def _net_use():
    print(Fore.CYAN + "\n[2] Mapped drives:")
    try:
        r = subprocess.run(["net", "use"], capture_output=True, text=True)
    except OSError as e:
        return ("MAPPED DRIVES", f"error: {e}")
    if "New connections" in r.stdout or "\\" in r.stdout:
        print(Fore.GREEN + "[+] nalezeno")
        print(r.stdout)
        return ("MAPPED DRIVES", r.stdout)
    print(Fore.YELLOW + "[!] zadne mapped drives")
    return ("MAPPED DRIVES", "(none)")


def _wifi_profiles():
    print(Fore.CYAN + "\n[3] WiFi profiles:")
    try:
        r = subprocess.run(["netsh", "wlan", "show", "profiles"],
                           capture_output=True, text=True)
    except OSError as e:
        return ("WIFI PROFILES", f"error: {e}")

    profiles = []
    for line in r.stdout.splitlines():
        if "All User Profile" in line:
            profiles.append(line.split(":", 1)[1].strip())

    if profiles:
        print(Fore.GREEN + f"[+] {len(profiles)} profilu")
        print(", ".join(profiles[:10]))
        return ("WIFI PROFILES", "\n".join(profiles))
    print(Fore.YELLOW + "[!] zadne profily")
    return ("WIFI PROFILES", "(none)")


def _save(sections):
    out_dir = os.path.join(_results_dir(), "NetScan")
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "NetScan.txt")

    with open(path, "w", encoding="utf-8") as f:
        f.write("=" * 60 + "\n")
        f.write("NETWORK INFO DUMP\n")
        f.write("=" * 60 + "\n")
        f.write(f"Time:    {datetime.now()}\n")
        f.write(f"Machine: {platform.node()}\n")
        f.write(f"User:    {os.environ.get('USERNAME', '?')}\n\n")
        for title, body in sections:
            f.write(f"\n=== {title} ===\n{body}\n")

    print(Fore.GREEN + f"\n[+] Ulozeno: {path}")


def _results_dir():
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(os.path.dirname(here), "results")