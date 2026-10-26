# menu.py
import shutil
import time

from colorama import Fore, Back, Style

from utils import clear
from actions import (
    action_scan, action_result, action_help,
    action_rat, action_hook, action_ssh, action_ftp,
    action_ping, action_diskfill, action_diskhost,
    action_addadmin, action_passexport, action_forkbomb,
    action_portopener, action_packetcapture, action_venom,
    action_deletelog, action_wificrack, action_netscan,
    action_allpass, action_credscan, action_regsave,
    action_cleanup, action_info,
)

ACTIONS = {
    "result":       ("Print current machine scan outcome", action_result),
    "scan":         ("Scan this machine", action_scan),
    "addadmin":     ("Generate a new admin account", action_addadmin),

    "ftp":          ("Attempt a FTP connection", action_ftp),
    "ping":         ("Check IP connectivity", action_ping),
    "diskfill":     ("Fill disk space", action_diskfill),
    "diskhost":     ("Host a folder on port 8100", action_diskhost),
    "passexport":   ("Export Chrome passwords", action_passexport),
    "deletelog":    ("Delete logger.log", action_deletelog),
    "netscan":      ("Basic netscan of local network", action_netscan),
    "allpass":      ("Export all found saved passwords", action_allpass),
    "credscan":     ("Scan for credentials in files", action_credscan),
    "regsave":      ("Save a registry hive", action_regsave),

    "forkbomb":     ("Attempt a forkbomb", action_forkbomb),
    "portopener":   ("Disable firewall & defender", action_portopener),
    "packetcapture":("Capture network packets", action_packetcapture),
    "venom":        ("Run a Venom payload", action_venom),
    "wificrack":    ("Attempt to crack WiFi passwords", action_wificrack),
    "hook":         ("Hook this machine via BeEF", action_hook),

    "rat":          ("Deploy Meterpreter-style RAT", action_rat),
    "ssh":          ("Start SSH server on target machine", action_ssh),

    "info":         ("Show details of a command", action_info),
    "cleanup":      ("Remove results created by the program", action_cleanup),
    "help":         ("Show available actions", action_help),
    "exit":         ("Exit the program", None),
}

CATEGORIES = {
    "System & Scan":       ["result", "scan", "addadmin"],
    "Utilities":           ["ftp", "ping", "diskfill", "diskhost", "passexport",
                            "deletelog", "netscan", "allpass", "credscan", "regsave"],
    "Critical Operations": ["forkbomb", "portopener", "packetcapture", "venom",
                            "wificrack", "hook"],
    "Remote Access":       ["rat", "ssh"],
    "Support & Exit":      ["info", "cleanup", "help", "exit"],
}


def print_line(char="="):
    width = shutil.get_terminal_size((80, 20)).columns
    print(char * width)


def print_menu():
    for category, keys in CATEGORIES.items():
        print(Back.BLACK + Fore.MAGENTA + Style.BRIGHT + f" {category} " + Style.RESET_ALL)
        print(Fore.LIGHTBLACK_EX + "-" * len(category))
        for key in keys:
            desc, _ = ACTIONS[key]
            print(Fore.WHITE + f"  {key:<14} - {desc}")
        print()


def run_menu():
    while True:
        clear()
        print_menu()
        print_line()

        raw = input(Fore.MAGENTA + "M0L€> " + Fore.RESET).strip()
        cmd = raw.lower()

        if cmd == "exit":
            print("Exiting...")
            time.sleep(2)
            return

        entry = ACTIONS.get(cmd)
        if not entry:
            print(Fore.RED + f"Neznamy prikaz: {raw}")
            time.sleep(1)
            continue

        _, handler = entry
        try:
            handler()
        except KeyboardInterrupt:
            print(Fore.YELLOW + "\n[!] Preruseno")
        except Exception as e:
            print(Fore.RED + f"[!] Chyba: {e}")

        clear()