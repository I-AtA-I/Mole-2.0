# modules/portopener.py
"""
Vypne firewall + Defender a otevre vsechny porty.
"""
import subprocess
from colorama import Fore


def run():
    print(Fore.RED + "!!! Toto vypne firewall a Defender a otevre vsechny porty !!!")
    if input("Pokracovat? y/n: ").strip().lower() != "y":
        print("Zruseno.")
        return

    commands = [
        ("Firewall off", "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False"),
        ("Defender realtime off", "Set-MpPreference -DisableRealtimeMonitoring $true"),
        ("Defender service disabled", "sc config MpsSvc start= disabled"),
        ("Defender service stopped", "net stop MpsSvc"),
        ("Delete all firewall rules", "netsh advfirewall firewall delete rule name=all"),
        ("Open all inbound TCP", 'netsh advfirewall firewall add rule name="OPEN_TCP_IN" dir=in action=allow protocol=TCP localport=1-65535'),
        ("Open all inbound UDP", 'netsh advfirewall firewall add rule name="OPEN_UDP_IN" dir=in action=allow protocol=UDP localport=1-65535'),
        ("Open all inbound", 'netsh advfirewall firewall add rule name="OPEN_ALL_IN" dir=in action=allow protocol=any'),
        ("Open all outbound", 'netsh advfirewall firewall add rule name="OPEN_ALL_OUT" dir=out action=allow protocol=any'),
    ]

    for label, cmd in commands:
        print(Fore.YELLOW + f"[*] {label}...")
        # PowerShell prikazy jdou pres powershell, netsh/sc jdou pres cmd
        if cmd.startswith(("Set-", "sc ", "net ")):
            subprocess.run(["powershell", "-NoProfile", "-Command", cmd],
                           capture_output=True)
        else:
            subprocess.run(cmd, shell=True, capture_output=True)

    print(Fore.GREEN + "[+] Hotovo.")