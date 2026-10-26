# utils.py
import hashlib
import logging
import os
import subprocess


def clear():
    os.system("cls" if os.name == "nt" else "clear")


def hash_pw(pw):
    return hashlib.sha256(pw.encode("utf-8")).hexdigest()


def setup_logging(enabled):
    if not enabled:
        return
    logging.basicConfig(
        filename="logger.log",
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )


def run_ps(command):
    """Spusti PowerShell prikaz a pocka na dokonceni."""
    ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    env = os.environ.copy()
    env["PATH"] += r";C:\Windows\System32\OpenSSH"
    proc = subprocess.Popen([ps, "-NoProfile", "-Command", command], env=env)
    proc.wait()