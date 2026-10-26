# modules/wificrack.py
"""
Extrakce WiFi hesel pres netsh wlan export profile key=clear.
"""
import glob
import json
import os
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET

from colorama import Fore


def run():
    print(Fore.YELLOW + "[*] Extrahuji WiFi profily...")

    tmpdir = tempfile.mkdtemp(prefix="wifi_")
    try:
        r = subprocess.run(
            ["netsh", "wlan", "export", "profile", "key=clear", f"folder={tmpdir}"],
            capture_output=True, text=True,
        )
        if "successfully" not in r.stdout.lower():
            print(Fore.RED + f"[!] netsh selhal: {r.stderr or r.stdout}")
            return

        entries = _parse_profiles(tmpdir)
        if not entries:
            print(Fore.YELLOW + "[!] Zadna hesla nenalezena")
            return

        for e in entries:
            print(Fore.CYAN + f"\n  SSID: {e['ssid']}")
            print(Fore.GREEN + f"  Pass: {e['password']}")

        _save(entries)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def _parse_profiles(folder):
    out = []
    for xml_path in glob.glob(os.path.join(folder, "*.xml")):
        try:
            tree = ET.parse(xml_path)
        except ET.ParseError:
            continue

        root = tree.getroot()
        # <WLANProfile><name>SSID</name><MSM>...<keyMaterial>pass</keyMaterial>
        ssid_el = root.find("name")
        key_el = root.find(".//keyMaterial")
        if ssid_el is None or key_el is None:
            continue
        if not ssid_el.text or not key_el.text:
            continue

        out.append({"ssid": ssid_el.text, "password": key_el.text})
    return out


def _save(entries):
    out_dir = os.path.join(_results_dir(), "WifiCrack")
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "WifiCrack.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=4, ensure_ascii=False)
    print(Fore.GREEN + f"\n[+] Ulozeno: {path} ({len(entries)} siti)")


def _results_dir():
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(os.path.dirname(here), "results")