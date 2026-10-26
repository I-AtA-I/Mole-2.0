# rat/config.py
import json
import os

from config import RAT_CONFIG_FILE

DEFAULTS = {
    "c2_host": "127.0.0.1",
    "c2_port": 4444,
    "persistence": False,
    "startup": False,
    "stealth_mode": True,
    "reconnect_interval": 30,
    "keylogger": False,
    "screenshare_port": 5555,
    "audio_port": 6666,
}


def load_rat_config():
    if not os.path.exists(RAT_CONFIG_FILE):
        return dict(DEFAULTS)

    with open(RAT_CONFIG_FILE, "r", encoding="utf-8") as f:
        try:
            user = json.load(f)
        except json.JSONDecodeError as e:
            print(f"[!] rat_config.json je rozbity: {e}")
            print("[!] Pouzivam defaulty.")
            return dict(DEFAULTS)

    cfg = dict(DEFAULTS)
    cfg.update(user)
    return cfg


def save_rat_config(cfg):
    with open(RAT_CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=4, ensure_ascii=False)