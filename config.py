# config.py
import os
import json

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(BASE_DIR, "results")
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")
RAT_CONFIG_FILE = os.path.join(BASE_DIR, "rat_config.json")

# heslo: env promenna pro dev, jinak se zepta
# (v produkci by mel byt hash v config.json, ne tady)
PASSWORD_ENV = "MOLE_PASSWORD"

def load_json(path, default=None):
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return default

def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

os.makedirs(RESULTS_DIR, exist_ok=True)