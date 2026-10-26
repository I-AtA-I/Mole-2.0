# modules/packetcapture.py
"""
Live packet capture pres dumpcap (Wireshark).
Pocita packety ctenim PCAP struktury, ne odhadem.
"""
import os
import platform
import shutil
import struct
import subprocess
import sys
import time

from colorama import Fore

if platform.system() == "Windows":
    import msvcrt
else:
    msvcrt = None


DUMPCAP_CANDIDATES = [
    r"C:\Program Files\Wireshark\dumpcap.exe",
    r"C:\Program Files (x86)\Wireshark\dumpcap.exe",
]


def run():
    dumpcap = _find_dumpcap()
    if not dumpcap:
        print(Fore.RED + "[!] dumpcap nenalezen (nainstaluj Wireshark)")
        return

    iface = _pick_interface(dumpcap)
    if iface is None:
        return

    out_dir = os.path.join(_results_dir(), "PacketCapture")
    os.makedirs(out_dir, exist_ok=True)
    pcap_path = os.path.join(out_dir, "PacketCapture.pcap")
    if os.path.exists(pcap_path):
        os.remove(pcap_path)

    print(f"\n{'=' * 60}")
    print(f"Interface: {iface}")
    print(f"Output:    {pcap_path}")
    print(f"{'=' * 60}")

    # FIX: bez -P -> dumpcap uklada do klasickeho pcap, ne pcapng
    proc = subprocess.Popen(
        [dumpcap, "-i", iface, "-w", pcap_path, "-q"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    packet_count, duration = _live_loop(proc, pcap_path)
    _print_stats(pcap_path, packet_count, duration)


def _find_dumpcap():
    p = shutil.which("dumpcap")
    if p:
        return p
    for c in DUMPCAP_CANDIDATES:
        if os.path.exists(c):
            return c
    return None


def _pick_interface(dumpcap):
    r = subprocess.run([dumpcap, "-D"], capture_output=True, text=True)
    print("\nDostupna rozhrani:")
    print(r.stdout or r.stderr or "(zadny vystup)")
    raw = input("\nCislo rozhrani: ").strip()
    return raw or None


def _live_loop(proc, pcap_path):
    print("\n LIVE PACKET COUNTER")
    print("-" * 30)

    start = time.time()
    packet_count = 0
    last_size = 0

    try:
        while proc.poll() is None:
            size = os.path.getsize(pcap_path) if os.path.exists(pcap_path) else 0
            if size > last_size:
                packet_count = _count_packets(pcap_path)
                last_size = size

            elapsed = time.time() - start
            mins, secs = divmod(int(elapsed), 60)
            rate = packet_count / elapsed if elapsed > 0 else 0

            sys.stdout.write(
                f"\r  {mins:02d}:{secs:02d} | "
                f"packets: {packet_count:,} | "
                f"rate: {rate:.1f} pkt/s | "
                f"'q' = stop   "
            )
            sys.stdout.flush()

            if msvcrt and msvcrt.kbhit():
                key = msvcrt.getch()
                if key in (b"q", b"Q"):
                    print("\n\n'q' -> ukoncuji capture...")
                    break

            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n\nCtrl+C -> ukoncuji...")

    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

    duration = time.time() - start
    packet_count = _count_packets(pcap_path)
    return packet_count, duration


def _count_packets(pcap_path):
    """Vrati pocet packetu v PCAP souboru (nebo 0, kdyz jeste neni)."""
    if not os.path.exists(pcap_path):
        return 0

    try:
        with open(pcap_path, "rb") as f:
            magic = f.read(4)
            if len(magic) < 4:
                return 0

            # FIX: magic urcuje endian; pcapng detekujeme a varujeme
            if magic == b"\xd4\xc3\xb2\xa1":
                endian = "<"
            elif magic == b"\xa1\xb2\xc3\xd4":
                endian = ">"
            elif magic == b"\x0a\x0d\x0d\x0a":
                # pcapng - jiny format, tady nepocitame
                return 0
            else:
                return 0

            count = 0
            while True:
                header = f.read(16)
                if len(header) < 16:
                    break
                incl_len = struct.unpack(endian + "I", header[8:12])[0]
                f.seek(incl_len, 1)
                count += 1
            return count
    except OSError:
        return 0


def _print_stats(pcap_path, packet_count, duration):
    print(f"\n\n{'=' * 60}")
    print("STATS")
    print(f"{'=' * 60}")

    mins, secs = divmod(int(duration), 60)
    print(f"Duration:  {mins:02d}:{secs:02d}")
    print(f"Packets:   {packet_count:,}")

    if os.path.exists(pcap_path):
        size = os.path.getsize(pcap_path)
        print(f"File size: {size:,} B ({size / 1024 / 1024:.2f} MB)")

        if duration > 0 and packet_count > 0:
            print(f"Avg pkt:   {size / packet_count:.0f} B")
            print(f"Pkt rate:  {packet_count / duration:.1f} pkt/s")
            print(f"Data rate: {size * 8 / duration / 1_000_000:.2f} Mbps")

    print(f"File:      {pcap_path}")
    print(f"{'=' * 60}")


def _results_dir():
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(os.path.dirname(here), "results")