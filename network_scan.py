"""
network_scan.py — REAL, READ-ONLY device discovery.

This module only ever reads the operating system's own ARP/neighbor table
and, optionally, sends ordinary ICMP pings (the same as running `ping`) to
populate that table. It never crafts, forges, or injects ARP packets. It has
no attack capability and nothing in this file should ever gain one.
"""
import ipaddress
import platform
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass


@dataclass
class RealDevice:
    ip: str
    mac: str
    kind: str = "REAL"  # always REAL; distinguishes from sim_network.SimRouter


def get_local_ip_and_prefix():
    """Best-effort local IPv4 + /24 network, used only to know which range to ping."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))  # no data sent, just picks the outbound interface
        local_ip = s.getsockname()[0]
    finally:
        s.close()
    net = ipaddress.ip_network(local_ip + "/24", strict=False)
    return local_ip, net


def ping_sweep(net: ipaddress.IPv4Network, timeout_s: float = 0.5, workers: int = 64):
    """Ordinary ICMP ping (via the system `ping` binary) to warm the ARP cache.
    This is exactly what `ping <ip>` does — standard, legitimate, non-intrusive."""
    system = platform.system().lower()

    def ping_one(ip):
        ip = str(ip)
        if system == "windows":
            cmd = ["ping", "-n", "1", "-w", str(int(timeout_s * 1000)), ip]
        else:
            cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout_s))), ip]
        try:
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout_s + 1)
        except Exception:
            pass

    hosts = list(net.hosts())
    with ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(ping_one, hosts))


def _read_linux_neigh():
    out = subprocess.run(["ip", "neigh", "show"], capture_output=True, text=True, timeout=5).stdout
    devices = []
    for line in out.splitlines():
        # "192.168.1.1 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
        m = re.match(r"(\S+)\s+dev\s+\S+\s+lladdr\s+([0-9a-fA-F:]{17})", line)
        if m:
            devices.append(RealDevice(ip=m.group(1), mac=m.group(2).lower()))
    return devices


def _read_generic_arp_a():
    out = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=5).stdout
    devices = []
    for line in out.splitlines():
        # "? (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on wlan0"  (Linux/macOS)
        # "192.168.1.1          aa-bb-cc-dd-ee-ff     dynamic"      (Windows)
        m = re.search(r"\(?(\d{1,3}(?:\.\d{1,3}){3})\)?.*?([0-9a-fA-F]{2}([:-][0-9a-fA-F]{2}){5})", line)
        if m:
            devices.append(RealDevice(ip=m.group(1), mac=m.group(2).lower().replace("-", ":")))
    return devices


def get_real_devices(do_ping_sweep: bool = True):
    """Return the machine's real neighbor-table entries. Read-only; see module docstring."""
    if do_ping_sweep:
        try:
            _, net = get_local_ip_and_prefix()
            ping_sweep(net)
        except Exception:
            pass  # discovery still works off whatever is already cached

    system = platform.system().lower()
    devices = []
    try:
        if system == "linux":
            devices = _read_linux_neigh()
            if not devices:
                devices = _read_generic_arp_a()
        else:
            devices = _read_generic_arp_a()
    except FileNotFoundError:
        devices = []

    # de-dup by IP, drop broadcast/incomplete entries
    seen, result = set(), []
    for d in devices:
        if d.ip in seen or d.mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            continue
        seen.add(d.ip)
        result.append(d)
    return result


if __name__ == "__main__":
    for d in get_real_devices():
        print(f"{d.ip:16}  {d.mac}")
