#!/usr/bin/env python3
"""
main.py — ARP lab entry point.

Starts a small simulated router network, scans real devices on your LAN
(read-only), and opens the arrow-key menu. Only [SIM] entries can be
attacked; [REAL] entries are informational.
"""
from network_scan import get_real_devices
from sim_network import SimNetwork
from wifi_info import get_wifi_name
import ui

BANNER = """
This tool can port-scan real devices on your current network.
Only continue if you own this network, or have explicit permission
(e.g. a classroom/lab network set up for this purpose) to test it.
"""

if __name__ == "__main__":
    print(BANNER)
    ssid = get_wifi_name()
    print(f"Currently connected network: {ssid or '(not available / not on Wi-Fi)'}")
    answer = input("Confirm you are authorized to scan this network? [y/N]: ").strip().lower()
    authorized = answer in ("y", "yes")
    if not authorized:
        print("Continuing without authorization — port scanning will be disabled for this session.\n")

    print("Discovering real devices (read-only ARP/neighbor table)...")
    real_devices = get_real_devices(do_ping_sweep=True)
    print(f"Found {len(real_devices)} real device(s). Starting simulated routers...")

    sim_net = SimNetwork(n_routers=2)
    ui.launch(sim_net, real_devices, authorized=authorized, ssid=ssid)
