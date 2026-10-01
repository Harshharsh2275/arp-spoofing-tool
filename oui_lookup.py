"""
oui_lookup.py — resolve a MAC address's vendor from its OUI (first 3 bytes).

Ships a small built-in table covering common vendors. For full coverage,
download the IEEE public OUI list (https://standards-oui.ieee.org/oui/oui.csv)
and point OUI_CSV_PATH at it — this module only reads that file locally, it
never fetches it itself.
"""
import csv
import os

OUI_CSV_PATH = os.environ.get("OUI_CSV_PATH", "")

_BUILTIN = {
    "00:1A:11": "Google",
    "3C:5A:B4": "Google",
    "F4:F5:D8": "Google",
    "AC:DE:48": "Apple",
    "00:1C:B3": "Apple",
    "F0:18:98": "Apple",
    "00:16:CB": "Apple",
    "00:1B:63": "Apple",
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Foundation",
    "00:0C:29": "VMware (virtual NIC)",
    "00:50:56": "VMware (virtual NIC)",
    "08:00:27": "VirtualBox (virtual NIC)",
    "00:1D:D8": "Microsoft",
    "00:15:5D": "Microsoft Hyper-V (virtual NIC)",
    "00:09:5B": "Netgear",
    "20:E5:2A": "Netgear",
    "00:1F:33": "Netgear",
    "00:24:B2": "TP-Link",
    "50:C7:BF": "TP-Link",
    "EC:08:6B": "TP-Link",
    "00:26:5A": "D-Link",
    "1C:7E:E5": "D-Link",
    "00:18:39": "Cisco",
    "00:1B:D4": "Cisco",
    "00:26:99": "Samsung",
    "5C:0A:5B": "Samsung",
    "02:00:00": "Locally administered (virtual/simulated)",
}

_csv_cache = None


def _load_csv():
    global _csv_cache
    if _csv_cache is not None:
        return _csv_cache
    table = {}
    if OUI_CSV_PATH and os.path.isfile(OUI_CSV_PATH):
        try:
            with open(OUI_CSV_PATH, newline="", encoding="utf-8", errors="ignore") as f:
                for row in csv.reader(f):
                    if len(row) >= 3 and len(row[1]) == 6:
                        prefix = ":".join(row[1][i:i+2] for i in range(0, 6, 2)).upper()
                        table[prefix] = row[2]
        except Exception:
            pass
    _csv_cache = table
    return table


def vendor_for_mac(mac: str) -> str:
    """mac like 'aa:bb:cc:dd:ee:ff' -> vendor name, or 'Unknown vendor'."""
    prefix = ":".join(mac.upper().split(":")[:3])
    table = _load_csv()
    if prefix in table:
        return table[prefix]
    if prefix in _BUILTIN:
        return _BUILTIN[prefix]
    # locally administered bit set (2nd hex digit of first byte is 2/6/a/e)
    first_byte = prefix.split(":")[0]
    if len(first_byte) == 2 and first_byte[1].upper() in "26AE":
        return "Locally administered (virtual/randomized)"
    return "Unknown vendor"
