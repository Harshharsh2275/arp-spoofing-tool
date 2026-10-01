"""
port_scan.py — TCP connect scan + banner grab.

Requires authorized=True on every call. This module will not scan anything
unless the caller has explicitly set that flag — the UI asks you to confirm
you own or have permission to test the target network before it does.
No exploitation, no evasion techniques, just: connect, read what the
service says back, note whether the port answered.
"""
import socket
from concurrent.futures import ThreadPoolExecutor

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 3306: "MySQL", 3389: "RDP", 5900: "VNC", 8080: "HTTP-alt",
}


class NotAuthorizedError(Exception):
    pass


def _scan_one(ip, port, timeout):
    result = {"port": port, "service": COMMON_PORTS.get(port, "?"), "open": False, "banner": None}
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            result["open"] = True
            s.settimeout(timeout)
            try:
                banner = s.recv(128)
                result["banner"] = banner.decode(errors="replace").strip() or None
            except (socket.timeout, OSError):
                pass  # plenty of services don't send anything until you speak first
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass
    return result


def scan_host(ip: str, ports=None, timeout: float = 0.6, authorized: bool = False, max_workers: int = 32):
    """Scan `ip` on `ports` (default: COMMON_PORTS). Raises NotAuthorizedError
    unless authorized=True — the caller must have confirmed permission first."""
    if not authorized:
        raise NotAuthorizedError(
            "Refusing to port-scan without explicit authorization. "
            "Only scan devices/networks you own or have written permission to test."
        )
    ports = ports or list(COMMON_PORTS.keys())
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        results = list(ex.map(lambda p: _scan_one(ip, p, timeout), ports))
    return [r for r in results if r["open"]] + [r for r in results if not r["open"]]


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    for r in scan_host(target, authorized=True):
        if r["open"]:
            print(f"{r['port']:5} {r['service']:10} OPEN  banner={r['banner']!r}")
