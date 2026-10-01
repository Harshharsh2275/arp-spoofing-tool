"""
packet_scanner.py — live packet metadata scanner.

Scope, deliberately:
  - METADATA ONLY: timestamp, src/dst IP, protocol, src/dst port, length.
    Payload bytes are never read, stored, or displayed. Capturing the
    *content* of someone else's traffic (credentials, messages, etc.) is
    interception of communications, which is a different and more serious
    thing than reading an ARP table or probing which ports are open — this
    module doesn't do it, even on a network you're authorized to test.
  - GATED the same way as port_scan.py: requires authorized=True.
  - BOUNDED: every capture has a time limit and a packet-count cap. No
    indefinite background sniffing.

Requires `scapy` and raw-socket privileges (run as root/sudo on Linux/macOS;
run as Administrator + have Npcap installed on Windows: https://npcap.com).
"""
import time
from dataclasses import dataclass

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    _SCAPY_AVAILABLE = True
except ImportError:
    _SCAPY_AVAILABLE = False


class NotAuthorizedError(Exception):
    pass


class ScapyNotAvailableError(Exception):
    pass


@dataclass
class PacketSummary:
    ts: float
    src: str
    dst: str
    proto: str
    sport: int | None
    dport: int | None
    length: int


def _summarize(pkt) -> PacketSummary | None:
    if IP not in pkt:
        return None
    ip = pkt[IP]
    sport = dport = None
    if TCP in pkt:
        proto, sport, dport = "TCP", pkt[TCP].sport, pkt[TCP].dport
    elif UDP in pkt:
        proto, sport, dport = "UDP", pkt[UDP].sport, pkt[UDP].dport
    elif ICMP in pkt:
        proto = "ICMP"
    else:
        proto = str(ip.proto)
    return PacketSummary(ts=time.time(), src=ip.src, dst=ip.dst, proto=proto,
                          sport=sport, dport=dport, length=len(pkt))


def scan_traffic(host: str | None = None, duration: float = 10.0, max_packets: int = 200,
                  authorized: bool = False) -> list[PacketSummary]:
    """Capture packet metadata for up to `duration` seconds or `max_packets`
    packets, whichever comes first. If `host` is given, only traffic to/from
    that IP is captured (like `tcpdump host <ip>`); otherwise all traffic on
    the default interface. Raises unless authorized=True."""
    if not authorized:
        raise NotAuthorizedError(
            "Refusing to capture packets without explicit authorization. "
            "Only sniff traffic on networks you own or have written permission to test."
        )
    if not _SCAPY_AVAILABLE:
        raise ScapyNotAvailableError(
            "scapy is not installed. Run: pip install scapy "
            "(Windows also needs Npcap installed: https://npcap.com)"
        )

    bpf_filter = f"host {host}" if host else None
    summaries: list[PacketSummary] = []

    def on_packet(pkt):
        s = _summarize(pkt)
        if s:
            summaries.append(s)

    try:
        sniff(filter=bpf_filter, prn=on_packet, store=False,
              timeout=duration, count=max_packets)
    except PermissionError as e:
        raise PermissionError(
            "Packet capture needs elevated privileges. "
            "Run as root/sudo (Linux/macOS) or as Administrator with Npcap installed (Windows)."
        ) from e
    except OSError as e:
        raise PermissionError(
            "Packet capture needs elevated privileges. "
            "Run as root/sudo (Linux/macOS) or as Administrator with Npcap installed (Windows)."
        ) from e
    except Exception as e:
        raise RuntimeError(
            f"Packet capture failed ({type(e).__name__}: {e}). "
            "Make sure libpcap (Linux/macOS) or Npcap (Windows, https://npcap.com) is installed, "
            "and that you're running with sufficient privileges."
        ) from e
    return summaries


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else None
    for s in scan_traffic(target, duration=5, authorized=True):
        print(f"{s.proto:5} {s.src:15} -> {s.dst:15} "
              f"{(s.sport or ''):>6}->{(s.dport or ''):<6} {s.length}B")
