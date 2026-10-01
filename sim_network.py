"""
sim_network.py — fully virtual routers. These are the ONLY valid targets for
arp_attack_sim.py. Each SimRouter is a local TCP server on 127.0.0.1 with a
made-up IP/MAC identity and its own ARP cache; nothing here touches your
real network interface or real traffic.
"""
import json
import random
import socket
import threading
import time
from dataclasses import dataclass, field


def _fake_mac():
    return "02:" + ":".join(f"{random.randint(0,255):02x}" for _ in range(5))


@dataclass
class ArpEvent:
    ts: float
    router_id: str
    claimed_ip: str
    old_mac: str
    new_mac: str
    source: str  # "legit" or "attacker"


@dataclass
class SimRouter:
    router_id: str
    virtual_ip: str
    virtual_mac: str
    port: int
    kind: str = "SIM"  # always SIM; this is what arp_attack_sim checks for
    arp_cache: dict = field(default_factory=dict)   # ip -> mac, this router's own view
    log: list = field(default_factory=list)          # list[ArpEvent], for the ML defender later
    _sock: socket.socket = field(default=None, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", self.port))
        self._sock.listen()
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def _accept_loop(self):
        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        f = conn.makefile("r", encoding="utf-8")
        try:
            for line in f:
                msg = json.loads(line)
                self._process(msg, conn)
        except OSError:
            pass
        finally:
            conn.close()

    def _process(self, msg, conn):
        # ARP_ANNOUNCE: "here is the mac for this ip" — legit hosts or the attacker both use this,
        # exactly like real ARP has no authentication, which is the whole point of the lab.
        if msg.get("type") == "ARP_ANNOUNCE":
            ip, mac = msg["ip"], msg["mac"]
            source = msg.get("source", "legit")
            with self._lock:
                old = self.arp_cache.get(ip)
                self.arp_cache[ip] = mac
                self.log.append(ArpEvent(time.time(), self.router_id, ip, old or "", mac, source))
            conn.sendall((json.dumps({"type": "ACK"}) + "\n").encode())
        elif msg.get("type") == "GET_CACHE":
            with self._lock:
                cache = dict(self.arp_cache)
            conn.sendall((json.dumps({"type": "CACHE", "cache": cache}) + "\n").encode())


class SimNetwork:
    """A handful of fake routers, each reachable on its own localhost port."""

    def __init__(self, n_routers: int = 2, base_port: int = 9500):
        self.routers: list[SimRouter] = []
        for i in range(n_routers):
            r = SimRouter(
                router_id=f"sim-router-{i+1}",
                virtual_ip=f"10.66.0.{i+1}",
                virtual_mac=_fake_mac(),
                port=base_port + i,
            )
            r.start()
            self.routers.append(r)

    def as_list(self):
        return self.routers
