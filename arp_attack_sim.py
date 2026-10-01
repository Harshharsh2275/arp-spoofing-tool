"""
arp_attack_sim.py — the spoofing attack, restricted to SimRouter targets.

attack_router() type-checks its target and raises if it isn't a SimRouter,
so this code cannot be pointed at a real device on your LAN even by
accident. It sends forged ARP_ANNOUNCE messages to the simulated router's
own local socket, exactly the way sim_network.py expects legit hosts to
announce themselves — the attack's realism is that the protocol has no
authentication, same as real ARP.
"""
import json
import socket
import threading
import time

from sim_network import SimRouter, _fake_mac


class ArpAttack:
    def __init__(self, router: SimRouter, victim_ip: str, interval_s: float = 1.0):
        if not isinstance(router, SimRouter) or router.kind != "SIM":
            raise TypeError("ArpAttack only accepts a SimRouter target — refusing to run against anything else.")
        self.router = router
        self.victim_ip = victim_ip
        self.interval_s = interval_s
        self.attacker_mac = _fake_mac()
        self._stop = threading.Event()
        self._thread = None

    def _loop(self):
        sock = socket.create_connection(("127.0.0.1", self.router.port))
        f = sock.makefile("r", encoding="utf-8")
        try:
            while not self._stop.is_set():
                msg = {"type": "ARP_ANNOUNCE", "ip": self.victim_ip,
                       "mac": self.attacker_mac, "source": "attacker"}
                sock.sendall((json.dumps(msg) + "\n").encode())
                f.readline()  # ACK
                time.sleep(self.interval_s)
        finally:
            sock.close()

    def start(self):
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)


def announce_legit(router: SimRouter, ip: str, mac: str):
    """Helper for a 'real' host to legitimately claim its IP/MAC with a sim router,
    so there's a baseline before the attacker overwrites it."""
    sock = socket.create_connection(("127.0.0.1", router.port))
    f = sock.makefile("r", encoding="utf-8")
    sock.sendall((json.dumps({"type": "ARP_ANNOUNCE", "ip": ip, "mac": mac, "source": "legit"}) + "\n").encode())
    f.readline()
    sock.close()
