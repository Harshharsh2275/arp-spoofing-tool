"""
arp_monitor.py — persistent IP->MAC history with change / flip-flop / new-device
detection on REAL scan results. This is the defensive counterpart to
sim_network.py's ArpEvent log: same shape, so later ML code can train on
either source. Read-only — it only records what network_scan.py observed.
"""
import json
import os
import time
from collections import deque
from dataclasses import dataclass, asdict, field


@dataclass
class MonitorEvent:
    ts: float
    ip: str
    old_mac: str
    new_mac: str
    kind: str  # "new_device" | "mac_changed" | "flip_flop"


class ArpMonitor:
    def __init__(self, history_file: str = "arp_history.json", flip_window_s: float = 60.0, flip_threshold: int = 3):
        self.history_file = history_file
        self.flip_window_s = flip_window_s
        self.flip_threshold = flip_threshold
        self.current: dict[str, str] = {}              # ip -> latest mac
        self.recent_changes: dict[str, deque] = {}       # ip -> deque[(ts, mac)]
        self.events: list[MonitorEvent] = []
        self._load()

    def _load(self):
        if os.path.isfile(self.history_file):
            try:
                with open(self.history_file) as f:
                    data = json.load(f)
                self.current = data.get("current", {})
            except Exception:
                pass

    def _save(self):
        try:
            with open(self.history_file, "w") as f:
                json.dump({"current": self.current}, f, indent=2)
        except Exception:
            pass

    def observe(self, ip: str, mac: str):
        """Feed one real (ip, mac) reading. Returns a MonitorEvent or None."""
        now = time.time()
        dq = self.recent_changes.setdefault(ip, deque())

        old_mac = self.current.get(ip)
        event = None
        if old_mac is None:
            event = MonitorEvent(now, ip, "", mac, "new_device")
        elif old_mac != mac:
            dq.append((now, mac))
            while dq and now - dq[0][0] > self.flip_window_s:
                dq.popleft()
            distinct = len({m for _, m in dq})
            kind = "flip_flop" if distinct >= self.flip_threshold else "mac_changed"
            event = MonitorEvent(now, ip, old_mac, mac, kind)

        self.current[ip] = mac
        if event:
            self.events.append(event)
        return event

    def observe_many(self, devices):
        """devices: iterable of objects/tuples with .ip/.mac or (ip, mac)."""
        out = []
        for d in devices:
            ip, mac = (d.ip, d.mac) if hasattr(d, "ip") else d
            ev = self.observe(ip, mac)
            if ev:
                out.append(ev)
        self._save()
        return out

    def export_events(self, path: str):
        with open(path, "w") as f:
            json.dump([asdict(e) for e in self.events], f, indent=2)
