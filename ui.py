"""
ui.py — interactive arrow-key terminal menu.

Lists real devices (tagged [REAL], view-only) above simulated routers
(tagged [SIM], selectable for the attack demo). Up/Down to move, Enter to
select, 'q' to quit a screen.
"""
import curses
import time

from network_scan import RealDevice, get_real_devices
from sim_network import SimNetwork, SimRouter
from arp_attack_sim import ArpAttack, announce_legit
from arp_monitor import ArpMonitor
from oui_lookup import vendor_for_mac
from port_scan import scan_host, NotAuthorizedError
from packet_scanner import scan_traffic, ScapyNotAvailableError


def _safe_addstr(stdscr, y, x, text, attr=0):
    """addstr that never crashes: clips to the window width and swallows the
    ERR that (mainly Windows) curses raises when a cell right at the bottom-right
    corner gets written to — a known curses quirk, not a real error."""
    max_y, max_x = stdscr.getmaxyx()
    if y < 0 or y >= max_y or x < 0 or x >= max_x:
        return
    clipped = text[: max_x - x - 1] if max_x - x - 1 >= 0 else ""
    try:
        stdscr.addstr(y, x, clipped, attr)
    except curses.error:
        pass


def _menu(stdscr, title, items, render):
    idx, top = 0, 0
    curses.curs_set(0)
    while True:
        stdscr.clear()
        max_y, max_x = stdscr.getmaxyx()
        _safe_addstr(stdscr, 0, 0, title, curses.A_BOLD)
        _safe_addstr(stdscr, 1, 0, "↑/↓ move   Enter select   q quit", curses.A_DIM)

        visible_rows = max(1, max_y - 3)  # rows 3..max_y-1 are available for items
        if idx < top:
            top = idx
        elif idx >= top + visible_rows:
            top = idx - visible_rows + 1

        for row, i in enumerate(range(top, min(len(items), top + visible_rows))):
            attr = curses.A_REVERSE if i == idx else curses.A_NORMAL
            _safe_addstr(stdscr, 3 + row, 2, render(items[i]), attr)

        stdscr.refresh()
        key = stdscr.getch()
        if key in (curses.KEY_UP, ord('k')):
            idx = (idx - 1) % len(items)
        elif key in (curses.KEY_DOWN, ord('j')):
            idx = (idx + 1) % len(items)
        elif key in (10, 13, curses.KEY_ENTER):
            return items[idx]
        elif key == ord('q'):
            return None


def _router_submenu(stdscr, router: SimRouter):
    # give it a plausible legit host first, so there's a baseline to hijack
    announce_legit(router, "10.66.0.50", "aa:bb:cc:00:00:50")
    attack = None
    while True:
        cache = router.arp_cache
        title = f"{router.router_id}  ({router.virtual_ip})  — cache size {len(cache)}"
        lines = [f"{ip} -> {mac}" for ip, mac in cache.items()]
        options = ["Start ARP spoof attack on 10.66.0.50" if not attack else "Stop attack",
                   "View live ARP cache (5s)", "Back"]
        choice = _menu(stdscr, title, options, lambda x: x)
        if choice is None or choice == "Back":
            if attack:
                attack.stop()
            return
        if choice.startswith("Start"):
            attack = ArpAttack(router, victim_ip="10.66.0.50", interval_s=1.0)
            attack.start()
        elif choice.startswith("Stop"):
            attack.stop()
            attack = None
        elif choice.startswith("View"):
            stdscr.clear()
            _safe_addstr(stdscr, 0, 0, "watching cache for 5s...", curses.A_BOLD)
            stdscr.refresh()
            end = time.time() + 5
            while time.time() < end:
                stdscr.clear()
                _safe_addstr(stdscr, 0, 0, f"{router.router_id} ARP cache (live)", curses.A_BOLD)
                for i, (ip, mac) in enumerate(router.arp_cache.items()):
                    _safe_addstr(stdscr, 2 + i, 2, f"{ip} -> {mac}")
                stdscr.refresh()
                time.sleep(0.3)


def _show_text_screen(stdscr, title, lines):
    stdscr.clear()
    _safe_addstr(stdscr, 0, 0, title, curses.A_BOLD)
    max_y, _ = stdscr.getmaxyx()
    visible = max(0, max_y - 4)  # leave room for title + footer
    for i, line in enumerate(lines[:visible]):
        _safe_addstr(stdscr, 2 + i, 2, line)
    if len(lines) > visible:
        _safe_addstr(stdscr, 2 + visible, 2, f"... and {len(lines) - visible} more (resize terminal to see all)", curses.A_DIM)
    _safe_addstr(stdscr, min(2 + len(lines) + 1, max_y - 1), 0, "press any key to go back", curses.A_DIM)
    stdscr.refresh()
    stdscr.getch()


def _real_device_submenu(stdscr, dev: RealDevice, monitor: ArpMonitor, authorized: bool):
    while True:
        title = f"[REAL] {dev.ip}  ({dev.mac}) — not attackable"
        options = ["Vendor / hostname lookup", "Port scan (common ports)",
                    "Sniff traffic (10s, metadata only)", "View this device's history", "Back"]
        choice = _menu(stdscr, title, options, lambda x: x)
        if choice is None or choice == "Back":
            return

        if choice == "Vendor / hostname lookup":
            vendor = vendor_for_mac(dev.mac)
            try:
                import socket
                hostname = socket.gethostbyaddr(dev.ip)[0]
            except Exception:
                hostname = "(no reverse DNS entry)"
            _show_text_screen(stdscr, f"{dev.ip} details", [
                f"MAC:      {dev.mac}",
                f"Vendor:   {vendor}",
                f"Hostname: {hostname}",
            ])

        elif choice == "Port scan (common ports)":
            stdscr.clear()
            _safe_addstr(stdscr, 0, 0, f"scanning {dev.ip} ...", curses.A_BOLD)
            stdscr.refresh()
            try:
                results = scan_host(dev.ip, authorized=authorized)
                open_ports = [r for r in results if r["open"]]
                lines = [f"{r['port']:5} {r['service']:10} banner={r['banner']!r}" for r in open_ports] \
                        or ["(no open ports found among common ports)"]
            except NotAuthorizedError as e:
                lines = [str(e)]
            _show_text_screen(stdscr, f"{dev.ip} open ports", lines)

        elif choice == "Sniff traffic (10s, metadata only)":
            stdscr.clear()
            _safe_addstr(stdscr, 0, 0, f"capturing traffic for {dev.ip} (10s, metadata only)...", curses.A_BOLD)
            stdscr.refresh()
            try:
                packets = scan_traffic(dev.ip, duration=10.0, max_packets=200, authorized=authorized)
                lines = [f"{time.strftime('%H:%M:%S', time.localtime(p.ts))} {p.proto:5} "
                         f"{p.src:15} -> {p.dst:15} "
                         f"{(str(p.sport) if p.sport else '-'):>6}->{(str(p.dport) if p.dport else '-'):<6} "
                         f"{p.length}B" for p in packets] or ["(no packets captured in this window)"]
            except (NotAuthorizedError, ScapyNotAvailableError, PermissionError, RuntimeError) as e:
                lines = [str(e)]
            _show_text_screen(stdscr, f"{dev.ip} traffic (last 10s)", lines)

        elif choice == "View this device's history":
            evs = [e for e in monitor.events if e.ip == dev.ip]
            lines = [f"{time.strftime('%H:%M:%S', time.localtime(e.ts))}  {e.kind:10}  {e.old_mac or '-':17} -> {e.new_mac}"
                     for e in evs] or ["(no changes recorded yet for this IP)"]
            _show_text_screen(stdscr, f"{dev.ip} change history", lines)


def _alerts_screen(stdscr, monitor: ArpMonitor):
    interesting = [e for e in monitor.events if e.kind in ("mac_changed", "flip_flop")]
    lines = [f"{time.strftime('%H:%M:%S', time.localtime(e.ts))}  {e.kind:10}  {e.ip:16} {e.old_mac} -> {e.new_mac}"
             for e in interesting] or ["(no MAC changes observed yet — rescan to check again)"]
    _show_text_screen(stdscr, "Alerts — MAC changes / flip-flops on real devices", lines)


def run(stdscr, sim_net: SimNetwork, real_devices, authorized: bool, ssid: str | None):
    monitor = ArpMonitor()
    monitor.observe_many(real_devices)

    def build_entries(devices):
        return [("REAL", d) for d in devices] + [("SIM", r) for r in sim_net.as_list()] \
               + [("ACTION", "Rescan real devices"), ("ACTION", "View alerts")]

    entries = build_entries(real_devices)

    def render(entry):
        kind, obj = entry
        if kind == "REAL":
            return f"[REAL] {obj.ip:16} {obj.mac}"
        if kind == "SIM":
            return f"[SIM]  {obj.router_id:16} {obj.virtual_ip}  (attackable)"
        return f"[...]  {obj}"

    while True:
        title = f"Network: {ssid or '(unknown)'}  —  Network Discovery  (real + simulated)"
        if not authorized:
            title += "  — port scanning disabled (not authorized)"
        choice = _menu(stdscr, title, entries, render)
        if choice is None:
            return
        kind, obj = choice
        if kind == "REAL":
            _real_device_submenu(stdscr, obj, monitor, authorized)
        elif kind == "SIM":
            _router_submenu(stdscr, obj)
        elif obj == "Rescan real devices":
            stdscr.clear()
            _safe_addstr(stdscr, 0, 0, "rescanning...", curses.A_BOLD)
            stdscr.refresh()
            real_devices = get_real_devices(do_ping_sweep=True)
            events = monitor.observe_many(real_devices)
            entries = build_entries(real_devices)
            if events:
                _show_text_screen(stdscr, "Changes since last scan", [
                    f"{e.kind:10} {e.ip:16} {e.old_mac or '-'} -> {e.new_mac}" for e in events])
        elif obj == "View alerts":
            _alerts_screen(stdscr, monitor)


def launch(sim_net: SimNetwork, real_devices, authorized: bool = False, ssid: str | None = None):
    curses.wrapper(run, sim_net, real_devices, authorized, ssid)