"""
wifi_info.py — read the currently-connected Wi-Fi network name (SSID).
Read-only: just asks the OS what it's already connected to.
"""
import platform
import re
import subprocess


def get_wifi_name():
    system = platform.system().lower()
    try:
        if system == "linux":
            # try nmcli first
            out = subprocess.run(["nmcli", "-t", "-f", "active,ssid", "dev", "wifi"],
                                  capture_output=True, text=True, timeout=5).stdout
            for line in out.splitlines():
                if line.startswith("yes:"):
                    return line.split(":", 1)[1]
            # fallback: iwgetid
            out = subprocess.run(["iwgetid", "-r"], capture_output=True, text=True, timeout=5).stdout.strip()
            return out or None

        if system == "darwin":
            path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
            out = subprocess.run([path, "-I"], capture_output=True, text=True, timeout=5).stdout
            m = re.search(r"\bSSID:\s*(.+)", out)
            return m.group(1).strip() if m else None

        if system == "windows":
            out = subprocess.run(["netsh", "wlan", "show", "interfaces"],
                                  capture_output=True, text=True, timeout=5).stdout
            m = re.search(r"^\s*SSID\s*:\s*(.+)$", out, re.MULTILINE)
            return m.group(1).strip() if m else None
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    return None


if __name__ == "__main__":
    name = get_wifi_name()
    print(f"Connected Wi-Fi: {name or '(not available / not connected via Wi-Fi)'}")
