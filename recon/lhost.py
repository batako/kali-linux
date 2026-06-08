"""Local attacker IPs for reverse shells (TryHackMe VPN → tun0)."""

from __future__ import annotations

import subprocess
from typing import Optional


def ipv4_on_iface(iface: str) -> Optional[str]:
    """Return IPv4 address on iface, or None if down / missing."""
    iface = (iface or "").strip()
    if not iface:
        return None
    try:
        proc = subprocess.run(
            ["ip", "-o", "-4", "addr", "show", iface],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    for line in (proc.stdout or "").splitlines():
        parts = line.split()
        if len(parts) >= 4:
            return parts[3].split("/", 1)[0]
    return None


def collect_lhost_info() -> dict:
    """tun0 IPv4 for reverse shells / MSF LHOST (TryHackMe VPN)."""
    return {"tun0": ipv4_on_iface("tun0")}
