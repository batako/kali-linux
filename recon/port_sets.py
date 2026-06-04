"""Nmap-aligned TCP port sets for scan coverage."""

from functools import lru_cache
from pathlib import Path

_DATA = Path(__file__).resolve().parent / "data" / "nmap-top-1000-tcp.txt"

FULL_TCP_START = 1
FULL_TCP_END = 65535
FULL_TCP_COUNT = FULL_TCP_END - FULL_TCP_START + 1


@lru_cache(maxsize=1)
def nmap_top1000_tcp():
    if not _DATA.exists():
        raise FileNotFoundError(f"missing port list: {_DATA}")
    ports = []
    for line in _DATA.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        ports.append(int(line))
    if len(ports) != 1000:
        raise ValueError(f"expected 1000 ports in {_DATA}, got {len(ports)}")
    return tuple(ports)


def full_tcp_ports():
    return range(FULL_TCP_START, FULL_TCP_END + 1)


def profile_port_set(profile: str):
    if profile == "basic":
        return nmap_top1000_tcp()
    if profile == "full":
        return full_tcp_ports()
    raise ValueError(f"unknown scan profile: {profile}")


def profile_port_count(profile: str) -> int:
    if profile == "basic":
        return 1000
    if profile == "full":
        return FULL_TCP_COUNT
    raise ValueError(f"unknown scan profile: {profile}")
