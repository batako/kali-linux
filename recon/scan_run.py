"""
Basic port scan: nmap -sC -sV with port_scan_coverage (skip already-scanned ports).
"""

import subprocess
import xml.etree.ElementTree as ET

from db import add_scan_range
from db import count_open_ports
from db import count_port_scan_coverage
from db import format_nmap_exclude_ports
from db import format_nmap_port_list
from db import get_scanned_ports
from db import has_scan_range
from db import mark_port_scanned
from db import seed_coverage_from_ports
from db import print_ports
from db import upsert_host
from db import upsert_port

# nmap default (no -p) ≈ top 1000 TCP — tracked as 1-1000 in scan_ranges
BASIC_SCAN_TYPE = "basic"
BASIC_RANGE_START = 1
BASIC_RANGE_END = 1000
BASIC_PORT_COUNT = BASIC_RANGE_END - BASIC_RANGE_START + 1

# Prefer -p <few> over --exclude-ports <many> when this many or fewer ports remain
INCREMENTAL_P_MAX = 50


def _basic_unscanned_ports(ip):
    scanned = set(get_scanned_ports(ip))
    return [p for p in range(BASIC_RANGE_START, BASIC_RANGE_END + 1) if p not in scanned]


def is_basic_coverage_complete(ip):
    return count_port_scan_coverage(ip) >= BASIC_PORT_COUNT


def plan_basic_scan(ip: str, force: bool = False):
    """
    Returns (cmd_or_none, info dict).
    cmd is None when nmap should not run (DB already has full basic coverage).
    """
    if force:
        cmd = f"nmap -sC -sV {ip} -oX -"
        return cmd, {
            "mode": "force",
            "covered": 0,
            "remaining": BASIC_PORT_COUNT,
        }

    seed_coverage_from_ports(ip)
    unscanned = _basic_unscanned_ports(ip)
    covered = BASIC_PORT_COUNT - len(unscanned)

    if not unscanned:
        return None, {
            "mode": "skip",
            "covered": covered,
            "remaining": 0,
        }

    if covered == 0:
        cmd = f"nmap -sC -sV {ip} -oX -"
        strategy = "full"
    elif len(unscanned) <= INCREMENTAL_P_MAX:
        plist = format_nmap_port_list(unscanned)
        cmd = f"nmap -sC -sV -p {plist} {ip} -oX -"
        strategy = "ports"
    else:
        scanned = get_scanned_ports(ip)
        exclude = format_nmap_exclude_ports(scanned)
        cmd = f"nmap -sC -sV --exclude-ports {exclude} {ip} -oX -"
        strategy = "exclude"

    return cmd, {
        "mode": "incremental",
        "strategy": strategy,
        "covered": covered,
        "remaining": len(unscanned),
    }


def build_basic_nmap_command(ip: str, force: bool = False):
    cmd, info = plan_basic_scan(ip, force=force)
    excluded_n = info.get("covered", 0) if info.get("mode") != "force" else 0
    return cmd, excluded_n, info


def ingest_nmap_ports_xml(xml_data, ip: str, scan_profile: str, record_tasks: bool = False):
    root = ET.fromstring(xml_data)

    for host in root.findall("host"):
        ports = host.find("ports")
        if ports is None:
            continue

        for p in ports.findall("port"):
            portid = int(p.attrib["portid"])
            proto = p.attrib.get("protocol", "tcp")

            state_el = p.find("state")
            state = state_el.attrib.get("state", "unknown") if state_el is not None else "unknown"

            service_elem = p.find("service")
            service = service_elem.attrib.get("name", "") if service_elem is not None else ""
            version = service_elem.attrib.get("version", "") if service_elem is not None else ""

            mark_port_scanned(ip, portid, proto, state, scan_profile)
            upsert_port(ip, portid, proto, state, service, version)

            if record_tasks:
                from scanner import generate_tasks

                generate_tasks(ip, portid, service)


def _print_skip_summary(ip):
    covered = count_port_scan_coverage(ip)
    print(f"[*] basic 1-{BASIC_RANGE_END} already covered ({covered} tcp port(s) in DB)")
    print("[*] nmap skipped — ports from recon.db below")


def _finish_scan_output(ip, quiet_ports=False):
    if quiet_ports:
        return
    print_ports(ip, split_open_closed=True, show_coverage=True)
    open_n = count_open_ports(ip)
    print(f"[+] open: {open_n}")


def run_basic_scan(
    ip: str,
    force: bool = False,
    dry_run: bool = False,
    quiet_ports: bool = False,
):
    upsert_host(ip, status="up")

    cmd, _excluded_n, info = build_basic_nmap_command(ip, force=force)
    mode = info.get("mode")

    print("========================")
    print(f"[SCAN] {ip}  profile={BASIC_SCAN_TYPE}")
    if mode == "skip":
        _print_skip_summary(ip)
        print("========================")
        if dry_run:
            print("[dry-run] nmap skipped")
        _finish_scan_output(ip, quiet_ports=quiet_ports)
        return 0

    if mode == "force":
        print("[*] --force: full rescan (ignoring coverage)")
    elif mode == "incremental":
        covered = info["covered"]
        remaining = info["remaining"]
        strategy = info.get("strategy", "")
        print(f"[*] using recon.db: {covered}/{BASIC_PORT_COUNT} tcp ports already covered")
        if strategy == "full":
            print(f"[*] first basic scan ({remaining} ports)")
        elif strategy == "ports":
            print(f"[*] scanning {remaining} remaining port(s) only (-p)")
        else:
            print(f"[*] scanning {remaining} remaining port(s) (--exclude-ports)")
            if remaining > INCREMENTAL_P_MAX:
                print("[!] large gap — run once: scan --force  (or finish host-scan quick)")
    else:
        print("[*] no prior coverage")
    print(f"[*] {cmd}")
    print("========================")

    if dry_run:
        print("[dry-run] not executed")
        _finish_scan_output(ip, quiet_ports=quiet_ports)
        return 0

    out = subprocess.getoutput(cmd)
    if not out.strip():
        print("[-] nmap produced no output")
        return 1

    try:
        ingest_nmap_ports_xml(out, ip, BASIC_SCAN_TYPE, record_tasks=False)
    except ET.ParseError as e:
        print(f"[-] failed to parse nmap XML: {e}")
        return 1

    if is_basic_coverage_complete(ip) and not has_scan_range(
        ip, BASIC_SCAN_TYPE, BASIC_RANGE_START, BASIC_RANGE_END
    ):
        add_scan_range(ip, BASIC_SCAN_TYPE, BASIC_RANGE_START, BASIC_RANGE_END)

    total = count_port_scan_coverage(ip)
    print(f"[+] scan done — coverage: {total} tcp port(s) recorded")
    _finish_scan_output(ip, quiet_ports=quiet_ports)
    return 0
