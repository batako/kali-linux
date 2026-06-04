"""
Scout: port scan (scan basic) + service-based probes on watched open ports.
"""

from dataclasses import dataclass
from typing import Optional

from db import upsert_host
from db import _fetch_ports
from executor import run_command_or_cache
from scan_run import run_scan
from scan_run import PROFILE_BASIC

# Which open ports enter the probe pipeline (expand over time).
SCOUT_WATCH_PORTS = frozenset({22, 80})

PROBE_TIMEOUT_SEC = 30


@dataclass(frozen=True)
class ProbePlan:
    probe_id: str
    task_type: str
    command: str


def _normalize_service(service: str) -> str:
    return (service or "").strip().lower()


def resolve_probe_plan(ip: str, port: int, service: str) -> Optional[ProbePlan]:
    """
    Decide one probe from nmap service name (no port-number guessing).
    Returns None when no rule matches (e.g. unknown / masquerade not handled yet).
    """
    svc = _normalize_service(service)

    if "ssh" in svc:
        return ProbePlan(
            probe_id="ssh",
            task_type="scout-ssh",
            command=f"nmap -p{port} --script ssh2-enum-algos {ip}",
        )

    if "ftp" in svc and "sftp" not in svc:
        return ProbePlan(
            probe_id="ftp",
            task_type="scout-ftp",
            command=f"curl -sS -m 10 ftp://{ip}:{port}/",
        )

    if "http" in svc or "https" in svc:
        if "https" in svc or svc.startswith("ssl/"):
            return ProbePlan(
                probe_id="https",
                task_type="scout-https",
                command=f"curl -sSk -m 10 -D- https://{ip}:{port}/",
            )
        return ProbePlan(
            probe_id="http",
            task_type="scout-http",
            command=f"curl -sS -m 10 -D- http://{ip}:{port}/",
        )

    return None


def _watched_open_rows(ip: str):
    rows = []
    for row in _fetch_ports(ip, "open"):
        port = int(row[0])
        if port in SCOUT_WATCH_PORTS:
            rows.append(row)
    return sorted(rows, key=lambda r: int(r[0]))


def _format_port_row(row) -> str:
    port, proto, _state, service, version = row
    svc = service or "-"
    ver = (version or "").strip()
    if ver:
        return f"{port}/{proto}  service={svc}  ({ver})"
    return f"{port}/{proto}  service={svc}"


def _run_probe_phase(ip: str, *, dry_run: bool = False) -> int:
    rows = _watched_open_rows(ip)
    print("")
    print(f"[*] phase 2: probes (watch {sorted(SCOUT_WATCH_PORTS)}, by service)")

    if not rows:
        print("[*] no open ports in watch set — skip")
        return 0

    rc = 0
    for row in rows:
        port = int(row[0])
        service = row[3]
        print(f"[*] {_format_port_row(row)}")

        plan = resolve_probe_plan(ip, port, service)
        if not plan:
            print("    -> skip (no probe rule for this service)")
            continue

        print(f"    -> {plan.probe_id} ({plan.task_type})")
        print(f"    $ {plan.command}")

        if dry_run:
            continue

        try:
            exec_id, cached = run_command_or_cache(
                ip,
                plan.command,
                timeout_sec=PROBE_TIMEOUT_SEC,
                stream=False,
                task_type=plan.task_type,
            )
            tag = "cached" if cached else "ran"
            print(f"    -> exec_id={exec_id} ({tag})  ev {exec_id}")
        except Exception as e:
            print(f"    -> failed: {e}")
            rc = 1

    print("")
    return rc


def run_scout(
    ip: str,
    *,
    force_scan: bool = False,
    dry_run: bool = False,
    quiet_ports: bool = False,
):
    upsert_host(ip, status="up")

    print("========================")
    print(f"[SCOUT] {ip}")
    print("========================")
    print("[*] phase 1: port scan (top 1000, -sC -sV)")
    print("")

    rc = run_scan(
        ip,
        profile=PROFILE_BASIC,
        force=force_scan,
        dry_run=dry_run,
        quiet_ports=quiet_ports,
    )
    if rc != 0:
        return rc

    return _run_probe_phase(ip, dry_run=dry_run)
