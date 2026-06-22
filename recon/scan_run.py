"""
Port scan: nmap -sC -sV with port_scan_coverage (scan = top 1000, scan -f = TCP 1-65535).
"""

import os
import shlex
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import as_completed

from db import add_scan_range
from db import db_file_lock
from db import format_scan_snapshot_lines
from db import count_port_scan_coverage
from db import count_tcp_coverage_in_ports
from db import format_nmap_exclude_ports
from db import get_scanned_ports
from db import reconcile_scan_ranges
from db import mark_port_scanned
from db import seed_coverage_from_ports
from db import print_ports
from db import upsert_host
from db import upsert_port
from port_sets import full_tcp_ports
from port_sets import nmap_top1000_tcp
from port_sets import profile_port_count
from port_sets import profile_port_set

PROFILE_BASIC = "basic"
PROFILE_FULL = "full"

INCREMENTAL_P_MAX = 50
FULL_CHUNK_PORTS = 1000
NMAP_PORT_ARG_MAX = 800
DEFAULT_FULL_JOBS = 1
MAX_FULL_JOBS = 8
NMAP_HOST_TIMEOUT = os.environ.get("NMAP_HOST_TIMEOUT", "15m")


def _nmap_scan_options() -> str:
    """Flags for CTF/THM targets: skip discovery/DNS, bound scan time, show progress on stderr."""
    return f"-n -Pn -T4 --host-timeout {NMAP_HOST_TIMEOUT} --max-retries 2"


def _nmap_xml_suffix(xml_path: str) -> str:
    return f"-oX {shlex.quote(xml_path)}"


def clamp_full_jobs(jobs):
    if jobs is None or jobs < 1:
        return 1
    return min(int(jobs), MAX_FULL_JOBS)


def split_ports_across_workers(ports, workers, max_per_worker=FULL_CHUNK_PORTS):
    """Split sorted port list into up to `workers` disjoint chunks for one parallel wave."""
    ports = sorted(set(int(p) for p in ports))
    if not ports or workers <= 1:
        return [ports] if ports else []

    workers = min(workers, len(ports))
    wave_cap = workers * max_per_worker
    ports = ports[:wave_cap]

    base, rem = divmod(len(ports), workers)
    chunks = []
    i = 0
    for w in range(workers):
        size = base + (1 if w < rem else 0)
        if size > 0:
            chunks.append(ports[i : i + size])
            i += size
    return chunks


def _unscanned_in_set(ip, port_iter, force: bool):
    if force:
        return sorted(port_iter)
    seed_coverage_from_ports(ip)
    scanned = set(get_scanned_ports(ip))
    return sorted(p for p in port_iter if p not in scanned)


def is_profile_coverage_complete(ip, profile: str) -> bool:
    scanned = set(get_scanned_ports(ip))
    if profile == PROFILE_BASIC:
        return all(p in scanned for p in nmap_top1000_tcp())
    if profile == PROFILE_FULL:
        return count_tcp_coverage_in_ports(ip, full_tcp_ports()) >= profile_port_count(
            PROFILE_FULL
        )
    return False


def ports_to_nmap_arg(ports):
    """Compress port list to nmap -p syntax (ranges where consecutive)."""
    ports = sorted(set(int(p) for p in ports))
    if not ports:
        return None

    parts = []
    start = prev = ports[0]
    for p in ports[1:]:
        if p == prev + 1:
            prev = p
            continue
        parts.append(f"{start}-{prev}" if start != prev else str(start))
        start = prev = p
    parts.append(f"{start}-{prev}" if start != prev else str(start))
    return ",".join(parts)


def _nmap_cmd(
    ip: str,
    ports_this_run,
    profile: str,
    force: bool,
    scanned_in_profile=None,
    *,
    strategy=None,
    allow_large_port_list=False,
):
    base = f"nmap {_nmap_scan_options()} -sC -sV"
    top_set = set(nmap_top1000_tcp())

    if force and profile == PROFILE_BASIC:
        port_sel = "--top-ports 1000"
    elif force and profile == PROFILE_FULL:
        port_sel = "-p-"
    elif profile == PROFILE_BASIC and strategy == "exclude-top1000":
        exclude = format_nmap_exclude_ports(scanned_in_profile or [])
        port_sel = f"--top-ports 1000 --exclude-ports {exclude}"
    elif (
        profile == PROFILE_BASIC
        and strategy == "top1000"
    ):
        port_sel = "--top-ports 1000"
    else:
        if allow_large_port_list:
            arg_ports = ports_this_run
        else:
            arg_ports = ports_this_run[:NMAP_PORT_ARG_MAX]
        p_arg = ports_to_nmap_arg(arg_ports)
        if not p_arg:
            return None
        port_sel = f"-p {p_arg}"
    return f"{base} {port_sel} {ip}"


def plan_scan(ip: str, profile: str = PROFILE_BASIC, force: bool = False):
    """
    Returns (cmd_or_none, info dict).
    Each scan --full invocation scans at most FULL_CHUNK_PORTS unscanned ports.
    """
    total = profile_port_count(profile)
    port_set = profile_port_set(profile)
    unscanned = _unscanned_in_set(ip, port_set, force=force)
    covered = total - len(unscanned)

    if force:
        if profile == PROFILE_FULL:
            ports_run = list(port_set)
            strategy = "force-all-tcp"
        else:
            ports_run = list(nmap_top1000_tcp())
            strategy = "force-top1000"
        cmd = _nmap_cmd(ip, ports_run, profile, force=True, strategy=strategy)
        return cmd, {
            "mode": "force",
            "profile": profile,
            "covered": 0,
            "remaining": len(unscanned) if unscanned else total,
            "total": total,
            "strategy": strategy,
            "chunk": len(ports_run),
            "ports_run": ports_run,
        }

    if not unscanned:
        return None, {
            "mode": "skip",
            "profile": profile,
            "covered": covered,
            "remaining": 0,
            "total": total,
        }

    scanned = set(get_scanned_ports(ip))
    top_set = set(nmap_top1000_tcp())
    scanned_in_profile = sorted(scanned & top_set) if profile == PROFILE_BASIC else sorted(scanned)

    if profile == PROFILE_FULL and len(unscanned) > FULL_CHUNK_PORTS:
        ports_run = unscanned[:FULL_CHUNK_PORTS]
        strategy = "chunk"
    elif len(unscanned) <= INCREMENTAL_P_MAX:
        ports_run = unscanned
        strategy = "ports"
    elif profile == PROFILE_BASIC and len(unscanned) == total:
        ports_run = unscanned
        strategy = "top1000"
    elif (
        profile == PROFILE_BASIC
        and scanned_in_profile
        and len(unscanned) > INCREMENTAL_P_MAX
    ):
        # Prefer -p <few remaining> over huge --exclude-ports (argv limit / nmap errors)
        if len(unscanned) <= len(scanned_in_profile):
            ports_run = unscanned
            strategy = "ports"
        else:
            ports_run = unscanned
            strategy = "exclude-top1000"
    else:
        ports_run = unscanned[:NMAP_PORT_ARG_MAX]
        strategy = "ports"

    cmd = _nmap_cmd(
        ip,
        ports_run,
        profile,
        force=False,
        scanned_in_profile=scanned_in_profile,
        strategy=strategy,
        allow_large_port_list=(strategy == "chunk"),
    )
    return cmd, {
        "mode": "incremental",
        "profile": profile,
        "covered": covered,
        "remaining": len(unscanned),
        "total": total,
        "strategy": strategy,
        "chunk": len(ports_run),
        "after_chunk_remaining": max(0, len(unscanned) - len(ports_run)),
        "ports_run": ports_run,
    }


def build_basic_nmap_command(ip: str, force: bool = False):
    """Backward-compatible alias for basic profile."""
    cmd, info = plan_scan(ip, PROFILE_BASIC, force=force)
    excluded_n = info.get("covered", 0) if info.get("mode") != "force" else 0
    return cmd, excluded_n, info


def ingest_nmap_ports_xml(
    xml_data,
    ip: str,
    scan_profile: str,
    ports_planned=None,
):
    root = ET.fromstring(xml_data)
    seen = set()

    for host in root.findall("host"):
        ports = host.find("ports")
        if ports is None:
            continue

        for p in ports.findall("port"):
            portid = int(p.attrib["portid"])
            proto = p.attrib.get("protocol", "tcp")
            seen.add(portid)

            state_el = p.find("state")
            state = state_el.attrib.get("state", "unknown") if state_el is not None else "unknown"

            service_elem = p.find("service")
            service = service_elem.attrib.get("name", "") if service_elem is not None else ""
            if service_elem is not None:
                product = service_elem.attrib.get("product", "") or ""
                ver = service_elem.attrib.get("version", "") or ""
                extra = service_elem.attrib.get("extrainfo", "") or ""
                version = " ".join(x for x in (product, ver, extra) if x).strip()
            else:
                version = ""

            mark_port_scanned(ip, portid, proto, state, scan_profile)
            upsert_port(ip, portid, proto, state, service, version)

    # nmap XML often omits closed ports; still mark the chunk as covered
    if ports_planned:
        for port in ports_planned:
            port = int(port)
            if port not in seen:
                mark_port_scanned(ip, port, "tcp", "closed", scan_profile)


def _record_chunk_range(ip, profile: str, ports_run):
    if not ports_run:
        return
    add_scan_range(ip, profile, min(ports_run), max(ports_run))


def _print_skip_summary(ip, profile: str):
    covered = count_port_scan_coverage(ip)
    total = profile_port_count(profile)
    label = "top 1000" if profile == PROFILE_BASIC else "TCP 1-65535"
    print(f"[*] {label} already covered ({covered} tcp port(s) in DB, profile complete)")
    print("[*] nmap skipped — ports from recon.db below")


def _print_scan_banner(ip: str, profile: str, subtitle: str = ""):
    print("========================")
    line = f"[SCAN] {ip}  profile={profile}"
    if subtitle:
        line = f"{line}  {subtitle}"
    print(line)
    print("========================")


_live_snapshot_lines = 0


def _profile_progress_line(ip: str, profile: str, jobs: int = 1) -> str:
    if profile == PROFILE_FULL:
        cov = count_tcp_coverage_in_ports(ip, full_tcp_ports())
        total = profile_port_count(PROFILE_FULL)
    else:
        cov = count_tcp_coverage_in_ports(ip, nmap_top1000_tcp())
        total = profile_port_count(PROFILE_BASIC)
    line = f"[*] {cov}/{total}"
    if profile == PROFILE_FULL and jobs > 1:
        line = f"{line}  ({jobs} workers)"
    return line


def _reset_live_snapshot():
    global _live_snapshot_lines
    _live_snapshot_lines = 0


def _refresh_live_snapshot(ip, profile, quiet_ports=False, jobs: int = 1):
    """Rewrite progress + OPEN/CLOSED in place (TTY). Append if not a terminal."""
    global _live_snapshot_lines
    if quiet_ports:
        return

    lines = format_scan_snapshot_lines(ip, _profile_progress_line(ip, profile, jobs=jobs))

    if not sys.stdout.isatty():
        if _live_snapshot_lines:
            print("")
        for line in lines:
            print(line)
        _live_snapshot_lines = len(lines)
        return

    if _live_snapshot_lines == 0:
        for line in lines:
            print(line)
    else:
        sys.stdout.write(f"\033[{_live_snapshot_lines}A")
        for line in lines:
            sys.stdout.write("\033[2K\r")
            sys.stdout.write(line + "\n")
        extra = _live_snapshot_lines - len(lines)
        for _ in range(extra):
            sys.stdout.write("\033[2K\r\n")
    _live_snapshot_lines = len(lines)
    sys.stdout.flush()


def _print_scan_snapshot(ip, profile, quiet_ports=False):
    if quiet_ports:
        return
    lines = format_scan_snapshot_lines(ip, _profile_progress_line(ip, profile))
    for line in lines:
        print(line)


def _finish_scan_output(ip, quiet_ports=False, profile=None):
    reconcile_scan_ranges(ip)
    _print_scan_snapshot(ip, profile, quiet_ports=quiet_ports)


def _print_plan_header(ip, profile: str, info: dict, cmd):
    print("========================")
    print(f"[SCAN] {ip}  profile={profile}")
    mode = info.get("mode")

    if mode == "skip":
        _print_skip_summary(ip, profile)
        print("========================")
        return

    if mode == "force":
        print("[*] --force: rescan (ignoring coverage)")
    elif mode == "incremental":
        covered = info["covered"]
        total = info["total"]
        remaining = info["remaining"]
        chunk = info.get("chunk", remaining)
        print(f"[*] recon.db: {covered}/{total} ports covered in this profile")
        strategy = info.get("strategy", "")
        if strategy == "chunk":
            after = info.get("after_chunk_remaining", 0)
            print(f"[*] chunk: {chunk} port(s) ({after} left in 1-65535 after this)")
        elif strategy == "ports":
            print(f"[*] scanning {chunk} remaining port(s) (-p)")
        elif strategy == "top1000":
            print(f"[*] first scan: nmap top 1000 ({remaining} ports)")
        elif strategy == "exclude-top1000":
            print(f"[*] scanning top 1000 minus {covered} covered (--exclude-ports)")
        else:
            print(f"[*] scanning {chunk} port(s)")

    print(f"[*] {cmd}")
    print("========================")


def _ingest_chunk_result(ip: str, profile: str, xml_out: str, ports_run) -> int:
    if not xml_out.strip():
        print("[-] nmap produced no output")
        return 1
    try:
        with db_file_lock():
            ingest_nmap_ports_xml(
                xml_out,
                ip,
                profile,
                ports_planned=ports_run,
            )
            _record_chunk_range(ip, profile, ports_run)
            reconcile_scan_ranges(ip)
    except ET.ParseError as e:
        print(f"[-] failed to parse nmap XML: {e}")
        preview = xml_out.strip().replace("\n", " ")[:240]
        if preview and not preview.lstrip().startswith("<?xml"):
            print(f"[-] nmap output: {preview}")
        return 1
    return 0


def _run_nmap_chunk(ip: str, profile: str, cmd: str, info: dict) -> int:
    """Run one planned nmap command; return 0 ok, 1 error."""
    ports_run = info.get("ports_run") or []
    _print_plan_header(ip, profile, info, f"{cmd} {_nmap_xml_suffix('<tmp>')}")
    print("[i] nmap progress below (Ctrl+C to cancel)", flush=True)
    sys.stdout.flush()

    xml_path = ""
    try:
        with tempfile.NamedTemporaryFile(
            prefix="nmap-",
            suffix=".xml",
            delete=False,
        ) as tf:
            xml_path = tf.name
        full_cmd = f"{cmd} {_nmap_xml_suffix(xml_path)}"
        rc = subprocess.call(full_cmd, shell=True)
    except OSError as exc:
        print(f"[-] nmap failed to start: {exc}")
        return 1

    out = ""
    try:
        if os.path.isfile(xml_path):
            with open(xml_path, encoding="utf-8", errors="replace") as fh:
                out = fh.read()
    finally:
        if xml_path:
            try:
                os.unlink(xml_path)
            except OSError:
                pass

    if rc != 0:
        print(f"[-] nmap exit code {rc}")
        if out.strip():
            return _ingest_chunk_result(ip, profile, out, ports_run)
        return 1

    return _ingest_chunk_result(ip, profile, out or "", ports_run)


def _nmap_subprocess_task(ip: str, profile: str, ports_run):
    """Worker: run nmap only (ingest in main thread under flock)."""
    cmd = _nmap_cmd(
        ip,
        ports_run,
        profile,
        force=False,
        strategy="ports",
        allow_large_port_list=True,
    )
    if not cmd:
        return {"ok": False, "error": "no command", "ports": ports_run, "xml": ""}
    xml_path = ""
    try:
        with tempfile.NamedTemporaryFile(
            prefix="nmap-",
            suffix=".xml",
            delete=False,
        ) as tf:
            xml_path = tf.name
        full_cmd = f"{cmd} {_nmap_xml_suffix(xml_path)}"
        rc = subprocess.call(full_cmd, shell=True)
        if rc != 0:
            return {"ok": False, "error": f"nmap exit {rc}", "ports": ports_run, "xml": ""}
        with open(xml_path, encoding="utf-8", errors="replace") as fh:
            out = fh.read()
        return {"ok": True, "xml": out, "ports": ports_run, "cmd": full_cmd}
    except OSError as exc:
        return {"ok": False, "error": str(exc), "ports": ports_run, "xml": ""}
    finally:
        if xml_path:
            try:
                os.unlink(xml_path)
            except OSError:
                pass


def _run_parallel_wave(ip: str, profile: str, port_chunks) -> int:
    if not port_chunks:
        return 0
    results = []
    with ThreadPoolExecutor(max_workers=len(port_chunks)) as pool:
        futures = [
            pool.submit(_nmap_subprocess_task, ip, profile, chunk)
            for chunk in port_chunks
        ]
        for fut in as_completed(futures):
            results.append(fut.result())

    for r in results:
        if not r.get("ok"):
            print(f"[-] worker failed: {r.get('error', 'unknown')}")
            return 1
        if _ingest_chunk_result(ip, profile, r["xml"], r["ports"]) != 0:
            return 1
    return 0


def _run_full_sequential(ip: str, force: bool, quiet_ports: bool) -> int:
    while True:
        cmd, info = plan_scan(ip, profile=PROFILE_FULL, force=force)
        if info.get("mode") == "skip":
            break
        if not cmd:
            print("[-] no nmap command planned")
            return 1
        if _run_nmap_chunk(ip, PROFILE_FULL, cmd, info) != 0:
            return 1
        _refresh_live_snapshot(ip, PROFILE_FULL, quiet_ports=quiet_ports, jobs=1)
        if is_profile_coverage_complete(ip, PROFILE_FULL):
            break
    return 0


def _run_full_parallel(ip: str, jobs: int, force: bool, quiet_ports: bool) -> int:
    wave = 0
    while True:
        unscanned = _unscanned_in_set(ip, full_tcp_ports(), force=force)
        if not unscanned:
            break
        chunks = split_ports_across_workers(unscanned, jobs)
        if not chunks:
            break
        wave += 1
        if _run_parallel_wave(ip, PROFILE_FULL, chunks) != 0:
            return 1
        _refresh_live_snapshot(ip, PROFILE_FULL, quiet_ports=quiet_ports, jobs=jobs)
        if is_profile_coverage_complete(ip, PROFILE_FULL):
            break
    return 0


def _run_full_auto(
    ip: str,
    dry_run: bool = False,
    quiet_ports: bool = False,
    jobs: int = 1,
    force: bool = False,
) -> int:
    """scan -f / --full: TCP 1-65535 until covered (sequential or parallel -j)."""
    jobs = clamp_full_jobs(jobs)
    _reset_live_snapshot()
    subtitle = "auto → 65535/65535"
    if jobs > 1:
        subtitle = f"{subtitle}  -j {jobs}"
    _print_scan_banner(ip, PROFILE_FULL, subtitle)

    unscanned = _unscanned_in_set(ip, full_tcp_ports(), force=force)
    if not unscanned:
        print("[*] nmap skipped (already complete)")
        _finish_scan_output(ip, quiet_ports=quiet_ports, profile=PROFILE_FULL)
        return 0

    if dry_run:
        remaining = len(unscanned)
        if jobs > 1:
            waves = max(1, (remaining + jobs * FULL_CHUNK_PORTS - 1) // (jobs * FULL_CHUNK_PORTS))
            print(f"[*] dry-run: ~{waves} wave(s) x {jobs} workers ({remaining} ports left)")
            chunks = split_ports_across_workers(unscanned, jobs)
            for i, ch in enumerate(chunks, 1):
                cmd = _nmap_cmd(ip, ch, PROFILE_FULL, False, strategy="ports", allow_large_port_list=True)
                print(f"[*] worker {i}: {cmd}")
        else:
            est = max(1, (remaining + FULL_CHUNK_PORTS - 1) // FULL_CHUNK_PORTS)
            print(f"[*] dry-run: ~{est} chunk(s) ({remaining} ports left)")
            cmd, _ = plan_scan(ip, PROFILE_FULL, force=force)
            if cmd:
                print(f"[*] {cmd}")
        _finish_scan_output(ip, quiet_ports=quiet_ports, profile=PROFILE_FULL)
        return 0

    if jobs > 1:
        rc = _run_full_parallel(ip, jobs, force=force, quiet_ports=quiet_ports)
    else:
        rc = _run_full_sequential(ip, force=force, quiet_ports=quiet_ports)

    if sys.stdout.isatty():
        print("")
    return rc


def run_scan(
    ip: str,
    profile: str = PROFILE_BASIC,
    force: bool = False,
    dry_run: bool = False,
    quiet_ports: bool = False,
    jobs: int = 1,
):
    upsert_host(ip, status="up")

    if profile == PROFILE_FULL:
        return _run_full_auto(
            ip,
            dry_run=dry_run,
            quiet_ports=quiet_ports,
            jobs=jobs,
            force=force,
        )

    cmd, info = plan_scan(ip, profile=profile, force=force)
    mode = info.get("mode")

    if mode == "skip":
        _print_plan_header(ip, profile, info, "")
        _finish_scan_output(ip, quiet_ports=quiet_ports, profile=profile)
        return 0

    if dry_run:
        _print_plan_header(ip, profile, info, cmd or "")
        _finish_scan_output(ip, quiet_ports=quiet_ports, profile=profile)
        return 0

    if not cmd:
        print("[-] no nmap command planned")
        return 1

    if _run_nmap_chunk(ip, profile, cmd, info) != 0:
        return 1

    _finish_scan_output(ip, quiet_ports=quiet_ports, profile=profile)
    return 0


def run_basic_scan(ip: str, force: bool = False, dry_run: bool = False, quiet_ports: bool = False):
    return run_scan(
        ip,
        profile=PROFILE_BASIC,
        force=force,
        dry_run=dry_run,
        quiet_ports=quiet_ports,
    )
