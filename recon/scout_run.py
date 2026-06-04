"""
Scout: port scan (scan basic) + service-based probes + background gobuster dirs.
"""

from __future__ import annotations

import os
import re
import shlex
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from db import find_running_scout_job
from db import get_scout_job
from db import insert_scout_job
from db import list_scout_jobs
from db import update_scout_job
from db import upsert_host
from db import _fetch_ports
from executor import run_command_or_cache
from scan_run import PROFILE_BASIC
from scan_run import run_scan

# Which open ports enter the probe pipeline (expand over time).
SCOUT_WATCH_PORTS = frozenset({22, 80})

PROBE_TIMEOUT_SEC = 30

DEFAULT_GB_WORDLIST = os.environ.get(
    "GB_WORDLIST",
    "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt",
)
DEFAULT_GB_THREADS = int(os.environ.get("GB_THREADS", "40"))

WEB_SERVICE_HINTS = (
    "http",
    "https",
    "nginx",
    "apache",
    "http-proxy",
    "lighttpd",
    "tomcat",
    "microsoft-iis",
    "gunicorn",
    "unicorn",
    "web",
)

INTERESTING_HIT_STATUS = frozenset({200, 301, 302, 401})
GOBUSTER_HIT_RE = re.compile(r"^\s*(\S+)\s+\(Status:\s*(\d+)\)")


@dataclass(frozen=True)
class ProbePlan:
    probe_id: str
    task_type: str
    command: str


@dataclass(frozen=True)
class DirsPlan:
    url: str
    port: Optional[int]
    wordlist: str
    threads: int
    extensions: Optional[str]
    command: str
    log_path: str


def _normalize_service(service: str) -> str:
    return (service or "").strip().lower()


def is_web_service(service: str) -> bool:
    svc = _normalize_service(service)
    if not svc or svc in ("-", "unknown"):
        return False
    if "sftp" in svc:
        return False
    return any(hint in svc for hint in WEB_SERVICE_HINTS)


def build_web_url(ip: str, port: int, service: str) -> str:
    svc = _normalize_service(service)
    use_https = "https" in svc or svc.startswith("ssl/")
    scheme = "https" if use_https else "http"
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        return f"{scheme}://{ip}/"
    return f"{scheme}://{ip}:{port}/"


def normalize_url(url_or_host: str) -> str:
    s = (url_or_host or "").strip()
    if not s:
        return s
    if not s.startswith(("http://", "https://")):
        s = f"http://{s}"
    return s


def discover_web_targets(ip: str) -> list[tuple[int, str]]:
    targets = []
    for row in _fetch_ports(ip, "open"):
        port = int(row[0])
        service = row[3] or ""
        if not is_web_service(service):
            continue
        targets.append((port, build_web_url(ip, port, service)))
    return targets


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


def _case_logs_dir() -> Optional[str]:
    case_home = os.environ.get("CASE_HOME")
    if case_home:
        logs = Path(case_home) / "logs"
        logs.mkdir(parents=True, exist_ok=True)
        return str(logs)

    if os.environ.get("CASE_LOOSE") == "1":
        root = os.environ.get("CASE_ROOT", "/workspace/cases")
        loose = Path(root) / "_unscoped" / "logs"
        loose.mkdir(parents=True, exist_ok=True)
        return str(loose)

    return None


def _url_host_slug(url: str) -> str:
    parsed = urlparse(url)
    host = parsed.netloc or parsed.path.split("/")[0]
    return host.replace(":", "_") or "target"


def _wordlist_slug(wordlist: str) -> str:
    base = Path(wordlist).name
    if base.endswith(".txt"):
        base = base[:-4]
    return re.sub(r"[^a-zA-Z0-9._-]", "_", base)


def build_dirs_log_path(url: str, wordlist: str, *, dry_run: bool = False) -> str:
    logs = _case_logs_dir()
    if not logs:
        if dry_run:
            logs = os.environ.get("TMPDIR", "/tmp")
        else:
            raise RuntimeError("case not set — cs <name> first (or export CASE_LOOSE=1)")

    host = _url_host_slug(url)
    slug = _wordlist_slug(wordlist)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    return str(Path(logs) / f"gobuster_{host}_{slug}_{ts}.log")


def build_gobuster_dir_argv(
    url: str,
    wordlist: str,
    threads: int,
    extensions: Optional[str] = None,
) -> list[str]:
    args = [
        "gobuster",
        "dir",
        "-u",
        url,
        "-w",
        wordlist,
        "-t",
        str(threads),
        "-q",
    ]
    if extensions:
        args.extend(["--extensions", extensions])
    return args


def build_dirs_plan(
    url: str,
    *,
    port: Optional[int] = None,
    wordlist: Optional[str] = None,
    threads: Optional[int] = None,
    extensions: Optional[str] = None,
    dry_run: bool = False,
) -> DirsPlan:
    url = normalize_url(url)
    wl = wordlist or DEFAULT_GB_WORDLIST
    th = threads if threads is not None else DEFAULT_GB_THREADS
    if not dry_run and not Path(wl).is_file():
        raise FileNotFoundError(f"wordlist not found: {wl}")

    argv = build_gobuster_dir_argv(url, wl, th, extensions)
    log_path = build_dirs_log_path(url, wl, dry_run=dry_run)
    command = " ".join(shlex.quote(a) for a in argv)
    return DirsPlan(
        url=url,
        port=port,
        wordlist=wl,
        threads=th,
        extensions=extensions,
        command=command,
        log_path=log_path,
    )


def parse_gobuster_hits(log_path: str, *, max_lines: int = 20) -> str:
    path = Path(log_path)
    if not path.is_file():
        return ""

    hits = []
    for line in path.read_text(errors="replace").splitlines():
        m = GOBUSTER_HIT_RE.match(line)
        if not m:
            continue
        path_part, status_s = m.group(1), m.group(2)
        try:
            status = int(status_s)
        except ValueError:
            continue
        if status not in INTERESTING_HIT_STATUS:
            continue
        if path_part.startswith(".ht"):
            continue
        hits.append(f"{path_part} (Status: {status})")

    if not hits:
        return ""
    if len(hits) > max_lines:
        extra = len(hits) - max_lines
        hits = hits[:max_lines]
        hits.append(f"... +{extra} more (see log)")
    return "\n".join(hits)


def _pid_alive(pid: Optional[int]) -> bool:
    if pid is None or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def reconcile_scout_job(job_id: int) -> None:
    row = get_scout_job(job_id)
    if not row or row["status"] != "running":
        return

    pid = row["pid"]
    if _pid_alive(pid):
        return

    exit_code = None
    if pid:
        try:
            wpid, status = os.waitpid(pid, os.WNOHANG)
            if wpid == pid:
                exit_code = os.waitstatus_to_exitcode(status)
        except (ChildProcessError, ProcessLookupError):
            pass

    log_path = row["log_path"] or ""
    hits = parse_gobuster_hits(log_path) if log_path else ""
    failed = exit_code not in (None, 0)
    if failed and log_path and Path(log_path).is_file() and hits:
        failed = False

    update_scout_job(
        job_id,
        status="failed" if failed else "done",
        exit_code=exit_code,
        hits_summary=hits or None,
        ended_at=datetime.now().isoformat(timespec="seconds"),
    )


def reconcile_scout_jobs(ip: str) -> None:
    for row in list_scout_jobs(ip, status="running", limit=200):
        reconcile_scout_job(int(row["id"]))


def _dispatch_dirs_job(
    ip: str,
    plan: DirsPlan,
    *,
    dry_run: bool = False,
    force: bool = False,
) -> Optional[int]:
    running = find_running_scout_job(ip, "dirs", plan.url, plan.wordlist)
    if running and not force:
        print(
            f"    -> skip (running job id={running['id']} pid={running['pid']})"
            " — use --force to start another"
        )
        return None

    print(f"    -> dirs {plan.url}")
    print(f"    $ {plan.command}")
    print(f"    log: {plan.log_path}")

    if dry_run:
        return None

    log_path = Path(plan.log_path)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "w") as logf:
        proc = subprocess.Popen(
            build_gobuster_dir_argv(
                plan.url,
                plan.wordlist,
                plan.threads,
                plan.extensions,
            ),
            stdout=logf,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )

    job_id = insert_scout_job(
        ip,
        "dirs",
        plan.url,
        port=plan.port,
        wordlist=plan.wordlist,
        command=plan.command,
        log_path=plan.log_path,
        status="running",
        pid=proc.pid,
    )
    print(f"    -> job_id={job_id} pid={proc.pid}  scout status")
    return job_id


def _run_dirs_phase(
    ip: str,
    *,
    urls: Optional[list[str]] = None,
    wordlist: Optional[str] = None,
    threads: Optional[int] = None,
    extensions: Optional[str] = None,
    dry_run: bool = False,
    force: bool = False,
) -> int:
    print("")
    print("[*] phase 3: directory brute (gobuster dir, background)")

    targets: list[tuple[Optional[int], str]] = []
    if urls:
        for raw in urls:
            targets.append((None, normalize_url(raw)))
    else:
        for port, url in discover_web_targets(ip):
            targets.append((port, url))

    if not targets:
        print("[*] no Web targets — skip")
        print("[i] run scout first, or: scout --dirs http://$IP:port/")
        return 0

    if _case_logs_dir() is None and not dry_run:
        print("[-] case not set — cs <name> first (or export CASE_LOOSE=1)")
        return 1

    rc = 0
    started = 0
    for port, url in targets:
        try:
            plan = build_dirs_plan(
                url,
                port=port,
                wordlist=wordlist,
                threads=threads,
                extensions=extensions,
                dry_run=dry_run,
            )
        except FileNotFoundError as e:
            print(f"[-] {e}")
            return 1
        except RuntimeError as e:
            print(f"[-] {e}")
            return 1

        job_id = _dispatch_dirs_job(ip, plan, dry_run=dry_run, force=force)
        if job_id is not None or dry_run:
            started += 1

    if started and not dry_run:
        print("")
        print(f"[*] {started} dir job(s) started — scout status")
    print("")
    return rc


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


def show_scout_status(ip: str) -> int:
    reconcile_scout_jobs(ip)
    rows = list_scout_jobs(ip, limit=30)

    print("========================")
    print(f"[SCOUT STATUS] {ip}")
    print("========================")

    if not rows:
        print("(no scout jobs)")
        return 0

    running = sum(1 for r in rows if r["status"] == "running")
    print(f"jobs: {len(rows)} shown ({running} running)")
    print("")

    for row in rows:
        job_id = row["id"]
        status = row["status"]
        url = row["url"]
        wl = Path(row["wordlist"] or "").name or "-"
        pid = row["pid"]
        log_path = row["log_path"] or "-"
        started = row["started_at"] or "-"

        line = f"id={job_id}  {status:7}  {url}  wl={wl}"
        if pid:
            line += f"  pid={pid}"
        print(line)
        print(f"         started={started}  log={log_path}")

        hits = row["hits_summary"]
        if hits:
            print("         hits:")
            for hit_line in hits.splitlines():
                print(f"           {hit_line}")
        elif status == "running":
            print("         hits: (running)")
        elif log_path and log_path != "-":
            parsed = parse_gobuster_hits(log_path)
            if parsed:
                print("         hits:")
                for hit_line in parsed.splitlines():
                    print(f"           {hit_line}")
            else:
                print("         hits: (none yet)")
        print("")

    return 0


def run_scout(
    ip: str,
    *,
    force_scan: bool = False,
    force_dirs: bool = False,
    dry_run: bool = False,
    quiet_ports: bool = False,
    dirs_only: bool = False,
    dirs_urls: Optional[list[str]] = None,
    wordlist: Optional[str] = None,
    threads: Optional[int] = None,
    extensions: Optional[str] = None,
):
    upsert_host(ip, status="up")

    if dirs_only:
        if not dirs_urls and not discover_web_targets(ip):
            print("[-] no Web targets in DB — run scout first, or pass a URL")
            return 1
        return _run_dirs_phase(
            ip,
            urls=dirs_urls,
            wordlist=wordlist,
            threads=threads,
            extensions=extensions,
            dry_run=dry_run,
            force=force_dirs,
        )

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

    rc = _run_probe_phase(ip, dry_run=dry_run)
    if rc != 0:
        return rc

    dirs_rc = _run_dirs_phase(
        ip,
        urls=dirs_urls,
        wordlist=wordlist,
        threads=threads,
        extensions=extensions,
        dry_run=dry_run,
        force=force_dirs,
    )
    return max(rc, dirs_rc)
