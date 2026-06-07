"""
Scout: port scan (scan basic) + service-based probes + background gobuster dirs.
"""

from __future__ import annotations

import os
import re
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin
from urllib.parse import urlparse

from db import connect
from db import find_done_scout_job
from db import find_running_scout_job
from db import format_scan_snapshot_lines
from db import get_scout_job
from db import insert_scout_job
from db import list_scout_jobs
from db import update_scout_job
from db import upsert_host
from db import _fetch_ports
from db import count_tcp_coverage_in_ports
from executor import run_command_or_cache
from scan_run import PROFILE_BASIC
from scan_run import run_scan
from url_util import canonicalize_url
from url_util import normalize_web_url

PROBE_TIMEOUT_SEC = 30

DEFAULT_WATCH_INTERVAL_SEC = 2.0

# Status screen: show this many finished jobs (+ all running at bottom).
SCOUT_STATUS_SLOTS = max(1, int(os.environ.get("SCOUT_STATUS_SLOTS", "4")))

DEFAULT_GB_THREADS = int(os.environ.get("GB_THREADS", "40"))
DEFAULT_DIRS_MULTI_THREADS = int(os.environ.get("GB_DIRS_THREADS", "15"))

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
GOBUSTER_REDIRECT_RE = re.compile(r"\[-->\s*(https?://[^\]]+)\]")

# Hidden paths worth showing when found (not extension-fuzz noise).
_HIDDEN_DIR_OK = frozenset({".git", ".svn", ".well-known", ".env"})

# Prefer 200 over redirect over 401 when deduplicating the same path.
_STATUS_RANK = {200: 0, 301: 1, 302: 1, 401: 2}


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
        return canonicalize_url(f"{scheme}://{ip}/")
    return canonicalize_url(f"{scheme}://{ip}:{port}/")


def normalize_url(url_or_host: str) -> str:
    s = (url_or_host or "").strip()
    if not s:
        return s
    if not s.startswith(("http://", "https://")):
        s = f"http://{s}"
    return s


def is_dirs_path_arg(s: str) -> bool:
    """Path or URL for scout -d (not an IP or flag)."""
    if not s or s.startswith("-"):
        return False
    if s.startswith(("http://", "https://", "/")):
        return True
    if looks_like_ipv4(s):
        return False
    return True


def looks_like_ipv4(s: str) -> bool:
    return bool(re.match(r"^\d+\.\d+\.\d+\.\d+$", (s or "").strip()))


def resolve_dirs_target(ip: str, path_or_url: str) -> str:
    """Turn /admin, admin, or full URL into a gobuster -u target."""
    s = (path_or_url or "").strip()
    if s.startswith(("http://", "https://")):
        return normalize_web_url(s)

    path = s if s.startswith("/") else f"/{s}/"
    if not path.endswith("/"):
        path = f"{path}/"

    # Prefer scheme/port from an open Web port when unambiguous.
    web = discover_web_targets(ip)
    if len(web) == 1:
        base = web[0][1]
    elif web:
        base = build_web_url(ip, 80, "http")
        for port, url in web:
            if port == 80:
                base = url
                break
    else:
        base = f"http://{ip}/"

    return canonicalize_url(urljoin(base, path.lstrip("/")))


def resolve_dirs_targets(ip: str, raw_urls: list[str]) -> list[str]:
    return [resolve_dirs_target(ip, u) for u in raw_urls]


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
        url = canonicalize_url(f"ftp://{ip}:{port}/")
        return ProbePlan(
            probe_id="ftp",
            task_type="scout-ftp",
            command=f"curl -sS -m 10 {url}",
        )

    if is_web_service(service):
        url = build_web_url(ip, port, service)
        if url.startswith("https://"):
            return ProbePlan(
                probe_id="https",
                task_type="scout-https",
                command=f"curl -sSk -m 10 -D- {url}",
            )
        return ProbePlan(
            probe_id="http",
            task_type="scout-http",
            command=f"curl -sS -m 10 -D- {url}",
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
    from wordlists.scout import resolve_scout_wordlist

    url = normalize_web_url(url)
    try:
        wl = resolve_scout_wordlist(wordlist, extensions=extensions)
    except ValueError as exc:
        raise FileNotFoundError(str(exc)) from exc
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


def _is_gobuster_noise(path_part: str) -> bool:
    if path_part in (".", ""):
        return True
    base = path_part.rstrip("/")
    if base in _HIDDEN_DIR_OK:
        return False
    if base.startswith("."):
        return True
    return False


def _looks_like_file(path: str) -> bool:
    name = path.rstrip("/").split("/")[-1]
    if not name or name == "/":
        return False
    if name in _HIDDEN_DIR_OK:
        return False
    if name.startswith("."):
        return True
    return "." in name


def _normalize_dir_path(path_part: str, full_line: str) -> Optional[str]:
    redir_m = GOBUSTER_REDIRECT_RE.search(full_line)
    if redir_m:
        parsed = urlparse(redir_m.group(1))
        p = parsed.path or "/"
        if p == "/":
            return None
        if not p.startswith("/"):
            p = f"/{p}"
        if _looks_like_file(p):
            return p.rstrip("/")
        if not p.endswith("/"):
            p = f"{p}/"
        return p

    if _is_gobuster_noise(path_part):
        return None

    clean = path_part.strip("/")
    if not clean:
        return None

    p = f"/{clean}"
    if _looks_like_file(p):
        return p
    return f"{p}/"


def _base_path_from_url(url: str) -> str:
    p = urlparse(normalize_url(url)).path or "/"
    if not p.endswith("/"):
        p = f"{p}/"
    return p


def resolve_site_path(base_url: str, path: str) -> str:
    """Map a gobuster hit to a site-root path (respecting the scan base URL)."""
    path = path if path.startswith("/") else f"/{path}"
    if _looks_like_file(path):
        path = path.rstrip("/")
    elif not path.endswith("/"):
        path = f"{path}/"
    base_p = _base_path_from_url(base_url)
    if base_p == "/":
        return path
    if path.startswith(base_p):
        return path
    return f"{base_p.rstrip('/')}{path}"


def extract_dir_findings(
    log_path: str,
    base_url: Optional[str] = None,
) -> list[tuple[str, int]]:
    """Parse gobuster log → site-root paths as (/path/, status), deduped."""
    path = Path(log_path)
    if not path.is_file():
        return []

    best: dict[str, int] = {}
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

        norm = _normalize_dir_path(path_part, line)
        if not norm:
            continue
        if base_url:
            norm = resolve_site_path(base_url, norm)

        prev = best.get(norm)
        if prev is None or _STATUS_RANK[status] < _STATUS_RANK[prev]:
            best[norm] = status

    return sorted(best.items(), key=lambda x: (x[0].lower(), x[1]))


def format_dir_findings(findings: list[tuple[str, int]], *, max_lines: int = 30) -> str:
    if not findings:
        return ""
    lines = [f"{p}  {status}" for p, status in findings]
    if len(lines) > max_lines:
        extra = len(lines) - max_lines
        lines = lines[:max_lines]
        lines.append(f"... +{extra} more (see log)")
    return "\n".join(lines)


def parse_gobuster_hits(
    log_path: str,
    *,
    base_url: Optional[str] = None,
    max_lines: int = 20,
) -> str:
    return format_dir_findings(
        extract_dir_findings(log_path, base_url=base_url),
        max_lines=max_lines,
    )


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
    exit_code = None
    # waitpid before _pid_alive: exited children stay as zombies and still
    # answer kill(0), so status would never flip to done during -ws watch.
    if pid:
        try:
            wpid, status = os.waitpid(pid, os.WNOHANG)
            if wpid == pid:
                exit_code = os.waitstatus_to_exitcode(status)
        except (ChildProcessError, ProcessLookupError):
            pass

    if exit_code is None and _pid_alive(pid):
        return

    log_path = row["log_path"] or ""
    hits = parse_gobuster_hits(log_path, base_url=row["url"]) if log_path else ""
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
    if not force:
        running = find_running_scout_job(ip, "dirs", plan.url, plan.wordlist)
        if running:
            print(
                f"    -> skip (running job id={running['id']} pid={running['pid']})"
                " — use --force to start another"
            )
            return None

        done = find_done_scout_job(ip, "dirs", plan.url, plan.wordlist)
        if done:
            print(
                f"    -> skip (done job id={done['id']})"
                " — use --force to rerun"
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
    wordlists: Optional[list[str]] = None,
    dirs_multi: bool = False,
    dirs_preset: str = "standard",
    dirs_multi_preset_from_flag: bool = False,
    dirs_multi_preset_is_next: bool = False,
    threads: Optional[int] = None,
    extensions: Optional[str] = None,
    dry_run: bool = False,
    force: bool = False,
) -> int:
    from wordlists.scout import resolve_dirs_multi_wordlist_ids
    from wordlists.scout import resolve_dirs_multi_wordlists

    targets: list[tuple[Optional[int], str]] = []
    if urls:
        for raw in urls:
            targets.append((None, resolve_dirs_target(ip, raw)))
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

    print("")
    rc = 0
    started = 0
    header_printed = False

    for port, url in targets:
        wl_paths: list[str] = []

        if dirs_multi and dirs_multi_preset_is_next:
            try:
                ids, label = resolve_dirs_multi_wordlist_ids(
                    preset="next",
                    extensions=extensions,
                    preset_is_next=True,
                    ip=ip,
                    url=url,
                )
            except ValueError as e:
                print(f"[-] {e}")
                return 1
            if not ids:
                print(f"[*] {url}  all preset tiers done")
                continue
            wl_paths = resolve_dirs_multi_wordlists(
                wordlist_ids=ids,
                extensions=extensions,
            )
            tier = label.split("/", 1)[-1]
            src = f"next/{tier} ({len(wl_paths)} wordlists"
            if extensions:
                src += f", -x {extensions}"
            src += ")"
            print(f"[*] phase 3: directory brute (multi, {src}, background)")
        elif dirs_multi:
            wl_paths = list(wordlists or [])
            if not header_printed:
                if dirs_multi_preset_from_flag:
                    src = f"preset {dirs_preset} ({len(wl_paths)} wordlists"
                elif extensions:
                    src = f"standard ({len(wl_paths)} wordlists, -x {extensions})"
                else:
                    src = f"standard ({len(wl_paths)} wordlists)"
                if extensions and dirs_multi_preset_from_flag:
                    src += f", -x {extensions}"
                src += ")"
                print(f"[*] phase 3: directory brute (multi, {src}, background)")
                if (
                    dirs_multi_preset_from_flag
                    and dirs_preset in ("deep", "wide")
                    and not dry_run
                ):
                    print(
                        f"[!] {dirs_preset} tier runs {len(wl_paths)} jobs per URL"
                        " — consider: scout -ds -p deep -t 10",
                        file=sys.stderr,
                    )
                header_printed = True
        else:
            if wordlists:
                wl_paths = list(wordlists)
            elif wordlist:
                wl_paths = [wordlist]
            if not header_printed:
                print("[*] phase 3: directory brute (gobuster dir, background)")
                header_printed = True

        wl_batch: list[Optional[str]] = wl_paths if wl_paths else [None]

        for wl in wl_batch:
            try:
                plan = build_dirs_plan(
                    url,
                    port=port,
                    wordlist=wl,
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


def _probe_open_rows(ip: str):
    """All open ports; resolve_probe_plan filters by service (ssh / web / ftp)."""
    return sorted(_fetch_ports(ip, "open"), key=lambda r: int(r[0]))


def _format_port_row(row) -> str:
    port, proto, _state, service, version = row
    svc = service or "-"
    ver = (version or "").strip()
    if ver:
        return f"{port}/{proto}  service={svc}  ({ver})"
    return f"{port}/{proto}  service={svc}"


def _run_probe_phase(ip: str, *, dry_run: bool = False) -> int:
    rows = _probe_open_rows(ip)
    print("")
    print("[*] phase 2: probes (all open ports, ssh + web by service)")

    if not rows:
        print("[*] no open ports — skip")
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


def _fetch_scout_executions(ip: str):
    conn = connect()
    cur = conn.cursor()
    rows = cur.execute(
        """
        SELECT id, task_type, command, status, exit_code, stdout, ended_at
        FROM executions
        WHERE ip = ? AND task_type LIKE 'scout-%'
        ORDER BY id ASC
        """,
        (ip,),
    ).fetchall()
    conn.close()
    return rows


def _probe_stdout_hint(stdout: str, *, max_len: int = 100) -> str:
    if not stdout or not stdout.strip():
        return "(no output)"

    for line in stdout.splitlines():
        s = line.strip()
        if s.startswith("HTTP/"):
            return s[:max_len]

    for line in stdout.splitlines():
        s = line.strip()
        if not s:
            continue
        if s.startswith("|") or s.startswith("SF-"):
            continue
        return s[:max_len]

    return stdout.strip().splitlines()[0][:max_len]


def _latest_dirs_jobs(jobs) -> list:
    by_url = {}
    for row in jobs:
        if row["kind"] != "dirs":
            continue
        url = row["url"]
        prev = by_url.get(url)
        if prev is None or int(row["id"]) > int(prev["id"]):
            by_url[url] = row
    return sorted(by_url.values(), key=lambda r: r["url"])


def _dirs_findings_for_job(row) -> list[tuple[str, int]]:
    log_path = row["log_path"] or ""
    base_url = row["url"] or ""
    if log_path:
        return extract_dir_findings(log_path, base_url=base_url)
    hits = row["hits_summary"] or ""
    if not hits:
        return []
    out = []
    for line in hits.splitlines():
        if line.startswith("... "):
            continue
        parts = line.rsplit("  ", 1)
        if len(parts) == 2 and parts[1].isdigit():
            out.append((parts[0], int(parts[1])))
    return out


def _merge_job_findings(rows) -> list[tuple[str, int]]:
    best: dict[str, int] = {}
    for row in rows:
        for path, status in _dirs_findings_for_job(row):
            prev = best.get(path)
            if prev is None or _STATUS_RANK[status] < _STATUS_RANK[prev]:
                best[path] = status
    return sorted(best.items(), key=lambda x: x[0].lower())


def _paths_tree_insert(tree: dict, parts: list[str], status: int) -> None:
    node = tree
    for i, part in enumerate(parts):
        node = node.setdefault(part, {"status": None, "children": {}})
        if i == len(parts) - 1:
            prev = node["status"]
            if prev is None or _STATUS_RANK[status] < _STATUS_RANK[prev]:
                node["status"] = status
        node = node["children"]


def _paths_tree_lines(tree: dict, *, depth: int = 0) -> list[str]:
    lines = []
    for name in sorted(tree.keys(), key=str.lower):
        entry = tree[name]
        indent = "  " * (depth + 1)
        st = entry["status"]
        suffix = f"  {st}" if st is not None else ""
        lines.append(f"{indent}{name}/{suffix}")
        lines.extend(_paths_tree_lines(entry["children"], depth=depth + 1))
    return lines


def format_paths_tree(
    findings: list[tuple[str, int]],
    *,
    root_label: str = "/",
) -> list[str]:
    tree: dict = {}
    for path, status in findings:
        parts = [p for p in path.strip("/").split("/") if p]
        if not parts:
            continue
        _paths_tree_insert(tree, parts, status)

    if not tree:
        return []
    lines = [root_label]
    lines.extend(_paths_tree_lines(tree))
    return lines


def _paths_root_label(ip: str, rows) -> str:
    for row in rows:
        url = row["url"] or ""
        if url:
            parsed = urlparse(normalize_url(url))
            if parsed.scheme and parsed.netloc:
                return f"{parsed.scheme}://{parsed.netloc}/"
    return f"http://{ip}/"


def _fetch_paths_report_state(ip: str) -> tuple[list, list[tuple[str, int]], bool]:
    """Latest dirs job per URL → merged findings and running flag."""
    reconcile_scout_jobs(ip)
    jobs = list_scout_jobs(ip, kind="dirs", limit=100)
    latest = _latest_dirs_jobs(jobs)
    if not latest:
        return [], [], False
    findings = _merge_job_findings(latest)
    running = any(r["status"] == "running" for r in latest)
    return latest, findings, running


def _print_paths_section(
    ip: str,
    latest,
    findings: list[tuple[str, int]],
    *,
    running: bool,
) -> None:
    print("--- PATHS ---")
    if not latest:
        print("(none)")
        return
    if findings:
        for line in format_paths_tree(findings, root_label=_paths_root_label(ip, latest)):
            print(line)
    elif running:
        print(_paths_root_label(ip, latest))
        print("  (running)")
    else:
        print("(none)")


def _print_paths_tree(rows, *, ip: str) -> None:
    findings = _merge_job_findings(rows)
    running = any(r["status"] == "running" for r in rows)
    _print_paths_section(ip, rows, findings, running=running)
    print("")


def _job_sort_key(row) -> tuple:
    started = row["started_at"] or ""
    return (started, int(row["id"]))


def _select_status_jobs(rows, *, max_finished: int = SCOUT_STATUS_SLOTS) -> list:
    """
    Finished jobs: oldest→newest (recent near bottom), cap at max_finished.
    Running jobs: always last (bottom of screen), oldest→newest among themselves.
    """
    running = [r for r in rows if r["status"] == "running"]
    finished = [r for r in rows if r["status"] != "running"]
    finished.sort(key=_job_sort_key)
    if len(finished) > max_finished:
        finished = finished[-max_finished:]
    running.sort(key=_job_sort_key)
    return finished + running


def _print_scout_job_row(row) -> None:
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
    print("")


def show_scout_ports(ip: str) -> int:
    """DB snapshot: OPEN + CLOSED port tables only (no scan, no probes)."""
    from port_sets import FULL_TCP_END
    from port_sets import full_tcp_ports
    from port_sets import nmap_top1000_tcp

    basic_cov = count_tcp_coverage_in_ports(ip, nmap_top1000_tcp())
    full_cov = count_tcp_coverage_in_ports(ip, full_tcp_ports())
    progress = f"[*] basic {basic_cov}/1000  full {full_cov}/{FULL_TCP_END}"

    print("")
    print(f"[*] report-ports {ip}")
    for line in format_scan_snapshot_lines(ip, progress):
        print(line)
    print("")
    return 0


def show_scout_report_exploits(ip: str) -> int:
    """DB snapshot: EXPLOITS section only (no searchsploit)."""
    print("")
    print(f"[*] report-exploits {ip}")
    print("")
    print("--- EXPLOITS ---")
    from scout_exploit import format_exploit_report_lines

    exploit_lines = format_exploit_report_lines(ip)
    for line in exploit_lines:
        print(line)
    print("")
    print("[i] detail: ev <id>  |  scout -se  |  scout -r")
    print("[i] tried & N/A: erj <EDB> [--port 80/tcp]  |  undo: eru <EDB>")
    return 0


def show_scout_report_paths(ip: str) -> int:
    """DB snapshot: PATHS tree only (no gobuster)."""
    latest, findings, running = _fetch_paths_report_state(ip)
    print("")
    print(f"[*] report-paths {ip}")
    print("")
    _print_paths_section(ip, latest, findings, running=running)
    print("")
    print("[i] detail: scout -s  |  scout -ws  |  scout -r")
    return 0


def show_scout_report(ip: str) -> int:
    """DB snapshot: ports + scout probes + dirs hits (no nmap/curl/gobuster)."""
    from port_sets import FULL_TCP_END
    from port_sets import full_tcp_ports
    from port_sets import nmap_top1000_tcp

    reconcile_scout_jobs(ip)

    basic_cov = count_tcp_coverage_in_ports(ip, nmap_top1000_tcp())
    full_cov = count_tcp_coverage_in_ports(ip, full_tcp_ports())
    progress = f"[*] basic {basic_cov}/1000  full {full_cov}/{FULL_TCP_END}"

    print("========================")
    print(f"[SCOUT REPORT] {ip}")
    print("========================")
    print("")
    for line in format_scan_snapshot_lines(ip, progress):
        print(line)
    print("")

    print("--- PROBES ---")
    execs = _fetch_scout_executions(ip)
    if not execs:
        print("(none)")
    else:
        for row in execs:
            exec_id = row["id"]
            task_type = row["task_type"] or "-"
            status = row["status"] or "-"
            exit_code = row["exit_code"]
            code = "-" if exit_code is None else str(exit_code)
            hint = _probe_stdout_hint(row["stdout"] or "")
            print(f"ev {exec_id}  {task_type}  {status}  exit={code}  {hint}")
            print(f"         $ {row['command']}")
    print("")

    latest, findings, running = _fetch_paths_report_state(ip)
    _print_paths_section(ip, latest, findings, running=running)
    print("")
    print("--- HINTS ---")
    from hints import format_hint_report_lines
    from hints import hint_scope_optional

    case = hint_scope_optional()
    if case:
        for line in format_hint_report_lines(case):
            print(line)
    else:
        print("(none — cs <case> to attach hints)")
    print("")
    print("--- EXPLOITS ---")
    from scout_exploit import format_exploit_report_lines

    exploit_lines = format_exploit_report_lines(ip)
    for line in exploit_lines:
        print(line)
    print("")
    print("[i] detail: ev <id>  |  scout -s  |  scout -se  |  scout -re  |  scout -rt")
    print("[i] hints: ha <text>  |  hl  |  hr <id>")
    print("[i] tried & N/A: erj <EDB>  |  undo: eru <EDB>")
    return 0


def show_scout_status(
    ip: str,
    *,
    wait_dirs: bool = False,
    interval_sec: float = DEFAULT_WATCH_INTERVAL_SEC,
) -> int:
    interval_sec = max(0.5, float(interval_sec))

    try:
        while True:
            if wait_dirs and sys.stdout.isatty():
                print("\033[2J\033[H", end="")

            reconcile_scout_jobs(ip)
            all_rows = list_scout_jobs(ip, limit=200)
            running_total = sum(1 for r in all_rows if r["status"] == "running")
            rows = _select_status_jobs(all_rows)

            print("========================")
            print(f"[SCOUT STATUS] {ip}")
            if wait_dirs:
                print(f"[*] -ws ({interval_sec:g}s) — Ctrl+C to stop")
            print("========================")

            if not all_rows:
                print("(no scout jobs)")
                return 0

            finished_total = len(all_rows) - running_total
            finished_shown = sum(1 for r in rows if r["status"] != "running")
            hidden = max(0, finished_total - finished_shown)
            line = f"jobs: {len(rows)} shown ({running_total} running)"
            if hidden:
                line += f", {hidden} older hidden"
            print(line)
            print("")

            for row in rows:
                _print_scout_job_row(row)

            _print_paths_tree(rows, ip=ip)

            if wait_dirs:
                sys.stdout.flush()

            if not wait_dirs or running_total == 0:
                if wait_dirs and running_total == 0:
                    print("[*] all dirs jobs finished")
                return 0

            time.sleep(interval_sec)
    except KeyboardInterrupt:
        print("\n[*] wait-dirs stopped")
        return 0


def _auto_wait_dirs(ip: str, *, dry_run: bool = False) -> int:
    """After scout dispatch, watch dirs until running jobs reach zero."""
    if dry_run:
        return 0
    reconcile_scout_jobs(ip)
    if not list_scout_jobs(ip, limit=1):
        return 0
    print("")
    print("[*] dirs watch (-ws) — Ctrl+C to stop")
    return show_scout_status(ip, wait_dirs=True)


def run_scout(
    ip: str,
    *,
    force_scan: bool = False,
    force_dirs: bool = False,
    dry_run: bool = False,
    quiet_ports: bool = False,
    dirs_only: bool = False,
    dirs_multi: bool = False,
    dirs_preset: str = "standard",
    dirs_multi_preset_from_flag: bool = False,
    dirs_multi_preset_is_next: bool = False,
    dirs_urls: Optional[list[str]] = None,
    wordlist: Optional[str] = None,
    wordlists: Optional[list[str]] = None,
    threads: Optional[int] = None,
    extensions: Optional[str] = None,
):
    upsert_host(ip, status="up")

    if dirs_only or dirs_multi:
        if not dirs_urls and not discover_web_targets(ip):
            print("[-] no Web targets in DB — run scout first, or pass a URL")
            return 1
        rc = _run_dirs_phase(
            ip,
            urls=dirs_urls,
            wordlist=wordlist,
            wordlists=wordlists,
            dirs_multi=dirs_multi,
            dirs_preset=dirs_preset,
            dirs_multi_preset_from_flag=dirs_multi_preset_from_flag,
            dirs_multi_preset_is_next=dirs_multi_preset_is_next,
            threads=threads,
            extensions=extensions,
            dry_run=dry_run,
            force=force_dirs,
        )
        wait_rc = _auto_wait_dirs(ip, dry_run=dry_run)
        return max(rc, wait_rc)

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

    from scout_exploit import run_exploit_phase

    exploit_rc = run_exploit_phase(ip, dry_run=dry_run)
    if exploit_rc != 0:
        return exploit_rc

    dirs_rc = _run_dirs_phase(
        ip,
        urls=dirs_urls,
        wordlist=wordlist,
        threads=threads,
        extensions=extensions,
        dry_run=dry_run,
        force=force_dirs,
    )
    wait_rc = _auto_wait_dirs(ip, dry_run=dry_run)
    return max(rc, exploit_rc, dirs_rc, wait_rc)
