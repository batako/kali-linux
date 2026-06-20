"""Case-scoped recon data (THM room, target IP changes, load-from lineage)."""

from __future__ import annotations

import os
import re
import shutil
import sys
from pathlib import Path

from db import connect

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_CASE_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$")
TARGET_FILE = ".target"
LOAD_FROM_FILE = ".load_from"
LINEAGE_FILE = ".lineage"
RESERVED_CASE_NAME = "_unscoped"


def looks_like_ipv4(value: str) -> bool:
    return bool(_IPV4_RE.match((value or "").strip()))


def case_name_from_env() -> str | None:
    case = (os.environ.get("CASE") or "").strip()
    return case or None


def case_name_required() -> str:
    case = case_name_from_env()
    if not case:
        raise ValueError("CASE not set — cases set <room> first")
    return case


def case_home_from_env() -> Path | None:
    home = (os.environ.get("CASE_HOME") or "").strip()
    if not home:
        case = case_name_from_env()
        root = (os.environ.get("CASE_ROOT") or "/workspace/cases").strip()
        if case:
            return Path(root) / case
        return None
    return Path(home)


def load_from_path() -> Path | None:
    home = case_home_from_env()
    if home is None:
        return None
    return home / LOAD_FROM_FILE


def read_load_from() -> str | None:
    home = case_home_from_env()
    if home is None:
        return None
    path = home / LOAD_FROM_FILE
    if not path.is_file():
        return None
    ip = path.read_text(encoding="utf-8").strip()
    return ip if looks_like_ipv4(ip) else None


def write_load_from(ip: str | None) -> None:
    path = load_from_path()
    if path is None:
        raise ValueError("CASE_HOME not set — cases set <room> first")
    ip = (ip or "").strip()
    if not ip:
        if path.is_file():
            path.unlink()
        return
    if not looks_like_ipv4(ip):
        raise ValueError(f"invalid ip: {ip!r}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(ip + "\n", encoding="utf-8")


def clear_load_from() -> None:
    write_load_from(None)


def lineage_path() -> Path | None:
    home = case_home_from_env()
    if home is None:
        return None
    return home / LINEAGE_FILE


def read_lineage() -> list[str]:
    """Same-VM IP history for recon scope (excludes current target)."""
    home = case_home_from_env()
    if home is not None:
        path = home / LINEAGE_FILE
        if path.is_file():
            ips: list[str] = []
            for line in path.read_text(encoding="utf-8").splitlines():
                ip = line.strip()
                if looks_like_ipv4(ip) and ip not in ips:
                    ips.append(ip)
            return ips
    return []


def write_lineage(ips: list[str]) -> None:
    path = lineage_path()
    if path is None:
        raise ValueError("CASE_HOME not set — cases set <room> first")
    deduped: list[str] = []
    seen: set[str] = set()
    for raw in ips:
        ip = (raw or "").strip()
        if looks_like_ipv4(ip) and ip not in seen:
            seen.add(ip)
            deduped.append(ip)
    if not deduped:
        if path.is_file():
            path.unlink()
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(deduped) + "\n", encoding="utf-8")


def clear_lineage() -> None:
    path = lineage_path()
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("", encoding="utf-8")


def append_lineage(ip: str) -> None:
    ip = (ip or "").strip()
    if not looks_like_ipv4(ip):
        return
    ips = read_lineage()
    if ip in ips:
        return
    write_lineage(ips + [ip])


def merge_lineage(extra: list[str]) -> None:
    ips = read_lineage()
    for raw in extra:
        ip = (raw or "").strip()
        if looks_like_ipv4(ip) and ip not in ips:
            ips.append(ip)
    write_lineage(ips)


def update_lineage_on_target_set(
    *,
    new_ip: str,
    previous_ip: str | None,
    mode: str,
    load_from: str | None,
) -> list[str]:
    """Maintain lineage file when target IP changes (THM reboot chain)."""
    new_ip = new_ip.strip()
    previous_ip = (previous_ip or "").strip() or None
    mode = (mode or "auto").strip().lower()

    if mode == "new":
        clear_lineage()
        return []

    if mode == "pick":
        if load_from and load_from != new_ip:
            merge_lineage([load_from])
        else:
            clear_lineage()
        return read_lineage()

    inherit_ip = (load_from or "").strip() or None
    if not inherit_ip and previous_ip and previous_ip != new_ip and ip_has_recon_data(previous_ip):
        inherit_ip = previous_ip
    if inherit_ip and inherit_ip != new_ip:
        append_lineage(inherit_ip)
    return read_lineage()


def update_lineage_on_load_from(load_from: str | None) -> list[str]:
    """Change inherit source without changing target IP (cases load)."""
    if load_from:
        merge_lineage([load_from])
    else:
        clear_lineage()
    return read_lineage()


def read_target_ip() -> str | None:
    path = case_home_from_env()
    if path is None:
        return None
    target = path / TARGET_FILE
    if not target.is_file():
        return None
    ip = target.read_text(encoding="utf-8").strip().splitlines()[0].strip()
    return ip if looks_like_ipv4(ip) else None


def write_target_ip(ip: str | None) -> None:
    path = case_home_from_env()
    if path is None:
        raise ValueError("CASE_HOME not set — cases set <room> first")
    target = path / TARGET_FILE
    ip = (ip or "").strip()
    if not ip:
        if target.is_file():
            target.unlink()
        return
    if not looks_like_ipv4(ip):
        raise ValueError(f"invalid ip: {ip!r}")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(ip + "\n", encoding="utf-8")


def register_case_ip(case_name: str, ip: str) -> None:
    """Remember an IP used under this case (append-only history)."""
    case_name = (case_name or "").strip()
    ip = (ip or "").strip()
    if not case_name or not looks_like_ipv4(ip):
        return

    conn = connect()
    conn.execute(
        """
        INSERT INTO case_ips (case_name, ip, first_seen, last_seen)
        VALUES (?, ?, datetime('now'), datetime('now'))
        ON CONFLICT(case_name, ip) DO UPDATE SET
            last_seen = datetime('now')
        """,
        (case_name, ip),
    )
    conn.commit()
    conn.close()


def list_case_ips(case_name: str) -> list[str]:
    conn = connect()
    rows = conn.execute(
        """
        SELECT ip FROM case_ips
        WHERE case_name = ?
        ORDER BY last_seen DESC, ip
        """,
        (case_name,),
    ).fetchall()
    conn.close()
    return [r["ip"] for r in rows]


def _case_dir(case_name: str) -> Path:
    home = case_home_from_env()
    if home is not None and case_name_from_env() == case_name:
        return home
    root = (os.environ.get("CASE_ROOT") or "/workspace/cases").strip()
    return Path(root) / case_name


def _ips_from_case_files(case_name: str) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    home = _case_dir(case_name)

    def add(raw: str) -> None:
        ip = (raw or "").strip().splitlines()[0].strip()
        if looks_like_ipv4(ip) and ip not in seen:
            seen.add(ip)
            out.append(ip)

    for name in (TARGET_FILE, LOAD_FROM_FILE, LINEAGE_FILE):
        path = home / name
        if path.is_file():
            if name == LINEAGE_FILE:
                for line in path.read_text(encoding="utf-8").splitlines():
                    add(line)
            else:
                add(path.read_text(encoding="utf-8"))

    logs = home / "logs"
    if logs.is_dir():
        ip_in_name = re.compile(r"(?<![0-9])(\d{1,3}(?:\.\d{1,3}){3})(?![0-9])")
        for entry in logs.iterdir():
            if not entry.is_file():
                continue
            for ip in ip_in_name.findall(entry.name):
                if looks_like_ipv4(ip) and ip not in seen:
                    seen.add(ip)
                    out.append(ip)
    return out


def _ips_from_recon_db(case_name: str) -> list[str]:
    conn = connect()
    seen: set[str] = set()
    out: list[str] = []

    def add(ip: str | None) -> None:
        ip = (ip or "").strip()
        if looks_like_ipv4(ip) and ip not in seen:
            seen.add(ip)
            out.append(ip)

    for sql in (
        "SELECT DISTINCT ip FROM executions WHERE case_name = ?",
        "SELECT DISTINCT ip FROM scout_jobs WHERE case_name = ?",
        "SELECT DISTINCT ip FROM artifacts WHERE case_name = ?",
    ):
        for row in conn.execute(sql, (case_name,)).fetchall():
            add(row["ip"])

    conn.close()
    return out


def discover_case_ips(case_name: str, *, extra: list[str] | None = None) -> list[str]:
    """All IPs associated with a case (registry + recon + files + hints)."""
    seen: set[str] = set()
    out: list[str] = []

    def add(ip: str | None) -> None:
        ip = (ip or "").strip()
        if looks_like_ipv4(ip) and ip not in seen:
            seen.add(ip)
            out.append(ip)

    for ip in list_case_ips(case_name):
        add(ip)
    for ip in _ips_from_recon_db(case_name):
        add(ip)
    for ip in _ips_from_case_files(case_name):
        add(ip)
    for ip in extra or ():
        add(ip)
    return out


def sync_case_ip_registry(case_name: str, *, extra: list[str] | None = None) -> list[str]:
    """Backfill case_ips from recon/files (migration from pre-load_from workflow)."""
    ips = discover_case_ips(case_name, extra=extra)
    for ip in ips:
        register_case_ip(case_name, ip)
    return ips


def register_case_ip_from_env(ip: str) -> None:
    case = case_name_from_env()
    if case:
        register_case_ip(case, ip)


def validate_case_name(case_name: str) -> str:
    case_name = (case_name or "").strip()
    if not case_name or not _CASE_NAME_RE.match(case_name):
        raise ValueError(f"invalid case name: {case_name!r}")
    if case_name == RESERVED_CASE_NAME:
        raise ValueError(f"reserved case name: {case_name}")
    return case_name


def wipe_case_directory(case_name: str) -> int:
    """Delete all files under cases/<room>/; recreate empty logs/ and exports/."""
    validate_case_name(case_name)
    case_dir = _case_dir(case_name)
    removed = 0
    if case_dir.is_dir():
        for child in case_dir.iterdir():
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()
            removed += 1
    case_dir.mkdir(parents=True, exist_ok=True)
    (case_dir / "logs").mkdir(parents=True, exist_ok=True)
    (case_dir / "exports").mkdir(parents=True, exist_ok=True)
    return removed


def reset_case_db_data(case_name: str) -> dict[str, int]:
    """Remove recon DB rows for one room (executions, scout, ports, hints, …)."""
    validate_case_name(case_name)
    ips = discover_case_ips(case_name)
    artifact_ips = list(dict.fromkeys([*ips, case_name]))

    conn = connect()
    cur = conn.cursor()
    counts: dict[str, int] = {}

    def _delete(table: str, where: str, params: tuple) -> int:
        row = cur.execute(
            f"SELECT COUNT(*) AS c FROM {table} WHERE {where}",
            params,
        ).fetchone()
        n = int(row["c"] if row else 0)
        if n:
            cur.execute(f"DELETE FROM {table} WHERE {where}", params)
        return n

    counts["case_ips"] = _delete("case_ips", "case_name = ?", (case_name,))

    if ips:
        placeholders = ",".join("?" * len(ips))
        counts["executions"] = _delete(
            "executions",
            f"case_name = ? OR ip IN ({placeholders})",
            (case_name, *ips),
        )
        counts["scout_jobs"] = _delete(
            "scout_jobs",
            f"case_name = ? OR ip IN ({placeholders})",
            (case_name, *ips),
        )
        counts["tasks"] = _delete(
            "tasks",
            f"case_name = ? OR ip IN ({placeholders})",
            (case_name, *ips),
        )
        for table in ("ports", "port_scan_coverage", "scan_ranges", "hosts"):
            counts[table] = _delete(table, f"ip IN ({placeholders})", tuple(ips))
    else:
        counts["executions"] = _delete("executions", "case_name = ?", (case_name,))
        counts["scout_jobs"] = _delete("scout_jobs", "case_name = ?", (case_name,))
        counts["tasks"] = _delete("tasks", "case_name = ?", (case_name,))

    if artifact_ips:
        placeholders = ",".join("?" * len(artifact_ips))
        counts["artifacts"] = _delete(
            "artifacts",
            f"case_name = ? OR ip IN ({placeholders})",
            (case_name, *artifact_ips),
        )
    else:
        counts["artifacts"] = _delete("artifacts", "case_name = ?", (case_name,))

    conn.commit()
    conn.close()
    return counts


def reset_case(case_name: str) -> dict:
    """Wipe cases/<room>/ files and delete all recon DB data for the room."""
    validate_case_name(case_name)
    db_counts = reset_case_db_data(case_name)
    files_removed = wipe_case_directory(case_name)
    return {"files_removed": files_removed, "db": db_counts}


def _bootstrap_lineage_candidate_ips(case_name: str, current: str) -> list[str]:
    """Reboot-chain IPs from load_from + case logs + scout jobs (not bare registry)."""
    candidates: list[str] = []
    seen: set[str] = set()

    def add(raw: str | None) -> None:
        ip = (raw or "").strip()
        if not looks_like_ipv4(ip) or ip == current or ip in seen:
            return
        seen.add(ip)
        candidates.append(ip)

    add(read_load_from())
    for ip in _ips_from_case_files(case_name):
        add(ip)
    conn = connect()
    for row in conn.execute(
        "SELECT DISTINCT ip FROM scout_jobs WHERE case_name = ?",
        (case_name,),
    ):
        add(row["ip"])
    conn.close()
    return [ip for ip in candidates if ip_has_recon_data(ip)]


def bootstrap_lineage_if_needed(*, current_ip: str | None = None) -> bool:
    """
    One-time backfill when lineage file was never created (pre-lineage cases).

    Triggered from scout report (`s -r`) so legacy reboot chains appear in PATHS.
    Skipped when lineage file already exists (including empty after target-set --new).
    """
    path = lineage_path()
    if path is None or path.is_file():
        return False
    case = case_name_from_env()
    if not case:
        return False
    current = (
        (current_ip or os.environ.get("IP") or read_target_ip() or "").strip()
    )
    if not current:
        return False
    candidates = _bootstrap_lineage_candidate_ips(case, current)
    if not candidates:
        return False
    write_lineage(candidates)
    return True


def recon_scope_ips(current_ip: str | None = None) -> list[str]:
    """IPs whose recon data is active (lineage + current target)."""
    current = (current_ip or os.environ.get("IP") or "").strip()
    out: list[str] = []
    seen: set[str] = set()
    for ip in read_lineage():
        if ip == current:
            continue
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    if current and looks_like_ipv4(current) and current not in seen:
        out.append(current)
    return out


def ip_has_recon_data(ip: str) -> bool:
    if not looks_like_ipv4(ip):
        return False
    conn = connect()
    row = conn.execute(
        """
        SELECT 1 WHERE EXISTS (SELECT 1 FROM ports WHERE ip = ? LIMIT 1)
           OR EXISTS (SELECT 1 FROM executions WHERE ip = ? LIMIT 1)
           OR EXISTS (SELECT 1 FROM scout_jobs WHERE ip = ? LIMIT 1)
        """,
        (ip, ip, ip),
    ).fetchone()
    conn.close()
    return row is not None


def _ip_activity_summary(ip: str) -> dict:
    conn = connect()
    ports = conn.execute(
        "SELECT COUNT(*) AS n FROM ports WHERE ip = ? AND state = 'open'",
        (ip,),
    ).fetchone()["n"]
    dirs = conn.execute(
        "SELECT COUNT(*) AS n FROM scout_jobs WHERE ip = ? AND kind = 'dirs' AND status = 'done'",
        (ip,),
    ).fetchone()["n"]
    last_exec = conn.execute(
        "SELECT MAX(COALESCE(ended_at, started_at)) AS ts FROM executions WHERE ip = ?",
        (ip,),
    ).fetchone()["ts"]
    last_seen = conn.execute(
        "SELECT last_seen FROM case_ips WHERE ip = ? ORDER BY last_seen DESC LIMIT 1",
        (ip,),
    ).fetchone()
    conn.close()
    return {
        "open_ports": int(ports or 0),
        "dirs_done": int(dirs or 0),
        "last_activity": last_exec or (last_seen["last_seen"] if last_seen else ""),
    }


def list_case_ip_candidates(
    case_name: str,
    *,
    current_ip: str | None = None,
    exclude_ip: str | None = None,
    also_ips: list[str] | None = None,
) -> list[dict]:
    """Rows for inherit picker: ip, last_seen, open_ports, dirs_done, last_activity."""
    current = (current_ip or os.environ.get("IP") or "").strip()
    exclude = (exclude_ip or current or "").strip()
    hints = [x for x in (also_ips or []) if x]
    hints.extend(read_lineage())
    if read_load_from():
        hints.append(read_load_from())
    sync_case_ip_registry(case_name, extra=hints)

    out: list[dict] = []
    seen: set[str] = set()

    conn = connect()
    rows = conn.execute(
        """
        SELECT ip, last_seen
        FROM case_ips
        WHERE case_name = ?
        ORDER BY last_seen DESC, ip
        """,
        (case_name,),
    ).fetchall()
    conn.close()

    for row in rows:
        ip = row["ip"]
        if not looks_like_ipv4(ip) or ip in seen:
            continue
        if exclude and ip == exclude:
            continue
        if not ip_has_recon_data(ip):
            continue
        seen.add(ip)
        summary = _ip_activity_summary(ip)
        out.append(
            {
                "ip": ip,
                "last_seen": row["last_seen"] or summary["last_activity"] or "",
                "open_ports": summary["open_ports"],
                "dirs_done": summary["dirs_done"],
                "last_activity": summary["last_activity"] or row["last_seen"] or "",
            }
        )

    out.sort(
        key=lambda r: (r.get("last_activity") or r.get("last_seen") or ""),
        reverse=True,
    )
    return out


PROMPT_PICK = "load> "


def _read_choice(prompt: str, *, stream=None) -> str:
    """TTY では prompt 付き input、テスト用 stream では write + readline。"""
    if stream is not None:
        sys.stdout.write(prompt)
        sys.stdout.flush()
        return (stream.readline() or "").strip()
    try:
        return input(prompt).strip()
    except EOFError:
        return ""


def format_candidate_line(row: dict, *, marker: str = "") -> str:
    ip = row["ip"]
    ts = (row.get("last_seen") or row.get("last_activity") or "-")[:19]
    ports = row.get("open_ports", 0)
    dirs = row.get("dirs_done", 0)
    parts = [f"last {ts}"]
    if ports:
        parts.append(f"open×{ports}")
    if dirs:
        parts.append(f"dirs×{dirs}")
    tag = f"{marker} " if marker else ""
    return f"{tag}{ip}  ({', '.join(parts)})"


def print_case_ip_picker(
    case_name: str,
    *,
    current_ip: str | None = None,
    previous_ip: str | None = None,
    also_ips: list[str] | None = None,
) -> None:
    hints = list(also_ips or [])
    if previous_ip:
        hints.append(previous_ip)
    candidates = list_case_ip_candidates(
        case_name,
        current_ip=current_ip,
        exclude_ip=current_ip,
        also_ips=hints or None,
    )
    print(f"case {case_name} — pick load source")
    if current_ip:
        print(f"target: {current_ip}")
    print("")
    print("  0  --new (no inherit)")
    idx = 1
    for row in candidates:
        marker = ""
        if previous_ip and row["ip"] == previous_ip:
            marker = "*"
        print(f"  {idx}  {format_candidate_line(row, marker=marker)}")
        idx += 1


def pick_load_from_interactive(
    case_name: str,
    *,
    current_ip: str | None = None,
    previous_ip: str | None = None,
    stream=None,
) -> str | None:
    """Return load_from ip, or None for --new. Reads choice line from stream."""
    if stream is None:
        stream = sys.stdin
    hints = [previous_ip] if previous_ip else None
    candidates = list_case_ip_candidates(
        case_name,
        current_ip=current_ip,
        exclude_ip=current_ip,
        also_ips=hints,
    )
    print_case_ip_picker(
        case_name,
        current_ip=current_ip,
        previous_ip=previous_ip,
        also_ips=hints,
    )
    print("")
    line = _read_choice(PROMPT_PICK, stream=stream)
    if not line or line in ("0", "new", "n"):
        return None
    if line.isdigit():
        n = int(line)
        if n == 0:
            return None
        if 1 <= n <= len(candidates):
            return candidates[n - 1]["ip"]
    if looks_like_ipv4(line):
        return line
    raise ValueError(f"invalid choice: {line!r}")

def resolve_load_from(
    *,
    new_ip: str,
    previous_ip: str | None,
    mode: str,
    from_ip: str | None = None,
) -> str | None:
    """
    Decide load_from IP after target-set.

    mode: auto (default) | new | pick
    auto: inherit previous target when it has recon data (no prompt)
    """
    case = case_name_required()
    new_ip = new_ip.strip()
    previous_ip = (previous_ip or "").strip() or None

    if mode == "new":
        return None
    if mode == "pick":
        return pick_load_from_interactive(
            case,
            current_ip=new_ip,
            previous_ip=previous_ip,
        )
    if from_ip:
        if not looks_like_ipv4(from_ip):
            raise ValueError(f"invalid --from ip: {from_ip!r}")
        return from_ip

    if previous_ip and previous_ip != new_ip and ip_has_recon_data(previous_ip):
        return previous_ip

    return read_load_from()
