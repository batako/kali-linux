"""Case-scoped recon data (THM room, target IP changes, load-from lineage)."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

from db import connect

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
LOAD_FROM_FILE = "load_from"


def looks_like_ipv4(value: str) -> bool:
    return bool(_IPV4_RE.match((value or "").strip()))


def case_name_from_env() -> str | None:
    case = (os.environ.get("CASE") or "").strip()
    return case or None


def case_name_required() -> str:
    case = case_name_from_env()
    if not case:
        raise ValueError("CASE not set — cs <case> first")
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
    path = load_from_path()
    if path is None or not path.is_file():
        return None
    ip = path.read_text(encoding="utf-8").strip()
    return ip if looks_like_ipv4(ip) else None


def write_load_from(ip: str | None) -> None:
    path = load_from_path()
    if path is None:
        raise ValueError("CASE_HOME not set — cs <case> first")
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


def read_target_ip() -> str | None:
    path = case_home_from_env()
    if path is None:
        return None
    target = path / "target"
    if not target.is_file():
        return None
    ip = target.read_text(encoding="utf-8").strip().splitlines()[0].strip()
    return ip if looks_like_ipv4(ip) else None


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

    for name in ("target", "load_from"):
        path = home / name
        if path.is_file():
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


def recon_scope_ips(current_ip: str | None = None) -> list[str]:
    """IPs whose recon data is active (load_from + current target)."""
    current = (current_ip or os.environ.get("IP") or "").strip()
    load_from = read_load_from()
    out: list[str] = []
    if load_from and load_from != current:
        out.append(load_from)
    if current and looks_like_ipv4(current):
        if current not in out:
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


PROMPT_INHERIT = "> "
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
    assume_yes: bool = False,
) -> str | None:
    """
    Decide load_from IP after ta.

    mode: inherit (default) | new | pick
    Returns load_from ip or None.
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
        if assume_yes:
            return previous_ip
        if not sys.stdin.isatty():
            return previous_ip
        print(f"[?] Continue from {previous_ip}?")
        print("    Y  inherit (default)   n  --new   p  pick")
        line = _read_choice(PROMPT_INHERIT).lower()
        if line in ("n", "no", "new"):
            return None
        if line in ("p", "pick", "l", "list"):
            return pick_load_from_interactive(
                case,
                current_ip=new_ip,
                previous_ip=previous_ip,
            )
        return previous_ip

    return read_load_from()
