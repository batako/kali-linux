import fcntl
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
import json

DEFAULT_CONTAINER_DB_PATH = "/workspace/recon/recon.db"


def _default_db_path() -> str:
    """
    Prefer container path (/workspace/...) but allow local fallback.
    Priority:
      1) RECON_DB_PATH env var
      2) /workspace/recon/recon.db if its parent exists
      3) <repo>/workspace/recon/recon.db
    """
    env = os.environ.get("RECON_DB_PATH")
    if env:
        return env

    container_parent = Path(DEFAULT_CONTAINER_DB_PATH).parent
    if container_parent.exists():
        return DEFAULT_CONTAINER_DB_PATH

    repo_root = Path(__file__).resolve().parents[1]
    return str(repo_root / "workspace" / "recon" / "recon.db")


DB_PATH = _default_db_path()

SQLITE_BUSY_TIMEOUT_MS = int(os.environ.get("RECON_SQLITE_BUSY_TIMEOUT_MS", "5000"))


@contextmanager
def db_file_lock():
    """Serialize recon.db writers (parallel scan ingest)."""
    lock_path = Path(DB_PATH).resolve().parent / "recon.db.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with open(lock_path, "w") as lf:
        fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lf.fileno(), fcntl.LOCK_UN)


def connect():
    # Ensure parent directory exists for local runs.
    Path(DB_PATH).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=max(SQLITE_BUSY_TIMEOUT_MS / 1000.0, 1.0), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    _configure_sqlite(conn)
    ensure_schema(conn)
    return conn


def _configure_sqlite(conn):
    cur = conn.cursor()
    # Better concurrency for multi-worker setup
    cur.execute("PRAGMA journal_mode=WAL")
    cur.execute("PRAGMA synchronous=NORMAL")
    cur.execute("PRAGMA foreign_keys=ON")
    cur.execute(f"PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS}")


def init_db():
    conn = connect()
    conn.close()


# =========================
# schema
# =========================

def ensure_schema(conn):
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS hosts (
        ip TEXT PRIMARY KEY,
        hostname TEXT,
        mac TEXT,
        status TEXT,
        first_seen TEXT,
        last_seen TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS ports (
        ip TEXT,
        port INTEGER,
        proto TEXT,
        state TEXT,
        service TEXT,
        version TEXT,
        first_seen TEXT,
        last_seen TEXT,
        PRIMARY KEY(ip, port, proto)
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS scan_ranges (
        ip TEXT,
        scan_type TEXT,
        range_start INTEGER,
        range_end INTEGER,
        scanned_at TEXT,
        PRIMARY KEY(ip, scan_type, range_start, range_end)
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS port_scan_coverage (
        ip TEXT NOT NULL,
        port INTEGER NOT NULL,
        proto TEXT NOT NULL DEFAULT 'tcp',
        last_state TEXT,
        scan_profile TEXT,
        last_scan_at TEXT,
        PRIMARY KEY (ip, port, proto)
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT,
        task_type TEXT,
        description TEXT,
        status TEXT,
        priority INTEGER DEFAULT 0,
        requires_human_ok INTEGER DEFAULT 1,
        created_at TEXT,
        updated_at TEXT,
        UNIQUE(ip, task_type)
    )
    """)

    # executions: command runs tied to tasks
    cur.execute("""
    CREATE TABLE IF NOT EXISTS executions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        task_id INTEGER,
        ip TEXT,
        task_type TEXT,
        command TEXT,
        cwd TEXT,
        status TEXT,
        exit_code INTEGER,
        started_at TEXT,
        ended_at TEXT,
        stdout TEXT,
        stderr TEXT
    )
    """)

    # artifacts: extracted findings from executions
    cur.execute("""
    CREATE TABLE IF NOT EXISTS artifacts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT,
        kind TEXT,
        key TEXT,
        value TEXT,
        execution_id INTEGER,
        created_at TEXT
    )
    """)

    # Backward-compatible migrations for older DBs
    _migrate_tasks_table(cur)
    _backfill_task_defaults(cur)

    conn.commit()

def _table_columns(cur, table_name: str):
    rows = cur.execute(f"PRAGMA table_info({table_name})").fetchall()
    return {r[1] for r in rows}  # name is column 2


def _migrate_tasks_table(cur):
    cols = _table_columns(cur, "tasks")

    if "priority" not in cols:
        cur.execute("ALTER TABLE tasks ADD COLUMN priority INTEGER DEFAULT 0")

    if "requires_human_ok" not in cols:
        cur.execute("ALTER TABLE tasks ADD COLUMN requires_human_ok INTEGER DEFAULT 1")


def _backfill_task_defaults(cur):
    """
    Best-effort backfill of priority / requires_human_ok for tasks
    created before these columns existed.
    """
    defaults = {
        "dir-brute": (90, 1),
        "ftp-anon": (80, 0),
        "ssh-audit": (60, 0),
        "nfs-enum": (40, 0),
    }

    for task_type, (prio, human_ok) in defaults.items():
        cur.execute(
            """
            UPDATE tasks
            SET priority = CASE WHEN priority IS NULL OR priority = 0 THEN ? ELSE priority END,
                requires_human_ok = CASE
                    WHEN requires_human_ok IS NULL THEN ?
                    WHEN ? = 0 AND requires_human_ok = 1 THEN 0
                    ELSE requires_human_ok
                END
            WHERE task_type = ?
            """,
            (prio, human_ok, human_ok, task_type),
        )

# =========================
# task
# =========================

def get_task_by_id(task_id):
    conn = connect()
    cur = conn.cursor()

    row = cur.execute("""
    SELECT id, ip, task_type, description, status, priority, requires_human_ok
    FROM tasks
    WHERE id = ?
    """, (task_id,)).fetchone()

    conn.close()
    return row


def add_task(ip, task_type, description, priority=0, requires_human_ok=1):
    conn = connect()
    cur = conn.cursor()

    cur.execute("""
    INSERT OR IGNORE INTO tasks (
        ip, task_type, description, status, priority, requires_human_ok, created_at, updated_at
    ) VALUES (
        ?, ?, ?, 'pending', ?, ?, datetime('now'), datetime('now')
    )
    """, (ip, task_type, description, int(priority), int(requires_human_ok)))

    conn.commit()
    conn.close()


def complete_task(task_id):
    conn = connect()
    cur = conn.cursor()

    cur.execute(
        """
        UPDATE tasks
        SET status = 'done',
            updated_at = datetime('now')
        WHERE id = ?
        """,
        (task_id,),
    )

    conn.commit()
    conn.close()

def set_task_status(task_id, status):
    conn = connect()
    cur = conn.cursor()

    cur.execute(
        """
        UPDATE tasks
        SET status = ?,
            updated_at = datetime('now')
        WHERE id = ?
        """,
        (status, task_id),
    )

    conn.commit()
    conn.close()

def claim_task(task_id):
    """
    Atomically mark a pending task as running.
    Returns True if claimed, False otherwise.
    """
    conn = connect()
    cur = conn.cursor()
    cur.execute("BEGIN IMMEDIATE")
    cur.execute(
        """
        UPDATE tasks
        SET status = 'running',
            updated_at = datetime('now')
        WHERE id = ?
          AND status = 'pending'
        """,
        (task_id,),
    )
    claimed = cur.rowcount == 1
    conn.commit()
    conn.close()
    return claimed


def claim_next_task_for_host(ip):
    """
    Atomically pick and claim the highest priority pending task for a host.
    Returns task_id or None.
    """
    conn = connect()
    cur = conn.cursor()
    cur.execute("BEGIN IMMEDIATE")
    row = cur.execute(
        """
        SELECT id
        FROM tasks
        WHERE ip = ?
          AND status = 'pending'
        ORDER BY priority DESC, id
        LIMIT 1
        """,
        (ip,),
    ).fetchone()

    if not row:
        conn.commit()
        conn.close()
        return None

    task_id = int(row["id"])
    cur.execute(
        """
        UPDATE tasks
        SET status = 'running',
            updated_at = datetime('now')
        WHERE id = ?
          AND status = 'pending'
        """,
        (task_id,),
    )

    if cur.rowcount != 1:
        conn.commit()
        conn.close()
        return None

    conn.commit()
    conn.close()
    return task_id

def get_tasks(ip=None):
    conn = connect()
    cur = conn.cursor()

    if ip:
        rows = cur.execute("""
        SELECT id, ip, task_type, description, status, priority, requires_human_ok
        FROM tasks
        WHERE ip = ?
        ORDER BY priority DESC, id
        """, (ip,))
    else:
        rows = cur.execute("""
        SELECT id, ip, task_type, description, status, priority, requires_human_ok
        FROM tasks
        ORDER BY priority DESC, id
        """)

    result = rows.fetchall()
    conn.close()
    return result


# =========================
# host
# =========================

def upsert_host(ip, hostname="", mac="", status="alive"):
    conn = connect()
    cur = conn.cursor()

    cur.execute("""
    INSERT INTO hosts VALUES (
        ?, ?, ?, ?, datetime('now'), datetime('now')
    )
    ON CONFLICT(ip)
    DO UPDATE SET
        hostname = excluded.hostname,
        mac = excluded.mac,
        status = excluded.status,
        last_seen = datetime('now')
    """, (ip, hostname, mac, status))

    conn.commit()
    conn.close()


def show_hosts():
    conn = connect()
    cur = conn.cursor()

    rows = cur.execute("""
    SELECT ip, status, last_seen
    FROM hosts
    ORDER BY ip
    """)

    print("")
    print("IP\tSTATUS\tLAST_SEEN")

    for r in rows.fetchall():
        print(f"{r[0]}\t{r[1]}\t{r[2]}")

    conn.close()


# =========================
# port
# =========================

def upsert_port(ip, port, proto, state, service, version):
    conn = connect()
    cur = conn.cursor()

    cur.execute("""
    INSERT INTO ports VALUES (
        ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now')
    )
    ON CONFLICT(ip, port, proto)
    DO UPDATE SET
        state = excluded.state,
        service = excluded.service,
        version = excluded.version,
        last_seen = datetime('now')
    """, (ip, port, proto, state, service, version))

    conn.commit()
    conn.close()


def _fetch_ports(ip, state=None, closed_with_service=False):
    conn = connect()
    cur = conn.cursor()
    if closed_with_service:
        rows = cur.execute(
            """
            SELECT port, proto, state, service, version
            FROM ports
            WHERE ip = ? AND state = 'closed'
              AND (
                TRIM(COALESCE(service, '')) != ''
                OR TRIM(COALESCE(version, '')) != ''
              )
            ORDER BY port
            """,
            (ip,),
        ).fetchall()
    elif state is None:
        rows = cur.execute(
            """
            SELECT port, proto, state, service, version
            FROM ports
            WHERE ip = ?
            ORDER BY port
            """,
            (ip,),
        ).fetchall()
    else:
        rows = cur.execute(
            """
            SELECT port, proto, state, service, version
            FROM ports
            WHERE ip = ? AND state = ?
            ORDER BY port
            """,
            (ip, state),
        ).fetchall()
    conn.close()
    return rows


def _port_group_heading(name):
    """Section title distinct from tabular column header."""
    return f"--- {name} ---"


def format_port_section_lines(label, rows, group=True, show_coverage=False, ip=None):
    lines = []
    lines.append(_port_group_heading(label) if group else label)
    header = "PORT\tPROTO\tSTATE\tSERVICE\tVERSION"
    if show_coverage and ip:
        covered = count_port_scan_coverage(ip)
        header = f"{header}\t(coverage: {covered})"
    lines.append(header)
    if not rows:
        lines.append("(none)")
    else:
        for p in rows:
            lines.append(f"{p[0]}\t{p[1]}\t{p[2]}\t{p[3]}\t{p[4]}")
    return lines


def format_scan_snapshot_lines(ip, progress_line):
    """Lines for live-updating scan UI (progress + OPEN + CLOSED)."""
    lines = [progress_line]
    lines.extend(format_port_section_lines("OPEN", _fetch_ports(ip, "open")))
    lines.extend(
        format_port_section_lines("CLOSED", _fetch_ports(ip, closed_with_service=True))
    )
    return lines


def _print_port_section(label, rows, show_coverage=False, ip=None, group=False):
    for line in format_port_section_lines(label, rows, group=group, show_coverage=show_coverage, ip=ip):
        print(line)
    print("")


def print_ports(ip, open_only=True, show_coverage=False, split_open_closed=False, compact=False):
    """Compact port table for scan output and host-view."""
    if not compact:
        print("")
    if split_open_closed:
        open_rows = _fetch_ports(ip, "open")
        # closed but nmap attached service/version (not bare closed noise)
        closed_rows = _fetch_ports(ip, closed_with_service=True)
        _print_port_section("OPEN", open_rows, show_coverage=show_coverage, ip=ip, group=True)
        _print_port_section("CLOSED", closed_rows, group=True)
        return

    if open_only:
        rows = _fetch_ports(ip, "open")
        label = "PORTS"
    else:
        rows = _fetch_ports(ip)
        label = "PORTS"

    _print_port_section(label, rows, show_coverage=show_coverage, ip=ip if show_coverage else None)


def show_host(ip):
    conn = connect()
    cur = conn.cursor()

    # -------------------------
    # tasks
    # -------------------------
    tasks = cur.execute("""
    SELECT id, task_type, status, description, priority, requires_human_ok
    FROM tasks
    WHERE ip = ?
    ORDER BY priority DESC, id
    """, (ip,)).fetchall()

    # -------------------------
    # scan ranges
    # -------------------------
    scans = cur.execute("""
    SELECT scan_type, range_start, range_end
    FROM scan_ranges
    WHERE ip = ?
    """, (ip,)).fetchall()

    # -------------------------
    # recent executions
    # -------------------------
    executions = cur.execute("""
    SELECT id, task_id, task_type, status, exit_code, started_at, ended_at
    FROM executions
    WHERE ip = ?
    ORDER BY id DESC
    LIMIT 10
    """, (ip,)).fetchall()

    # -------------------------
    # artifacts
    # -------------------------
    artifacts = cur.execute("""
    SELECT kind, key, value, created_at
    FROM artifacts
    WHERE ip = ?
    ORDER BY id DESC
    LIMIT 50
    """, (ip,)).fetchall()

    ports = cur.execute("""
    SELECT port, proto, state, service, version
    FROM ports
    WHERE ip = ?
    ORDER BY port
    """, (ip,)).fetchall()

    print("")
    print(f"HOST: {ip}")
    print("")

    print_ports(ip, open_only=False, show_coverage=True)

    # =========================
    # SCAN PROGRESS
    # =========================
    print("SCAN HISTORY")

    if scans:
        for s in scans:
            print(f"{s[0]}\t{s[1]}-{s[2]}")
    else:
        print("no scan data")

    try:
        from port_sets import nmap_top1000_tcp
        from port_sets import FULL_TCP_START
        from port_sets import FULL_TCP_END

        basic_cov = count_tcp_coverage_in_ports(ip, nmap_top1000_tcp())
        full_cov = count_tcp_coverage_in_ports(ip, range(FULL_TCP_START, FULL_TCP_END + 1))
        print(f"basic coverage: {basic_cov}/1000 (top ports)")
        print(f"full coverage: {full_cov}/65535 (tcp)")
        if full_cov > 0 and full_cov < 65535:
            print("full status: in progress — run scan -f until complete")
        elif full_cov >= 65535:
            print("full status: complete")
    except FileNotFoundError:
        pass

    print("")

    # =========================
    # TASKS
    # =========================
    print("TASKS")

    if not tasks:
        print("no tasks")
    else:
        for t in tasks:
            status_mark = "[x]" if t["status"] in ("done",) else "[ ]"
            needs_ok = " (human-ok)" if int(t["requires_human_ok"] or 0) == 1 else ""
            print(f"{status_mark} id={t['id']} p={t['priority']} {t['task_type']}{needs_ok} - {t['description']}")

    print("")

    # =========================
    # EXECUTIONS
    # =========================
    print("RECENT EXECUTIONS")

    if not executions:
        print("no executions")
    else:
        for e in executions:
            ended = e["ended_at"] or "-"
            code = e["exit_code"] if e["exit_code"] is not None else "-"
            print(f"- exec_id={e['id']} task_id={e['task_id']} {e['task_type']} status={e['status']} exit={code} ended={ended}")

    print("")

    # =========================
    # ARTIFACTS
    # =========================
    print("ARTIFACTS")

    if not artifacts:
        print("no artifacts")
    else:
        for a in artifacts:
            key = f"{a['kind']}:{a['key']}" if a["key"] else a["kind"]
            print(f"- {key} = {a['value']}")

    print("")

    # =========================
    # ATTACK HINTS
    # =========================
    print("ATTACK HINTS")

    services = {(p[3] or "").lower() for p in ports if p[3]}

    if "ftp" in services:
        print("- ftp anonymous check")
    if "http" in services:
        print("- web directory brute force")
    if "rpcbind" in services:
        print("- possible NFS enumeration")
    if "ssh" in services:
        print("- check weak credentials / keys")

    print("")

    # =========================
    # NEXT ACTION
    # =========================
    pending = [t for t in tasks if t["status"] not in ("done", "skipped")]

    if pending:
        print("NEXT ACTION")
        t = pending[0]
        print(f"- id={t['id']} {t['task_type']}: {t['description']} (p={t['priority']})")

    conn.close()


# =========================
# scan tracking
# =========================

def reset_host_scan_data(ip):
    """Remove ports, coverage, and scan history for one host (scan re-test)."""
    conn = connect()
    cur = conn.cursor()
    counts = {}
    for table in ("port_scan_coverage", "ports", "scan_ranges"):
        n = cur.execute(
            f"SELECT COUNT(*) AS c FROM {table} WHERE ip = ?",
            (ip,),
        ).fetchone()["c"]
        cur.execute(f"DELETE FROM {table} WHERE ip = ?", (ip,))
        counts[table] = int(n)
    conn.commit()
    conn.close()
    return counts


def add_scan_range(ip, scan_type, start, end):
    conn = connect()
    cur = conn.cursor()

    cur.execute("""
    INSERT OR IGNORE INTO scan_ranges VALUES (
        ?, ?, ?, ?, datetime('now')
    )
    """, (ip, scan_type, start, end))

    conn.commit()
    conn.close()


def has_scan_range(ip, scan_type, range_start, range_end):
    conn = connect()
    cur = conn.cursor()
    row = cur.execute(
        """
        SELECT 1 FROM scan_ranges
        WHERE ip = ? AND scan_type = ? AND range_start = ? AND range_end = ?
        """,
        (ip, scan_type, range_start, range_end),
    ).fetchone()
    conn.close()
    return row is not None


# =========================
# port scan coverage (偵察済みポート)
# =========================

def mark_port_scanned(ip, port, proto, state, scan_profile):
    conn = connect()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO port_scan_coverage (
            ip, port, proto, last_state, scan_profile, last_scan_at
        ) VALUES (?, ?, ?, ?, ?, datetime('now'))
        ON CONFLICT(ip, port, proto) DO UPDATE SET
            last_state = excluded.last_state,
            scan_profile = excluded.scan_profile,
            last_scan_at = datetime('now')
        """,
        (ip, int(port), proto, state, scan_profile),
    )
    conn.commit()
    conn.close()


def get_scanned_ports(ip, proto="tcp"):
    conn = connect()
    cur = conn.cursor()
    rows = cur.execute(
        """
        SELECT port FROM port_scan_coverage
        WHERE ip = ? AND proto = ?
        ORDER BY port
        """,
        (ip, proto),
    ).fetchall()
    conn.close()
    return [int(r["port"]) for r in rows]


def count_tcp_coverage_in_ports(ip, port_iter):
    """How many ports from port_iter appear in port_scan_coverage."""
    scanned = set(get_scanned_ports(ip))
    return sum(1 for p in port_iter if p in scanned)


def count_port_scan_coverage(ip, proto="tcp"):
    conn = connect()
    cur = conn.cursor()
    row = cur.execute(
        """
        SELECT COUNT(*) AS n FROM port_scan_coverage
        WHERE ip = ? AND proto = ?
        """,
        (ip, proto),
    ).fetchone()
    conn.close()
    return int(row["n"]) if row else 0


def format_nmap_port_list(ports, max_ports=800):
    """Comma-separated port list for nmap -p / --exclude-ports (argv limit)."""
    if not ports:
        return ""
    ports = sorted(set(int(p) for p in ports))
    if len(ports) > max_ports:
        ports = ports[:max_ports]
    return ",".join(str(p) for p in ports)


def format_nmap_exclude_ports(ports, max_ports=800):
    return format_nmap_port_list(ports, max_ports=max_ports)


def seed_coverage_from_ports(ip, profile="seed"):
    """Backfill coverage from ports table (legacy rows without port_scan_coverage)."""
    conn = connect()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO port_scan_coverage (
            ip, port, proto, last_state, scan_profile, last_scan_at
        )
        SELECT ip, port, proto, COALESCE(state, 'unknown'), ?, datetime('now')
        FROM ports
        WHERE ip = ?
        ON CONFLICT(ip, port, proto) DO NOTHING
        """,
        (profile, ip),
    )
    conn.commit()
    conn.close()


def count_open_ports(ip):
    conn = connect()
    cur = conn.cursor()
    row = cur.execute(
        """
        SELECT COUNT(*) AS n FROM ports
        WHERE ip = ? AND state = 'open'
        """,
        (ip,),
    ).fetchone()
    conn.close()
    return int(row["n"]) if row else 0


def show_scan_report(ip):
    """DB port summary for hacking: coverage line + OPEN + CLOSED (same as scan end)."""
    from port_sets import FULL_TCP_END
    from port_sets import FULL_TCP_START
    from port_sets import full_tcp_ports
    from port_sets import nmap_top1000_tcp

    basic_cov = count_tcp_coverage_in_ports(ip, nmap_top1000_tcp())
    full_cov = count_tcp_coverage_in_ports(ip, full_tcp_ports())
    progress = f"[*] basic {basic_cov}/1000  full {full_cov}/{FULL_TCP_END}"

    print("========================")
    print(f"[SCAN REPORT] {ip}")
    print("========================")
    print("")
    for line in format_scan_snapshot_lines(ip, progress):
        print(line)
    print("")


# =========================
# tasks view
# =========================

def show_tasks():
    rows = get_tasks()

    print("")
    print("ID\tIP\tTYPE\tPRIORITY\tSTATUS\tHUMAN_OK\tDESCRIPTION")

    for r in rows:
        print(f"{r['id']}\t{r['ip']}\t{r['task_type']}\t{r['priority']}\t{r['status']}\t{r['requires_human_ok']}\t{r['description']}")


# =========================
# execution & artifacts
# =========================

def add_execution(task_id, ip, task_type, command, cwd="/", status="running"):
    conn = connect()
    cur = conn.cursor()

    cur.execute("""
    INSERT INTO executions (
        task_id, ip, task_type, command, cwd, status, started_at
    ) VALUES (
        ?, ?, ?, ?, ?, ?, datetime('now')
    )
    """, (task_id, ip, task_type, command, cwd, status))

    exec_id = cur.lastrowid
    conn.commit()
    conn.close()
    return exec_id


def finish_execution(execution_id, status, exit_code=None, stdout="", stderr=""):
    conn = connect()
    cur = conn.cursor()

    cur.execute("""
    UPDATE executions
    SET status = ?,
        exit_code = ?,
        stdout = ?,
        stderr = ?,
        ended_at = datetime('now')
    WHERE id = ?
    """, (status, exit_code, stdout, stderr, execution_id))

    conn.commit()
    conn.close()


def find_done_execution(ip: str, command: str):
    """Return latest successful execution for ip+command, or None."""
    command = (command or "").strip()
    if not ip or not command:
        return None

    conn = connect()
    cur = conn.cursor()
    row = cur.execute(
        """
        SELECT id, ip, command, status, exit_code, stdout, stderr, started_at, ended_at
        FROM executions
        WHERE ip = ?
          AND command = ?
          AND status = 'done'
          AND exit_code = 0
        ORDER BY id DESC
        LIMIT 1
        """,
        (ip, command),
    ).fetchone()
    conn.close()
    return row


def add_artifact(ip, kind, key, value, execution_id=None):
    """
    Insert artifact if (ip, kind, key, value) is new.
    On duplicate: skip insert; refresh execution_id when provided.
    Returns artifact id.
    """
    key = key or ""
    conn = connect()
    cur = conn.cursor()

    row = cur.execute(
        """
        SELECT id
        FROM artifacts
        WHERE ip = ? AND kind = ? AND key = ? AND value = ?
        ORDER BY id DESC
        LIMIT 1
        """,
        (ip, kind, key, value),
    ).fetchone()

    if row:
        art_id = int(row["id"])
        if execution_id is not None:
            cur.execute(
                """
                UPDATE artifacts
                SET execution_id = ?, created_at = datetime('now')
                WHERE id = ?
                """,
                (execution_id, art_id),
            )
            conn.commit()
        conn.close()
        return art_id

    cur.execute(
        """
        INSERT INTO artifacts (
            ip, kind, key, value, execution_id, created_at
        ) VALUES (?, ?, ?, ?, ?, datetime('now'))
        """,
        (ip, kind, key, value, execution_id),
    )
    art_id = int(cur.lastrowid)
    conn.commit()
    conn.close()
    return art_id


def _get_password_artifact(ip: str, username: str):
    conn = connect()
    row = conn.execute(
        """
        SELECT id, value
        FROM artifacts
        WHERE ip = ? AND kind = 'password' AND key = ?
        ORDER BY id DESC
        LIMIT 1
        """,
        (ip, username),
    ).fetchone()
    conn.close()
    return row


def _username_artifact_exists(ip: str, username: str) -> bool:
    conn = connect()
    row = conn.execute(
        """
        SELECT 1
        FROM artifacts
        WHERE ip = ? AND kind = 'username' AND value = ?
        LIMIT 1
        """,
        (ip, username),
    ).fetchone()
    conn.close()
    return row is not None


def creds_upsert(ip: str, username: str, password: str, execution_id=None) -> str:
    """
    Insert or update ssh credentials for (ip, username).
    Returns: saved | updated | unchanged
    """
    if not ip or not username or not password:
        raise ValueError("ip, username, and password required")

    existing = _get_password_artifact(ip, username)
    if existing and (existing["value"] or "") == password:
        return "unchanged"

    conn = connect()
    cur = conn.cursor()

    if existing:
        cur.execute(
            """
            UPDATE artifacts
            SET value = ?, execution_id = ?, created_at = datetime('now')
            WHERE id = ?
            """,
            (password, execution_id, int(existing["id"])),
        )
        status = "updated"
    else:
        cur.execute(
            """
            INSERT INTO artifacts (
                ip, kind, key, value, execution_id, created_at
            ) VALUES (?, 'password', ?, ?, ?, datetime('now'))
            """,
            (ip, username, password, execution_id),
        )
        status = "saved"

    has_user = cur.execute(
        """
        SELECT 1 FROM artifacts
        WHERE ip = ? AND kind = 'username' AND value = ?
        LIMIT 1
        """,
        (ip, username),
    ).fetchone()

    if not has_user:
        cur.execute(
            """
            INSERT INTO artifacts (
                ip, kind, key, value, execution_id, created_at
            ) VALUES (?, 'username', '', ?, ?, datetime('now'))
            """,
            (ip, username, execution_id),
        )

    conn.commit()
    conn.close()
    return status


def creds_delete(ip: str, username: str = None) -> int:
    """
    Remove stored credentials for ip (optional: single username).
    Deletes password/username rows and ssh_last_user when applicable.
    """
    if not ip:
        raise ValueError("ip required")

    conn = connect()
    cur = conn.cursor()

    if username:
        cur.execute(
            """
            DELETE FROM artifacts
            WHERE ip = ? AND (
                (kind IN ('password', 'username') AND (key = ? OR value = ?))
                OR (kind = 'ssh_last_user' AND value = ?)
            )
            """,
            (ip, username, username, username),
        )
    else:
        cur.execute(
            """
            DELETE FROM artifacts
            WHERE ip = ? AND kind IN ('password', 'username', 'ssh_last_user')
            """,
            (ip,),
        )

    deleted = cur.rowcount
    conn.commit()
    conn.close()
    return deleted


# Stored for creds/ssh; hidden from artifact-list (use creds-list / cl)
_ARTIFACT_CRED_KINDS = ("username", "password", "ssh_last_user")


def list_ssh_creds(ip: str):
    """Return [{username, password}, ...] one row per username (latest password)."""
    conn = connect()
    rows = conn.execute(
        """
        SELECT key AS username, value AS password
        FROM artifacts
        WHERE id IN (
            SELECT MAX(id)
            FROM artifacts
            WHERE ip = ? AND kind = 'password' AND key != ''
            GROUP BY key
        )
        ORDER BY key
        """,
        (ip,),
    ).fetchall()
    conn.close()
    return [{"username": r["username"], "password": r["password"]} for r in rows]


def get_ssh_last_user(ip: str):
    conn = connect()
    row = conn.execute(
        """
        SELECT value
        FROM artifacts
        WHERE ip = ? AND kind = 'ssh_last_user' AND key = ''
        ORDER BY id DESC
        LIMIT 1
        """,
        (ip,),
    ).fetchone()
    conn.close()
    return row["value"] if row else None


def set_ssh_last_user(ip: str, username: str, execution_id=None):
    if get_ssh_last_user(ip) == username:
        return
    conn = connect()
    cur = conn.cursor()
    cur.execute(
        "DELETE FROM artifacts WHERE ip = ? AND kind = 'ssh_last_user'",
        (ip,),
    )
    cur.execute(
        """
        INSERT INTO artifacts (
            ip, kind, key, value, execution_id, created_at
        ) VALUES (?, 'ssh_last_user', '', ?, ?, datetime('now'))
        """,
        (ip, username, execution_id),
    )
    conn.commit()
    conn.close()


def get_host_summary(ip: str, executions_limit: int = 10, artifacts_limit: int = 50):
    conn = connect()
    cur = conn.cursor()

    host = cur.execute(
        """
        SELECT ip, hostname, mac, status, first_seen, last_seen
        FROM hosts
        WHERE ip = ?
        """,
        (ip,),
    ).fetchone()

    ports = cur.execute(
        """
        SELECT port, proto, state, service, version, first_seen, last_seen
        FROM ports
        WHERE ip = ?
        ORDER BY port
        """,
        (ip,),
    ).fetchall()

    tasks = cur.execute(
        """
        SELECT id, task_type, description, status, priority, requires_human_ok, created_at, updated_at
        FROM tasks
        WHERE ip = ?
        ORDER BY priority DESC, id
        """,
        (ip,),
    ).fetchall()

    scans = cur.execute(
        """
        SELECT scan_type, range_start, range_end, scanned_at
        FROM scan_ranges
        WHERE ip = ?
        ORDER BY scanned_at DESC
        """,
        (ip,),
    ).fetchall()

    executions = cur.execute(
        """
        SELECT id, task_id, task_type, command, cwd, status, exit_code, started_at, ended_at
        FROM executions
        WHERE ip = ?
        ORDER BY id DESC
        LIMIT ?
        """,
        (ip, int(executions_limit)),
    ).fetchall()

    artifacts = cur.execute(
        """
        SELECT id, kind, key, value, execution_id, created_at
        FROM artifacts
        WHERE ip = ?
        ORDER BY id DESC
        LIMIT ?
        """,
        (ip, int(artifacts_limit)),
    ).fetchall()

    conn.close()

    def row_to_dict(r):
        return dict(r) if r is not None else None

    return {
        "ip": ip,
        "host": row_to_dict(host),
        "ports": [dict(r) for r in ports],
        "tasks": [dict(r) for r in tasks],
        "scan_ranges": [dict(r) for r in scans],
        "executions_recent": [dict(r) for r in executions],
        "artifacts_recent": [dict(r) for r in artifacts],
    }


def print_host_summary_json(ip: str, executions_limit: int = 10, artifacts_limit: int = 50):
    summary = get_host_summary(ip, executions_limit=executions_limit, artifacts_limit=artifacts_limit)
    print(json.dumps(summary, ensure_ascii=False, indent=2))


def list_executions(ip: str = None, limit: int = 50):
    conn = connect()
    cur = conn.cursor()

    if ip:
        rows = cur.execute(
            """
            SELECT id, ip, task_id, task_type, status, exit_code, started_at, ended_at, command
            FROM executions
            WHERE ip = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (ip, int(limit)),
        ).fetchall()
    else:
        rows = cur.execute(
            """
            SELECT id, ip, task_id, task_type, status, exit_code, started_at, ended_at, command
            FROM executions
            ORDER BY id DESC
            LIMIT ?
            """,
            (int(limit),),
        ).fetchall()

    conn.close()
    return rows


def get_execution(execution_id: int):
    conn = connect()
    cur = conn.cursor()

    row = cur.execute(
        """
        SELECT id, ip, task_id, task_type, command, cwd, status, exit_code, started_at, ended_at, stdout, stderr
        FROM executions
        WHERE id = ?
        """,
        (int(execution_id),),
    ).fetchone()

    conn.close()
    return row


def list_artifacts(ip: str = None, limit: int = 100):
    """
    Distinct artifacts for list view: latest row per (ip, kind, key, value).
    Excludes cred-related kinds (see creds-list / cl).
    """
    conn = connect()
    kinds_placeholders = ",".join("?" * len(_ARTIFACT_CRED_KINDS))
    params = list(_ARTIFACT_CRED_KINDS)

    if ip:
        rows = conn.execute(
            f"""
            SELECT a.id, a.ip, a.kind, a.key, a.value, a.execution_id, a.created_at
            FROM artifacts a
            INNER JOIN (
                SELECT MAX(id) AS id
                FROM artifacts
                WHERE ip = ?
                  AND kind NOT IN ({kinds_placeholders})
                GROUP BY kind, COALESCE(key, ''), value
            ) d ON a.id = d.id
            ORDER BY a.id DESC
            LIMIT ?
            """,
            (ip, *params, int(limit)),
        ).fetchall()
    else:
        rows = conn.execute(
            f"""
            SELECT a.id, a.ip, a.kind, a.key, a.value, a.execution_id, a.created_at
            FROM artifacts a
            INNER JOIN (
                SELECT MAX(id) AS id
                FROM artifacts
                WHERE kind NOT IN ({kinds_placeholders})
                GROUP BY ip, kind, COALESCE(key, ''), value
            ) d ON a.id = d.id
            ORDER BY a.id DESC
            LIMIT ?
            """,
            (*params, int(limit)),
        ).fetchall()

    conn.close()
    return rows


def delete_artifact(artifact_id: int):
    conn = connect()
    cur = conn.cursor()
    cur.execute("DELETE FROM artifacts WHERE id = ?", (int(artifact_id),))
    deleted = cur.rowcount
    conn.commit()
    conn.close()
    return deleted
