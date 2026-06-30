import fcntl
import os
import re
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

_DIRS_HOST_CMD_RE = re.compile(
    r"""-H\s+(?:'|")?Host:\s*([^\s'"]+)""",
    re.IGNORECASE,
)

DEFAULT_CONTAINER_DB_PATH = "/opt/recon/data/recon.db"


def _default_db_path() -> str:
    """
    Prefer container path (/opt/recon/data/...) but allow local fallback.
    Priority:
      1) RECON_DB_PATH env var
      2) /opt/recon/data/recon.db if its parent exists (container)
      3) <recon>/data/recon.db (local tests / repo checkout)
    """
    env = os.environ.get("RECON_DB_PATH")
    if env:
        return env

    container_parent = Path(DEFAULT_CONTAINER_DB_PATH).parent
    if container_parent.exists():
        return DEFAULT_CONTAINER_DB_PATH

    recon_root = Path(__file__).resolve().parent
    return str(recon_root / "data" / "recon.db")


DB_PATH = _default_db_path()

SQLITE_BUSY_TIMEOUT_MS = int(os.environ.get("RECON_SQLITE_BUSY_TIMEOUT_MS", "15000"))
SQLITE_WRITE_RETRIES = int(os.environ.get("RECON_SQLITE_WRITE_RETRIES", "10"))
SQLITE_WRITE_RETRY_BASE_SEC = float(
    os.environ.get("RECON_SQLITE_WRITE_RETRY_BASE_SEC", "0.05")
)
_SCHEMA_INITIALIZED: set[str] = set()


def _sqlite_busy(exc: sqlite3.OperationalError) -> bool:
    msg = str(exc).lower()
    return "locked" in msg or "busy" in msg


def db_write(fn, /, *args, **kwargs):
    """Run *fn(conn, *args, **kwargs) under file lock with retry on busy/locked."""
    delay = SQLITE_WRITE_RETRY_BASE_SEC
    last_err = None
    for attempt in range(SQLITE_WRITE_RETRIES):
        try:
            with db_file_lock():
                conn = connect()
                try:
                    result = fn(conn, *args, **kwargs)
                    conn.commit()
                    return result
                except Exception:
                    conn.rollback()
                    raise
                finally:
                    conn.close()
        except sqlite3.OperationalError as exc:
            if not _sqlite_busy(exc):
                raise
            last_err = exc
            if attempt + 1 >= SQLITE_WRITE_RETRIES:
                raise
            time.sleep(delay)
            delay = min(delay * 2, 1.0)
    if last_err:
        raise last_err


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
    db_key = str(Path(DB_PATH).expanduser().resolve())
    if db_key in _SCHEMA_INITIALIZED:
        return

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

    # executions: command runs (task_id legacy column, unused)
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

    cur.execute("""
    CREATE TABLE IF NOT EXISTS scout_jobs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT NOT NULL,
        kind TEXT NOT NULL,
        url TEXT NOT NULL,
        port INTEGER,
        wordlist TEXT,
        command TEXT,
        log_path TEXT,
        status TEXT NOT NULL,
        pid INTEGER,
        exit_code INTEGER,
        hits_summary TEXT,
        started_at TEXT,
        ended_at TEXT
    )
    """)

    cur.execute("""
    CREATE INDEX IF NOT EXISTS idx_scout_jobs_ip_status
    ON scout_jobs (ip, status, started_at DESC)
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS case_ips (
        case_name TEXT NOT NULL,
        ip TEXT NOT NULL,
        first_seen TEXT,
        last_seen TEXT,
        PRIMARY KEY (case_name, ip)
    )
    """)

    # Backward-compatible migrations for older DBs
    _migrate_tasks_table(cur)
    _migrate_case_scope_columns(cur)

    conn.commit()
    _SCHEMA_INITIALIZED.add(db_key)

def _table_columns(cur, table_name: str):
    rows = cur.execute(f"PRAGMA table_info({table_name})").fetchall()
    return {r[1] for r in rows}  # name is column 2


def _migrate_tasks_table(cur):
    """Create tasks table or replace legacy schema (no dedupe_key)."""
    rows = cur.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'tasks'"
    ).fetchall()
    if rows:
        cols = _table_columns(cur, "tasks")
        if "dedupe_key" not in cols:
            cur.execute("DROP TABLE tasks")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_name TEXT,
        ip TEXT NOT NULL,
        port INTEGER,
        service TEXT,
        task_type TEXT NOT NULL,
        dedupe_key TEXT NOT NULL UNIQUE,
        command TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        outcome TEXT,
        source TEXT DEFAULT 'scout-plan',
        assignee TEXT,
        execution_id INTEGER,
        result_summary TEXT,
        meta TEXT,
        created_at TEXT,
        updated_at TEXT,
        started_at TEXT,
        ended_at TEXT
    )
    """)

    cur.execute("""
    CREATE INDEX IF NOT EXISTS idx_tasks_case_status
    ON tasks (case_name, status, created_at DESC)
    """)
    cur.execute("""
    CREATE INDEX IF NOT EXISTS idx_tasks_ip_status
    ON tasks (ip, status, created_at DESC)
    """)


def _migrate_case_scope_columns(cur):
    for table in ("executions", "artifacts", "scout_jobs"):
        cols = _table_columns(cur, table)
        if "case_name" not in cols:
            cur.execute(f"ALTER TABLE {table} ADD COLUMN case_name TEXT")

    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_executions_case
        ON executions (case_name, id DESC)
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_scout_jobs_case
        ON scout_jobs (case_name, started_at DESC)
        """
    )


def _current_case_name() -> str | None:
    from case_scope import case_name_from_env

    return case_name_from_env()


def _touch_case_ip(ip: str) -> None:
    from case_scope import looks_like_ipv4
    from case_scope import register_case_ip_from_env

    if looks_like_ipv4(ip or ""):
        register_case_ip_from_env(ip)


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


def _fetch_reportable_open_ports(ip):
    conn = connect()
    cur = conn.cursor()
    rows = cur.execute(
        """
        SELECT port, proto, state, service, version
        FROM ports
        WHERE ip = ?
          AND state = 'open'
        ORDER BY port, proto
        """,
        (ip,),
    ).fetchall()
    conn.close()
    return rows


def _fetch_reportable_unknown_ports(ip):
    conn = connect()
    cur = conn.cursor()
    rows = cur.execute(
        """
        SELECT port, proto, state, service, version
        FROM ports
        WHERE ip = ?
          AND proto = 'udp'
          AND state = 'open|filtered'
        ORDER BY port, proto
        """,
        (ip,),
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
        if any((p[2] or "").strip() == "open|filtered" for p in rows):
            lines.append("[i] open|filtered is tentative (common on UDP); verify manually before acting on it")
    return lines


def format_scan_snapshot_lines(ip, progress_line):
    """Lines for live-updating scan UI (progress + OPEN + CLOSED)."""
    lines = [progress_line]
    lines.extend(format_port_section_lines("OPEN", _fetch_reportable_open_ports(ip)))
    lines.extend(format_port_section_lines("UNKNOWN", _fetch_reportable_unknown_ports(ip)))
    lines.extend(
        format_port_section_lines("CLOSED", _fetch_ports(ip, closed_with_service=True))
    )
    return lines


def _print_port_section(label, rows, show_coverage=False, ip=None, group=False):
    for line in format_port_section_lines(label, rows, group=group, show_coverage=show_coverage, ip=ip):
        print(line)
    print("")


def print_ports(ip, open_only=True, show_coverage=False, split_open_closed=False, compact=False):
    """Compact port table for scan / scout report output."""
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


# =========================
# scout jobs
# =========================

def insert_scout_job(
    ip,
    kind,
    url,
    *,
    port=None,
    wordlist=None,
    command=None,
    log_path=None,
    status="running",
    pid=None,
):
    case_name = _current_case_name()
    _touch_case_ip(ip)
    conn = connect()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO scout_jobs (
            ip, kind, url, port, wordlist, command, log_path,
            status, pid, started_at, case_name
        ) VALUES (
            ?, ?, ?, ?, ?, ?, ?,
            ?, ?, datetime('now'), ?
        )
        """,
        (ip, kind, url, port, wordlist, command, log_path, status, pid, case_name),
    )
    job_id = int(cur.lastrowid)
    conn.commit()
    conn.close()
    return job_id


def update_scout_job(job_id, **fields):
    if not fields:
        return
    allowed = {
        "status",
        "pid",
        "exit_code",
        "hits_summary",
        "ended_at",
        "log_path",
        "command",
    }
    parts = []
    values = []
    for key, val in fields.items():
        if key not in allowed:
            continue
        parts.append(f"{key} = ?")
        values.append(val)
    if not parts:
        return
    values.append(job_id)
    conn = connect()
    cur = conn.cursor()
    cur.execute(
        f"UPDATE scout_jobs SET {', '.join(parts)} WHERE id = ?",
        values,
    )
    conn.commit()
    conn.close()


def list_scout_jobs(ip, *, kind=None, status=None, limit=50):
    conn = connect()
    cur = conn.cursor()
    sql = """
    SELECT id, ip, kind, url, port, wordlist, command, log_path,
           status, pid, exit_code, hits_summary, started_at, ended_at
    FROM scout_jobs
    WHERE ip = ?
    """
    params = [ip]
    if kind:
        sql += " AND kind = ?"
        params.append(kind)
    if status:
        sql += " AND status = ?"
        params.append(status)
    sql += " ORDER BY started_at DESC, id DESC LIMIT ?"
    params.append(int(limit))
    rows = cur.execute(sql, params).fetchall()
    conn.close()
    return rows


def _recon_scope_ips(current_ip: str | None = None) -> list[str]:
    from case_scope import recon_scope_ips

    return recon_scope_ips(current_ip or os.environ.get("IP"))


def list_scout_jobs_for_case(
    case_name: str,
    *,
    current_ip: str | None = None,
    kind=None,
    status=None,
    limit=200,
):
    ips = _recon_scope_ips(current_ip)
    scope, params = _case_scope_sql(case_name, ips=ips)
    conn = connect()
    sql = f"""
    SELECT id, ip, kind, url, port, wordlist, command, log_path,
           status, pid, exit_code, hits_summary, started_at, ended_at
    FROM scout_jobs
    WHERE {scope}
    """
    if kind:
        sql += " AND kind = ?"
        params.append(kind)
    if status:
        sql += " AND status = ?"
        params.append(status)
    sql += " ORDER BY started_at DESC, id DESC LIMIT ?"
    params.append(int(limit))
    rows = conn.execute(sql, params).fetchall()
    conn.close()
    return rows


def fetch_merged_open_ports(current_ip: str, *, proto: str | None = None):
    """Union open ports across load_from + current target; prefer current_ip service info."""
    case = _current_case_name()
    order: list[str] = []
    if case:
        order.extend(_recon_scope_ips(current_ip))
    elif current_ip:
        order.append(current_ip)
    if current_ip and current_ip not in order:
        order.append(current_ip)
    elif current_ip in order:
        order = [ip for ip in order if ip != current_ip] + [current_ip]

    merged: dict[tuple[int, str], tuple] = {}
    for ip in order:
        for row in _fetch_ports(ip, "open"):
            row_proto = (row[1] or "").strip()
            if proto and row_proto != proto:
                continue
            merged[(int(row[0]), row_proto)] = row
    return [merged[key] for key in sorted(merged, key=lambda item: (item[0], item[1]))]


def fetch_merged_reportable_open_ports(current_ip: str):
    case = _current_case_name()
    order: list[str] = []
    if case:
        order.extend(_recon_scope_ips(current_ip))
    elif current_ip:
        order.append(current_ip)
    if current_ip and current_ip not in order:
        order.append(current_ip)
    elif current_ip in order:
        order = [ip for ip in order if ip != current_ip] + [current_ip]

    merged: dict[tuple[int, str], tuple] = {}
    for ip in order:
        for row in _fetch_reportable_open_ports(ip):
            row_proto = (row[1] or "").strip()
            merged[(int(row[0]), row_proto)] = row
    return [merged[key] for key in sorted(merged, key=lambda item: (item[0], item[1]))]


def fetch_merged_reportable_unknown_ports(current_ip: str):
    case = _current_case_name()
    order: list[str] = []
    if case:
        order.extend(_recon_scope_ips(current_ip))
    elif current_ip:
        order.append(current_ip)
    if current_ip and current_ip not in order:
        order.append(current_ip)
    elif current_ip in order:
        order = [ip for ip in order if ip != current_ip] + [current_ip]

    merged: dict[tuple[int, str], tuple] = {}
    for ip in order:
        for row in _fetch_reportable_unknown_ports(ip):
            row_proto = (row[1] or "").strip()
            merged[(int(row[0]), row_proto)] = row
    return [merged[key] for key in sorted(merged, key=lambda item: (item[0], item[1]))]


def fetch_merged_closed_ports(current_ip: str):
    case = _current_case_name()
    order: list[str] = []
    if case:
        order.extend(_recon_scope_ips(current_ip))
    elif current_ip:
        order.append(current_ip)
    if current_ip and current_ip not in order:
        order.append(current_ip)
    elif current_ip in order:
        order = [ip for ip in order if ip != current_ip] + [current_ip]

    merged: dict[int, tuple] = {}
    for ip in order:
        for row in _fetch_ports(ip, closed_with_service=True):
            merged[int(row[0])] = row
    return [merged[p] for p in sorted(merged)]


def format_scan_snapshot_case_lines(case_name: str, current_ip: str, progress_line: str):
    """Case-scoped port snapshot (union across room IPs, same machine config)."""
    lines = [progress_line]
    lines.extend(format_port_section_lines("OPEN", fetch_merged_reportable_open_ports(current_ip)))
    lines.extend(format_port_section_lines("UNKNOWN", fetch_merged_reportable_unknown_ports(current_ip)))
    lines.extend(
        format_port_section_lines("CLOSED", fetch_merged_closed_ports(current_ip))
    )
    return lines


def case_has_basic_scan(case_name: str, *, current_ip: str | None = None) -> bool:
    from scan_run import PROFILE_BASIC
    from scan_run import is_profile_coverage_complete

    for ip in _recon_scope_ips(current_ip):
        if is_profile_coverage_complete(ip, PROFILE_BASIC):
            return True
    return False


def normalize_dirs_host_header(host) -> str:
    h = (host or "").strip()
    if h.lower().startswith("host:"):
        h = h.split(":", 1)[1].strip()
    return h.lower()


def dirs_command_host_header(command) -> str | None:
    match = _DIRS_HOST_CMD_RE.search(command or "")
    if not match:
        return None
    return normalize_dirs_host_header(match.group(1))


def dirs_job_host_matches(command, host_header) -> bool:
    want = normalize_dirs_host_header(host_header)
    got = dirs_command_host_header(command)
    if not want:
        return got is None
    return got == want


def _find_scout_job(ip, kind, url, wordlist, *, status, host_header=None):
    from url_util import canonicalize_url

    url = canonicalize_url((url or "").strip())
    if not ip or not url:
        return None

    conn = connect()
    cur = conn.cursor()

    def _accept(candidate):
        if candidate is None:
            return None
        if not dirs_job_host_matches(candidate["command"], host_header):
            return None
        return candidate

    def _fetch(exact_url: str):
        return cur.execute(
            """
            SELECT id, ip, kind, url, port, wordlist, command, log_path,
                   status, pid, exit_code, hits_summary, started_at, ended_at
            FROM scout_jobs
            WHERE ip = ? AND kind = ? AND url = ? AND wordlist = ?
              AND status = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (ip, kind, exact_url, wordlist, status),
        ).fetchone()

    row = _accept(_fetch(url))
    if row is None:
        rows = cur.execute(
            """
            SELECT id, ip, kind, url, port, wordlist, command, log_path,
                   status, pid, exit_code, hits_summary, started_at, ended_at
            FROM scout_jobs
            WHERE ip = ? AND kind = ? AND wordlist = ? AND status = ?
            ORDER BY id DESC
            LIMIT 200
            """,
            (ip, kind, wordlist, status),
        ).fetchall()
        for candidate in rows:
            if canonicalize_url(candidate["url"] or "") != url:
                continue
            row = _accept(candidate)
            if row is not None:
                break

    if row is None:
        case = _current_case_name()
        if case:
            from url_util import url_path_key

            want_path = url_path_key(url)
            scope_ips = [x for x in _recon_scope_ips(ip) if x != ip]
            if scope_ips:
                placeholders = ",".join("?" * len(scope_ips))
                batches = cur.execute(
                    f"""
                    SELECT id, ip, kind, url, port, wordlist, command, log_path,
                           status, pid, exit_code, hits_summary, started_at, ended_at
                    FROM scout_jobs
                    WHERE kind = ? AND wordlist = ? AND status = ?
                      AND ip IN ({placeholders})
                    ORDER BY id DESC
                    LIMIT 200
                    """,
                    (kind, wordlist, status, *scope_ips),
                ).fetchall()
                for candidate in batches:
                    if url_path_key(candidate["url"] or "") != want_path:
                        continue
                    row = _accept(candidate)
                    if row is not None:
                        break

    conn.close()
    return row


def find_running_scout_job(ip, kind, url, wordlist, *, host_header=None):
    return _find_scout_job(
        ip, kind, url, wordlist, status="running", host_header=host_header
    )


def find_done_scout_job(ip, kind, url, wordlist, *, host_header=None):
    return _find_scout_job(
        ip, kind, url, wordlist, status="done", host_header=host_header
    )


def find_cached_scout_job(ip, kind, url, wordlist, *, host_header=None):
    """Most recent dirs job that should block re-dispatch (running, done, or failed)."""
    for status in ("running", "done", "failed"):
        row = _find_scout_job(
            ip, kind, url, wordlist, status=status, host_header=host_header
        )
        if row is not None:
            return row, status
    return None, None


def get_scout_job(job_id):
    conn = connect()
    cur = conn.cursor()
    row = cur.execute(
        """
        SELECT id, ip, kind, url, port, wordlist, command, log_path,
               status, pid, exit_code, hits_summary, started_at, ended_at
        FROM scout_jobs
        WHERE id = ?
        """,
        (job_id,),
    ).fetchone()
    conn.close()
    return row


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


def reconcile_scan_ranges(ip):
    """
    Remove scan_ranges rows that misrepresent coverage (legacy 1-1000 / 1-65535 markers).
    Per-chunk rows from scan (actual min-max ports) are kept.
    """
    conn = connect()
    cur = conn.cursor()
    cur.execute(
        """
        DELETE FROM scan_ranges
        WHERE ip = ? AND (
            (scan_type IN ('basic', 'quick') AND range_start = 1 AND range_end = 1000)
            OR (scan_type = 'full' AND range_start = 1 AND range_end = 65535)
        )
        """,
        (ip,),
    )
    deleted = int(cur.rowcount)
    conn.commit()
    conn.close()
    return deleted


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


def get_scanned_ports(ip, proto="tcp", *, profiles=None):
    conn = connect()
    cur = conn.cursor()
    if profiles:
        allowed = tuple(profiles)
        placeholders = ",".join("?" for _ in allowed)
        rows = cur.execute(
            f"""
        SELECT port FROM port_scan_coverage
        WHERE ip = ? AND proto = ? AND scan_profile IN ({placeholders})
        ORDER BY port
        """,
            (ip, proto, *allowed),
        ).fetchall()
    else:
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


def count_tcp_coverage_in_ports(ip, port_iter, *, profiles=None):
    """How many ports from port_iter appear in port_scan_coverage."""
    scanned = set(get_scanned_ports(ip, profiles=profiles))
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
# execution & artifacts
# =========================

def add_execution(task_id, ip, task_type, command, cwd="/", status="running"):
    case_name = _current_case_name()
    _touch_case_ip(ip)

    def _write(conn):
        cur = conn.cursor()
        cur.execute("""
        INSERT INTO executions (
            task_id, ip, task_type, command, cwd, status, started_at, case_name
        ) VALUES (
            ?, ?, ?, ?, ?, ?, datetime('now'), ?
        )
        """, (task_id, ip, task_type, command, cwd, status, case_name))
        return cur.lastrowid

    return db_write(_write)


def finish_execution(execution_id, status, exit_code=None, stdout="", stderr=""):
    def _write(conn):
        conn.execute("""
        UPDATE executions
        SET status = ?,
            exit_code = ?,
            stdout = ?,
            stderr = ?,
            ended_at = datetime('now')
        WHERE id = ?
        """, (status, exit_code, stdout, stderr, execution_id))

    db_write(_write)


def find_done_execution(ip: str, command: str):
    """Return latest successful execution for ip+command, or None.

    Falls back to other IPs registered on the current CASE when the target
    IP changed (THM machine reboot).
    """
    from url_util import canonicalize_probe_command

    command = (command or "").strip()
    if not ip or not command:
        return None

    canon = canonicalize_probe_command(command)

    conn = connect()
    cur = conn.cursor()

    def _fetch_for_ip(target_ip: str, exact: str):
        return cur.execute(
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
            (target_ip, exact),
        ).fetchone()

    def _fetch_canonical_for_ip(target_ip: str):
        row = _fetch_for_ip(target_ip, canon)
        if row is None and command != canon:
            row = _fetch_for_ip(target_ip, command)
        if row is not None:
            return row
        rows = cur.execute(
            """
            SELECT id, ip, command, status, exit_code, stdout, stderr, started_at, ended_at
            FROM executions
            WHERE ip = ?
              AND status = 'done'
              AND exit_code = 0
            ORDER BY id DESC
            LIMIT 200
            """,
            (target_ip,),
        ).fetchall()
        for candidate in rows:
            if canonicalize_probe_command(candidate["command"]) == canon:
                return candidate
        return None

    row = _fetch_canonical_for_ip(ip)
    if row is None:
        case = _current_case_name()
        if case:
            for alt_ip in _recon_scope_ips(ip):
                if alt_ip == ip:
                    continue
                row = _fetch_canonical_for_ip(alt_ip)
                if row is not None:
                    break

    conn.close()
    return row


def add_artifact(ip, kind, key, value, execution_id=None, *, case_name=None):
    """
    Insert artifact if (ip, kind, key, value) is new.
    On duplicate: skip insert; refresh execution_id when provided.
    Returns artifact id.
    """
    key = key or ""
    if case_name is None:
        case_name = _current_case_name()
    from case_scope import looks_like_ipv4

    if looks_like_ipv4(ip or ""):
        _touch_case_ip(ip)

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
        if execution_id is not None or case_name:
            cur.execute(
                """
                UPDATE artifacts
                SET execution_id = COALESCE(?, execution_id),
                    case_name = COALESCE(?, case_name),
                    created_at = datetime('now')
                WHERE id = ?
                """,
                (execution_id, case_name, art_id),
            )
            conn.commit()
        conn.close()
        return art_id

    cur.execute(
        """
        INSERT INTO artifacts (
            ip, kind, key, value, execution_id, created_at, case_name
        ) VALUES (?, ?, ?, ?, ?, datetime('now'), ?)
        """,
        (ip, kind, key, value, execution_id, case_name),
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


def _get_creds_comment_artifact(ip: str, username: str):
    conn = connect()
    row = conn.execute(
        """
        SELECT id, value
        FROM artifacts
        WHERE ip = ? AND kind = 'creds_comment' AND key = ?
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


def creds_upsert(
    ip: str,
    username: str,
    password: str,
    execution_id=None,
    comment: str | None = None,
) -> str:
    """
    Insert or update credentials for (ip, username).
    comment: when set, stored as usage hint (e.g. SSH, HTTP Basic); None leaves comment unchanged.
    Returns: saved | updated | unchanged
    """
    if not ip or not username or password is None:
        raise ValueError("ip, username, and password required")

    case_name = _current_case_name()
    _touch_case_ip(ip)

    def _write(conn):
        cur = conn.cursor()

        existing = cur.execute(
            """
            SELECT id, value
            FROM artifacts
            WHERE ip = ? AND kind = 'password' AND key = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (ip, username),
        ).fetchone()
        existing_comment_row = cur.execute(
            """
            SELECT id, value
            FROM artifacts
            WHERE ip = ? AND kind = 'creds_comment' AND key = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (ip, username),
        ).fetchone()
        existing_comment = (
            (existing_comment_row["value"] or "") if existing_comment_row else ""
        )

        password_same = existing and (existing["value"] or "") == password
        comment_same = comment is None or comment == existing_comment
        if password_same and comment_same:
            return "unchanged"

        if existing:
            if not password_same:
                cur.execute(
                    """
                    UPDATE artifacts
                    SET value = ?, execution_id = ?, case_name = COALESCE(?, case_name),
                        created_at = datetime('now')
                    WHERE id = ?
                    """,
                    (password, execution_id, case_name, int(existing["id"])),
                )
            status = "updated"
        else:
            cur.execute(
                """
                INSERT INTO artifacts (
                    ip, kind, key, value, execution_id, created_at, case_name
                ) VALUES (?, 'password', ?, ?, ?, datetime('now'), ?)
                """,
                (ip, username, password, execution_id, case_name),
            )
            status = "saved"

        if comment is not None and not comment_same:
            if existing_comment_row:
                cur.execute(
                    """
                    UPDATE artifacts
                    SET value = ?, execution_id = ?, case_name = COALESCE(?, case_name),
                        created_at = datetime('now')
                    WHERE id = ?
                    """,
                    (comment, execution_id, case_name, int(existing_comment_row["id"])),
                )
            else:
                cur.execute(
                    """
                    INSERT INTO artifacts (
                        ip, kind, key, value, execution_id, created_at, case_name
                    ) VALUES (?, 'creds_comment', ?, ?, ?, datetime('now'), ?)
                    """,
                    (ip, username, comment, execution_id, case_name),
                )
            if password_same:
                status = "updated"

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
                    ip, kind, key, value, execution_id, created_at, case_name
                ) VALUES (?, 'username', '', ?, ?, datetime('now'), ?)
                """,
                (ip, username, execution_id, case_name),
            )

        return status

    return db_write(_write)


def creds_delete(ip: str, username: str = None) -> int:
    """
    Remove stored credentials for ip (optional: single username).
    Deletes password/username rows and ssh/dav last-user rows when applicable.
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
                (kind IN ('password', 'username', 'creds_comment') AND (key = ? OR value = ?))
                OR (kind = 'ssh_last_user' AND value = ?)
                OR (kind = 'dav_last_user' AND value = ?)
                OR (kind = 'ssh_last_key' AND key = ?)
            )
            """,
            (ip, username, username, username, username, username),
        )
    else:
        cur.execute(
            """
            DELETE FROM artifacts
            WHERE ip = ? AND kind IN ('password', 'username', 'creds_comment', 'ssh_last_user', 'dav_last_user', 'ssh_last_key')
            """,
            (ip,),
        )

    deleted = cur.rowcount
    conn.commit()
    conn.close()
    return deleted


def _get_hash_artifact(ip: str, username: str):
    conn = connect()
    row = conn.execute(
        """
        SELECT id, value
        FROM artifacts
        WHERE ip = ? AND kind = 'hash' AND key = ?
        ORDER BY id DESC
        LIMIT 1
        """,
        (ip, username),
    ).fetchone()
    conn.close()
    return row


def hash_upsert_entry(ip: str, entry, execution_id=None) -> str:
    """Insert or update hash-list entry. Returns saved|updated|unchanged."""
    from hash_store import HashEntry
    from hash_store import entry_from_import
    from hash_store import merge_on_import

    if not ip or not entry.username:
        raise ValueError("ip and username required")

    if not isinstance(entry, HashEntry):
        entry = entry_from_import(entry)

    case_name = _current_case_name()
    _touch_case_ip(ip)

    existing_row = _get_hash_artifact(ip, entry.username)
    existing = (
        HashEntry.from_json(entry.username, existing_row["value"])
        if existing_row
        else None
    )
    merged, status = merge_on_import(existing, entry)

    conn = connect()
    cur = conn.cursor()
    if existing_row:
        cur.execute(
            """
            UPDATE artifacts
            SET value = ?, execution_id = ?, case_name = COALESCE(?, case_name),
                created_at = datetime('now')
            WHERE id = ?
            """,
            (merged.to_json(), execution_id, case_name, int(existing_row["id"])),
        )
    else:
        cur.execute(
            """
            INSERT INTO artifacts (
                ip, kind, key, value, execution_id, created_at, case_name
            ) VALUES (?, 'hash', ?, ?, ?, datetime('now'), ?)
            """,
            (ip, entry.username, merged.to_json(), execution_id, case_name),
        )
    conn.commit()
    conn.close()
    return status


def hash_save_entry(ip: str, entry) -> str:
    """Persist entry (state/john updates). Returns updated|unchanged."""
    from hash_store import HashEntry

    row = _get_hash_artifact(ip, entry.username)
    if not row:
        raise ValueError(f"hash not found: {entry.username}@{ip}")
    stored = HashEntry.from_json(entry.username, row["value"])
    if stored.to_json() == entry.to_json():
        return "unchanged"
    conn = connect()
    conn.execute(
        """
        UPDATE artifacts
        SET value = ?, created_at = datetime('now')
        WHERE id = ?
        """,
        (entry.to_json(), int(row["id"])),
    )
    conn.commit()
    conn.close()
    return "updated"


def list_hash_entries(ip: str) -> list:
    from hash_store import HashEntry

    conn = connect()
    rows = conn.execute(
        """
        SELECT key, value
        FROM artifacts
        WHERE ip = ? AND kind = 'hash' AND key != ''
        ORDER BY key
        """,
        (ip,),
    ).fetchall()
    conn.close()
    return [HashEntry.from_json(r["key"], r["value"]) for r in rows]


def hash_delete(ip: str, username: str = None) -> int:
    if not ip:
        raise ValueError("ip required")
    conn = connect()
    cur = conn.cursor()
    if username:
        cur.execute(
            "DELETE FROM artifacts WHERE ip = ? AND kind = 'hash' AND key = ?",
            (ip, username),
        )
    else:
        cur.execute(
            "DELETE FROM artifacts WHERE ip = ? AND kind = 'hash'",
            (ip,),
        )
    deleted = cur.rowcount
    conn.commit()
    conn.close()
    return deleted


# Stored for creds/ssh/hash; hidden from artifact-list (use cl / hlist)
_ARTIFACT_CRED_KINDS = (
    "username",
    "password",
    "creds_comment",
    "ssh_last_user",
    "dav_last_user",
    "msfr_last_user",
    "hash",
)


def _creds_row_dict(row) -> dict:
    return {
        "username": row["username"],
        "password": row["password"],
        "comment": row["comment"] or "",
    }


def list_ssh_creds(ip: str):
    """Return [{username, password, comment}, ...] one row per username (latest password)."""
    conn = connect()
    rows = conn.execute(
        """
        SELECT
            p.key AS username,
            p.value AS password,
            (
                SELECT value
                FROM artifacts
                WHERE ip = p.ip AND kind = 'creds_comment' AND key = p.key
                ORDER BY id DESC
                LIMIT 1
            ) AS comment
        FROM artifacts p
        WHERE p.id IN (
            SELECT MAX(id)
            FROM artifacts
            WHERE ip = ? AND kind = 'password' AND key != ''
            GROUP BY key
        )
        ORDER BY p.key
        """,
        (ip,),
    ).fetchall()
    conn.close()
    return [_creds_row_dict(r) for r in rows]


def _case_scope_sql(case_name: str, *, ips: list[str]) -> tuple[str, list]:
    if ips:
        placeholders = ",".join("?" * len(ips))
        return (
            f"ip IN ({placeholders}) AND (case_name = ? OR case_name IS NULL)",
            [*ips, case_name],
        )
    return "case_name = ?", [case_name]


def list_ssh_creds_for_case(case_name: str, *, all_case: bool = False):
    """Return [{ip, username, password, comment}, ...] for recon scope (or whole case)."""
    if all_case:
        from case_scope import list_case_ips

        ips = list_case_ips(case_name)
    else:
        ips = _recon_scope_ips()
    scope, params = _case_scope_sql(case_name, ips=ips)
    conn = connect()
    rows = conn.execute(
        f"""
        SELECT
            a.ip AS ip,
            a.key AS username,
            a.value AS password,
            (
                SELECT value
                FROM artifacts
                WHERE ip = a.ip AND kind = 'creds_comment' AND key = a.key
                ORDER BY id DESC
                LIMIT 1
            ) AS comment
        FROM artifacts a
        INNER JOIN (
            SELECT MAX(id) AS id
            FROM artifacts
            WHERE kind = 'password' AND key != ''
              AND {scope}
            GROUP BY ip, key
        ) d ON a.id = d.id
        ORDER BY a.ip, a.key
        """,
        params,
    ).fetchall()
    conn.close()
    return [
        {
            "ip": r["ip"],
            "username": r["username"],
            "password": r["password"],
            "comment": r["comment"] or "",
        }
        for r in rows
    ]


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


def get_dav_last_user(ip: str):
    conn = connect()
    row = conn.execute(
        """
        SELECT value
        FROM artifacts
        WHERE ip = ? AND kind = 'dav_last_user' AND key = ''
        ORDER BY id DESC
        LIMIT 1
        """,
        (ip,),
    ).fetchone()
    conn.close()
    return row["value"] if row else None


def set_dav_last_user(ip: str, username: str, execution_id=None):
    if get_dav_last_user(ip) == username:
        return
    conn = connect()
    cur = conn.cursor()
    cur.execute(
        "DELETE FROM artifacts WHERE ip = ? AND kind = 'dav_last_user'",
        (ip,),
    )
    cur.execute(
        """
        INSERT INTO artifacts (
            ip, kind, key, value, execution_id, created_at
        ) VALUES (?, 'dav_last_user', '', ?, ?, datetime('now'))
        """,
        (ip, username, execution_id),
    )
    conn.commit()
    conn.close()


def get_ssh_last_key(ip: str, username: str):
    conn = connect()
    row = conn.execute(
        """
        SELECT value
        FROM artifacts
        WHERE ip = ? AND kind = 'ssh_last_key' AND key = ?
        ORDER BY id DESC
        LIMIT 1
        """,
        (ip, username),
    ).fetchone()
    conn.close()
    return row["value"] if row else None


def set_ssh_last_key(ip: str, username: str, key_path: str, execution_id=None):
    if get_ssh_last_key(ip, username) == key_path:
        return
    conn = connect()
    cur = conn.cursor()
    cur.execute(
        "DELETE FROM artifacts WHERE ip = ? AND kind = 'ssh_last_key' AND key = ?",
        (ip, username),
    )
    cur.execute(
        """
        INSERT INTO artifacts (
            ip, kind, key, value, execution_id, created_at
        ) VALUES (?, 'ssh_last_key', ?, ?, ?, datetime('now'))
        """,
        (ip, username, key_path, execution_id),
    )
    conn.commit()
    conn.close()


def get_msfr_last_user(ip: str, family: str):
    conn = connect()
    row = conn.execute(
        """
        SELECT value
        FROM artifacts
        WHERE ip = ? AND kind = 'msfr_last_user' AND key = ?
        ORDER BY id DESC
        LIMIT 1
        """,
        (ip, family),
    ).fetchone()
    conn.close()
    return row["value"] if row else None


def set_msfr_last_user(ip: str, family: str, username: str, execution_id=None):
    if get_msfr_last_user(ip, family) == username:
        return
    conn = connect()
    cur = conn.cursor()
    cur.execute(
        "DELETE FROM artifacts WHERE ip = ? AND kind = 'msfr_last_user' AND key = ?",
        (ip, family),
    )
    cur.execute(
        """
        INSERT INTO artifacts (
            ip, kind, key, value, execution_id, created_at
        ) VALUES (?, 'msfr_last_user', ?, ?, ?, datetime('now'))
        """,
        (ip, family, username, execution_id),
    )
    conn.commit()
    conn.close()


def list_executions(ip: str = None, *, case_name: str = None, limit: int = 50, all_case: bool = False):
    if case_name:
        return list_executions_for_case(case_name, limit=limit, all_case=all_case)

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


def list_executions_for_case(case_name: str, *, limit: int = 50, all_case: bool = False):
    if all_case:
        from case_scope import list_case_ips

        ips = list_case_ips(case_name)
    else:
        ips = _recon_scope_ips()
    scope, params = _case_scope_sql(case_name, ips=ips)
    conn = connect()
    rows = conn.execute(
        f"""
        SELECT id, ip, task_id, task_type, status, exit_code, started_at, ended_at, command
        FROM executions
        WHERE {scope}
        ORDER BY id DESC
        LIMIT ?
        """,
        (*params, int(limit)),
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


# =========================
# tasks (strike queue)
# =========================

def build_task_dedupe_key(
    case_name: str | None,
    ip: str,
    port: int,
    task_type: str,
) -> str:
    case = (case_name or "").strip()
    return f"{case}:{ip}:{int(port)}:{task_type}"


def upsert_task(
    *,
    ip: str,
    port: int,
    service: str,
    task_type: str,
    command: str,
    case_name: str | None = None,
    source: str = "scout-plan",
    meta: dict | None = None,
) -> tuple[str, int]:
    """
    Insert or refresh a pending task. Skips when status is done or running.
    Returns (action, task_id) where action is created|updated|skipped.
    """
    import json

    case_name = case_name if case_name is not None else _current_case_name()
    dedupe_key = build_task_dedupe_key(case_name, ip, port, task_type)
    meta_json = json.dumps(meta, ensure_ascii=False) if meta else None
    _touch_case_ip(ip)

    conn = connect()
    cur = conn.cursor()
    row = cur.execute(
        "SELECT id, status FROM tasks WHERE dedupe_key = ?",
        (dedupe_key,),
    ).fetchone()

    if row:
        task_id = int(row["id"])
        if row["status"] in ("done", "running"):
            conn.close()
            return "skipped", task_id
        cur.execute(
            """
            UPDATE tasks
            SET command = ?,
                service = ?,
                case_name = ?,
                source = ?,
                meta = ?,
                updated_at = datetime('now')
            WHERE id = ?
            """,
            (command, service or "", case_name, source, meta_json, task_id),
        )
        conn.commit()
        conn.close()
        return "updated", task_id

    cur.execute(
        """
        INSERT INTO tasks (
            case_name, ip, port, service, task_type, dedupe_key, command,
            status, source, meta, created_at, updated_at
        ) VALUES (
            ?, ?, ?, ?, ?, ?, ?,
            'pending', ?, ?, datetime('now'), datetime('now')
        )
        """,
        (
            case_name,
            ip,
            int(port),
            service or "",
            task_type,
            dedupe_key,
            command,
            source,
            meta_json,
        ),
    )
    task_id = int(cur.lastrowid)
    conn.commit()
    conn.close()
    return "created", task_id


def get_task(task_id: int):
    conn = connect()
    row = conn.execute("SELECT * FROM tasks WHERE id = ?", (int(task_id),)).fetchone()
    conn.close()
    return row


def list_tasks(
    ip: str | None = None,
    *,
    case_name: str | None = None,
    status: str | None = None,
    task_type_prefix: str | None = None,
    scope_ips: list[str] | None = None,
    limit: int = 200,
):
    conn = connect()
    clauses: list[str] = []
    params: list = []

    if scope_ips:
        placeholders = ",".join("?" * len(scope_ips))
        clauses.append(f"ip IN ({placeholders})")
        params.extend(scope_ips)
    elif ip:
        clauses.append("ip = ?")
        params.append(ip)

    if case_name:
        clauses.append("case_name = ?")
        params.append(case_name)

    if status:
        clauses.append("status = ?")
        params.append(status)

    if task_type_prefix:
        clauses.append("task_type LIKE ?")
        params.append(f"{task_type_prefix}%")

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    rows = conn.execute(
        f"""
        SELECT *
        FROM tasks
        {where}
        ORDER BY
            CASE status
                WHEN 'pending' THEN 0
                WHEN 'running' THEN 1
                WHEN 'failed' THEN 2
                WHEN 'done' THEN 3
                ELSE 4
            END,
            port ASC,
            id ASC
        LIMIT ?
        """,
        (*params, int(limit)),
    ).fetchall()
    conn.close()
    return rows


def mark_task_running(task_id: int) -> None:
    def _write(conn):
        conn.execute(
            """
            UPDATE tasks
            SET status = 'running',
                started_at = datetime('now'),
                updated_at = datetime('now')
            WHERE id = ?
            """,
            (int(task_id),),
        )

    db_write(_write)


def finish_task(
    task_id: int,
    *,
    status: str,
    outcome: str | None = None,
    execution_id: int | None = None,
    result_summary: str | None = None,
) -> None:
    def _write(conn):
        conn.execute(
            """
            UPDATE tasks
            SET status = ?,
                outcome = ?,
                execution_id = ?,
                result_summary = ?,
                ended_at = datetime('now'),
                updated_at = datetime('now')
            WHERE id = ?
            """,
            (
                status,
                outcome,
                execution_id,
                (result_summary or "")[:500] if result_summary else None,
                int(task_id),
            ),
        )

    db_write(_write)


def reset_task_pending(task_id: int) -> None:
    def _write(conn):
        conn.execute(
            """
            UPDATE tasks
            SET status = 'pending',
                outcome = NULL,
                execution_id = NULL,
                result_summary = NULL,
                started_at = NULL,
                ended_at = NULL,
                updated_at = datetime('now')
            WHERE id = ?
            """,
            (int(task_id),),
        )

    db_write(_write)
