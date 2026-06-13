"""Helpers for msfr (Metasploit preset runner)."""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from dataclasses import field
from pathlib import Path

from db import fetch_merged_open_ports

WEB_SERVICE_NAMES = frozenset(
    {"http", "https", "http-proxy", "ssl/http", "ssl/https", "http-alt"}
)
WEB_HINTS = (
    "http",
    "nginx",
    "apache",
    "tomcat",
    "lighttpd",
    "iis",
    "webmin",
    "gunicorn",
    "web",
)


def module_family(module: str) -> str:
    m = (module or "").lower()
    if "postgres" in m:
        return "postgres"
    if "mysql" in m:
        return "mysql"
    if "/ssh/" in m or m.endswith("/ssh"):
        return "ssh"
    if "/ftp/" in m:
        return "ftp"
    if "smb" in m:
        return "smb"
    if any(x in m for x in ("http", "tomcat", "webmin", "nginx", "apache")):
        return "http"
    return "generic"


def resolve_port_from_scout(ip: str, family: str) -> int | None:
    for row in fetch_merged_open_ports(ip):
        port = int(row[0])
        svc = (row[3] or "").lower()
        ver = (row[4] or "").lower()
        blob = f"{svc} {ver}"
        if family == "postgres" and "postgres" in blob:
            return port
        if family == "mysql" and "mysql" in blob:
            return port
        if family == "ssh" and svc == "ssh":
            return port
        if family == "ftp" and svc == "ftp":
            return port
        if family == "http" and (
            svc in WEB_SERVICE_NAMES or any(h in blob for h in WEB_HINTS)
        ):
            return port
        if family == "smb" and ("microsoft-ds" in svc or "smb" in blob):
            return port
    return None


FAMILY_DEFAULT_PORTS: dict[str, int] = {
    "postgres": 5432,
    "mysql": 3306,
    "ssh": 22,
    "ftp": 21,
    "http": 80,
    "smb": 445,
}

FAMILY_ENV_PORTS: dict[str, str] = {
    "postgres": "DB_PORT",
    "mysql": "MYSQL_PORT",
    "ssh": "SSH_PORT",
    "ftp": "FTP_PORT",
    "http": "HTTP_PORT",
    "smb": "SMB_PORT",
}


def resolve_rport(
    ip: str,
    module: str,
    *,
    explicit: int | None = None,
) -> int | None:
    if explicit is not None:
        return explicit
    global_port = os.environ.get("MSFR_PORT", "").strip()
    if global_port.isdigit():
        return int(global_port)
    family = module_family(module)
    env_key = FAMILY_ENV_PORTS.get(family)
    if env_key:
        val = os.environ.get(env_key, "").strip()
        if val.isdigit():
            return int(val)
    scout = resolve_port_from_scout(ip, family)
    if scout is not None:
        return scout
    return FAMILY_DEFAULT_PORTS.get(family)


def cred_option_names(module: str) -> tuple[str, str]:
    family = module_family(module)
    if family == "http":
        return "HttpUsername", "HttpPassword"
    if family == "smb":
        return "SMBUser", "SMBPass"
    if family == "ftp":
        return "FTPUSER", "FTPPASS"
    return "USERNAME", "PASSWORD"


def default_ssl(rport: int | None, module: str) -> bool:
    if rport == 443:
        return True
    if rport == 10000 and module_family(module) == "http":
        return True
    return False


PRESET_FAMILY = {
    "pg-login": "postgres",
    "postgres-login": "postgres",
    "pg-sql": "postgres",
    "postgres-sql": "postgres",
    "pg-readfile": "postgres",
    "postgres-readfile": "postgres",
    "pg-hashdump": "postgres",
    "postgres-hashdump": "postgres",
    "pg-shell": "postgres",
    "postgres-shell": "postgres",
    "pg-rce": "postgres",
    "postgres-rce": "postgres",
    "my-login": "mysql",
    "mysql-login": "mysql",
    "my-sql": "mysql",
    "mysql-sql": "mysql",
    "my-hashdump": "mysql",
    "mysql-hashdump": "mysql",
    "my-shell": "mysql",
    "mysql-shell": "mysql",
    "my-rce": "mysql",
    "mysql-rce": "mysql",
    "ssh-login": "ssh",
    "ftp-login": "ftp",
}


def preset_family(preset: str) -> str:
    return PRESET_FAMILY.get((preset or "").lower(), module_family(preset))


LOGIN_PRESETS = frozenset(
    {
        "pg-login",
        "postgres-login",
        "my-login",
        "mysql-login",
        "ssh-login",
        "ftp-login",
    }
)


class LoginScanConfigError(Exception):
    pass


def is_login_scan_preset(preset: str) -> bool:
    return (preset or "").lower() in LOGIN_PRESETS


SECLISTS_ROOT = Path("/usr/share/seclists")

# Services without MSF built-in default creds → seclists betterdefaultpasslist
FAMILY_QUICK_USERPASS_REL: dict[str, str] = {
    "ssh": "Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt",
    "ftp": "Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt",
}

FAMILY_QUICK_USERPASS_ENV: dict[str, str] = {
    "ssh": "MSFR_SSH_USERPASS",
    "ftp": "MSFR_FTP_USERPASS",
}


def default_quick_userpass_file(family: str) -> str:
    env_key = FAMILY_QUICK_USERPASS_ENV.get(family)
    if env_key:
        val = os.environ.get(env_key, "").strip()
        if val:
            return val
    global_val = os.environ.get("MSFR_QUICK_USERPASS", "").strip()
    if global_val:
        return global_val
    rel = FAMILY_QUICK_USERPASS_REL.get(family)
    if not rel:
        raise LoginScanConfigError(f"no quick userpass list for family: {family}")
    return str(SECLISTS_ROOT / rel)


def _require_file(path: str, label: str) -> str:
    if not path or not os.path.isfile(path):
        raise LoginScanConfigError(f"{label} not found: {path}")
    return path


def _first_userpass_line(path: str) -> str:
    with open(path, encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            line = raw.strip()
            if line and not line.startswith("#"):
                return line
    return ""


def _is_colon_userpass_file(path: str) -> bool:
    sample = _first_userpass_line(path)
    if not sample:
        return False
    if " " in sample:
        return False
    return ":" in sample


def prepare_msf_userpass_file(path: str) -> tuple[str, bool]:
    """Return (path, is_temp). SecLists user:pass → MSF space-separated USERPASS_FILE."""
    path = _require_file(path, "quick user:pass list")
    if not _is_colon_userpass_file(path):
        return path, False

    fd, tmp = tempfile.mkstemp(prefix="msfr-userpass.", suffix=".txt")
    with os.fdopen(fd, "w", encoding="utf-8") as out:
        with open(path, encoding="utf-8", errors="replace") as src:
            for raw in src:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if ":" in line:
                    user, _, passwd = line.partition(":")
                    out.write(f"{user.strip()} {passwd.strip()}\n")
                else:
                    out.write(f"{line}\n")
    return tmp, True


@dataclass
class LoginScanResult:
    sets: list[tuple[str, str]] = field(default_factory=list)
    temp_files: list[str] = field(default_factory=list)

    def __iter__(self):
        """Backward compat: old msfr zsh iterated result directly."""
        return iter(self.sets)


def login_scan_resource_sets(
    preset: str,
    *,
    user: str = "",
    password: str = "",
) -> LoginScanResult:
    """USERPASS_FILE / USERNAME for ssh-login / ftp-login (no MSF built-in defaults).

    Default: seclists *-betterdefaultpasslist.txt via USERPASS_FILE.
    postgres/mysql login presets return empty (MSF module defaults).
    Full wordlist spray → hydrassh / hydraftp.
    """
    family = preset_family(preset)
    if family not in ("ssh", "ftp"):
        return LoginScanResult()

    user_key = "USERNAME" if family == "ssh" else "FTPUSER"
    pass_key = "PASSWORD" if family == "ssh" else "FTPPASS"
    sets: list[tuple[str, str]] = []
    temp_files: list[str] = []

    if user and password:
        sets.append((user_key, user))
        sets.append((pass_key, password))
        return LoginScanResult(sets=sets)

    if user:
        sets.append((user_key, user))
        return LoginScanResult(sets=sets)

    source = default_quick_userpass_file(family)
    msf_path, is_temp = prepare_msf_userpass_file(source)
    if is_temp:
        temp_files.append(msf_path)
    sets.append(("USERPASS_FILE", msf_path))
    return LoginScanResult(sets=sets, temp_files=temp_files)


def _db_cred_excluded(comment: str, family: str) -> bool:
    from creds import MSFR_DB_EXCLUDE_COMMENT_HINTS

    low = (comment or "").lower()
    hints = MSFR_DB_EXCLUDE_COMMENT_HINTS.get(family, ())
    return any(hint in low for hint in hints)


def _postgres_cred_sort_key(row: dict, tags: tuple[str, ...], hlist_users: set[str]) -> tuple:
    user = row["username"]
    comment = row.get("comment") or ""
    if any(tag in comment for tag in tags):
        return (0, user)
    if user in hlist_users:
        return (1, user)
    if not comment.strip():
        return (2, user)
    return (3, user)


def list_msfr_creds(ip: str, family: str) -> list[dict]:
    from creds import MSFR_FAMILY_CRED_TAGS
    from db import list_ssh_creds

    tags = MSFR_FAMILY_CRED_TAGS.get(family, ())
    if not tags:
        return []

    if family in ("postgres", "mysql"):
        from db import list_hash_entries
        from hash_store import STATE_UNSUPPORTED

        hlist_users = {
            e.username
            for e in list_hash_entries(ip)
            if e.state != STATE_UNSUPPORTED
        }

        candidates: list[dict] = []
        for r in list_ssh_creds(ip):
            user = r["username"]
            if not user:
                continue
            if _db_cred_excluded(r.get("comment") or "", family):
                continue
            candidates.append(r)

        candidates.sort(
            key=lambda row: _postgres_cred_sort_key(row, tags, hlist_users)
        )
        return candidates

    out: list[dict] = []
    seen: set[str] = set()
    for r in list_ssh_creds(ip):
        user = r["username"]
        if not user or user in seen:
            continue
        comment = r.get("comment") or ""
        if any(tag in comment for tag in tags):
            out.append(r)
            seen.add(user)
    return out


class MsfrPickError(Exception):
    pass


def _prompt_choice(prompt: str) -> str:
    """Read a line without writing the prompt to stdout (safe inside $(...) )."""
    import sys

    sys.stderr.write(prompt)
    sys.stderr.flush()
    return sys.stdin.readline().strip()


def resolve_msfr_user(
    ip: str,
    family: str,
    *,
    user: str = "",
    default_user: str = "",
) -> str:
    """Resolve username for msfr: explicit -u, else pick from family creds in cl."""
    from db import list_ssh_creds

    if user:
        for r in list_ssh_creds(ip):
            if r["username"] == user:
                return user
        raise MsfrPickError(f"user {user} not in creds-list for {ip}")

    return pick_msfr_user(ip, family, default_user=default_user)


def pick_msfr_user(ip: str, family: str, *, default_user: str = "") -> str:
    """Choose a creds-list user for msfr presets (family-tagged creds in cl)."""
    import sys

    from db import get_msfr_last_user
    from db import list_ssh_creds

    rows = list_msfr_creds(ip, family)
    if not rows and default_user:
        for r in list_ssh_creds(ip):
            if r["username"] == default_user:
                return default_user

    if not rows:
        hint = (
            "hash-crack / creds-add"
            if family in ("postgres", "mysql")
            else f"msfr {family}-login or creds-add"
        )
        raise MsfrPickError(f"no {family} creds in creds-list ({hint})")

    if len(rows) == 1:
        return rows[0]["username"]

    last = get_msfr_last_user(ip, family)
    print(f"[*] {ip} — choose {family} account:", file=sys.stderr)
    idx = None
    for i, r in enumerate(rows, 1):
        u = r["username"]
        c = (r.get("comment") or "").strip()
        if c:
            label = f"{u} ({c})"
        elif family in ("postgres", "mysql"):
            label = f"{u} (manual)"
        else:
            label = u
        if last and u == last:
            print(f"  {i}) {label} (last)", file=sys.stderr)
            idx = str(i)
        else:
            print(f"  {i}) {label}", file=sys.stderr)
    users = [r["username"] for r in rows]

    if idx:
        choice = _prompt_choice(f"#? [{idx}]: ")
        if not choice:
            choice = idx
    else:
        choice = _prompt_choice("#? ")

    if choice.isdigit() and 1 <= int(choice) <= len(users):
        return users[int(choice) - 1]

    raise MsfrPickError("invalid choice")


def pick_msfr_user_dry(
    ip: str,
    family: str,
    *,
    user: str = "",
    default_user: str = "",
) -> str:
    """Non-interactive user pick for msfr --dry-run."""
    import sys

    from db import get_msfr_last_user
    from db import list_ssh_creds

    if user:
        return resolve_msfr_user(ip, family, user=user, default_user=default_user)

    rows = list_msfr_creds(ip, family)
    if not rows and default_user:
        for r in list_ssh_creds(ip):
            if r["username"] == default_user:
                return default_user

    if not rows:
        hint = (
            "hash-crack / creds-add"
            if family in ("postgres", "mysql")
            else f"msfr {family}-login or creds-add"
        )
        raise MsfrPickError(f"no {family} creds in creds-list ({hint})")

    users = [r["username"] for r in rows]
    if len(users) == 1:
        return users[0]

    last = get_msfr_last_user(ip, family)
    if last in users:
        print(
            f"[*] dry-run: msfr-last → {last} ({len(users)} candidates)",
            file=sys.stderr,
        )
        return last

    print(
        f"[*] dry-run: would prompt; using {users[0]} ({len(users)} candidates)",
        file=sys.stderr,
    )
    return users[0]
