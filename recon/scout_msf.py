"""
Scout Metasploit lookup: search + info -j from nmap service/version → msf_report artifact.
"""

from __future__ import annotations

import csv
import json
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Optional

from db import add_artifact
from db import connect
from executor import run_command
from scout_exploit import _version_tokens
from scout_exploit import build_search_query

TASK_TYPE = "scout-msf"
MSF_GENERIC_PORTS = frozenset({21, 22, 23, 25, 80, 110, 143, 443, 445, 993, 995, 3389})
MSF_REPORT_KIND = "msf_report"
MSF_TIMEOUT_SEC = 120
MSF_INFO_BATCH = 12
MSF_MODULE_LIMIT = 24

_MSF_MODULE_RE = re.compile(r"\b(exploit/[A-Za-z0-9_./-]+)\b")
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _msfconsole_bin() -> Optional[str]:
    return shutil.which("msfconsole")


def build_msf_search_queries(
    service: str,
    version: str,
    *,
    port: int = 0,
) -> list[str]:
    """Search keywords for msf search (deduped, order preserved)."""
    queries: list[str] = []
    seen: set[str] = set()

    def add(q: str) -> None:
        q = (q or "").strip()
        if not q:
            return
        key = q.lower()
        if key in seen:
            return
        seen.add(key)
        queries.append(q)

    ver_raw = (version or "").strip()
    ver = ver_raw.lower()
    svc = (service or "").lower()

    if "ssh" in svc:
        tokens = _version_tokens(ver_raw)
        if "openssh" in ver and tokens:
            add(f"openssh {tokens[0]}")
        elif "openssh" in ver:
            add("openssh")
        return queries

    if "miniserv" in ver or "webmin" in ver or "miniserv" in svc or "webmin" in svc:
        # Product search only — port:10000 fills results with unrelated modules
        # (Oracle, Veritas, …) and pushes out webmin_backdoor.
        add("webmin")
        return queries

    if "tomcat" in ver:
        add("tomcat")
        if tokens := _version_tokens(ver_raw):
            add(f"tomcat {tokens[0]}")

    base = build_search_query(service, version, port=port)
    if base and len(base) <= 48:
        add(base)

    if port and port not in MSF_GENERIC_PORTS:
        add(f"port:{port}")

    return queries


def product_keywords(service: str, version: str) -> list[str]:
    """Tokens for matching MSF module paths to the detected product."""
    ver = (version or "").lower()
    svc = (service or "").lower()
    keys: list[str] = []
    seen: set[str] = set()

    def add(k: str) -> None:
        k = k.strip().lower()
        if k and k not in seen:
            seen.add(k)
            keys.append(k)

    if "webmin" in ver or "miniserv" in ver or "webmin" in svc or "miniserv" in svc:
        add("webmin")
        add("miniserv")
    if "tomcat" in ver:
        add("tomcat")
    if "apache httpd" in ver or ("apache" in ver and "httpd" in ver):
        add("apache")
    if "openssh" in ver or "ssh" in svc:
        add("openssh")
    if "vsftpd" in ver or "ftp" in svc:
        add("vsftpd")
    return keys


def prioritize_module_names(
    module_names: list[str],
    *,
    service: str,
    version: str,
) -> list[str]:
    """
    Keep modules whose path matches the product; drop port-noise when product hits exist.
    """
    keys = product_keywords(service, version)
    if not keys:
        return module_names

    matched = [m for m in module_names if any(k in m.lower() for k in keys)]
    if matched:
        return matched
    return module_names


def _msf_search_csv_command(query: str, csv_path: str) -> str:
    q = query.replace('"', '\\"')
    path = csv_path.replace('"', '\\"')
    return f'msfconsole -q -x "search {q} type:exploit -o {path}; exit"'


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text or "")


def _parse_msf_search_csv(csv_path: str) -> list[str]:
    path = Path(csv_path)
    if not path.is_file():
        return []

    modules: list[str] = []
    seen: set[str] = set()
    with path.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            name = (row.get("Name") or "").strip()
            if not name.startswith("exploit/"):
                continue
            if name not in seen:
                seen.add(name)
                modules.append(name)
    return modules


def _run_msf_command(ip: str, command: str) -> tuple[int, str]:
    exec_id = run_command(
        ip,
        command,
        timeout_sec=MSF_TIMEOUT_SEC,
        stream=False,
        task_type=TASK_TYPE,
    )
    conn = connect()
    row = conn.execute(
        "SELECT stdout FROM executions WHERE id = ?",
        (exec_id,),
    ).fetchone()
    conn.close()
    stdout = (row["stdout"] if row else "") or ""
    return exec_id, stdout


def _parse_msf_search_stdout(stdout: str) -> list[str]:
    """Fallback when CSV export is unavailable (ANSI codes stripped)."""
    modules: list[str] = []
    seen: set[str] = set()
    for line in (stdout or "").splitlines():
        line = _strip_ansi(line)
        if "\\_ target:" in line or " \\_ target:" in line:
            continue
        for match in _MSF_MODULE_RE.finditer(line):
            mod = match.group(1).rstrip(",")
            if mod not in seen:
                seen.add(mod)
                modules.append(mod)
    return modules


def _run_msf_search(ip: str, query: str) -> tuple[int, list[str]]:
    """
    Run msf search and return module fullnames.

    Uses `search -o file.csv` (same as manual workflow); stdout table is fallback only.
    """
    fd, csv_path = tempfile.mkstemp(prefix="msf_scout_", suffix=".csv")
    os.close(fd)
    try:
        last_exec_id, stdout = _run_msf_command(
            ip,
            _msf_search_csv_command(query, csv_path),
        )
        modules = _parse_msf_search_csv(csv_path)
        if not modules:
            modules = _parse_msf_search_stdout(stdout)
        if not modules:
            last_exec_id, stdout = _run_msf_command(
                ip,
                _msf_search_csv_command(query, csv_path),
            )
            modules = _parse_msf_search_csv(csv_path) or _parse_msf_search_stdout(stdout)
        return last_exec_id, modules
    finally:
        Path(csv_path).unlink(missing_ok=True)


def _msf_info_command(fullnames: list[str]) -> str:
    mods = " ".join(fullnames)
    return f'msfconsole -q -x "info -j {mods}; exit"'


def _parse_msf_info_json(stdout: str) -> list[dict]:
    out: list[dict] = []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict) and data.get("fullname"):
            out.append(data)
    return out


def _option_map(module: dict) -> dict[str, str]:
    opts: dict[str, str] = {}
    for row in module.get("options") or []:
        if not isinstance(row, dict):
            continue
        name = (row.get("name") or "").strip()
        if not name:
            continue
        opts[name] = str(row.get("display_value") or "")
    return opts


def _fetch_modules_info(ip: str, module_names: list[str]) -> tuple[list[dict], Optional[int]]:
    """info -j for module list; retry individually for any batch misses."""
    modules: list[dict] = []
    by_name: dict[str, dict] = {}
    last_exec_id: Optional[int] = None

    def ingest(batch: list[str], stdout: str) -> None:
        for raw in _parse_msf_info_json(stdout):
            fullname = raw.get("fullname")
            if fullname:
                by_name[fullname] = _normalize_module(raw)

    if not module_names:
        return modules, last_exec_id

    for i in range(0, len(module_names), MSF_INFO_BATCH):
        batch = module_names[i : i + MSF_INFO_BATCH]
        last_exec_id, stdout = _run_msf_command(ip, _msf_info_command(batch))
        ingest(batch, stdout)

    missing = [name for name in module_names if name not in by_name]
    for name in missing:
        last_exec_id, stdout = _run_msf_command(ip, _msf_info_command([name]))
        ingest([name], stdout)

    for name in module_names:
        if name in by_name:
            modules.append(by_name[name])
    return modules, last_exec_id


def _normalize_module(module: dict) -> dict:
    refs = module.get("references") or []
    cves = [r for r in refs if isinstance(r, str) and "CVE" in r.upper()]
    opts = _option_map(module)
    key_opts = {}
    for name in ("RPORT", "SSL", "TARGETURI", "RHOSTS"):
        if name in opts:
            key_opts[name] = opts[name]
    return {
        "fullname": module.get("fullname") or "",
        "name": module.get("name") or "",
        "rank": module.get("rank") or "",
        "check": module.get("check_supported")
        if "check_supported" in module
        else module.get("check"),
        "description": (module.get("description") or "").strip(),
        "references": refs,
        "cves": cves,
        "options": key_opts,
    }


def _clear_msf_artifacts(ip: str) -> None:
    conn = connect()
    conn.execute(
        "DELETE FROM artifacts WHERE ip = ? AND kind = ?",
        (ip, MSF_REPORT_KIND),
    )
    conn.commit()
    conn.close()


def _store_msf_report(
    ip: str,
    port_key: str,
    *,
    queries: list[str],
    service: str,
    version: str,
    modules: list[dict],
    execution_id: Optional[int],
) -> None:
    payload = {
        "queries": queries,
        "service": service,
        "version": version,
        "exec_id": execution_id,
        "modules": modules,
    }
    conn = connect()
    conn.execute(
        "DELETE FROM artifacts WHERE ip = ? AND kind = ? AND key = ?",
        (ip, MSF_REPORT_KIND, port_key),
    )
    conn.commit()
    conn.close()
    add_artifact(
        ip,
        MSF_REPORT_KIND,
        port_key,
        json.dumps(payload, ensure_ascii=False),
        execution_id,
    )


def load_msf_reports(ip: str) -> list[dict]:
    conn = connect()
    rows = conn.execute(
        """
        SELECT key, value FROM artifacts
        WHERE ip = ? AND kind = ?
        ORDER BY id DESC
        """,
        (ip, MSF_REPORT_KIND),
    ).fetchall()
    conn.close()

    out: list[dict] = []
    seen: set[str] = set()
    for row in rows:
        key = row["key"]
        if key in seen:
            continue
        seen.add(key)
        try:
            data = json.loads(row["value"])
        except (json.JSONDecodeError, TypeError):
            continue
        data["port_key"] = key
        out.append(data)

    return sorted(out, key=lambda r: (int(r["port_key"].split("/")[0]), r["port_key"]))


def lookup_msf_for_port(
    ip: str,
    port: int,
    proto: str,
    service: str,
    version: str,
    *,
    force: bool = False,
) -> Optional[dict]:
    """Run MSF search + info -j for one open port; store msf_report artifact."""
    port_key = f"{int(port)}/{proto}"
    queries = build_msf_search_queries(service, version, port=int(port))
    if not queries:
        return None

    if not _msfconsole_bin():
        return {
            "port_key": port_key,
            "queries": queries,
            "service": service,
            "version": version,
            "modules": [],
            "error": "msfconsole not found",
            "exec_id": None,
        }

    if force:
        conn = connect()
        conn.execute(
            "DELETE FROM artifacts WHERE ip = ? AND kind = ? AND key = ?",
            (ip, MSF_REPORT_KIND, port_key),
        )
        conn.commit()
        conn.close()

    module_names: list[str] = []
    seen_mod: set[str] = set()
    last_exec_id: Optional[int] = None

    for query in queries:
        if len(module_names) >= MSF_MODULE_LIMIT:
            break
        last_exec_id, found = _run_msf_search(ip, query)
        for mod in found:
            if mod not in seen_mod:
                seen_mod.add(mod)
                module_names.append(mod)
            if len(module_names) >= MSF_MODULE_LIMIT:
                break

    module_names = prioritize_module_names(
        module_names,
        service=service or "",
        version=version or "",
    )[:MSF_MODULE_LIMIT]

    modules, info_exec_id = _fetch_modules_info(ip, module_names)
    if info_exec_id is not None:
        last_exec_id = info_exec_id

    _store_msf_report(
        ip,
        port_key,
        queries=queries,
        service=service or "",
        version=version or "",
        modules=modules,
        execution_id=last_exec_id,
    )

    return {
        "port_key": port_key,
        "queries": queries,
        "service": service,
        "version": version,
        "modules": modules,
        "exec_id": last_exec_id,
    }


def run_msf_phase(ip: str, *, force: bool = True, quiet: bool = False) -> int:
    from db import fetch_merged_open_ports

    if not _msfconsole_bin():
        if not quiet:
            print("[-] msfconsole not found — MSF section will be empty")
        return 0

    if force:
        _clear_msf_artifacts(ip)

    rows = sorted(fetch_merged_open_ports(ip), key=lambda r: int(r[0]))
    if not rows:
        return 0

    if not quiet:
        print("[*] exploit-pack: metasploit lookup")

    for row in rows:
        port, proto, _state, service, version = row
        result = lookup_msf_for_port(
            ip,
            int(port),
            proto,
            service or "",
            version or "",
            force=False,
        )
        if not quiet and result:
            n = len(result.get("modules") or [])
            q = ", ".join(result.get("queries") or [])
            print(f"[*] {port}/{proto}  queries={q}  modules={n}")

    return 0
