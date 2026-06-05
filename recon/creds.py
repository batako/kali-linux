import re

from db import creds_upsert

# hydra success: host/login/password with optional fields (e.g. misc: (null))
HYDRA_SSH_FOUND = re.compile(
    r"\[\d+\]\[ssh\]\s+host:\s+(\S+).*?\blogin:\s+(\S+)\s+password:\s*(\S*)",
    re.IGNORECASE,
)
HYDRA_FTP_FOUND = re.compile(
    r"\[\d+\]\[ftp\]\s+host:\s+(\S+).*?\blogin:\s+(\S+)\s+password:\s*(\S*)",
    re.IGNORECASE,
)
HYDRA_HTTP_FOUND = re.compile(
    r"\[\d+\]\[(?:https?-(?:post|get)-form)\]\s+host:\s+(\S+).*?\blogin:\s+(\S+)\s+password:\s*(\S*)",
    re.IGNORECASE,
)


def _import_hydra_matches(text: str, pattern, ip: str = None, execution_id=None):
    if not text:
        return []

    results = []
    seen = set()

    for m in pattern.finditer(text):
        host, username, password = m.group(1), m.group(2), m.group(3)
        if not username:
            continue
        target_ip = ip or host
        dedupe_key = (target_ip, username, password)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)

        status = creds_upsert(
            ip=target_ip,
            username=username,
            password=password,
            execution_id=execution_id,
        )
        results.append(
            {
                "ip": target_ip,
                "username": username,
                "password": password,
                "status": status,
            }
        )

    return results


def import_hydra_ssh(text: str, ip: str = None, execution_id=None):
    """Parse hydra output for ssh valid pairs."""
    return _import_hydra_matches(text, HYDRA_SSH_FOUND, ip=ip, execution_id=execution_id)


def import_hydra_ftp(text: str, ip: str = None, execution_id=None):
    """Parse hydra output for ftp valid pairs."""
    return _import_hydra_matches(text, HYDRA_FTP_FOUND, ip=ip, execution_id=execution_id)


def import_hydra_http(text: str, ip: str = None, execution_id=None):
    """Parse hydra output for http(s)-form valid pairs."""
    return _import_hydra_matches(text, HYDRA_HTTP_FOUND, ip=ip, execution_id=execution_id)


def import_hydra(text: str, ip: str = None, execution_id=None):
    """Parse hydra output for ssh, ftp, and http-form valid pairs."""
    combined = []
    seen = set()
    for importer in (import_hydra_ssh, import_hydra_ftp, import_hydra_http):
        for row in importer(text, ip=ip, execution_id=execution_id):
            key = (row["ip"], row["username"], row["password"])
            if key not in seen:
                seen.add(key)
                combined.append(row)
    return combined


RECON_CREDS_BANNER = "----- recon -----"


def _status_line(r):
    ip = r["ip"]
    user = r["username"]
    st = r["status"]
    if st == "unchanged":
        return f"[=] creds unchanged: {user}@{ip}"
    if st == "updated":
        return f"[~] creds updated: {user}@{ip}"
    return f"[+] creds saved: {user}@{ip}"


def format_import_results(results):
    return [_status_line(r) for r in results]


def emit_import_results(results, stream=None):
    """
    Print creds import summary after tool output (stdout).
    Banner separates recon lines from hydra; login/password repeated in plain text
    (hydra highlights are lost in logs and tee).
    """
    import sys

    if stream is None:
        stream = sys.stdout

    if not results:
        return

    print("", file=stream)
    print(RECON_CREDS_BANNER, file=stream)
    for r in results:
        print(_status_line(r), file=stream)
        print(f"    login:    {r['username']}", file=stream)
        print(f"    password: {r['password']}", file=stream)
