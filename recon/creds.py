import re

from db import creds_upsert

# hydra ssh success: host/login/password with optional fields (e.g. misc: (null))
HYDRA_SSH_FOUND = re.compile(
    r"\[\d+\]\[ssh\]\s+host:\s+(\S+).*?\blogin:\s+(\S+)\s+password:\s+(\S+)",
    re.IGNORECASE,
)


def import_hydra_ssh(text: str, ip: str = None, execution_id=None):
    """
    Parse hydra stdout/stderr for ssh valid pairs and upsert creds.
    Returns list of dicts: {ip, username, password, status}
    """
    if not text:
        return []

    results = []
    seen = set()

    for m in HYDRA_SSH_FOUND.finditer(text):
        host, username, password = m.group(1), m.group(2), m.group(3)
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
