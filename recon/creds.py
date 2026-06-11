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
HYDRA_POP3_FOUND = re.compile(
    r"\[\d+\]\[pop3\]\s+host:\s+(\S+).*?\blogin:\s+(\S+)\s+password:\s*(\S*)",
    re.IGNORECASE,
)
HYDRA_HTTP_FORM_FOUND = re.compile(
    r"\[\d+\]\[(?:https?-(?:post|get)-form)\]\s+host:\s+(\S+).*?\blogin:\s+(\S+)\s+password:\s*(\S*)",
    re.IGNORECASE,
)
HYDRA_HTTP_BASIC_FOUND = re.compile(
    r"\[\d+\]\[https?-get\]\s+host:\s+(\S+).*?\blogin:\s+(\S+)\s+password:\s*(\S*)",
    re.IGNORECASE,
)

# Metasploit scanner/login modules
# MSF 6.4 postgres_login: "Login Successful: user:pass@db" (no quotes)
# Older: "Success: 'user:pass@db'"
MSF_POSTGRES_SUCCESS = re.compile(
    r"(?:Success:\s*'|Login Successful:\s*)([^:]+):([^@]+)@(?:[^']+'|\S+)",
    re.IGNORECASE,
)
# MSF 6.4 ssh_login may use "Login Successful: user pass proof"
MSF_SSH_SUCCESS = re.compile(
    r"(?:Success:\s*'|Login Successful:\s*)([^'\s]+)['\s]+'([^']*)'",
    re.IGNORECASE,
)
MSF_FTP_SUCCESS = re.compile(
    r"(?:Success:\s*'|Login Successful:\s*)([^:]+):([^'\s]+)'?",
    re.IGNORECASE,
)

MSFR_COMMENT = {
    "postgres": "PostgreSQL (msfr)",
    "ssh": "SSH (msfr)",
    "ftp": "FTP (msfr)",
}

# creds-list comments that qualify for msfr user pick (per family)
MSFR_FAMILY_CRED_TAGS = {
    "postgres": ("PostgreSQL (msfr)", "hash-crack postgres"),
    "ssh": ("SSH (msfr)",),
    "ftp": ("FTP (msfr)",),
}

# postgres msfr picker: exclude creds clearly tagged for other services
MSFR_POSTGRES_EXCLUDE_COMMENT_HINTS = (
    "ssh",
    "hydra",
    "ftp",
    "borg",
    "http",
    "pop3",
    "tomcat",
)


def _import_hydra_matches(text: str, pattern, ip: str = None, execution_id=None, comment: str = ""):
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
            comment=comment,
        )
        results.append(
            {
                "ip": target_ip,
                "username": username,
                "password": password,
                "comment": comment,
                "status": status,
            }
        )

    return results


def import_hydra_ssh(text: str, ip: str = None, execution_id=None):
    """Parse hydra output for ssh valid pairs."""
    return _import_hydra_matches(
        text, HYDRA_SSH_FOUND, ip=ip, execution_id=execution_id, comment="SSH (hydra)"
    )


def import_hydra_ftp(text: str, ip: str = None, execution_id=None):
    """Parse hydra output for ftp valid pairs."""
    return _import_hydra_matches(
        text, HYDRA_FTP_FOUND, ip=ip, execution_id=execution_id, comment="FTP (hydra)"
    )


def import_hydra_http(text: str, ip: str = None, execution_id=None):
    """Parse hydra output for http(s)-post/get-form valid pairs."""
    return _import_hydra_matches(
        text, HYDRA_HTTP_FORM_FOUND, ip=ip, execution_id=execution_id, comment="HTTP form (hydra)"
    )


def import_hydra_http_basic(text: str, ip: str = None, execution_id=None):
    """Parse hydra output for http(s)-get (Basic Auth) valid pairs."""
    return _import_hydra_matches(
        text, HYDRA_HTTP_BASIC_FOUND, ip=ip, execution_id=execution_id, comment="HTTP Basic (hydra)"
    )


def import_hydra_pop3(text: str, ip: str = None, execution_id=None):
    """Parse hydra output for pop3 valid pairs."""
    return _import_hydra_matches(
        text, HYDRA_POP3_FOUND, ip=ip, execution_id=execution_id, comment="POP3 (hydra)"
    )


def _import_msf_pairs(
    text: str,
    pattern,
    ip: str,
    *,
    comment: str,
    execution_id=None,
):
    if not text or not ip:
        return []

    results = []
    seen = set()
    for m in pattern.finditer(text):
        username, password = m.group(1), m.group(2)
        if not username:
            continue
        dedupe_key = (ip, username, password)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)

        status = creds_upsert(
            ip=ip,
            username=username,
            password=password,
            execution_id=execution_id,
            comment=comment,
        )
        results.append(
            {
                "ip": ip,
                "username": username,
                "password": password,
                "comment": comment,
                "status": status,
            }
        )
    return results


def import_msf_postgres_login(text: str, ip: str = None, execution_id=None):
    if not ip:
        return []
    return _import_msf_pairs(
        text,
        MSF_POSTGRES_SUCCESS,
        ip,
        comment=MSFR_COMMENT["postgres"],
        execution_id=execution_id,
    )


def import_msf_ssh_login(text: str, ip: str = None, execution_id=None):
    if not ip:
        return []
    return _import_msf_pairs(
        text,
        MSF_SSH_SUCCESS,
        ip,
        comment=MSFR_COMMENT["ssh"],
        execution_id=execution_id,
    )


def import_msf_ftp_login(text: str, ip: str = None, execution_id=None):
    if not ip:
        return []
    return _import_msf_pairs(
        text,
        MSF_FTP_SUCCESS,
        ip,
        comment=MSFR_COMMENT["ftp"],
        execution_id=execution_id,
    )


MSF_LOGIN_IMPORTERS = {
    "pg-login": import_msf_postgres_login,
    "postgres-login": import_msf_postgres_login,
    "ssh-login": import_msf_ssh_login,
    "ftp-login": import_msf_ftp_login,
}


def import_msf_login(preset: str, text: str, ip: str = None, execution_id=None):
    importer = MSF_LOGIN_IMPORTERS.get((preset or "").lower())
    if not importer:
        return []
    return importer(text, ip=ip, execution_id=execution_id)


def import_hydra(text: str, ip: str = None, execution_id=None):
    """Parse hydra output for ssh, ftp, http-form, and http-get (Basic) valid pairs."""
    combined = []
    seen = set()
    for importer in (
        import_hydra_ssh,
        import_hydra_ftp,
        import_hydra_http,
        import_hydra_http_basic,
        import_hydra_pop3,
    ):
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
        if r.get("comment"):
            print(f"    comment:  {r['comment']}", file=stream)
