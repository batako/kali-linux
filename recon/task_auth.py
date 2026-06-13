"""Auth-quick task catalog: plan generation from scout open ports."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from db import fetch_merged_open_ports

SECLISTS_ROOT = Path("/usr/share/seclists")

POSTGRES_USERPASS = (
    SECLISTS_ROOT / "Passwords/Default-Credentials/postgres-betterdefaultpasslist.txt"
)

SSH_QUICK_USERPASS = (
    Path(__file__).resolve().parent / "wordlists" / "ssh-quick-userpass.txt"
)

FTP_QUICK_USERPASS = (
    Path(__file__).resolve().parent / "wordlists" / "ftp-quick-userpass.txt"
)


@dataclass(frozen=True)
class AuthTaskPlan:
    ip: str
    port: int
    service: str
    task_type: str
    command: str
    hydra_service: str
    meta: dict


def _normalize_service(service: str) -> str:
    return (service or "").lower().strip()


def _service_blob(service: str, version: str) -> str:
    return f"{_normalize_service(service)} {(version or '').lower()}"


def _port_flag(port: int) -> str:
    return f"-s {int(port)} "


def build_auth_command(
    *,
    ip: str,
    port: int,
    task_type: str,
) -> tuple[str, str, dict]:
    """Return (command, hydra_service, meta)."""
    pf = _port_flag(port)
    if task_type == "auth-ftp-anon":
        userpass = str(FTP_QUICK_USERPASS)
        cmd = f"hydra -C {userpass} -t 4 -f -V {pf}{ip} ftp"
        return cmd, "ftp", {"userpass": userpass}

    if task_type == "auth-pg-quick":
        userpass = str(POSTGRES_USERPASS)
        cmd = f"hydra -C {userpass} -t 4 -f -V {pf}{ip} postgres"
        return cmd, "postgres", {"userpass": userpass}

    if task_type == "auth-my-quick":
        cmd = f"hydra -l root -e ns -t 4 -f -V {pf}{ip} mysql"
        return cmd, "mysql", {"mode": "root-empty-ns"}

    if task_type == "auth-ssh-quick":
        userpass = str(SSH_QUICK_USERPASS)
        cmd = f"hydra -C {userpass} -t 4 -f -V {pf}{ip} ssh"
        return cmd, "ssh", {"userpass": userpass}

    raise ValueError(f"unknown auth task_type: {task_type}")


def match_auth_plans(
    ip: str,
    port: int,
    service: str,
    version: str = "",
) -> list[AuthTaskPlan]:
    svc = _normalize_service(service)
    blob = _service_blob(service, version)
    plans: list[AuthTaskPlan] = []

    if "ftp" in svc and "sftp" not in svc:
        cmd, hydra_svc, meta = build_auth_command(
            ip=ip, port=port, task_type="auth-ftp-anon"
        )
        plans.append(
            AuthTaskPlan(
                ip=ip,
                port=int(port),
                service=service or "ftp",
                task_type="auth-ftp-anon",
                command=cmd,
                hydra_service=hydra_svc,
                meta=meta,
            )
        )

    if "postgres" in blob:
        cmd, hydra_svc, meta = build_auth_command(
            ip=ip, port=port, task_type="auth-pg-quick"
        )
        plans.append(
            AuthTaskPlan(
                ip=ip,
                port=int(port),
                service=service or "postgresql",
                task_type="auth-pg-quick",
                command=cmd,
                hydra_service=hydra_svc,
                meta=meta,
            )
        )

    if "mysql" in blob or "mariadb" in blob:
        cmd, hydra_svc, meta = build_auth_command(
            ip=ip, port=port, task_type="auth-my-quick"
        )
        plans.append(
            AuthTaskPlan(
                ip=ip,
                port=int(port),
                service=service or "mysql",
                task_type="auth-my-quick",
                command=cmd,
                hydra_service=hydra_svc,
                meta=meta,
            )
        )

    if "ssh" in svc and "sftp" not in svc:
        cmd, hydra_svc, meta = build_auth_command(
            ip=ip, port=port, task_type="auth-ssh-quick"
        )
        plans.append(
            AuthTaskPlan(
                ip=ip,
                port=int(port),
                service=service or "ssh",
                task_type="auth-ssh-quick",
                command=cmd,
                hydra_service=hydra_svc,
                meta=meta,
            )
        )

    return plans


def resolve_auth_task_plans(ip: str) -> list[AuthTaskPlan]:
    plans: list[AuthTaskPlan] = []
    for row in fetch_merged_open_ports(ip):
        port = int(row[0])
        service = row[3] or ""
        version = row[4] or ""
        plans.extend(match_auth_plans(ip, port, service, version))
    return plans
