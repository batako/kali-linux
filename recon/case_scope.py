"""Case-scoped recon data (THM room survives target IP changes)."""

from __future__ import annotations

import os
import re

from db import connect

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


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


def register_case_ip(case_name: str, ip: str) -> None:
    """Remember an IP used under this case (append-only history for el/cl)."""
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


def register_case_ip_from_env(ip: str) -> None:
    case = case_name_from_env()
    if case:
        register_case_ip(case, ip)
