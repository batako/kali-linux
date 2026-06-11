"""Hash-crack helpers (john line conversion, etc.)."""

from __future__ import annotations

import re

_POSTGRES_STORED_MD5 = re.compile(r"^md5([a-fA-F0-9]{32})$", re.IGNORECASE)


def is_postgres_stored_md5(value: str) -> bool:
    return bool(_POSTGRES_STORED_MD5.match((value or "").strip()))


def postgres_stored_to_john_line(username: str, stored_hash: str) -> str:
    """
    PostgreSQL pg_authid / MSF hashdump → john dynamic_1034 line.

    Stored: md5 + md5(password || username) hex
    John:   user:$dynamic_1034$<hex>   (dynamic_1034 = md5($p.$u))
    """
    m = _POSTGRES_STORED_MD5.match((stored_hash or "").strip())
    if not m:
        raise ValueError(f"invalid postgres stored md5: {stored_hash!r}")
    user = (username or "").strip()
    if not user:
        raise ValueError("username required for postgres md5 hash")
    return f"{user}:$dynamic_1034${m.group(1).lower()}"
