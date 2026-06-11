"""Parse hashdump output (MSF and manual) into canonical HashRecords."""

from __future__ import annotations

import re
from dataclasses import dataclass

_POSTGRES_MD5 = re.compile(r"^md5([a-fA-F0-9]{32})$", re.IGNORECASE)
_SCRAM = re.compile(r"^SCRAM-SHA-256\$", re.IGNORECASE)

# MSF postgres_hashdump table rows
_MSF_TABLE = re.compile(
    r"^([A-Za-z0-9_.-]+)\s+md5([a-fA-F0-9]{32})\s*$",
    re.IGNORECASE,
)
_MSF_COLON = re.compile(
    r"^([A-Za-z0-9_.-]+):md5([a-fA-F0-9]{32})\s*$",
    re.IGNORECASE,
)
_MANUAL_COLON = re.compile(
    r"^([A-Za-z0-9_.-]+):([^\s]+)\s*$",
)

_SKIP_PREFIXES = ("username", "--------", "#", "[", "(*)", "query text")


@dataclass
class HashRecord:
    username: str
    format: str
    stored: str
    raw: str
    parser: str


def _canonical_postgres_md5(hex_part: str) -> str:
    return f"md5{hex_part.lower()}"


def _record_postgres(username: str, hex_part: str, raw: str, parser: str) -> HashRecord:
    return HashRecord(
        username=username,
        format="postgres_md5",
        stored=_canonical_postgres_md5(hex_part),
        raw=raw,
        parser=parser,
    )


def _record_scram(username: str, value: str, raw: str, parser: str) -> HashRecord:
    return HashRecord(
        username=username,
        format="scram_sha256",
        stored=value.strip(),
        raw=raw,
        parser=parser,
    )


def _try_line(line: str) -> HashRecord | None:
    line = line.strip()
    if not line:
        return None
    low = line.lower()
    if any(low.startswith(p) for p in _SKIP_PREFIXES):
        return None

    m = _MSF_TABLE.match(line)
    if m:
        return _record_postgres(m.group(1), m.group(2), line, "msf_hashdump/table")

    m = _MSF_COLON.match(line)
    if m:
        return _record_postgres(m.group(1), m.group(2), line, "msf_hashdump/colon")

    m = _MANUAL_COLON.match(line)
    if m:
        user, val = m.group(1), m.group(2)
        if _POSTGRES_MD5.match(val):
            return _record_postgres(user, _POSTGRES_MD5.match(val).group(1), line, "manual/colon")
        if _SCRAM.match(val):
            return _record_scram(user, val, line, "manual/scram")
        return HashRecord(user, "unknown", val, line, "manual/unknown")

    parts = line.split()
    if len(parts) == 2:
        user, val = parts
        if _POSTGRES_MD5.match(val):
            return _record_postgres(user, _POSTGRES_MD5.match(val).group(1), line, "manual/fields")
        if _SCRAM.match(val):
            return _record_scram(user, val, line, "manual/fields")

    return None


def parse_hashdump_text(text: str) -> list[HashRecord]:
    if not text:
        return []
    seen: set[tuple[str, str]] = set()
    out: list[HashRecord] = []
    for line in text.splitlines():
        rec = _try_line(line)
        if not rec:
            continue
        key = (rec.username, rec.stored)
        if key in seen:
            continue
        seen.add(key)
        out.append(rec)
    return out


def parse_msf_hashdump(text: str) -> list[HashRecord]:
    return parse_hashdump_text(text)
