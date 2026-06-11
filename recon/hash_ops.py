"""Hash-list import and CLI helpers."""

from __future__ import annotations

from hash_import import HashRecord
from hash_import import parse_hashdump_text
from hash_import import parse_msf_hashdump

from db import hash_upsert_entry


def import_hash_records(ip: str, records: list[HashRecord]) -> list[dict]:
    results = []
    for rec in records:
        status = hash_upsert_entry(ip, rec)
        results.append(
            {
                "ip": ip,
                "username": rec.username,
                "stored": rec.stored,
                "format": rec.format,
                "status": status,
                "parser": rec.parser,
            }
        )
    return results


def import_msf_hashdump(text: str, ip: str) -> list[dict]:
    return import_hash_records(ip, parse_msf_hashdump(text))


def import_hash_text(text: str, ip: str) -> list[dict]:
    return import_hash_records(ip, parse_hashdump_text(text))


def format_import_lines(results: list[dict]) -> list[str]:
    lines = []
    for r in results:
        st = r["status"]
        user = r["username"]
        ip = r["ip"]
        if st == "unchanged":
            lines.append(f"[=] hash unchanged: {user}@{ip}")
        elif st == "updated":
            lines.append(f"[~] hash updated: {user}@{ip}")
        else:
            lines.append(f"[+] hash saved: {user}@{ip}")
        lines.append(f"    stored: {r['stored']}")
        if r.get("parser"):
            lines.append(f"    parser: {r['parser']}")
    return lines
