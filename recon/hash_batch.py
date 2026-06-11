"""Batch hash-crack against hash-list store."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from db import creds_upsert
from db import hash_save_entry
from db import list_hash_entries
from hash_crack import UnsupportedHashFormat
from hash_crack import john_format_for
from hash_store import STATE_CRACKED
from hash_store import STATE_FAILED
from hash_store import STATE_UNSUPPORTED
from hash_store import ensure_john_line
from hash_store import mark_cracked
from hash_store import mark_failed
from hash_store import should_crack

_JOHN_SHOW_LINE = re.compile(r"^([^:]+):\$dynamic_1034\$[^:]+:(.+)$")


def prepare_batch(ip: str, *, force: bool = False) -> tuple[list[str], list[str], str | None]:
    """
    Convert pending hash-list entries to john lines.
    Returns (john_lines, usernames, john_format).
    """
    entries = list_hash_entries(ip)
    lines: list[str] = []
    users: list[str] = []
    fmt: str | None = None

    for entry in entries:
        if not should_crack(entry, force=force):
            continue
        try:
            entry = ensure_john_line(entry)
            hash_save_entry(ip, entry)
        except UnsupportedHashFormat:
            entry.state = STATE_UNSUPPORTED
            hash_save_entry(ip, entry)
            continue
        jf = john_format_for(entry.format)
        if fmt is None:
            fmt = jf
        elif jf != fmt:
            raise RuntimeError(
                f"mixed hash formats in batch ({fmt} vs {jf}); crack per-user"
            )
        if entry.john:
            lines.append(entry.john)
            users.append(entry.username)

    return lines, users, fmt


def parse_john_show(text: str) -> dict[str, str]:
    cracked: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or "0 password hashes" in line:
            continue
        m = _JOHN_SHOW_LINE.match(line)
        if m:
            cracked[m.group(1)] = m.group(2)
            continue
        if "$dynamic_1034$" in line and ":" in line:
            parts = line.split(":")
            if len(parts) >= 3 and parts[1].startswith("$dynamic_1034$"):
                cracked[parts[0]] = ":".join(parts[2:])
            elif len(parts) == 2:
                cracked[parts[0]] = parts[1]
    return cracked


def parse_john_crack_stdout(text: str) -> dict[str, str]:
    """Fallback: john progress lines like 'password         (username)'."""
    cracked: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        m = re.match(r"^(\S+)\s+\(([^)]+)\)\s*$", line)
        if m:
            cracked[m.group(2)] = m.group(1)
    return cracked


def apply_batch_results(
    ip: str,
    attempted_users: list[str],
    show_text: str,
    *,
    crack_text: str = "",
    comment: str = "hash-crack postgres",
) -> list[dict]:
    cracked_map = parse_john_show(show_text)
    if not cracked_map and crack_text:
        cracked_map = parse_john_crack_stdout(crack_text)
    results = []
    for user in attempted_users:
        entries = [e for e in list_hash_entries(ip) if e.username == user]
        if not entries:
            continue
        entry = entries[0]
        if user in cracked_map:
            entry = mark_cracked(entry)
            hash_save_entry(ip, entry)
            status = creds_upsert(
                ip=ip,
                username=user,
                password=cracked_map[user],
                comment=comment,
            )
            results.append(
                {
                    "ip": ip,
                    "username": user,
                    "password": cracked_map[user],
                    "comment": comment,
                    "status": status,
                    "hash_state": STATE_CRACKED,
                }
            )
        else:
            entry = mark_failed(entry)
            hash_save_entry(ip, entry)
    return results


def run_john_batch(
    hash_file: Path,
    pot_file: Path,
    wordlist: Path,
    john_format: str,
    *,
    force: bool = False,
) -> tuple[int, str]:
    if force and pot_file.exists():
        pot_file.unlink()

    args = [
        "john",
        f"--format={john_format}",
        str(hash_file),
        f"--wordlist={wordlist}",
        f"--pot={pot_file}",
    ]
    proc = subprocess.run(args, capture_output=True, text=True)
    out = (proc.stdout or "") + (proc.stderr or "")
    if proc.stdout:
        print(proc.stdout, end="")
    if proc.stderr:
        print(proc.stderr, end="")
    return proc.returncode, out


def show_john_batch(
    hash_file: Path, pot_file: Path, john_format: str
) -> str:
    """--show must use the same --pot as the crack run (isolated per batch)."""
    attempts: list[list[str]] = []
    if pot_file.exists():
        attempts.append(
            ["john", f"--format={john_format}", f"--pot={pot_file}", "--show", str(hash_file)]
        )
    attempts.append(
        ["john", f"--format={john_format}", "--show", str(hash_file)]
    )

    for args in attempts:
        proc = subprocess.run(args, capture_output=True, text=True)
        text = (proc.stdout or "") + (proc.stderr or "")
        if text.strip() and "0 password hashes" not in text:
            return text
    return ""
