"""Hash-list storage (artifacts kind=hash) with lifecycle state."""

from __future__ import annotations

import json
from dataclasses import asdict
from dataclasses import dataclass
from datetime import datetime
from datetime import timezone

from hash_crack import UnsupportedHashFormat
from hash_crack import convert_to_john

HASH_KIND = "hash"
HASH_SOURCE_MSF = "msfr/pg-hashdump"
HASH_SOURCE_MANUAL = "manual"

STATE_IMPORTED = "imported"
STATE_JOHN_READY = "john_ready"
STATE_CRACKED = "cracked"
STATE_FAILED = "failed"
STATE_UNSUPPORTED = "unsupported"

CRACKABLE_STATES = frozenset({STATE_IMPORTED, STATE_JOHN_READY, STATE_FAILED})


@dataclass
class HashEntry:
    username: str
    format: str
    stored: str
    state: str = STATE_IMPORTED
    john: str | None = None
    source: str = HASH_SOURCE_MANUAL
    raw: str = ""
    parser: str = ""
    imported_at: str = ""
    converted_at: str = ""
    cracked_at: str = ""

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, separators=(",", ":"))

    @classmethod
    def from_json(cls, username: str, raw: str) -> HashEntry:
        data = json.loads(raw or "{}")
        kwargs = {name: data[name] for name in cls.__dataclass_fields__ if name in data}
        kwargs.setdefault("username", username)
        return cls(**kwargs)


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def new_entry(
    *,
    username: str,
    format: str,
    stored: str,
    source: str = HASH_SOURCE_MANUAL,
    raw: str = "",
    parser: str = "",
    state: str | None = None,
) -> HashEntry:
    if format == "scram_sha256" or state == STATE_UNSUPPORTED:
        st = STATE_UNSUPPORTED
    else:
        st = state or STATE_IMPORTED
    return HashEntry(
        username=username,
        format=format,
        stored=stored,
        state=st,
        source=source,
        raw=raw,
        parser=parser,
        imported_at=_now_iso(),
    )


def entry_from_import(record) -> HashEntry:
    return new_entry(
        username=record.username,
        format=record.format,
        stored=record.stored,
        source=HASH_SOURCE_MSF,
        raw=record.raw,
        parser=record.parser,
        state=STATE_UNSUPPORTED if record.format == "unsupported" else STATE_IMPORTED,
    )


def merge_on_import(existing: HashEntry | None, incoming: HashEntry) -> tuple[HashEntry, str]:
    """Return (entry, status) where status is saved|updated|unchanged."""
    if existing is None:
        return incoming, "saved"
    if existing.stored == incoming.stored and existing.format == incoming.format:
        return existing, "unchanged"
    incoming.state = (
        STATE_UNSUPPORTED if incoming.format == "unsupported" else STATE_IMPORTED
    )
    incoming.john = None
    incoming.converted_at = ""
    incoming.cracked_at = ""
    incoming.imported_at = _now_iso()
    return incoming, "updated"


def ensure_john_line(entry: HashEntry) -> HashEntry:
    if entry.state == STATE_UNSUPPORTED:
        raise UnsupportedHashFormat(entry.format)
    if entry.state == STATE_CRACKED:
        return entry
    if entry.state == STATE_JOHN_READY and entry.john:
        return entry
    entry.john = convert_to_john(entry.format, entry.username, entry.stored)
    entry.state = STATE_JOHN_READY
    entry.converted_at = _now_iso()
    return entry


def mark_cracked(entry: HashEntry) -> HashEntry:
    entry.state = STATE_CRACKED
    entry.cracked_at = _now_iso()
    return entry


def mark_failed(entry: HashEntry) -> HashEntry:
    entry.state = STATE_FAILED
    return entry


def should_crack(entry: HashEntry, *, force: bool = False) -> bool:
    if entry.state == STATE_UNSUPPORTED:
        return False
    if entry.state == STATE_CRACKED:
        return False
    if entry.state == STATE_FAILED:
        return force
    return entry.state in {STATE_IMPORTED, STATE_JOHN_READY}
